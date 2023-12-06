#![allow(clippy::type_complexity)]
use clap::{Parser, ValueHint};
use forge_permission_resolver::permissions_resolver::{
    get_permission_resolver_confluence, get_permission_resolver_jira,
};
use miette::{IntoDiagnostic, Result};
use std::{
    collections::HashSet,
    convert::TryFrom,
    fs,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use swc_core::{
    common::{Globals, Mark, SourceMap, GLOBALS},
    ecma::{
        ast::EsVersion,
        parser::{parse_file_as_module, Syntax, TsConfig},
        transforms::base::resolver,
        visit::FoldWith,
    },
};
use tracing::{debug, instrument, warn};
use tracing_subscriber::{prelude::*, EnvFilter};
use tracing_tree::HierarchicalLayer;

use forge_analyzer::{
    checkers::{
        AuthZChecker, AuthenticateChecker, DefintionAnalysisRunner, PermissionChecker,
        PermissionVuln, PrototypePollutionChecker, SecretChecker,
    },
    ctx::{AppCtx, ModId},
    definitions::{run_resolver, DefId, Environment, PackageData},
    interp::Interp,
    reporter::Reporter,
    resolver::resolve_calls,
};

use forge_loader::manifest::{ForgeManifest, FunctionRef, FunctionTy};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    debug: bool,

    /// Dump a graphviz formatted callgraph
    #[arg(long)]
    callgraph: bool,

    /// Dump a graphviz formatted control flow graph of the function specified in `--function`
    #[arg(long)]
    cfg: bool,

    /// A specific function to scan. Must be an entrypoint specified in `manifest.yml`
    #[arg(short, long)]
    function: Option<String>,

    /// The Marketplace app key.
    #[arg(long)]
    appkey: Option<String>,

    /// A file to redirect output to.
    #[arg(short, long)]
    out: Option<PathBuf>,

    // Run the permission checker
    #[arg(long)]
    check_permissions: bool,

    // Run the prototype pollution scanner
    #[arg(long)]
    check_prototype_pollution: bool,

    /// The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level
    /// directory, and that the source code is located in `src/`
    #[arg(name = "DIRS", value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
struct Opts {
    dump_cfg: bool,
    dump_callgraph: bool,
    check_permissions: bool,
    check_prototype_pollution: bool,
    appkey: Option<String>,
    out: Option<PathBuf>,
}

struct ForgeProject {
    #[allow(dead_code)]
    sm: Arc<SourceMap>,
    ctx: AppCtx,
    env: Environment,
    funcs: Vec<FunctionTy<(String, PathBuf, ModId, DefId)>>,
    opts: Opts,
}

impl ForgeProject {
    #[instrument(skip(src, iter))]
    fn with_files_and_sourceroot<P: AsRef<Path>, I: IntoIterator<Item = PathBuf>>(
        src: P,
        iter: I,
        secret_packages: Vec<PackageData>,
    ) -> Self {
        let sm = Arc::<SourceMap>::default();
        let target = EsVersion::latest();
        let globals = Globals::new();
        let ctx = AppCtx::new(src);
        let ctx = iter.into_iter().fold(ctx, |mut ctx, p| {
            let sourcemap = Arc::clone(&sm);
            GLOBALS.set(&globals, || {
                debug!(file = %p.display(), "parsing");
                let src = sourcemap.load_file(&p).unwrap();
                debug!("loaded sourcemap");
                let mut recovered_errors = vec![];
                let module = parse_file_as_module(
                    &src,
                    Syntax::Typescript(TsConfig {
                        tsx: true,
                        decorators: true,
                        ..Default::default()
                    }),
                    target,
                    None,
                    &mut recovered_errors,
                )
                .unwrap();
                debug!("finished parsing");
                let mut hygeine = resolver(Mark::new(), Mark::new(), true);
                let module = module.fold_with(&mut hygeine);
                ctx.load_module(p, module);
                ctx
            })
        });
        let keys = ctx.module_ids().collect::<Vec<_>>();
        debug!(?keys);
        let env = run_resolver(ctx.modules(), ctx.file_resolver(), secret_packages);
        Self {
            sm,
            ctx,
            env,
            funcs: vec![],
            opts: Opts::default(),
        }
    }

    fn add_funcs<'a, I: IntoIterator<Item = FunctionTy<(&'a str, PathBuf)>>>(&mut self, iter: I) {
        self.funcs.extend(iter.into_iter().flat_map(|ftype| {
            ftype.sequence(|(func_name, path)| {
                let modid = self.ctx.modid_from_path(&path)?;
                let func = self.env.module_export(modid, func_name)?;
                Some((func_name.to_owned(), path, modid, func))
            })
        }));
    }
}

fn is_js_file<P: AsRef<Path>>(path: P) -> bool {
    matches!(
        path.as_ref().extension().map(|s| s.as_bytes()),
        Some(b"jsx" | b"js" | b"tsx" | b"ts")
    )
}

fn collect_sourcefiles<P: AsRef<Path>>(root: P) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root)
        .min_depth(1)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| {
            let path = e.ok()?.into_path();
            is_js_file(&path).then_some(path)
        })
}

#[tracing::instrument(level = "debug")]
fn scan_directory(dir: PathBuf, function: Option<&str>, opts: Opts) -> Result<ForgeProject> {
    let mut manifest_file = dir.clone();
    manifest_file.push("manifest.yaml");
    if !manifest_file.exists() {
        manifest_file.set_extension("yml");
    }
    debug!(?manifest_file);

    let manifest = fs::read_to_string(&manifest_file).into_diagnostic()?;
    let manifest: ForgeManifest = serde_yaml::from_str(&manifest).into_diagnostic()?;
    let name = manifest.app.name.unwrap_or_default();

    let requested_permissions = manifest.permissions;
    let permission_scopes = requested_permissions.scopes;
    let permissions_declared: HashSet<String> =
        HashSet::from_iter(permission_scopes.iter().map(|s| s.replace("\"", "")));

    let secret_packages: Vec<PackageData> =
        if let Result::Ok(f) = std::fs::File::open("secretdata.yaml") {
            let scrape_config: Vec<PackageData> =
                serde_yaml::from_reader(f).expect("Failed to deserialize package");
            scrape_config
        } else {
            vec![]
        };

    let paths = collect_sourcefiles(dir.join("src/")).collect::<HashSet<_>>();

    let transpiled_async = paths.iter().any(|path| {
        if let Ok(data) = fs::read_to_string(path) {
            return data
                .lines()
                .next()
                .is_some_and(|data| data == "\"use strict\";" || data == "'use strict';");
        }
        false
    });
    let run_permission_checker = opts.check_permissions && !transpiled_async;

    let funcrefs = manifest.modules.into_analyzable_functions().flat_map(|f| {
        f.sequence(|fmod| {
            let resolved_func = FunctionRef::try_from(fmod)?.try_resolve(&paths, &dir)?;
            Ok::<_, forge_loader::Error>(resolved_func.into_func_path())
        })
    });
    let src_root = dir.join("src");
    let mut proj =
        ForgeProject::with_files_and_sourceroot(src_root, paths.clone(), secret_packages);
    if transpiled_async {
        warn!("Unable to scan due to transpiled async");
    }
    proj.opts = opts.clone();
    proj.add_funcs(funcrefs);
    resolve_calls(&mut proj.ctx);

    let permissions = Vec::from_iter(permissions_declared.iter().cloned());

    let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira();
    let (confluence_permission_resolver, confluence_regex_map) =
        get_permission_resolver_confluence();

    let mut defintion_analysis_interp = Interp::new(
        &proj.env,
        true,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );

    let mut interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    let mut authn_interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    let mut perm_interp = Interp::new(
        &proj.env,
        true,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    let mut reporter = Reporter::new();
    let mut secret_interp = Interp::new(
        &proj.env,
        true,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    let mut pp_interp = Interp::new(
        &proj.env,
        true,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    reporter.add_app(opts.appkey.unwrap_or_default(), name.to_owned());
    //let mut all_used_permissions = HashSet::default();

    for func in &proj.funcs {
        match *func {
            FunctionTy::Invokable((ref func, ref path, _, def)) => {
                let mut runner = DefintionAnalysisRunner::new();
                debug!("checking Invokable {func} at {path:?}");
                if let Err(err) = defintion_analysis_interp.run_checker(
                    def,
                    &mut runner,
                    path.clone(),
                    func.clone(),
                ) {
                    warn!("error while getting definition analysis {func} in {path:?}: {err}");
                }
                let mut checker = AuthZChecker::new();
                debug!("Authorization Scaner on Invokable FunctionTy: checking {func} at {path:?}");
                if let Err(err) = interp.run_checker(def, &mut checker, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker.into_vulns());

                let mut checker2 = SecretChecker::new();
                secret_interp.value_manager.varid_to_value = defintion_analysis_interp.get_defs();
                secret_interp.value_manager.defid_to_value = defintion_analysis_interp
                    .value_manager
                    .defid_to_value
                    .clone();
                debug!("Secret Scanner on Invokable FunctionTy: checking {func} at {path:?}");
                if let Err(err) =
                    secret_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker2.into_vulns());

                debug!("Permission Scanners on Invokable FunctionTy: checking {func} at {path:?}");
                if run_permission_checker {
                    perm_interp.value_manager.varid_to_value = defintion_analysis_interp.get_defs();
                    perm_interp.value_manager.defid_to_value = defintion_analysis_interp
                        .value_manager
                        .defid_to_value
                        .clone();
                    let mut checker2 = PermissionChecker::new();
                    if let Err(err) =
                        perm_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                    {
                        warn!("error while scanning {func} in {path:?}: {err}");
                    }
                }
                if opts.check_prototype_pollution {
                    pp_interp.value_manager.varid_to_value = defintion_analysis_interp.get_defs();
                    pp_interp.value_manager.defid_to_value = defintion_analysis_interp
                        .value_manager
                        .defid_to_value
                        .clone();
                    pp_interp.run_checker(
                        def,
                        &mut PrototypePollutionChecker,
                        path.clone(),
                        func.clone(),
                    );
                }
            }
            FunctionTy::WebTrigger((ref func, ref path, _, def)) => {
                let mut runner = DefintionAnalysisRunner::new();
                debug!("checking Web Trigger {func} at {path:?}");
                if let Err(err) = defintion_analysis_interp.run_checker(
                    def,
                    &mut runner,
                    path.clone(),
                    func.clone(),
                ) {
                    warn!("error while getting definition analysis {func} in {path:?}: {err}");
                }

                let mut checker2 = SecretChecker::new();
                secret_interp.value_manager.varid_to_value = defintion_analysis_interp.get_defs();
                secret_interp.value_manager.defid_to_value = defintion_analysis_interp
                    .value_manager
                    .defid_to_value
                    .clone();
                debug!("Secret Scanner on Web Triggers: checking {func} at {path:?}");
                if let Err(err) =
                    secret_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker2.into_vulns());

                let mut checker = AuthenticateChecker::new();
                debug!("Authentication Checker on Web Triggers: checking webtrigger {func} at {path:?}");
                if let Err(err) =
                    authn_interp.run_checker(def, &mut checker, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker.into_vulns());

                debug!(
                    "Permission Checker on Web Triggers: checking webtrigger {func} at {path:?}"
                );
                if run_permission_checker {
                    perm_interp.value_manager.varid_to_value = defintion_analysis_interp.get_defs();
                    perm_interp.value_manager.defid_to_value = defintion_analysis_interp
                        .value_manager
                        .defid_to_value
                        .clone();
                    let mut checker2 = PermissionChecker::new();
                    if let Err(err) =
                        perm_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                    {
                        warn!("error while scanning {func} in {path:?}: {err}");
                    }
                }
            }
        }
    }

    if run_permission_checker {
        if perm_interp.permissions.len() > 0 {
            reporter.add_vulnerabilities(
                vec![PermissionVuln::new(perm_interp.permissions)].into_iter(),
            );
        }
    }

    let report = serde_json::to_string(&reporter.into_report()).into_diagnostic()?;
    debug!("On the debug layer: Writing Report");
    match opts.out {
        Some(path) => {
            fs::write(path, report).into_diagnostic()?;
        }
        None => println!("{report}"),
    }

    Ok(proj)
}

fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::registry()
        .with(HierarchicalLayer::new(2))
        .with(EnvFilter::from_env("FORGE_LOG"))
        .init();
    let function = args.function.as_deref();
    let opts = Opts {
        dump_callgraph: args.callgraph,
        dump_cfg: args.cfg,
        check_permissions: args.check_permissions,
        check_prototype_pollution: args.check_prototype_pollution,
        out: args.out,
        appkey: args.appkey,
    };
    for dir in args.dirs {
        debug!(?dir);
        scan_directory(dir, function, opts.clone())?;
    }
    Ok(())
}
