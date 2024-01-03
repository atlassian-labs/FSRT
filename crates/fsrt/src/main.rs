#![allow(clippy::type_complexity)]
use clap::{Parser, ValueHint};
use clap::{Parser, ValueHint};
use forge_permission_resolver::permissions_resolver::{
    get_permission_resolver_confluence, get_permission_resolver_jira,
};
use miette::{IntoDiagnostic, Result};
use miette::{IntoDiagnostic, Result};
use std::{
    collections::HashSet,
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

use forge_loader::manifest::{Entrypoint, ForgeManifest, Resolved};
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

    /// Dump the IR for the specified function
    #[arg(long)]
    dump_ir: Option<String>,

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

    /// The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level
    /// directory, and that the source code is located in `src/`
    #[arg(name = "DIRS", value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct ResolvedEntryPoint<'a> {
    func_name: &'a str,
    path: PathBuf,
    module: ModId,
    def_id: DefId,
    webtrigger: bool,
    invokable: bool,
    admin: bool,
}

struct ForgeProject<'a> {
    #[allow(dead_code)]
    sm: Arc<SourceMap>,
    ctx: AppCtx,
    env: Environment,
    funcs: Vec<ResolvedEntryPoint<'a>>,
}

impl<'a> ForgeProject<'a> {
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
    // TODO: edit to work with new iterator that not FUNCTIONTY
    fn add_funcs<I: IntoIterator<Item = Entrypoint<'a, Resolved>>>(&mut self, iter: I) {
        self.funcs.extend(iter.into_iter().filter_map(|entrypoint| {
            let (func_name, path) = entrypoint.function.into_func_path();
            let module = self.ctx.modid_from_path(&path)?;
            let def_id = self.env.module_export(module, func_name)?;
            Some(ResolvedEntryPoint {
                func_name,
                path,
                module,
                def_id,
                invokable: entrypoint.invokable,
                webtrigger: entrypoint.web_trigger,
                admin: entrypoint.admin,
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
fn scan_directory(dir: PathBuf, function: Option<&str>, opts: &Args) -> Result<()> {
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

    let funcrefs = manifest
        .modules
        .into_analyzable_functions()
        .flat_map(|entrypoint| {
            Ok::<_, forge_loader::Error>(Entrypoint {
                function: entrypoint.function.try_resolve(&paths, &dir)?,
                invokable: entrypoint.invokable,
                web_trigger: entrypoint.web_trigger,
                admin: entrypoint.admin,
            })
        });

    let src_root = dir.join("src");
    let mut proj = ForgeProject::with_files_and_sourceroot(src_root, paths.clone());
    proj.opts = opts.clone();
    proj.add_funcs(funcrefs);
    resolve_calls(&mut proj.ctx);
    if let Some(func) = opts.dump_ir.as_ref() {
        let mut lock = std::io::stdout().lock();
        proj.env.dump_function(&mut lock, func);
        return Ok(());
    }

    let permissions = Vec::from_iter(permissions_declared.iter().cloned());

    let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira();
    let (confluence_permission_resolver, confluence_regex_map) =
        get_permission_resolver_confluence();

    let mut definition_analysis_interp = Interp::<DefintionAnalysisRunner>::new(
        &proj.env,
        false,
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
    let mut reporter = Reporter::new();
    let mut secret_interp = Interp::<SecretChecker>::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    reporter.add_app(opts.appkey.clone().unwrap_or_default(), name.to_owned());
    //let mut all_used_permissions = HashSet::default();

    let mut perm_interp = Interp::<PermissionChecker>::new(
        &proj.env,
        false,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
    );
    for func in &proj.funcs {
        let mut def_checker = DefintionAnalysisRunner::new();
        if let Err(err) = definition_analysis_interp.run_checker(
            func.def_id,
            &mut def_checker,
            func.path.clone(),
            func.func_name.to_string(),
        ) {
            warn!(
                "error while scanning {:?} in {:?}: {err}",
                func.func_name, func.path,
            );
        }

        if run_permission_checker {
            let mut checker = PermissionChecker::new();
            perm_interp.value_manager.varid_to_value =
                definition_analysis_interp.value_manager.varid_to_value;
            perm_interp.value_manager.defid_to_value =
                definition_analysis_interp.value_manager.defid_to_value;
            if let Err(err) = perm_interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_owned(),
            ) {
                warn!("error while running permission checker: {err}");
            }
            definition_analysis_interp.value_manager.varid_to_value =
                perm_interp.value_manager.varid_to_value;
            definition_analysis_interp.value_manager.defid_to_value =
                perm_interp.value_manager.defid_to_value;
        }

        let mut checker = SecretChecker::new();
        secret_interp.value_manager.varid_to_value =
            definition_analysis_interp.value_manager.varid_to_value;
        secret_interp.value_manager.defid_to_value =
            definition_analysis_interp.value_manager.defid_to_value;
        if let Err(err) = secret_interp.run_checker(
            func.def_id,
            &mut checker,
            func.path.clone(),
            func.func_name.to_owned(),
        ) {
            warn!("error while running secret checker: {err}");
        } else {
            reporter.add_vulnerabilities(checker.into_vulns());
        }
        definition_analysis_interp.value_manager.varid_to_value =
            secret_interp.value_manager.varid_to_value;
        definition_analysis_interp.value_manager.defid_to_value =
            secret_interp.value_manager.defid_to_value;

        // Get entrypoint value from tuple
        // Logic for performing scans.
        // If it's invokable, then run invokable scan. If web_trigger, then trigger scan.
        // And if it's both, run both scans.
        if func.invokable {
            let mut checker = AuthZChecker::new();
            debug!("checking {:?} at {:?}", func.func_name, &func.path);
            if let Err(err) = interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_string(),
            ) {
                warn!(
                    "error while scanning {:?} in {:?}: {err}",
                    func.func_name, func.path,
                );
            }
            reporter.add_vulnerabilities(checker.into_vulns());
        } else if func.webtrigger {
            let mut checker = AuthenticateChecker::new();
            debug!(
                "checking webtrigger {:?} at {:?}",
                func.func_name, func.path,
            );
            if let Err(err) = authn_interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_string(),
            ) {
                warn!(
                    "error while scanning {:?} in {:?}: {err}",
                    func.func_name, func.path,
                );
            }
            reporter.add_vulnerabilities(checker.into_vulns());
        }
    }

    if perm_interp.permissions.len() > 0 {
        reporter
            .add_vulnerabilities(vec![PermissionVuln::new(perm_interp.permissions)].into_iter());
    }

    let report = serde_json::to_string(&reporter.into_report()).into_diagnostic()?;
    debug!("On the debug layer: Writing Report");
    match &opts.out {
        Some(path) => {
            fs::write(path, report).into_diagnostic()?;
        }
        None => println!("{report}"),
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    tracing_subscriber::registry()
        .with(HierarchicalLayer::new(2))
        .with(EnvFilter::from_env("FORGE_LOG"))
        .init();
    let dirs = std::mem::take(&mut args.dirs);
    let function = args.function.as_deref();
    for dir in dirs {
        debug!(?dir);
        scan_directory(dir, function, &args)?;
    }
    Ok(())
}
