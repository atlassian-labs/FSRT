#![allow(clippy::type_complexity)]
use clap::{Parser, ValueHint};
use forge_loader::forgepermissions::ForgePermissions;
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
    checkers::{AuthZChecker, AuthenticateChecker, PermissionChecker, PermissionVuln},
    ctx::{AppCtx, ModId},
    definitions::{run_resolver, DefId, Environment},
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

    /// The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level
    /// directory, and that the source code is located in `src/`
    #[arg(name = "DIRS", value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
struct Opts {
    dump_cfg: bool,
    dump_callgraph: bool,
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
        let env = run_resolver(ctx.modules(), ctx.file_resolver());
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
    let mut permissions_declared: HashSet<ForgePermissions> =
        HashSet::from_iter(permission_scopes.iter().cloned());

    let paths = collect_sourcefiles(dir.join("src/")).collect::<HashSet<_>>();
    let funcrefs = manifest.modules.into_analyzable_functions().flat_map(|f| {
        f.sequence(|fmod| {
            let resolved_func = FunctionRef::try_from(fmod)?.try_resolve(&paths, &dir)?;
            Ok::<_, forge_loader::Error>(resolved_func.into_func_path())
        })
    });
    let src_root = dir.join("src");
    let mut proj = ForgeProject::with_files_and_sourceroot(src_root.clone(), paths.clone());
    proj.opts = opts.clone();
    proj.add_funcs(funcrefs);
    resolve_calls(&mut proj.ctx);

    let mut interp = Interp::new(&proj.env);
    let mut authn_interp = Interp::new(&proj.env);
    let mut perm_interp = Interp::new(&proj.env);
    let mut reporter = Reporter::new();
    reporter.add_app(opts.appkey.unwrap_or_default(), name.to_owned());
    let mut all_used_permissions = HashSet::default();

    for func in &proj.funcs {
        match *func {
            FunctionTy::Invokable((ref func, ref path, _, def)) => {
                let mut checker = AuthZChecker::new();
                debug!("checking {func} at {path:?}");
                if let Err(err) = interp.run_checker(def, &mut checker, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker.into_vulns());
                let mut checker2 = PermissionChecker::new(permissions_declared.clone());
                if let Err(err) =
                    perm_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                {
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                all_used_permissions.extend(checker2.used_permissions);
            }
            FunctionTy::WebTrigger((ref func, ref path, _, def)) => {
                let mut checker = AuthenticateChecker::new();
                debug!("checking webtrigger {func} at {path:?}");
                if let Err(err) =
                    authn_interp.run_checker(def, &mut checker, path.clone(), func.clone())
                {
                    println!("error while scanning {func} in {path:?}: {err}");
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                reporter.add_vulnerabilities(checker.into_vulns());
                let mut checker2 = PermissionChecker::new(permissions_declared.clone());
                if let Err(err) =
                    perm_interp.run_checker(def, &mut checker2, path.clone(), func.clone())
                {
                    println!("error while scanning {func} in {path:?}: {err}");
                    warn!("error while scanning {func} in {path:?}: {err}");
                }
                all_used_permissions.extend(checker2.used_permissions);
            }
        }
    }
    let unused_permissions = permissions_declared.difference(&all_used_permissions);
    if unused_permissions.clone().count() > 0 {
        reporter.add_vulnerabilities(
            vec![PermissionVuln::new(HashSet::<ForgePermissions>::from_iter(
                unused_permissions.cloned().into_iter(),
            ))]
            .into_iter(),
        );
    }

    let report = serde_json::to_string(&reporter.into_report()).into_diagnostic()?;
    debug!("Writing Report");
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
        out: args.out,
        appkey: args.appkey,
    };
    for dir in args.dirs {
        debug!(?dir);
        scan_directory(dir, function, opts.clone())?;
    }
    Ok(())
}
