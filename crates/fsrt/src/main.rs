#![allow(clippy::type_complexity)]
use std::{
    collections::HashSet,
    convert::TryFrom,
    fs,
    io::stdout,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, ValueHint};
use miette::{IntoDiagnostic, Result};

use swc_core::{
    common::{Globals, Mark, SourceMap, GLOBALS},
    ecma::{
        ast::{EsVersion, Id},
        parser::{parse_file_as_module, Syntax, TsConfig},
        transforms::base::resolver,
        visit::FoldWith,
    },
};
use tracing::{debug, instrument, warn};
use tracing_subscriber::{prelude::*, EnvFilter};
use tracing_tree::HierarchicalLayer;

use forge_analyzer::{
    analyzer::AuthZVal,
    ctx::{AppCtx, ModId, ModItem},
    definitions::run_resolver,
    engine::Machine,
    resolver::{dump_callgraph_dot, dump_cfg_dot, resolve_calls},
};
use forge_file_resolver::FileResolver;
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

    /// The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level
    /// directory, and that the source code is located in `src/`
    #[arg(name = "DIRS", value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Opts {
    dump_cfg: bool,
    dump_callgraph: bool,
}

struct ForgeProject {
    #[allow(dead_code)]
    sm: Arc<SourceMap>,
    ctx: AppCtx,
    funcs: Vec<FunctionTy<(ModId, Id)>>,
    opts: Opts,
}

impl ForgeProject {
    #[instrument(level = "debug", skip(self))]
    fn verify_funs(&mut self) -> impl Iterator<Item = (ModId, Id, AuthZVal)> + '_ {
        self.funcs.iter().cloned().map(|fty| {
            let (modid, func) = fty.into_inner();
            // TODO(perf): reuse the same `Machine` between iterations
            let func_item = ModItem::new(modid, func.clone());
            let mut machine = Machine::new(modid, func.clone(), &mut self.ctx);
            let res = (modid, func, machine.run());
            if self.opts.dump_callgraph {
                let _ = dump_cfg_dot(&self.ctx, &func_item, stdout());
            }
            res
        })
    }

    fn verify_fun(&mut self, func: &str) -> (ModItem, AuthZVal) {
        let (modid, ref ident) = *self
            .funcs
            .iter()
            .find(|&ty| {
                let (_, ref ident) = *ty.as_ref();
                *ident.0 == *func
            })
            .unwrap()
            .as_ref();
        let funcitem = ModItem::new(modid, ident.clone());
        let mut machine = Machine::new(modid, ident.clone(), &mut self.ctx);
        let res = machine.run();
        if self.opts.dump_cfg {
            let _ = dump_cfg_dot(&self.ctx, &funcitem, stdout());
        }
        if self.opts.dump_callgraph {
            let _ = dump_callgraph_dot(&self.ctx, &funcitem, stdout());
        }
        (funcitem, res)
    }

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
                let src = sourcemap.load_file(&p).unwrap();
                let mut recovered_errors = vec![];
                let module = parse_file_as_module(
                    &src,
                    Syntax::Typescript(TsConfig {
                        tsx: true,
                        ..Default::default()
                    }),
                    target,
                    None,
                    &mut recovered_errors,
                )
                .unwrap();
                let mut hygeine = resolver(Mark::new(), Mark::new(), true);
                let module = module.fold_with(&mut hygeine);
                ctx.load_module(p, module);
                ctx
            })
        });
        let keys = ctx.module_ids().collect::<Vec<_>>();
        debug!(?keys);
        Self {
            sm,
            ctx,
            funcs: vec![],
            opts: Opts::default(),
        }
    }

    fn add_funcs<'a, I: IntoIterator<Item = FunctionTy<(&'a str, PathBuf)>>>(&mut self, iter: I) {
        self.funcs.extend(iter.into_iter().flat_map(|ftype| {
            ftype.sequence(|(func, path)| {
                let modid = self.ctx.modid_from_path(&path)?;
                let func = self.ctx.export(modid, func)?;
                Some((modid, func))
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
    let paths = collect_sourcefiles(dir.join("src/")).collect::<HashSet<_>>();
    let funcrefs = manifest.modules.into_analyzable_functions().flat_map(|f| {
        f.sequence(|fmod| {
            let resolved_func = FunctionRef::try_from(fmod)?.try_resolve(&paths, &dir)?;
            Ok::<_, forge_loader::Error>(resolved_func.into_func_path())
        })
    });
    let src_root = dir.join("src");
    let mut proj = ForgeProject::with_files_and_sourceroot(src_root, paths.clone());
    proj.opts = opts;
    proj.add_funcs(funcrefs);
    resolve_calls(&mut proj.ctx);
    let (res, foreign) = run_resolver(proj.ctx.modules(), proj.ctx.file_resolver());
    proj.ctx
        .modules()
        .iter_enumerated()
        .map(|(id, _)| id)
        .for_each(|id| {
            println!(
                "path: {:?}",
                proj.ctx.file_resolver().get_module_path(id.into()).unwrap()
            );
            for (sym, def) in res.module_exports(id) {
                let kind = res.def_kind(def);
                println!("{sym}: {def:?} kind: {kind}");
            }
            if let Some(def) = res.default_export(id) {
                let kind = res.def_kind(def);
                println!("default: {def:?} defkind: {kind}");
            }
        });
    for item in &foreign {
        println!("foreign: {item}");
    }

    // for path in proj.ctx.path_ids().keys() {
    //     let path = path.strip_prefix(&dir).unwrap();
    //     let path = path
    //         .parent()
    //         .unwrap()
    //         .join("../src/auth.jsx")
    //         .canonicalize()
    //         .unwrap();
    //     println!("stripped path: {path:?}");
    //     let path = path.to_string_lossy();
    //     let (base, src) = path.split_once("src/").unwrap();
    //     println!("resolved path = {base} {src}");
    // }
    if let Some(func) = function {
        proj.verify_fun(func);
    } else {
        for (modid, fun, res) in proj.verify_funs() {
            debug!(module = ?modid, function = ?fun.0, result = ?res, "analysis of");
        }
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
    };
    for dir in args.dirs {
        debug!(?dir);
        scan_directory(dir, function, opts)?;
    }
    Ok(())
}
