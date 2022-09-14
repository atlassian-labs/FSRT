// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_imports, unused_variables, dead_code)]

use std::io;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::Parser;
use forge_analyzer::ImportCollector;
use swc_core::common::Globals;
use swc_core::common::Mark;
use swc_core::common::SourceFile;
use swc_core::common::SourceMap;
use swc_core::common::GLOBALS;
use swc_core::ecma::ast::{EsVersion, Module};
use swc_core::ecma::atoms::{atom, JsWord};
use swc_core::ecma::transforms::base::resolver;
use swc_core::ecma::visit::{FoldWith, VisitWith};
use swc_ecma_parser::parse_file_as_module;
use swc_ecma_parser::EsConfig;
use swc_ecma_parser::Syntax;
use tracing::info;
use walkdir::WalkDir;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    root: PathBuf,
}

fn is_js_file<P: AsRef<Path>>(path: P) -> bool {
    matches!(
        path.as_ref().extension().map(|s| s.as_bytes()),
        Some(b"jsx" | b"js" | b"tsx" | b"ts")
    )
}

fn analyze_module(module: Module) {
    // TODO: make typescript configurable
    let mut initial_resolver = resolver(Mark::new(), Mark::new(), true);
    let module = module.fold_with(&mut initial_resolver);
    let mut imports = ImportCollector::new();
    module.visit_with(&mut imports);
    println!("IMPORTS: ---------------------");
    for (id, import) in imports.imports.iter() {
        println!("import: {:?} -> {:?}", id, import);
    }
    println!("---------------------");
    println!("\nPATHS: ---------------------");
    for path in imports.paths.iter() {
        println!("path: {:?}", path);
    }
    println!("---------------------\n");
    let atom: JsWord = "@forge/api".into();
    if let Some(idents) = imports.paths.get(&atom) {
        println!("idents: {idents:?}");
        for (ident, _) in idents
            .into_iter()
            .filter_map(|&idx| imports.imports.get_index(idx.try_into().unwrap()))
        {
            println!("{ident:?}");
        }
    }
}

fn collect_to_sourcemap<P: AsRef<Path>>(root: P, conf: EsConfig) -> Result<Arc<SourceMap>> {
    let root = root.as_ref();
    let sourcemap = Arc::<SourceMap>::default();
    let target = EsVersion::latest();
    let globs = Globals::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok().and_then(|f| is_js_file(f.path()).then_some(f)))
    {
        let path = entry.path();
        if path.is_dir() {
            println!("in dir: {}", path.display());
            // collect_to_sourcemap(&root.join(path), conf)?;
        } else {
            let sourcemap = sourcemap.clone();
            GLOBALS.set(&globs, || {
                let src = sourcemap
                    .load_file(path)
                    .unwrap_or_else(|_| panic!("failed to load file: {}", path.display()));
                let mut recovered_errors = Vec::new();
                let module = parse_file_as_module(
                    &src,
                    Syntax::Es(conf),
                    target,
                    None,
                    &mut recovered_errors,
                )
                .unwrap_or_else(|_| panic!("failed to parse file: {}", path.display()));
                analyze_module(module);
            });
        }
    }
    Ok(sourcemap)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let entry = cli.root;
    info!("parsing {entry:?}");
    let loader_config = EsConfig {
        jsx: true,
        fn_bind: true,
        ..Default::default()
    };
    let sm = collect_to_sourcemap(&entry, loader_config)?;
    sm.files().iter().for_each(|src_file| {
        let SourceFile { name, .. } = &**src_file;
        println!("filename: {name}");
    });

    Ok(())
}
