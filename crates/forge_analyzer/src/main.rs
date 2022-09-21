// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_variables, dead_code)]

use std::os::unix::prelude::OsStrExt;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use anyhow::Result;
use clap::Parser;
use swc_core::{
    common::{Globals, SourceFile, SourceMap, GLOBALS},
    ecma::{
        ast::EsVersion,
        parser::{parse_file_as_module, EsConfig, Syntax},
    },
};
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
            let sourcemap = Arc::clone(&sourcemap);
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
            });
        }
    }
    Ok(sourcemap)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let entry = cli.root;
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env("FORGE_LOG"))
        .init();
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
