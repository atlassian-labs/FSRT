use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use clap::{Parser, ValueHint};

use forge_authz_rs::manifest::{ForgeModules, FunctionRef};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    debug: bool,

    #[clap(name = "DIRS", parse(from_os_str), value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

fn try_read_manifest<P: AsRef<Path>>(path: P) -> Result<()> {
    let manifest = fs::read_to_string(path.as_ref())?;
    let manifest: ForgeModules = serde_json::from_str(&manifest)?;
    let manifest = manifest
        .functions
        .into_iter()
        .map(FunctionRef::try_from)
        .collect::<Result<Vec<_>, _>>();
    let _manifest = manifest.map_err(|e| anyhow!("could not resolve function: {e}"))?;
    Ok(())
}

fn scan_directory(dir: PathBuf) -> Result<HashSet<PathBuf>> {
    let manifest_file = dir.with_file_name("manifest.yaml");
    try_read_manifest(manifest_file)?;
    let paths = fs::read_dir(dir)?
        .into_iter()
        .flatten()
        .map(|entry| entry.path())
        .collect::<HashSet<_>>();
    Ok(paths)
}

fn main() -> Result<()> {
    let args = Args::parse();
    for dir in args.dirs {
        println!("{dir:?}");
        scan_directory(dir)?;
    }
    Ok(())
}
