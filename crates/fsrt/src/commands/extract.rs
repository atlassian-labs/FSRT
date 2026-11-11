//! Hidden `extract` subcommand: lists the domains and IP addresses, with any
//! port and pathname, that a Forge app's manifest, backend source, and UI
//! resources reference. The list feeds threat-intelligence matching, so it
//! favors sensitivity; see [`forge_analyzer::endpoints`].

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

use clap::ValueHint;
use forge_analyzer::endpoints::Endpoints;
use serde_yaml::Value;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::{Result, forge_project::find_manifest_path};

/// Lockfiles hold a registry URL for every dependency. They describe how
/// dependencies are fetched, not what the app references.
const LOCKFILES: [&str; 4] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
];

/// swc parses and visits nested expressions recursively, and minified
/// bundles nest deeply, so extraction runs on a thread with a large stack.
/// Only the pages the thread touches are committed.
const WORKER_STACK_BYTES: usize = 256 * 1024 * 1024;

#[derive(clap::Args, Debug)]
pub(crate) struct ExtractArgs {
    /// The Forge app directory, containing `manifest.yml`.
    #[arg(default_value = ".", value_hint = ValueHint::DirPath)]
    dir: PathBuf,

    /// Write the list to this file instead of stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub(crate) fn run(args: &ExtractArgs) -> Result<()> {
    let endpoints = std::thread::scope(|scope| -> Result<Endpoints> {
        let worker = std::thread::Builder::new()
            .name("extract".into())
            .stack_size(WORKER_STACK_BYTES)
            .spawn_scoped(scope, || extract(&args.dir).map_err(|err| err.to_string()))?;
        let result = worker
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        Ok(result?)
    })?;
    let mut output = String::new();
    for endpoint in endpoints.iter() {
        output.push_str(endpoint);
        output.push('\n');
    }
    match &args.out {
        Some(path) => fs::write(path, output)?,
        None => std::io::stdout().lock().write_all(output.as_bytes())?,
    }
    Ok(())
}

fn extract(app_dir: &Path) -> Result<Endpoints> {
    let manifest_path = find_manifest_path(app_dir)?;
    let manifest_text = fs::read_to_string(&manifest_path)?;
    let mut endpoints = Endpoints::new();
    let manifest = add_manifest(&mut endpoints, &manifest_text).unwrap_or_else(|err| {
        warn!(path = %manifest_path.display(), %err, "could not parse manifest; reading it as plain text and skipping resources");
        Value::Null
    });

    let mut files = BTreeSet::new();
    collect_files(&app_dir.join("src"), &mut files);
    for root in resource_roots(app_dir, &manifest) {
        collect_files(&root, &mut files);
    }
    for file in files {
        debug!(file = %file.display(), "extracting");
        match fs::read(&file).map(String::from_utf8) {
            Ok(Ok(text)) => endpoints.add_source(&file, &text),
            Ok(Err(_)) => debug!(file = %file.display(), "skipping non-UTF-8 file"),
            Err(err) => warn!(file = %file.display(), %err, "could not read file"),
        }
    }
    Ok(endpoints)
}

/// Properties that name a file and export, such as `handler: index.run`,
/// never a network address. Skipped at any depth.
const FILE_REFERENCE_KEYS: [&str; 1] = ["handler"];

/// Properties of a `resources` entry that name files, such as
/// `path: static/site.app`.
const RESOURCE_FILE_KEYS: [&str; 2] = ["path", "entry"];

/// Adds the endpoints in a manifest's values and comments, except for
/// properties that name files, and returns the parsed manifest. When the
/// manifest does not parse, the whole text is read instead.
fn add_manifest(endpoints: &mut Endpoints, text: &str) -> serde_yaml::Result<Value> {
    let manifest = match serde_yaml::from_str::<Value>(text) {
        Ok(manifest) => manifest,
        Err(err) => {
            endpoints.add_text(text);
            return Err(err);
        }
    };
    for comment in yaml_comments(text) {
        endpoints.add_text(comment);
    }
    match &manifest {
        Value::Mapping(entries) => {
            for (key, value) in entries {
                add_yaml(endpoints, key, &[]);
                match (key.as_str(), value) {
                    (Some("resources"), Value::Sequence(resources)) => {
                        for resource in resources {
                            add_yaml(endpoints, resource, &RESOURCE_FILE_KEYS);
                        }
                    }
                    _ => add_yaml(endpoints, value, &[]),
                }
            }
        }
        other => add_yaml(endpoints, other, &[]),
    }
    Ok(manifest)
}

/// Adds every key and string in `value`, skipping `FILE_REFERENCE_KEYS`
/// everywhere and `skipped` in this mapping only.
fn add_yaml(endpoints: &mut Endpoints, value: &Value, skipped: &[&str]) {
    match value {
        Value::String(text) => endpoints.add_text(text),
        Value::Sequence(items) => items.iter().for_each(|item| add_yaml(endpoints, item, &[])),
        Value::Mapping(entries) => {
            for (key, value) in entries {
                let is_skipped = key.as_str().is_some_and(|key| {
                    FILE_REFERENCE_KEYS.contains(&key) || skipped.contains(&key)
                });
                if !is_skipped {
                    add_yaml(endpoints, key, &[]);
                    add_yaml(endpoints, value, &[]);
                }
            }
        }
        Value::Tagged(tagged) => add_yaml(endpoints, &tagged.value, skipped),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The text after each `#` that starts a YAML comment: at the start of a
/// line or after whitespace. Quotes are not tracked, so a `#` inside a
/// quoted value also counts; that only rereads text the values cover.
fn yaml_comments(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let (start, _) = line.char_indices().find(|&(index, c)| {
            c == '#'
                && line[..index]
                    .chars()
                    .next_back()
                    .is_none_or(char::is_whitespace)
        })?;
        Some(&line[start + 1..])
    })
}

/// Paths of the manifest's `resources`, plus the package that builds each.
///
/// A Custom UI resource points at build output, such as `static/app/build`,
/// which a source checkout often lacks. The nearest directory below the app
/// root that holds a `package.json` is the Custom UI project, so its sources
/// are read too.
fn resource_roots(app_dir: &Path, manifest: &Value) -> Vec<PathBuf> {
    let resource_paths = manifest
        .get("resources")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|resource| resource.get("path")?.as_str());
    let mut roots = Vec::new();
    for relative in resource_paths {
        let path = app_dir.join(relative);
        if !path.exists() {
            warn!(path = %path.display(), "resource path does not exist");
        }
        // Searching upward from a path that leaves the app root could reach
        // an unrelated package.
        let stays_inside = Path::new(relative)
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir));
        if stays_inside && let Some(package) = enclosing_package(app_dir, &path) {
            roots.push(package);
        }
        roots.push(path);
    }
    roots
}

fn enclosing_package(app_dir: &Path, path: &Path) -> Option<PathBuf> {
    let mut dir = path.parent()?;
    while dir != app_dir && dir.starts_with(app_dir) {
        if dir.join("package.json").is_file() {
            return Some(dir.to_owned());
        }
        dir = dir.parent()?;
    }
    None
}

/// Adds the files under `root`, or `root` itself when it is a file.
/// `node_modules` holds third-party code, and hidden directories hold VCS
/// data and tool caches, so neither is entered.
fn collect_files(root: &Path, files: &mut BTreeSet<PathBuf>) {
    let skipped_dir = |name: &OsStr| {
        name == "node_modules" || name.to_str().is_some_and(|name| name.starts_with('.'))
    };
    let walker = WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0 || !entry.file_type().is_dir() || !skipped_dir(entry.file_name())
        });
    for entry in walker {
        match entry {
            Ok(entry)
                if entry.file_type().is_file()
                    && !LOCKFILES
                        .iter()
                        .any(|lockfile| entry.file_name() == *lockfile) =>
            {
                files.insert(entry.into_path());
            }
            Ok(_) => {}
            Err(err) => debug!(root = %root.display(), %err, "could not walk"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_manifest(text: &str) -> Vec<String> {
        let mut endpoints = Endpoints::new();
        let _ = add_manifest(&mut endpoints, text);
        endpoints.iter().map(str::to_owned).collect()
    }

    #[test]
    fn skips_handlers_and_resource_files() {
        let manifest = r#"
modules:
  function:
    - key: main
      handler: index.run
  jira:issuePanel:
    - key: panel
      resource: site
      icon: https://icons.example.com/panel.svg
resources:
  - key: site
    path: static/site.app
    entry:
      main: index.app
remotes:
  - key: backend
    baseUrl: https://remote.example.com
    path: evil.example.org
"#;
        assert_eq!(
            from_manifest(manifest),
            [
                "evil.example.org",
                "icons.example.com",
                "icons.example.com/panel.svg",
                "remote.example.com"
            ]
        );
    }

    #[test]
    fn reads_comments_but_not_commented_handlers() {
        let manifest = r#"
# Old backend: old.example.net
permissions:
  external:
    fetch:
      backend:
        - a.example.com # was b.example.com
modules:
  function:
    - key: main
      handler: index.run # also index.app
      title: issue#tracker.example.com
"#;
        assert_eq!(
            from_manifest(manifest),
            // `index.app` is in a comment, which is kept for sensitivity.
            // The `#` in the title is not a comment, so the value is read.
            [
                "a.example.com",
                "b.example.com",
                "index.app",
                "old.example.net",
                "tracker.example.com"
            ]
        );
    }

    #[test]
    fn reads_unparseable_manifest_as_text() {
        assert_eq!(
            from_manifest("handler: index.run\n  bad: [indent\nurl: https://x.example.com"),
            ["index.run", "x.example.com"]
        );
    }
}
