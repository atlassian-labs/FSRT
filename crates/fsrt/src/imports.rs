//! First-party code outside `src/`: a file there is read only when a file the scan already reads
//! imports it, directly or through other such files.
//!
//! `src/` is collected by walking it. Anywhere else in the app, the scan follows imports instead
//! of walking folders, so a front-end bundle or a leftover build folder nothing imports is never
//! read, and a backend helper under `static/` or `common/` that `src/` does import is.

use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Component, Path, PathBuf},
    sync::LazyLock,
};

use forge_file_resolver::{import_target, module_candidates};
use regex::Regex;
use tracing::{debug, warn};

/// The most files outside `src/` one app may add. The files nearest to `src/` (fewest import
/// hops) are added first; once the cap is reached the rest stay unread, as if they were outside
/// the app, and the scan warns about it.
pub(crate) const MAX_FILES_OUTSIDE_SRC: usize = 2_000;

/// Import specifiers written as a string literal: `import x from "y"`, `import "y"`,
/// `export * from "y"`, `export { a } from "y"`, `require("y")` and `import("y")`. A lighter
/// check than a parse, so it also sees a specifier inside a comment or a string; that only ever
/// reads one more file. A dynamic import with a variable, a template literal or a path alias
/// from `tsconfig.json` is not followed.
static SPECIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:from|import|require\s*\(|import\s*\()\s*["']([^"'\n]+)["']"#)
        .expect("specifier pattern is valid")
});

fn specifiers(source: &str) -> impl Iterator<Item = &str> {
    SPECIFIER
        .captures_iter(source)
        .filter_map(|capture| capture.get(1))
        .map(|specifier| specifier.as_str())
}

/// Whether a path below the app root runs through a directory the scan never reads: a
/// dot-directory (`.git`, `.cache`) or `node_modules`.
fn in_unscanned_directory(relative: &Path) -> bool {
    let parent = relative.parent().unwrap_or(Path::new(""));
    parent.components().any(|component| {
        matches!(component, Component::Normal(name)
            if name.to_str().is_none_or(|name| name.starts_with('.') || name == "node_modules"))
    })
}

/// A minified build (`libavoid.min.js`) is vendored third-party code whose huge lines can take
/// the analysis minutes: one under `static/` that `src/` imports made a scan of a second take
/// over five minutes. An import never makes the scan read one.
fn is_minified_build(relative: &Path) -> bool {
    relative
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.ends_with(".min"))
}

/// Whether `relative`, a path below `app_root`, may be read: a regular file, or a link to one,
/// that resolves to a place inside the app and outside `node_modules` and dot-directories.
fn readable_in_app(app_root: &Path, relative: &Path) -> bool {
    if in_unscanned_directory(relative) || is_minified_build(relative) {
        return false;
    }
    let Ok(real) = fs::canonicalize(app_root.join(relative)) else {
        return false;
    };
    real.is_file()
        && real
            .strip_prefix(app_root)
            .is_ok_and(|inside| !in_unscanned_directory(inside))
}

/// The files outside `src/` that the files in `src_files` import, transitively.
///
/// `app_dir` is the app directory as the scan was given it and `src_files` the files collected
/// from `src/`, both in that form; the returned paths are in that form too. Imports are
/// resolved with the rules of the file resolver, using `declared_packages` from `package.json`.
/// A specifier that names a package, a file outside the app, a folder, a missing file, a file in
/// `node_modules` or a dot-directory, a minified `*.min.js` build, a link to a file outside the app, or a file under `src/`
/// (collected by the walk of `src/` or not read on purpose) adds nothing.
pub(crate) fn collect_imported_files_outside_src(
    app_dir: &Path,
    src_files: &[PathBuf],
    declared_packages: &HashSet<String>,
) -> Vec<PathBuf> {
    let Ok(app_root) = fs::canonicalize(app_dir) else {
        return vec![];
    };
    let src = app_root.join("src");
    let relative_to_app = |path: &Path| path.strip_prefix(app_dir).ok().map(Path::to_path_buf);

    let mut queue: VecDeque<PathBuf> = src_files
        .iter()
        .filter_map(|path| relative_to_app(path))
        .collect();
    let mut seen: HashSet<PathBuf> = queue.iter().cloned().collect();
    let mut added: Vec<PathBuf> = vec![];

    while let Some(relative) = queue.pop_front() {
        let Ok(source) = fs::read(app_dir.join(&relative)) else {
            continue;
        };
        let source = String::from_utf8_lossy(&source);
        let importer = app_root.join(&relative);
        for specifier in specifiers(&source) {
            let Some(target) = import_target(&importer, specifier, &src, declared_packages) else {
                continue;
            };
            // `src/` is read as collected; an import into it adds nothing
            let Ok(target) = target.strip_prefix(&app_root) else {
                continue;
            };
            if target.starts_with("src") {
                continue;
            }
            // the file the resolver would pick: the first candidate that exists
            let mut found = None;
            for candidate in module_candidates(target) {
                if seen.contains(&candidate) {
                    break;
                }
                if readable_in_app(&app_root, &candidate) {
                    found = Some(candidate);
                    break;
                }
            }
            let Some(found) = found else {
                continue;
            };
            seen.insert(found.clone());
            if added.len() >= MAX_FILES_OUTSIDE_SRC {
                warn!(
                    "{} files outside src/ are imported; reading only the first {MAX_FILES_OUTSIDE_SRC}",
                    app_dir.display()
                );
                return added.iter().map(|path| app_dir.join(path)).collect();
            }
            debug!(file = %found.display(), from = %relative.display(), "following import");
            added.push(found.clone());
            queue.push_back(found);
        }
    }
    added.iter().map(|path| app_dir.join(path)).collect()
}
