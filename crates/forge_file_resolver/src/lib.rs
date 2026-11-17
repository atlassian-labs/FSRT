use std::{
    collections::HashSet,
    error,
    ffi::OsStr,
    fmt,
    hash::Hash,
    path::{Component, Path, PathBuf},
};

pub trait FileResolver: Sized {
    type Id: Copy + Eq + Into<usize> + Hash;
    type Error;

    fn with_sourceroot<P: AsRef<Path>>(src: P) -> Self;

    fn get_module_path(&self, id: Self::Id) -> Result<&Path, Self::Error>;

    fn add_module<P: AsRef<Path>>(&mut self, path: P) -> Self::Id;

    fn resolve_import<P: AsRef<Path>>(
        &self,
        module: Self::Id,
        import: P,
    ) -> Result<Self::Id, Self::Error>;
}

#[derive(Debug)]
pub enum Error {
    InvalidId(usize),
    UnknownModule {
        base: usize,
        path: PathBuf,
        attempts: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone)]
pub struct ForgeResolver {
    modules: Vec<PathBuf>,
    no_ext: Vec<PathBuf>,
    src: PathBuf,
    declared_packages: HashSet<String>,
}

impl FileResolver for ForgeResolver {
    type Id = usize;
    type Error = Error;

    fn with_sourceroot<P: AsRef<Path>>(src: P) -> Self {
        let src = src.as_ref();
        assert!(src.ends_with("src"));
        Self {
            src: normalize_path(src),
            no_ext: Default::default(),
            modules: Default::default(),
            declared_packages: Default::default(),
        }
    }

    fn get_module_path(&self, id: Self::Id) -> Result<&Path, Self::Error> {
        self.modules
            .get(id)
            .map(PathBuf::as_path)
            .ok_or(Error::InvalidId(id))
    }

    #[inline]
    fn add_module<P: AsRef<Path>>(&mut self, path: P) -> usize {
        let path = path.as_ref();
        self.add_module_inner(path)
    }

    #[inline]
    fn resolve_import<P: AsRef<Path>>(&self, module: Self::Id, import: P) -> Result<usize, Error> {
        let import = import.as_ref();
        self.resolve_import_path(module, import)
    }
}

fn normalize_path(p: &Path) -> PathBuf {
    let mut comps = p.components().peekable();
    let mut normalized = match comps.peek() {
        Some(c @ Component::Prefix(_)) => {
            let path = PathBuf::from(c.as_os_str());
            comps.next();
            path
        }
        _ => PathBuf::new(),
    };

    for comp in comps {
        match comp {
            Component::Prefix(_) => unreachable!("prefix path should be stripped"),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(c) => normalized.push(c),
        }
    }
    normalized
}

fn is_jslike(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| matches!(ext, "js" | "ts" | "jsx" | "tsx"))
}

impl ForgeResolver {
    /// Names of the packages the app declares (`package.json` dependencies).
    pub fn set_declared_packages(&mut self, packages: impl IntoIterator<Item = String>) {
        self.declared_packages = packages.into_iter().collect();
    }

    fn add_module_inner(&mut self, path: &Path) -> usize {
        let path = normalize_path(path);
        self.no_ext.push(path.with_extension(""));
        self.modules.push(path);
        self.modules.len() - 1
    }

    /// Find the module `path` names, with or without a JS/TS extension. A module may be its own
    /// match: importing oneself is legal JavaScript.
    fn search_normalized(&self, path: &Path) -> Option<usize> {
        let path = normalize_path(path);
        // only resolve files with no extension if the import doesn't have one or is a [jt]sx? file
        let by_stem = path.extension().is_none() || is_jslike(&path);
        let path_no_extension = path.with_extension("");
        self.modules
            .iter()
            .zip(&self.no_ext)
            .position(|(modpath, no_ext)| {
                *modpath == path || (by_stem && *no_ext == path_no_extension)
            })
    }

    /// Whether a bare specifier names a package (npm, scoped, or Node builtin) that can never be
    /// a file of the app, so the project-relative fallback must not look for it.
    fn is_package_specifier(&self, specifier: &str) -> bool {
        if specifier.starts_with('@') || specifier.starts_with("node:") {
            return true;
        }
        let first_segment = specifier.split('/').next().unwrap_or(specifier);
        NODE_BUILTINS.contains(&first_segment) || self.declared_packages.contains(first_segment)
    }

    fn resolve_import_path(&self, module: usize, import: &Path) -> Result<usize, Error> {
        let current_file = self.modules.get(module).ok_or(Error::InvalidId(module))?;
        let unknown = |attempts: Vec<PathBuf>| Error::UnknownModule {
            base: module,
            path: import.to_owned(),
            attempts,
        };
        let specifier = import.to_str().unwrap_or_default();
        let is_relative = matches!(specifier, "." | "..")
            || specifier.starts_with("./")
            || specifier.starts_with("../");

        if is_relative {
            // `./x` and `../x` name a file relative to the importing file, and only there
            let relative_path = current_file
                .parent()
                .map_or_else(|| current_file.clone(), |dir| dir.join(import));
            return self
                .search_normalized(&relative_path)
                .ok_or_else(|| unknown(vec![relative_path]));
        }
        if import.is_absolute() {
            // `/x` names a file relative to the app root
            let app_root = self.src.parent().unwrap_or(Path::new(""));
            let rooted = app_root.join(specifier.trim_start_matches('/'));
            return self
                .search_normalized(&rooted)
                .ok_or_else(|| unknown(vec![rooted]));
        }
        // A bare specifier names a package, never a file next to the importer. Only a
        // `baseUrl`-style import (`utils/db`) of something that is not a known package is looked
        // up under the source root.
        if self.is_package_specifier(specifier) {
            return Err(unknown(vec![]));
        }
        let project_relative = self.src.join(import);
        self.search_normalized(&project_relative)
            .ok_or_else(|| unknown(vec![project_relative]))
    }
}

/// Node.js core modules, which `import "fs"` names even when the app has a file called `fs.js`.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidId(modid) => write!(f, "module id {modid} does not exist"),
            Error::UnknownModule {
                base,
                path,
                attempts,
            } => write!(
                f,
                "could not find import {path:?} from {base}, tried searching: {attempts:?}"
            ),
        }
    }
}

impl error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push() {
        let mut file_resolver = ForgeResolver::with_sourceroot("test/src");
        let id = file_resolver.add_module("index.js");
        assert_eq!(id, 0);
    }

    #[test]
    fn resolves_relative_import_out_of_src_to_sibling_folder() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let index = file_resolver.add_module("app/src/index.js");
        let helper = file_resolver.add_module("app/lib/helper.js");
        let nested = file_resolver.add_module("app/common/util/request-util.ts");

        assert_eq!(
            file_resolver
                .resolve_import(index, "../lib/helper")
                .unwrap(),
            helper
        );
        assert_eq!(
            file_resolver
                .resolve_import(index, "../common/util/request-util.ts")
                .unwrap(),
            nested
        );
        assert_eq!(
            file_resolver
                .resolve_import(helper, "../src/index")
                .unwrap(),
            index
        );
    }

    #[test]
    fn a_module_may_import_itself() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let index = file_resolver.add_module("app/src/index.js");
        let other = file_resolver.add_module("app/src/other.js");

        for specifier in ["./index", "./index.js", "../src/index"] {
            assert_eq!(
                file_resolver.resolve_import(index, specifier).unwrap(),
                index,
                "{specifier}"
            );
        }
        assert_eq!(
            file_resolver.resolve_import(index, "./other").unwrap(),
            other
        );
    }

    #[test]
    fn relative_specifiers_resolve_next_to_the_importer() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let axios = file_resolver.add_module("app/lib/axios.js");
        let sibling = file_resolver.add_module("app/lib/other.js");
        let parent = file_resolver.add_module("app/util.js");

        assert_eq!(
            file_resolver.resolve_import(sibling, "./axios").unwrap(),
            axios
        );
        assert_eq!(
            file_resolver.resolve_import(sibling, "../util").unwrap(),
            parent
        );
        assert_eq!(
            file_resolver.resolve_import(axios, "./other.js").unwrap(),
            sibling
        );
    }

    /// A bare specifier names a package, never a file next to the importer.
    #[test]
    fn bare_specifiers_are_not_resolved_next_to_the_importer() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let wrapper = file_resolver.add_module("app/lib/axios.js");
        let sibling = file_resolver.add_module("app/lib/other.js");
        let index = file_resolver.add_module("app/src/index.js");
        let local_axios = file_resolver.add_module("app/src/axios.js");
        file_resolver.add_module("app/src/fs.js");

        // Without a `package.json` nothing says `axios` is a package, so the `baseUrl`-style
        // lookup finds `src/axios.js` (but never `lib/axios.js` next to the importer).
        assert_eq!(
            file_resolver.resolve_import(wrapper, "axios").unwrap(),
            local_axios
        );
        assert_eq!(
            file_resolver.resolve_import(sibling, "axios").unwrap(),
            local_axios
        );

        // `import axios from "axios"` in `lib/axios.js` or a sibling is the package.
        file_resolver.set_declared_packages(["axios".to_owned()]);
        assert!(file_resolver.resolve_import(wrapper, "axios").is_err());
        assert!(file_resolver.resolve_import(sibling, "axios").is_err());
        // so is it in `src/index.js`, although `src/axios.js` exists
        assert!(file_resolver.resolve_import(index, "axios").is_err());
        assert!(file_resolver.resolve_import(index, "axios/lib/x").is_err());
    }

    #[test]
    fn node_builtins_and_scoped_packages_stay_foreign() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let index = file_resolver.add_module("app/src/index.js");
        file_resolver.add_module("app/src/fs.js");
        file_resolver.add_module("app/src/path.js");
        file_resolver.add_module("app/src/@forge/api.js");
        file_resolver.add_module("app/src/fs/promises.js");

        for specifier in [
            "fs",
            "path",
            "node:fs",
            "fs/promises",
            "@forge/api",
            "@forge/resolver",
        ] {
            assert!(
                file_resolver.resolve_import(index, specifier).is_err(),
                "{specifier}"
            );
        }
    }

    /// TypeScript `baseUrl`-style imports (`utils/db`) are looked up under `src/`, unless the
    /// first segment is a package the app declares.
    #[test]
    fn project_relative_fallback_applies_to_undeclared_bare_specifiers_only() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let deep = file_resolver.add_module("app/src/a/b/deep.ts");
        let db = file_resolver.add_module("app/src/utils/db.ts");
        let lodash = file_resolver.add_module("app/src/lodash/fp.js");

        assert_eq!(file_resolver.resolve_import(deep, "utils/db").unwrap(), db);
        assert_eq!(
            file_resolver.resolve_import(deep, "lodash/fp").unwrap(),
            lodash
        );

        file_resolver.set_declared_packages(["lodash".to_owned()]);
        assert_eq!(file_resolver.resolve_import(deep, "utils/db").unwrap(), db);
        assert!(file_resolver.resolve_import(deep, "lodash/fp").is_err());
        assert!(file_resolver.resolve_import(deep, "lodash").is_err());
    }

    #[test]
    fn absolute_specifiers_resolve_from_the_app_root() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let index = file_resolver.add_module("app/src/a/index.js");
        let lib = file_resolver.add_module("app/lib/helper.js");

        assert_eq!(
            file_resolver.resolve_import(index, "/lib/helper").unwrap(),
            lib
        );
        assert!(file_resolver.resolve_import(index, "/lib/missing").is_err());
    }
}
