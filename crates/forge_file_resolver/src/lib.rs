use std::{
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
    fn add_module_inner(&mut self, path: &Path) -> usize {
        let path = normalize_path(path);
        self.no_ext.push(path.with_extension(""));
        self.modules.push(path);
        self.modules.len() - 1
    }

    /// Find the module `path` names, never `importer` itself.
    ///
    /// Import specifiers are tried relative to the importing file first, so a bare package name
    /// matches a sibling file with that name. A wrapper such as `lib/axios.js` doing
    /// `import axios from "axios"` would otherwise resolve to itself, not the package.
    fn search_normalized(&self, path: &Path, importer: usize) -> Option<usize> {
        let path = normalize_path(path);
        // only resolve files with no extension if the import doesn't have one or is a [jt]sx? file
        let by_stem = path.extension().is_none() || is_jslike(&path);
        let path_no_extension = path.with_extension("");
        self.modules
            .iter()
            .zip(&self.no_ext)
            .enumerate()
            .find_map(|(id, (modpath, no_ext))| {
                (id != importer && (*modpath == path || (by_stem && *no_ext == path_no_extension)))
                    .then_some(id)
            })
    }

    fn resolve_import_path(&self, module: usize, import: &Path) -> Result<usize, Error> {
        let current_file = self.modules.get(module).ok_or(Error::InvalidId(module))?;
        // see if the file exists relative to the path of `module`
        let relative_path = 'rel: {
            let Some(file_dir) = current_file.parent() else {
                break 'rel current_file.clone();
            };
            let relative_path = file_dir.join(import);
            match self.search_normalized(&relative_path, module) {
                Some(modid) => return Ok(modid),
                None => relative_path,
            }
        };

        // if not, try to search relative to the base of the project
        let project_relative = self.src.join(import);
        self.search_normalized(&project_relative, module)
            .ok_or_else(|| Error::UnknownModule {
                base: module,
                path: import.to_owned(),
                attempts: vec![project_relative, relative_path],
            })
    }
}

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
    fn import_never_resolves_to_the_importing_module() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let axios = file_resolver.add_module("app/lib/axios.js");
        let sibling = file_resolver.add_module("app/lib/other.js");

        // `import axios from "axios"` in `axios.js` names the package, not the file itself.
        assert!(file_resolver.resolve_import(axios, "axios").is_err());
        assert!(file_resolver.resolve_import(axios, "./axios.js").is_err());
        assert_eq!(
            file_resolver.resolve_import(axios, "./other").unwrap(),
            sibling
        );
        assert_eq!(
            file_resolver.resolve_import(sibling, "./axios").unwrap(),
            axios
        );
    }

    #[test]
    fn import_skips_the_importer_when_another_module_has_the_same_stem() {
        let mut file_resolver = ForgeResolver::with_sourceroot("app/src");
        let ts = file_resolver.add_module("app/lib/util.ts");
        let js = file_resolver.add_module("app/lib/util.js");

        assert_eq!(file_resolver.resolve_import(ts, "./util").unwrap(), js);
        assert_eq!(file_resolver.resolve_import(js, "./util").unwrap(), ts);
    }
}
