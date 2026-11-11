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

const JS_EXTENSIONS: [&str; 4] = ["js", "jsx", "ts", "tsx"];

/// Only `./x` and `../x` style specifiers name a file relative to the importer; anything else
/// is a package or project-rooted path and must not pick up directory indexes.
fn is_relative_specifier(import: &Path) -> bool {
    import
        .components()
        .next()
        .is_some_and(|c| matches!(c, Component::CurDir | Component::ParentDir))
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

    /// Look up `path` among the known modules.
    ///
    /// When `relative` is set (the import was written `./x` or `../x`), two Node-style
    /// fallbacks are tried after the exact and extension-swapped matches, so a file always
    /// wins over a directory of the same name:
    /// * dotted file names, `./a.service` -> `a.service.ts`
    /// * directory indexes, `./resolvers` -> `resolvers/index.js`
    fn search_normalized(&self, path: &Path, relative: bool) -> Option<usize> {
        let path = normalize_path(path);
        // only resolve files with no extension if the import doesn't have one or is a [jt]sx? file
        let direct = if path.extension().is_none() || is_jslike(&path) {
            let path_no_extension = path.with_extension("");
            self.modules
                .iter()
                .zip(&self.no_ext)
                .position(|(modpath, no_ext)| *modpath == path || *no_ext == path_no_extension)
        } else {
            self.modules.iter().position(|modpath| *modpath == path)
        };
        if direct.is_some() || !relative {
            return direct;
        }
        self.search_dotted_name(&path)
            .or_else(|| self.search_directory_index(&path))
    }

    /// `a.service` -> `a.service.{js,jsx,ts,tsx}`.
    fn search_dotted_name(&self, path: &Path) -> Option<usize> {
        JS_EXTENSIONS.iter().find_map(|ext| {
            let mut candidate = path.as_os_str().to_owned();
            candidate.push(".");
            candidate.push(ext);
            let candidate = PathBuf::from(candidate);
            self.modules
                .iter()
                .position(|modpath| *modpath == candidate)
        })
    }

    /// `resolvers` -> `resolvers/index.{js,jsx,ts,tsx}`.
    fn search_directory_index(&self, path: &Path) -> Option<usize> {
        JS_EXTENSIONS.iter().find_map(|ext| {
            let candidate = path.join(format!("index.{ext}"));
            self.modules
                .iter()
                .position(|modpath| *modpath == candidate)
        })
    }

    fn resolve_import_path(&self, module: usize, import: &Path) -> Result<usize, Error> {
        let current_file = self.modules.get(module).ok_or(Error::InvalidId(module))?;
        let relative = is_relative_specifier(import);
        // see if the file exists relative to the path of `module`
        let relative_path = 'rel: {
            let Some(file_dir) = current_file.parent() else {
                break 'rel current_file.clone();
            };
            let relative_path = file_dir.join(import);
            match self.search_normalized(&relative_path, relative) {
                Some(modid) => return Ok(modid),
                None => relative_path,
            }
        };

        // if not, try to search relative to the base of the project
        let project_relative = self.src.join(import);
        self.search_normalized(&project_relative, relative)
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

    fn resolver_with(modules: &[&str]) -> ForgeResolver {
        let mut file_resolver = ForgeResolver::with_sourceroot("src");
        for module in modules {
            file_resolver.add_module(module);
        }
        file_resolver
    }

    #[test]
    fn relative_directory_import_resolves_to_its_index() {
        let resolver = resolver_with(&["src/index.js", "src/resolvers/index.ts"]);
        assert_eq!(resolver.resolve_import(0, "./resolvers").unwrap(), 1);
        assert_eq!(resolver.resolve_import(0, "./resolvers/").unwrap(), 1);
    }

    #[test]
    fn relative_import_of_a_dotted_file_name_resolves() {
        let resolver = resolver_with(&["src/index.ts", "src/a.service.ts", "src/b.module.js"]);
        assert_eq!(resolver.resolve_import(0, "./a.service").unwrap(), 1);
        assert_eq!(resolver.resolve_import(0, "./b.module").unwrap(), 2);
    }

    #[test]
    fn parent_directory_import_resolves_to_its_index() {
        let resolver = resolver_with(&["src/deep/index.js", "src/shared/index.js"]);
        assert_eq!(resolver.resolve_import(0, "../shared").unwrap(), 1);
    }

    #[test]
    fn file_is_preferred_over_directory_index() {
        let resolver =
            resolver_with(&["src/index.js", "src/resolvers/index.js", "src/resolvers.js"]);
        assert_eq!(resolver.resolve_import(0, "./resolvers").unwrap(), 2);
    }

    #[test]
    fn bare_specifier_does_not_resolve_to_a_directory_index() {
        let resolver = resolver_with(&["src/index.js", "src/resolvers/index.js"]);
        assert!(resolver.resolve_import(0, "resolvers").is_err());
    }

    #[test]
    fn directory_without_an_index_does_not_resolve() {
        let resolver = resolver_with(&["src/index.js", "src/resolvers/main.js"]);
        assert!(resolver.resolve_import(0, "./resolvers").is_err());
    }

    #[test]
    fn existing_extension_swapping_still_resolves() {
        let resolver = resolver_with(&["src/index.js", "src/util.ts"]);
        assert_eq!(resolver.resolve_import(0, "./util").unwrap(), 1);
        assert_eq!(resolver.resolve_import(0, "./util.js").unwrap(), 1);
    }

    #[test]
    fn test_push() {
        let mut file_resolver = ForgeResolver::with_sourceroot("test/src");
        let id = file_resolver.add_module("index.js");
        assert_eq!(id, 0);
    }
}
