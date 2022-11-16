use std::{
    error, fmt,
    hash::Hash,
    path::{Component, Path, PathBuf},
    result::Result,
};

pub trait FileResolver: Sized {
    type Id: Copy + Eq + Into<usize> + Hash;
    type Error;

    fn with_sourceroot<P: AsRef<Path>>(src: P) -> Self;

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

impl ForgeResolver {
    fn add_module_inner(&mut self, path: &Path) -> usize {
        let path = normalize_path(path);
        self.no_ext.push(path.with_extension(""));
        self.modules.push(path);
        self.modules.len() - 1
    }

    fn search_normalized(&self, path: &Path) -> Option<usize> {
        let path = normalize_path(path);
        let path_no_extension = path.with_extension("");
        self.modules
            .iter()
            .enumerate()
            .zip(&self.no_ext)
            .find_map(|((modid, modpath), no_ext)| {
                (*modpath == path || *no_ext == path_no_extension).then_some(modid)
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
            match self.search_normalized(&relative_path) {
                Some(modid) => return Ok(modid),
                None => relative_path,
            }
        };

        // if not, try to search relative to the base of the project
        let project_relative = self.src.join(import);
        self.search_normalized(&project_relative)
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
}
