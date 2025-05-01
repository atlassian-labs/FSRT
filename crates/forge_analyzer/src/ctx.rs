use std::path::Path;
use std::{borrow::Borrow, hash::Hash, path::PathBuf};

use forge_file_resolver::{FileResolver, ForgeResolver};
use forge_utils::FxHashMap;
use forge_utils::create_newtype;
use petgraph::prelude::NodeIndex;
use petgraph::stable_graph::DefaultIx;
use swc_core::ecma::ast::{Id, Module};
use tracing::instrument;
use typed_index_collections::TiVec;

create_newtype! {
    pub struct ModId(u32);
}

create_newtype! {
    pub struct StmtId(u32);
}

create_newtype! {
    pub struct BasicBlockId(u32);
}

impl BasicBlockId {
    #[inline]
    pub(crate) fn to_bits(self) -> u32 {
        self.0
    }
}

impl From<BasicBlockId> for NodeIndex<DefaultIx> {
    fn from(value: BasicBlockId) -> Self {
        Self::new(value.to_bits() as usize)
    }
}

pub const UNKNOWN_MODULE: ModId = ModId(u32::MAX);

#[derive(Clone, Debug)]
pub struct AppCtx {
    // Map from import Id -> module name
    pub(crate) import_ids: FxHashMap<Id, Id>,
    pub(crate) file_resolver: ForgeResolver,

    pub(crate) path_ids: FxHashMap<PathBuf, ModId>,
    pub(crate) modules: TiVec<ModId, Module>,
}

impl AppCtx {
    #[inline]
    pub fn new<P: AsRef<Path>>(src_root: P) -> Self {
        Self {
            import_ids: FxHashMap::default(),
            file_resolver: ForgeResolver::with_sourceroot(src_root),
            path_ids: FxHashMap::default(),
            modules: TiVec::default(),
        }
    }

    #[instrument(level = "debug", skip(self, module))]
    pub fn load_module(&mut self, path: PathBuf, module: Module) -> ModId {
        let mod_id = self.modules.push_and_get_key(module);
        self.file_resolver.add_module(path.clone());
        self.path_ids.insert(path, mod_id);
        mod_id
    }

    #[inline]
    pub fn modid_from_path<P>(&self, path: &P) -> Option<ModId>
    where
        PathBuf: Borrow<P>,
        P: Hash + Eq,
    {
        self.path_ids.get(path).copied()
    }

    #[inline]
    pub fn module_ids(&self) -> impl DoubleEndedIterator<Item = ModId> + ExactSizeIterator + '_ {
        self.modules.keys()
    }

    #[inline]
    pub fn import_ids(&self) -> &FxHashMap<Id, Id> {
        &self.import_ids
    }

    #[inline]
    pub fn path_ids(&self) -> &FxHashMap<PathBuf, ModId> {
        &self.path_ids
    }

    #[inline]
    pub fn file_resolver(&self) -> &ForgeResolver {
        &self.file_resolver
    }

    #[inline]
    pub fn modules(&self) -> &TiVec<ModId, Module> {
        &self.modules
    }
}
