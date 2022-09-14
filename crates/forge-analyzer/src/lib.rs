#![allow(unused_imports, dead_code)]

pub mod analyzer;
pub mod utils;

use std::default;

use smallvec::SmallVec;
use swc_core::ecma::ast::{
    Id, ImportDecl, ImportDefaultSpecifier, ImportNamedSpecifier, ImportStarAsSpecifier,
    ModuleExportName, Str,
};
use swc_core::ecma::atoms::{Atom, JsWord, JsWordStaticSet};
use swc_core::ecma::visit::{noop_visit_type, Visit, VisitWith};
use utils::{FxHashMap, FxIndexMap, FxIndexSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum ImportKind {
    Renamed(ModuleExportName),
    Star(Id),
    Same(Id),
    #[default]
    Default,
}

impl From<ModuleExportName> for ImportKind {
    fn from(m: ModuleExportName) -> Self {
        Self::Renamed(m)
    }
}

impl From<Id> for ImportKind {
    fn from(id: Id) -> Self {
        Self::Same(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub exported_name: ImportKind,
    pub path_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleCtx {
    pub imports: FxIndexMap<Id, ImportDescriptor>,
    pub paths: FxIndexMap<Id, SmallVec<[u32; 4]>>,
}

impl ModuleCtx {
    pub fn new() -> Self {
        Self {
            imports: FxIndexMap::default(),
            paths: FxIndexMap::default(),
        }
    }
}

impl Default for ModuleCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ImportCollector {
    pub imports: FxIndexMap<Id, ImportDescriptor>,
    // The indices of paths and import_ids should match
    // each index represents a unique path
    pub paths: FxIndexMap<JsWord, SmallVec<[u32; 4]>>,
    current_id: u32,
}

impl ImportCollector {
    pub fn new() -> Self {
        Self {
            imports: FxIndexMap::default(),
            paths: FxIndexMap::default(),
            current_id: 0,
        }
    }
}

impl Default for ImportCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Visit for ImportCollector {
    noop_visit_type!();

    fn visit_import_decl(&mut self, n: &ImportDecl) {
        let ImportDecl {
            src: Str { value, .. },
            ..
        } = n;
        let entry = self.paths.entry(value.clone());
        let id = entry.index();
        entry.or_default();
        let old_id = self.current_id;
        self.current_id = id.try_into().expect("too many imports");
        n.visit_children_with(self);
        self.current_id = old_id;
    }

    fn visit_import_named_specifier(&mut self, n: &ImportNamedSpecifier) {
        if n.is_type_only {
            return;
        }
        let ImportNamedSpecifier {
            local, imported, ..
        } = n;
        let exported_name = imported.clone();
        let local = local.to_id();
        let exported_name = match exported_name {
            Some(exported_name) => ImportKind::Renamed(exported_name),
            None => ImportKind::Same(local.clone()),
        };
        let (id, _) = self.imports.insert_full(
            local,
            ImportDescriptor {
                exported_name,
                path_id: self.current_id,
            },
        );
        self.paths
            .get_index_mut(
                self.current_id
                    .try_into()
                    .expect("current_id should be valid"),
            )
            .expect("current_id should point to the current import")
            .1
            .push(id.try_into().expect("id should be valid"));
    }

    fn visit_import_default_specifier(&mut self, n: &ImportDefaultSpecifier) {
        let ImportDefaultSpecifier { local, .. } = n;
        let (id, _) = self.imports.insert_full(
            local.to_id(),
            ImportDescriptor {
                path_id: self.current_id,
                exported_name: ImportKind::Default,
            },
        );
        self.paths
            .get_index_mut(
                self.current_id
                    .try_into()
                    .expect("current_id should be valid"),
            )
            .expect("current_id should point to the current import")
            .1
            .push(id.try_into().expect("id should be valid"));
    }

    fn visit_import_star_as_specifier(&mut self, n: &ImportStarAsSpecifier) {
        let ImportStarAsSpecifier { local, .. } = n;
        let local = local.to_id();
        let (id, _) = self.imports.insert_full(
            local.clone(),
            ImportDescriptor {
                path_id: self.current_id,
                exported_name: ImportKind::Star(local),
            },
        );
        self.paths
            .get_index_mut(
                self.current_id
                    .try_into()
                    .expect("current_id should be valid"),
            )
            .expect("current_id should point to the current import")
            .1
            .push(id.try_into().expect("id should be valid"));
    }
}

struct ExportCollector {
    exports: FxHashMap<Id, String>,
}
