pub mod analyzer;
pub mod ctx;
pub mod engine;
pub mod exports;
pub mod lattice;
pub mod utils;

use ctx::ModuleCtx;
use exports::ExportCollector;
use smallvec::SmallVec;
use swc_core::ecma::ast::{
    Id, ImportDecl, ImportDefaultSpecifier, ImportNamedSpecifier, ImportStarAsSpecifier, Module,
    ModuleDecl, ModuleExportName, ModuleItem, Str,
};
use swc_core::ecma::visit::{noop_visit_type, Visit, VisitWith};
use tracing::debug;
use utils::FxHashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub(crate) enum ImportKind {
    Renamed(Id),
    Star(Id),
    Same(Id),
    #[default]
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportDescriptor {
    pub exported_name: ImportKind,
    pub path_id: u32,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ForgeImports {
    authorize: Option<Id>,
    api: Option<Id>,
    as_app: Option<Id>,
}

#[derive(Debug, Clone)]
enum Exports {
    Default(Id),
    Named(FxHashMap<Id, Id>),
}

#[derive(Debug, Default)]
pub(crate) struct ImportCollector {
    // The indices of paths and import_ids should match
    // each index represents a unique path
    pub(crate) imports: FxHashMap<Id, SmallVec<[ImportKind; 8]>>,
    pub(crate) ident_to_import: FxHashMap<Id, Id>,
    pub(crate) forge_imports: ForgeImports,
    in_forge_import: bool,
    current_import: Id,
}

pub fn lower_module(module: &Module) -> ModuleCtx {
    let mut external = ImportCollector::new();
    module.visit_children_with(&mut external);
    let mut export_collector = ExportCollector::new();
    module.visit_children_with(&mut export_collector);
    let mut ctx = ModuleCtx {
        imports: external.imports,
        forge_imports: external.forge_imports,
        ident_to_import: external.ident_to_import,
        exports: export_collector.exports,
        functions: Default::default(),
    };
    ctx.functions = analyzer::collect_functions(module, &ctx);
    ctx
}

impl ImportCollector {
    pub fn new() -> Self {
        Self {
            imports: Default::default(),
            forge_imports: ForgeImports::new(),
            ident_to_import: Default::default(),
            in_forge_import: false,
            current_import: Default::default(),
        }
    }

    fn add_import(&mut self, kind: ImportKind) {
        if let ImportKind::Renamed(id) | ImportKind::Star(id) | ImportKind::Same(id) = &kind {
            self.ident_to_import
                .insert(id.clone(), self.current_import.clone());
        }
        self.imports
            .entry(self.current_import.clone())
            .or_default()
            .push(kind);
    }
}

pub(crate) fn export_name_into_id(n: &ModuleExportName) -> Id {
    match n {
        ModuleExportName::Ident(ident) => ident.to_id(),
        ModuleExportName::Str(Str {
            span,
            value,
            raw: _,
        }) => (value.clone(), span.ctxt()),
    }
}

impl ForgeImports {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_api(&self, id: &Id) -> bool {
        debug!(import = ?self.api, ?id, "checking if api import");
        Some(id) == self.api.as_ref()
    }

    pub(crate) fn is_authorize(&self, id: &Id) -> bool {
        Some(id) == self.authorize.as_ref()
    }

    pub(crate) fn is_as_app(&self, id: &Id) -> bool {
        debug!(import = ?self.as_app, ?id, "checking if asApp import");
        Some(id) == self.as_app.as_ref()
    }

    pub(crate) fn contains_forge_imports(&self) -> bool {
        self.api
            .as_ref()
            .or(self.as_app.as_ref())
            .or(self.authorize.as_ref())
            .is_some()
    }
}

impl Visit for ImportCollector {
    noop_visit_type!();

    #[tracing::instrument(level = "debug", skip_all)]
    fn visit_import_decl(&mut self, n: &ImportDecl) {
        let ImportDecl {
            src: Str { value, span, .. },
            ..
        } = n;
        if value == "@forge/api" {
            debug!("found @forge/api");
            self.in_forge_import = true;
        }
        let old_import = self.current_import.clone();
        self.current_import = (value.clone(), span.ctxt());
        n.visit_children_with(self);
        // there shouldn't be nested import decls...
        self.current_import = old_import;
        self.in_forge_import = false;
    }

    fn visit_import_named_specifier(&mut self, n: &ImportNamedSpecifier) {
        if n.is_type_only {
            return;
        }
        let ImportNamedSpecifier {
            local, imported, ..
        } = n;
        debug!(?local, orig = ?imported, ?self.in_forge_import, "adding named specifier");
        let exported_name = imported.clone();
        let local = local.to_id();
        let exported_name = match exported_name {
            Some(exported_name) => exported_name.into(),
            None => ImportKind::Same(local.clone()),
        };

        if self.in_forge_import {
            let imported = imported.as_ref();
            if &local.0 == "authorize" {
                self.forge_imports.authorize = Some(imported.map_or(local, export_name_into_id));
                return;
            } else if &local.0 == "asApp" {
                self.forge_imports.as_app = Some(imported.map_or(local, export_name_into_id));
                return;
            }
        }
        self.add_import(exported_name);
    }

    fn visit_import_default_specifier(&mut self, n: &ImportDefaultSpecifier) {
        let ImportDefaultSpecifier { local, .. } = n;
        let local = local.to_id();
        debug!(?local);
        if self.in_forge_import && &local.0 == "api" {
            debug!("adding forge import");
            self.forge_imports.api = Some(local);
            return;
        }
        self.add_import(ImportKind::Default);
    }

    fn visit_import_star_as_specifier(&mut self, n: &ImportStarAsSpecifier) {
        let ImportStarAsSpecifier { local, .. } = n;
        let local = local.to_id();
        debug!(?local, "adding star import");
        self.add_import(ImportKind::Star(local));
    }

    fn visit_module_item(&mut self, n: &ModuleItem) {
        match n {
            ModuleItem::ModuleDecl(ModuleDecl::Import(n)) => n.visit_with(self),
            ModuleItem::Stmt(_) => {}
            _ => {}
        }
    }

    // #[tracing::instrument(level = "debug", skip_all)]
    // fn visit_export_specifier(&mut self, n: &ExportSpecifier) {
    //     match n {
    //         // TODO: handle this case for this
    //         ExportSpecifier::Namespace(_) => {}
    //         ExportSpecifier::Default(ExportDefaultSpecifier { exported }) => {
    //             let ident = exported.to_id();
    //             debug!(?ident, "adding default export");
    //             self.exports = Some(Exports::Default(ident))
    //         }
    //         ExportSpecifier::Named(ExportNamedSpecifier { orig, exported, .. }) => {
    //             let exports = self
    //                 .exports
    //                 .get_or_insert_with(|| Exports::Named(Default::default()));
    //             let orig = export_name_into_id(orig);
    //             let exported = exported
    //                 .as_ref()
    //                 .map_or_else(|| orig.clone(), export_name_into_id);
    //             debug!(?orig, ?exported, "adding named export");
    //             exports.add_named(orig, exported);
    //         }
    //     }
    // }
}

impl Exports {
    fn add_named(&mut self, orig: Id, exported: Id) {
        match self {
            Exports::Named(map) => map.insert(orig, exported),
            Exports::Default(_) => panic!("expected named exports"),
        };
    }

    pub(crate) fn orig_from_str(&self, lookup: &str) -> Option<Id> {
        match self {
            Exports::Default(_) => None,
            Exports::Named(exports) => exports
                .iter()
                .find_map(|(orig, exported)| (&exported.0 == lookup).then(|| orig.clone())),
        }
    }

    pub(crate) fn find_orig(&self, lookup: &Id) -> Option<Id> {
        match self {
            Exports::Default(_) => None,
            Exports::Named(exports) => exports
                .iter()
                .find_map(|(orig, exported)| (exported.0 == lookup.0).then(|| orig.clone())),
        }
    }
}

impl ImportKind {
    pub(crate) fn equal_funcname(&self, func: &str) -> bool {
        match self {
            ImportKind::Renamed(id) | ImportKind::Same(id) => &id.0 == func,
            ImportKind::Star(_) => false,
            ImportKind::Default => false,
        }
    }
}

impl From<ModuleExportName> for ImportKind {
    fn from(m: ModuleExportName) -> Self {
        Self::Renamed(match m {
            ModuleExportName::Ident(ident) => ident.to_id(),
            ModuleExportName::Str(Str {
                span,
                value,
                raw: _,
            }) => (value, span.ctxt()),
        })
    }
}

impl From<Id> for ImportKind {
    fn from(id: Id) -> Self {
        Self::Same(id)
    }
}
