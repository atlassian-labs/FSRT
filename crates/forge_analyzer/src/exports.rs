use crate::Exports;
use rustc_hash::FxHashMap;
use swc_core::ecma::{
    ast::{
        BindingIdent, Decl, ExportAll, ExportDecl, ExportDefaultDecl, ExportDefaultExpr, FnDecl,
        ModuleDecl, ModuleItem, Pat, VarDecl, VarDeclarator,
    },
    visit::{noop_visit_type, Visit, VisitWith},
};
use tracing::debug;

#[derive(Debug, Default)]
pub(crate) struct ExportCollector {
    pub(crate) exports: Option<Exports>,
}

impl ExportCollector {
    #[inline]
    pub(crate) fn new() -> Self {
        Self { exports: None }
    }
}

impl Visit for ExportCollector {
    noop_visit_type!();
    fn visit_export_decl(&mut self, n: &ExportDecl) {
        match &n.decl {
            Decl::Class(_) => {}
            Decl::Fn(FnDecl { ident, .. }) => {
                let export_ids = self
                    .exports
                    .get_or_insert_with(|| Exports::Named(FxHashMap::default()));
                let ident = ident.to_id();
                debug!(?ident, "function export");
                // TODO: redo export layout to avoid clones
                export_ids.add_named(ident.clone(), ident);
            }
            Decl::Var(VarDecl { decls, .. }) => {
                decls.iter().for_each(|var| self.visit_var_declarator(var));
            }
            Decl::TsInterface(_) => {}
            Decl::TsTypeAlias(_) => {}
            Decl::TsEnum(_) => {}
            Decl::TsModule(_) => {}
        };
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        if let Pat::Ident(BindingIdent { id, .. }) = &n.name {
            let export_ids = self
                .exports
                .get_or_insert_with(|| Exports::Named(FxHashMap::default()));
            let id = id.to_id();
            debug!(ident = ?id, "variable export");
            // TODO: redo export layout to avoid clones
            export_ids.add_named(id.clone(), id);
        }
    }

    fn visit_module_item(&mut self, n: &ModuleItem) {
        match n {
            ModuleItem::ModuleDecl(decl)
                if matches!(
                    decl,
                    ModuleDecl::ExportDecl(_)
                        | ModuleDecl::ExportDefaultDecl(_)
                        | ModuleDecl::ExportDefaultExpr(_)
                        | ModuleDecl::ExportAll(_)
                        | ModuleDecl::ExportNamed(_)
                ) =>
            {
                decl.visit_children_with(self)
            }
            _ => {}
        }
    }

    fn visit_export_all(&mut self, _: &ExportAll) {}

    fn visit_export_default_decl(&mut self, _: &ExportDefaultDecl) {}
    fn visit_export_default_expr(&mut self, _: &ExportDefaultExpr) {}
}
