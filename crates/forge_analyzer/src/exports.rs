use crate::Exports;
use forge_utils::FxHashMap;
use swc_core::ecma::{
    ast::{
        AssignExpr, BindingIdent, Decl, ExportAll, ExportDecl, ExportDefaultDecl,
        ExportDefaultExpr, Expr, FnDecl, MemberProp, ModuleDecl, ModuleExportName, ModuleItem, Pat,
        PatOrExpr, VarDecl, VarDeclarator,
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
        //println!("export collector {n:?}");
        println!();

        match &n.decl {
            Decl::Class(_) => {}
            Decl::Fn(FnDecl { ident, .. }) => {
                let export_ids = self
                    .exports
                    .get_or_insert_with(|| Exports::Named(FxHashMap::default()));
                let ident = ident.to_id();
                debug!(?ident, "function export");
                // TODO: redo export layout to avoid clones
                println!("exported ident {ident:?}");
                export_ids.add_named(ident.clone(), ident);
            }
            Decl::Var(vardecls) => {
                let VarDecl { decls, .. } = &**vardecls;
                //println!("exported vardecls {vardecls:?}");
                decls.iter().for_each(|var| self.visit_var_declarator(var));
            }
            Decl::TsInterface(_) => {}
            Decl::TsTypeAlias(_) => {}
            Decl::TsEnum(_) => {}
            Decl::TsModule(_) => {}
        };
    }

    fn visit_module_export_name(&mut self, n: &ModuleExportName) {
        //println!("visiting module_export name");
        //println!("{n:?}");
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        // clean this before pushing
        if let PatOrExpr::Expr(expr) = &n.left {
            println!("here found moudle.exports");
            if let Expr::Member(mem_expr) = &**expr {
                if let Expr::Ident(ident) = &*mem_expr.obj {
                    println!("here found moudle.exports");
                    if ident.sym.to_string() == "module" {
                        if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                            if ident_property.sym.to_string() == "export" {
                                println!("here found moudle.exports")
                            }
                        }
                    }
                }
            }
        }
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
