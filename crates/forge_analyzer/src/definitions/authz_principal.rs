//! AST facts needed for immutable boolean arguments. The legacy IR omits some
//! writes (notably catches and updates), so IR assignment counts are insufficient.
use super::*;

#[derive(Default)]
pub(super) struct Writes {
    ids: HashSet<Id>,
    reassigned: HashSet<Id>,
    pub opaque: bool,
}

impl Writes {
    fn target<N: VisitWith<Identifiers>>(&mut self, node: &N) {
        let mut ids = Identifiers::default();
        node.visit_with(&mut ids);
        self.reassigned.extend(ids.0.iter().cloned());
        self.ids.extend(ids.0);
    }
}

#[derive(Default)]
struct Identifiers(HashSet<Id>);
impl Visit for Identifiers {
    fn visit_ident(&mut self, ident: &Ident) {
        self.0.insert(ident.to_id());
    }
}

impl Visit for Writes {
    fn visit_assign_expr(&mut self, expr: &AssignExpr) {
        self.target(&expr.left);
        expr.visit_children_with(self);
    }
    fn visit_update_expr(&mut self, expr: &UpdateExpr) {
        self.target(&expr.arg);
        expr.visit_children_with(self);
    }
    fn visit_var_declarator(&mut self, decl: &VarDeclarator) {
        if decl.init.is_some() {
            let mut ids = Identifiers::default();
            decl.name.visit_with(&mut ids);
            self.ids.extend(ids.0);
        }
        decl.visit_children_with(self);
    }
    fn visit_fn_decl(&mut self, decl: &FnDecl) {
        self.ids.insert(decl.ident.to_id());
        decl.visit_children_with(self);
    }
    fn visit_for_of_stmt(&mut self, stmt: &ForOfStmt) {
        self.target(&stmt.left);
        stmt.visit_children_with(self);
    }
    fn visit_for_in_stmt(&mut self, stmt: &ForInStmt) {
        self.target(&stmt.left);
        stmt.visit_children_with(self);
    }
    fn visit_ident(&mut self, ident: &Ident) {
        // Deliberately conservative, including shadowed names. Dynamic code and
        // aliased arguments must not create an immutable-parameter proof.
        self.opaque |= matches!(ident.sym.as_ref(), "arguments" | "eval" | "Function");
    }
}

pub(super) fn record(
    env: &Environment,
    module: ModId,
    body: &mut Body,
    params: &[Pat],
    writes: Writes,
) {
    body.authz_principal_opaque = writes.opaque;
    body.authz_written_bindings = writes
        .reassigned
        .iter()
        .filter_map(|id| env.sym_to_id(id.clone(), module))
        .collect();
    body.authz_bool_parameters = params
        .iter()
        .map(|param| {
            let (ident, default) = match param {
                Pat::Ident(ident) => (ident, None),
                Pat::Assign(assign) => {
                    let Pat::Ident(ident) = &*assign.left else {
                        return None;
                    };
                    let default = match &*assign.right {
                        Expr::Lit(Lit::Bool(value)) => Some(value.value),
                        _ => None,
                    };
                    (ident, default)
                }
                _ => return None,
            };
            if writes.ids.contains(&ident.to_id()) {
                return None;
            }
            Some((env.sym_to_id(ident.to_id(), module)?, default))
        })
        .collect();
}
