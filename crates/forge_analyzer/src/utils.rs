use swc_core::ecma::ast::{CallExpr, Callee, Expr, MemberProp};

pub fn call_func_with_name(n: &CallExpr, name: &str) -> bool {
    if let Callee::Expr(expr) = &n.callee {
        if let Expr::Member(mem) = &**expr {
            if let MemberProp::Ident(ident) = &mem.prop {
                if ident.sym.to_string() == name {
                    return true;
                }
            }
        }
    }
    false
}
