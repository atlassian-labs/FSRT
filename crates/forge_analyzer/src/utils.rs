use crate::definitions::CalleeRef;
use swc_core::ecma::ast::{Expr, MemberProp};

pub fn calls_method(n: CalleeRef<'_>, name: &str) -> bool {
    if let CalleeRef::Expr(Expr::Member(mem)) = &n {
        if let MemberProp::Ident(ident) = &mem.prop {
            return ident.sym == *name;
        }
    }
    false
}
