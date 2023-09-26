use crate::definitions::CalleeRef;
use swc_core::ecma::ast::{Expr, Lit, MemberProp};

pub fn calls_method(n: CalleeRef<'_>, name: &str) -> bool {
    if let CalleeRef::Expr(Expr::Member(mem)) = &n {
        if let MemberProp::Ident(ident) = &mem.prop {
            return ident.sym == *name;
        }
    }
    false
}

pub fn eq_prop_name(n: &MemberProp, name: &str) -> bool {
    match n {
        MemberProp::Ident(ident) => ident.sym == *name,
        MemberProp::Computed(expr) => match expr.expr.as_ref() {
            Expr::Lit(Lit::Str(lit)) => *lit.value == *name,
            _ => false,
        },
        _ => false,
    }
}

const RED_ZONE: usize = 100 * 1024;

const STACK_SIZE: usize = 1024 * 1024;

#[inline]
pub(crate) fn ensure_sufficient_stack<T>(f: impl FnOnce() -> T) -> T {
    stacker::maybe_grow(RED_ZONE, STACK_SIZE, || f())
}
