//! Finds JavaScript constructs whose data flow the IR lowering drops or only
//! approximates. A body that contains one is not flow complete: a policy that
//! concludes something from the *absence* of a flow (a response that never
//! reaches the return value, a route no caller input reaches) must not rely on
//! it. Everything here is deliberately conservative; a construct that is merely
//! unusual is reported as lossy.
//!
//! Function values passed as call arguments are not lossy: their bodies are kept
//! apart (`Environment::authz_closures`) and the flow analysis joins them to the
//! call. Function values anywhere else (returned, stored, assigned) are.
use super::*;

/// The first construct in a function's own statements whose data flow is not
/// fully lowered, or `None` when the function is flow complete.
pub(super) fn flow_gap<B: VisitWith<Lossy>>(params: &[Pat], body: &B) -> Option<&'static str> {
    let mut lossy = Lossy::default();
    // A rest parameter is not bound at all.
    if params.iter().any(|param| matches!(param, Pat::Rest(_))) {
        lossy.set("rest parameter");
    }
    params.visit_with(&mut lossy);
    body.visit_with(&mut lossy);
    lossy.0
}

#[derive(Default)]
pub(super) struct Lossy(Option<&'static str>);

impl Lossy {
    fn set(&mut self, reason: &'static str) {
        self.0.get_or_insert(reason);
    }

    fn literal(expr: &Expr) -> bool {
        matches!(expr, Expr::Lit(_))
            || matches!(expr, Expr::Tpl(tpl) if tpl.exprs.is_empty())
            || matches!(expr, Expr::Array(array) if array.elems.is_empty())
            || matches!(expr, Expr::Object(object) if object.props.is_empty())
            || matches!(expr, Expr::Ident(ident) if ident.sym == *"undefined")
    }

    /// Whether the statements of a callback contain a `return` of their own.
    pub(super) fn returns(block: &BlockStmt) -> bool {
        #[derive(Default)]
        struct Returns(bool);
        impl Visit for Returns {
            noop_visit_type!();
            fn visit_return_stmt(&mut self, _: &ReturnStmt) {
                self.0 = true;
            }
            fn visit_function(&mut self, _: &Function) {}
            fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
        }
        let mut returns = Returns::default();
        block.visit_with(&mut returns);
        returns.0
    }

    /// An expression that only reads: a reference, a property path of one, or a
    /// default between such reads.
    pub(super) fn pure(expr: &Expr) -> bool {
        match expr {
            Expr::Ident(_) => true,
            Expr::Member(member) => {
                Self::pure(&member.obj)
                    && match &member.prop {
                        MemberProp::Ident(_) => true,
                        MemberProp::Computed(computed) => {
                            matches!(&*computed.expr, Expr::Lit(_) | Expr::Ident(_))
                        }
                        MemberProp::PrivateName(_) => false,
                    }
            }
            Expr::Paren(paren) => Self::pure(&paren.expr),
            Expr::TsNonNull(inner) => Self::pure(&inner.expr),
            Expr::TsAs(inner) => Self::pure(&inner.expr),
            Expr::OptChain(chain) => match &*chain.base {
                swc_core::ecma::ast::OptChainBase::Member(member) => {
                    Self::pure(&member.obj) && matches!(&member.prop, MemberProp::Ident(_))
                }
                swc_core::ecma::ast::OptChainBase::Call(_) => false,
            },
            Expr::Bin(bin) => {
                matches!(
                    bin.op,
                    swc_core::ecma::ast::BinaryOp::LogicalOr
                        | swc_core::ecma::ast::BinaryOp::LogicalAnd
                        | swc_core::ecma::ast::BinaryOp::NullishCoalescing
                ) && (Self::pure(&bin.left) || Self::literal(&bin.left))
                    && (Self::pure(&bin.right) || Self::literal(&bin.right))
            }
            _ => false,
        }
    }

    /// The arguments of a call, leaving out function values: those are analysed
    /// with the call.
    fn arguments<'a>(&mut self, args: impl IntoIterator<Item = &'a ExprOrSpread>) {
        for arg in args {
            if !matches!(&*arg.expr, Expr::Arrow(_) | Expr::Fn(_)) {
                arg.visit_with(self);
            }
        }
    }
}

impl Visit for Lossy {
    noop_visit_type!();

    // The handler is lowered as a body of its own and checked there.
    fn visit_try_stmt(&mut self, stmt: &TryStmt) {
        stmt.block.visit_with(self);
        stmt.finalizer.visit_with(self);
    }

    // A function value that is not the initializer of a binding is returned,
    // stored or assigned, and nothing connects its body to the flow.
    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        declarator.name.visit_with(self);
        match declarator.init.as_deref() {
            Some(Expr::Arrow(_) | Expr::Fn(_)) | None => {}
            Some(init) => init.visit_with(self),
        }
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        call.callee.visit_with(self);
        self.arguments(&call.args);
    }

    fn visit_opt_call(&mut self, call: &OptCall) {
        call.callee.visit_with(self);
        self.arguments(&call.args);
    }

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {
        self.set("function value");
    }

    fn visit_fn_expr(&mut self, _: &FnExpr) {
        self.set("function value");
    }

    fn visit_class(&mut self, _: &swc_core::ecma::ast::Class) {
        self.set("class");
    }

    // Function declarations are bindings with bodies of their own.
    fn visit_fn_decl(&mut self, _: &FnDecl) {}

    fn visit_object_lit(&mut self, object: &ObjectLit) {
        for prop in &object.props {
            match prop {
                // The lowering drops a computed key's value.
                PropOrSpread::Prop(prop) if matches!(&**prop, Prop::KeyValue(kv) if matches!(kv.key, PropName::Computed(_))) => {
                    self.set("computed key")
                }
                PropOrSpread::Prop(prop)
                    if matches!(&**prop, Prop::KeyValue(_) | Prop::Shorthand(_)) => {}
                // What a spread copies is linked to the object.
                PropOrSpread::Spread(_) => {}
                _ => self.set("object method or accessor"),
            }
        }
        object.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, expr: &NewExpr) {
        if !matches!(&*expr.callee, Expr::Ident(_)) {
            self.set("new of a non-identifier");
        }
        expr.callee.visit_with(self);
        self.arguments(expr.args.iter().flatten());
    }

    fn visit_callee(&mut self, callee: &Callee) {
        match callee {
            Callee::Expr(expr) => expr.visit_with(self),
            Callee::Super(_) | Callee::Import(_) => self.set("super or dynamic import"),
        }
    }

    fn visit_this_expr(&mut self, _: &ThisExpr) {
        self.set("this");
    }

    fn visit_yield_expr(&mut self, _: &YieldExpr) {
        self.set("yield");
    }

    fn visit_meta_prop_expr(&mut self, _: &MetaPropExpr) {
        self.set("meta property");
    }

    fn visit_with_stmt(&mut self, _: &WithStmt) {
        self.set("with");
    }

    fn visit_jsx_element(&mut self, _: &JSXElement) {
        self.set("jsx");
    }

    fn visit_jsx_fragment(&mut self, _: &JSXFragment) {
        self.set("jsx");
    }

    fn visit_for_head(&mut self, head: &ForHead) {
        if matches!(head, ForHead::UsingDecl(_)) {
            self.set("using declaration");
        }
        head.visit_children_with(self);
    }

    fn visit_decl(&mut self, decl: &Decl) {
        if matches!(decl, Decl::Class(_) | Decl::Using(_)) {
            self.set("class or using declaration");
        }
        decl.visit_children_with(self);
    }

    // The lowering drops default values.
    fn visit_assign_pat(&mut self, pat: &AssignPat) {
        if !Self::literal(&pat.right) {
            self.set("default value");
        }
        pat.visit_children_with(self);
    }

    fn visit_assign_pat_prop(&mut self, prop: &AssignPatProp) {
        if prop
            .value
            .as_deref()
            .is_some_and(|value| !Self::literal(value))
        {
            self.set("default value");
        }
        prop.visit_children_with(self);
    }

    fn visit_simple_assign_target(&mut self, target: &SimpleAssignTarget) {
        if matches!(target, SimpleAssignTarget::SuperProp(_)) {
            self.set("super property");
        }
        target.visit_children_with(self);
    }
}
