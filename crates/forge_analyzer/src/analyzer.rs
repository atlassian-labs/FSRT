// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0

use crate::ctx::{BasicBlockId, FunctionMeta, IrStmt, ModuleCtx, STARTING_BLOCK};
use crate::lattice::MeetSemiLattice;
use crate::utils::FxHashMap;
use swc_core::ecma::ast::{
    ArrowExpr, BindingIdent, CallExpr, Callee, Expr, ExprOrSpread, FnDecl, FnExpr, Id, IfStmt,
    JSXElementName, JSXOpeningElement, MemberExpr, MemberProp, Pat, Str, TplElement, VarDeclarator,
};
use swc_core::ecma::visit::{noop_visit_type, Visit, VisitWith};
use tracing::{debug, instrument};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthZVal {
    Authorize, // BOT
    Unauthorized,
    Noop,
    #[default]
    Unknown, // TOP
}

impl MeetSemiLattice for AuthZVal {
    // true if we would change the other
    // note: try to use exhaustive pattern matching on these functions
    // even if [`matches!`] is terser, since we should be looking at this
    // every time [`AuthZVal`] changes
    fn meet(&mut self, other: Self) -> bool {
        use AuthZVal::*;
        if *self == Unauthorized || other == Unauthorized {
            debug!(?self, ?other, "found unauthorized");
        }
        match (*self, other) {
            (_, Authorize) => {
                *self = Authorize;
                false
            }
            (Authorize, _) => true,
            (Unauthorized, Noop | Unknown) => true,
            (Unauthorized | Unknown | Noop, Unauthorized) => {
                *self = Unauthorized;
                false
            }
            (Unknown, Noop) => {
                *self = Noop;
                false
            }
            (Noop, Unknown) => true,
            (Noop, Noop) | (Unknown, Unknown) => false,
        }
    }
}

pub(crate) struct FunctionCollector<'ctx> {
    functions: FxHashMap<Id, FunctionMeta>,
    ctx: &'ctx ModuleCtx,
}

#[instrument(level = "debug", skip_all)]
pub(crate) fn collect_functions<N>(node: &N, ctx: &ModuleCtx) -> FxHashMap<Id, FunctionMeta>
where
    for<'a> N: VisitWith<FunctionCollector<'a>>,
{
    let mut collector = FunctionCollector::new(ctx);
    node.visit_with(&mut collector);
    collector.functions
}

impl<'ctx> FunctionCollector<'ctx> {
    #[inline]
    fn new(ctx: &'ctx ModuleCtx) -> Self {
        Self {
            ctx,
            functions: FxHashMap::default(),
        }
    }

    #[inline]
    #[instrument(level = "debug", skip(self, body))]
    fn add_func_meta<N>(&mut self, id: Id, body: &N)
    where
        for<'a> N: VisitWith<FunctionAnalyzer<'a>>,
    {
        let meta = analyze_functions(body, self.ctx);
        self.functions.insert(id, meta);
    }
}

struct FunctionAnalyzer<'a> {
    ctx: &'a ModuleCtx,
    meta: FunctionMeta,
    curr_block: BasicBlockId,
}

// technically the HRTB is unnecessary, since we only need the lifetime from `ForgeImports`,
// however, I might add more lifetime params to [`FunctionAnalyzer`] in the future
fn analyze_functions<N>(body: &N, forge_imports: &ModuleCtx) -> FunctionMeta
where
    for<'a> N: VisitWith<FunctionAnalyzer<'a>>,
{
    let mut analyzer = FunctionAnalyzer::new(forge_imports);
    body.visit_children_with(&mut analyzer);
    analyzer.meta
}

struct CheckApiCalls {
    perms_related: bool,
}

fn contains_perms_check<N: VisitWith<CheckApiCalls>>(node: &N) -> bool {
    let mut perms_checker = CheckApiCalls {
        perms_related: false,
    };
    node.visit_with(&mut perms_checker);
    return perms_checker.perms_related;

    impl Visit for CheckApiCalls {
        fn visit_str(&mut self, n: &Str) {
            if n.value.contains("perm") {
                self.perms_related = true;
            }
        }

        fn visit_tpl_element(&mut self, n: &TplElement) {
            if n.raw.contains("perm") {
                self.perms_related = true;
            }
        }
    }
}

impl<'a> FunctionAnalyzer<'a> {
    #[inline]
    fn new(ctx: &'a ModuleCtx) -> Self {
        Self {
            ctx,
            meta: FunctionMeta::new(),
            curr_block: STARTING_BLOCK,
        }
    }

    #[inline]
    fn add_ir_stmt(&mut self, stmt: IrStmt) {
        debug!(?stmt, "adding new ir stmt");
        self.meta.add_stmt(self.curr_block, stmt);
    }

    fn is_as_app_access(&self, n: &Expr) -> bool {
        let callee = as_callee(n);
        match callee {
            Some(Expr::Ident(ident)) => self.ctx.is_as_app(&ident.to_id()),
            Some(Expr::Member(MemberExpr {
                obj,
                prop: MemberProp::Ident(ident),
                ..
            })) if &ident.sym == "asApp" => {
                let ident = ident.to_id();
                debug!(?obj, prop = ?&ident.0, "checking api import");
                obj.as_ident()
                    .filter(|obj| self.ctx.is_api(&obj.to_id()))
                    .is_some()
            }
            _ => false,
        }
    }
}

#[inline]
fn as_callee(n: &Expr) -> Option<&Expr> {
    match n {
        Expr::Call(CallExpr {
            callee: Callee::Expr(callee),
            ..
        }) => Some(callee),
        _ => None,
    }
}

impl Visit for FunctionAnalyzer<'_> {
    noop_visit_type!();

    /**
    fn visit_if_stmt(&mut self, n: &IfStmt) {
        n.test.visit_with(self);
        let pred = self.curr_block;
        self.curr_block = self.meta.create_block_from(pred);
        n.cons.visit_with(self);
        let next = self.meta.create_block_from(self.curr_block);
        if let Some(stmt) = &n.alt {
            self.curr_block = self.meta.create_block_from(pred);
            stmt.visit_with(self);
            self.meta.add_edge(self.curr_block, next);
        }
        self.curr_block = next;
    }
    */

    // FIXME: desugaring the jsx may make analysis simpler
    fn visit_jsx_opening_element(&mut self, n: &JSXOpeningElement) {
        n.visit_children_with(self);
        match &n.name {
            JSXElementName::Ident(id) => self.add_ir_stmt(id.into()),
            // FIXME: add cases for these
            JSXElementName::JSXMemberExpr(_) => {}
            JSXElementName::JSXNamespacedName(_) => {}
        }
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        n.visit_children_with(self);
        let CallExpr { callee, args, .. } = n;
        if let Callee::Expr(expr) = callee {
            match &**expr {
                Expr::Ident(id) => {
                    let id = id.to_id();
                    debug!(?id, "analyzing function call");
                    let irstmt = if self.ctx.is_authorize(&id) {
                        IrStmt::Resolved(AuthZVal::Authorize)
                    } else if self.ctx.has_import(&id, "@forge/ui", "useState") {
                        // FIXME: recognize more cases of lazy initialization
                        if let [ExprOrSpread { expr, .. }] = &**args {
                            match &**expr {
                                Expr::Arrow(ArrowExpr { body, .. }) => body.visit_with(self),
                                Expr::Fn(FnExpr { ident: _, function }) => {
                                    if let Some(body) = &function.body {
                                        body.visit_with(self);
                                    }
                                }
                                _ => {}
                            }
                        }
                        // we don't need to add this to the IR, since we know it's useless
                        return;
                    } else {
                        id.into()
                    };
                    self.add_ir_stmt(irstmt);
                }
                Expr::Member(MemberExpr { obj, prop, .. }) => match prop {
                    MemberProp::Ident(ident) => {
                        let ident = ident.to_id();
                        debug!(propname = ?&ident.0, "analyzing method call");
                        if &ident.0 == "requestJira" || &ident.0 == "requestConfluence" {
                            debug!(api = ?&ident.0, "found api call");
                            let perms = args.iter().any(|e| contains_perms_check(&e.expr));
                            debug!(perms_check = ?perms);
                            if perms {
                                self.add_ir_stmt(IrStmt::Resolved(AuthZVal::Authorize));
                            } else if self.is_as_app_access(obj) {
                                self.add_ir_stmt(IrStmt::Resolved(AuthZVal::Unauthorized));
                            }
                        }
                    }
                    // FIXME: also check asApp calls using these params
                    MemberProp::PrivateName(_) => {}
                    MemberProp::Computed(_) => {}
                },
                _ => {}
            }
        }
    }

    // intentionally no-ops to avoid tainting the current functions IR
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}

    fn visit_fn_expr(&mut self, _: &FnExpr) {}

    fn visit_fn_decl(&mut self, _: &FnDecl) {}
}

impl Visit for FunctionCollector<'_> {
    noop_visit_type!();

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let id = n.ident.to_id();
        self.add_func_meta(id, &n.function);
        n.function.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        if let VarDeclarator {
            name: Pat::Ident(BindingIdent { id, .. }),
            init: Some(expr),
            ..
        } = n
        {
            let id = id.to_id();
            debug!(?id, "binding ident");

            match &**expr {
                Expr::Arrow(expr) => {
                    self.add_func_meta(id, &expr.body);
                    expr.visit_children_with(self);
                }
                Expr::Fn(expr) => {
                    self.add_func_meta(id, &expr.function);
                    expr.visit_children_with(self);
                }
                Expr::Call(CallExpr {
                    callee: Callee::Expr(expr),
                    args,
                    ..
                }) => {
                    // mfw no deref patterns
                    if let Expr::Ident(ident) = &**expr {
                        let ident = ident.to_id();
                        debug!(var = ?ident, "checking call to");
                        if self.ctx.has_import(&ident, "@forge/ui", "render") {
                            self.add_func_meta(id, args);
                            expr.visit_children_with(self);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
