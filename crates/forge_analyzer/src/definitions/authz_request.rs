//! Reads the HTTP method and route of `requestJira(route, options)` and its
//! siblings from the call's arguments. Only inline literals are trusted: a
//! spread, a computed key or a value this lowering cannot see is `Unknown`.
use super::*;
use crate::request::{ConstFacts, Fact, HttpMethod, Piece, RequestFacts, RouteText};

impl FunctionAnalyzer<'_> {
    pub(super) fn request_facts(&self, args: &[ExprOrSpread]) -> RequestFacts {
        if args.is_empty() || args.len() > 2 || args.iter().any(|arg| arg.spread.is_some()) {
            return RequestFacts {
                route: Fact::Unknown,
                method: Fact::Unknown,
            };
        }
        RequestFacts {
            route: self.route_fact(&args[0].expr),
            method: self.method_fact(args.get(1).map(|arg| &*arg.expr)),
        }
    }

    /// What a `const` initializer says about a route or the request options.
    pub(super) fn const_facts(&self, init: &Expr) -> ConstFacts {
        ConstFacts {
            route: match self.route_text(init) {
                Some(text) if !matches!(unwrap_expr(init), Expr::Object(_)) => Some(text),
                _ => None,
            },
            method: match unwrap_expr(init) {
                Expr::Object(options) => options_method(options),
                _ => None,
            },
        }
    }

    fn route_fact(&self, expr: &Expr) -> Fact<RouteText> {
        match unwrap_expr(expr) {
            Expr::Ident(ident) => self
                .res
                .sym_to_id(ident.to_id(), self.module)
                .map_or(Fact::Unknown, Fact::Binding),
            expr => self.route_text(expr).map_or(Fact::Unknown, Fact::Known),
        }
    }

    fn method_fact(&self, options: Option<&Expr>) -> Fact<HttpMethod> {
        let Some(options) = options else {
            return Fact::Known(HttpMethod::Get);
        };
        match unwrap_expr(options) {
            Expr::Ident(ident) => self
                .res
                .sym_to_id(ident.to_id(), self.module)
                .map_or(Fact::Unknown, Fact::Binding),
            Expr::Object(options) => options_method(options).map_or(Fact::Unknown, Fact::Known),
            _ => Fact::Unknown,
        }
    }

    /// Whether `tag` is the `route` template tag imported from `@forge/api`,
    /// which only escapes its holes. Other tags may rewrite the whole string.
    fn is_route_tag(&self, tag: &Expr) -> bool {
        let Expr::Ident(ident) = unwrap_expr(tag) else {
            return false;
        };
        self.res
            .sym_to_id(ident.to_id(), self.module)
            .and_then(|def| self.res.is_imported_from(def, "@forge/api"))
            .is_some_and(|import| matches!(import, ImportKind::Named(name) if *name == *"route"))
    }

    fn template(&self, tpl: &Tpl) -> RouteText {
        let mut pieces = Vec::new();
        for (index, quasi) in tpl.quasis.iter().enumerate() {
            pieces.push(Piece::Text(quasi.raw.clone()));
            if index < tpl.exprs.len() {
                pieces.push(Piece::Hole);
            }
        }
        RouteText::new(pieces)
    }

    /// Route text written inline. A hole is any part that is not a literal.
    fn route_text(&self, expr: &Expr) -> Option<RouteText> {
        match unwrap_expr(expr) {
            Expr::Lit(Lit::Str(value)) => Some(RouteText::new([Piece::Text(
                value.value.to_string().into(),
            )])),
            Expr::Tpl(tpl) => Some(self.template(tpl)),
            Expr::TaggedTpl(tagged) if self.is_route_tag(&tagged.tag) => {
                Some(self.template(&tagged.tpl))
            }
            Expr::Bin(BinExpr {
                op: swc_core::ecma::ast::BinaryOp::Add,
                left,
                right,
                ..
            }) => {
                let part = |expr: &Expr| {
                    self.route_text(expr)
                        .unwrap_or_else(|| RouteText::new([Piece::Hole]))
                };
                let (left, right) = (part(left), part(right));
                // `a + b` is only text when one side is, as in `'/issue/' + key`.
                let text = |route: &RouteText| {
                    route
                        .pieces()
                        .iter()
                        .any(|piece| matches!(piece, Piece::Text(_)))
                };
                (text(&left) || text(&right)).then(|| left.concat(right))
            }
            _ => None,
        }
    }
}

fn unwrap_expr(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(paren) => &paren.expr,
            Expr::TsAs(cast) => &cast.expr,
            Expr::TsNonNull(cast) => &cast.expr,
            Expr::TsSatisfies(cast) => &cast.expr,
            Expr::TsConstAssertion(cast) => &cast.expr,
            Expr::Await(await_expr) => &await_expr.arg,
            _ => return expr,
        };
    }
}

/// The method of an options literal: GET when it names none, the literal when
/// it names one, and nothing when the literal may hide a method (a spread, a
/// computed key, an accessor, `__proto__`, or a method that is not a string).
fn options_method(options: &ObjectLit) -> Option<HttpMethod> {
    let mut method = HttpMethod::Get;
    for prop in &options.props {
        let PropOrSpread::Prop(prop) = prop else {
            return None;
        };
        let (key, value) = match &**prop {
            Prop::KeyValue(KeyValueProp { key, value }) => (key, Some(value)),
            Prop::Shorthand(ident) => {
                if ident.sym == *"method" || ident.sym == *"__proto__" {
                    return None;
                }
                continue;
            }
            _ => return None,
        };
        let name = match key {
            PropName::Ident(key) => key.sym.as_ref(),
            PropName::Str(key) => key.value.as_ref(),
            _ => return None,
        };
        if name == "__proto__" {
            return None;
        }
        if name == "method" {
            let Expr::Lit(Lit::Str(value)) = unwrap_expr(value?) else {
                return None;
            };
            method = HttpMethod::from_literal(&value.value);
        }
    }
    Some(method)
}

impl FunctionAnalyzer<'_> {
    /// Refuse to vouch for the flow through this function.
    pub(super) fn flow_gap(&mut self, reason: &'static str) {
        self.body.authz_flow_gap.get_or_insert(reason);
    }

    /// The parameters of a callback that was lowered without binding them take
    /// the receiver's elements.
    pub(super) fn link_parameters(&mut self, receiver: &Operand, params: &[Pat]) {
        #[derive(Default)]
        struct Bound(Vec<Id>);
        impl Visit for Bound {
            noop_visit_type!();
            fn visit_binding_ident(&mut self, ident: &BindingIdent) {
                self.0.push(ident.id.to_id());
            }
        }
        let mut bound = Bound::default();
        params.visit_with(&mut bound);
        for id in bound.0 {
            let def = self.res.get_or_insert_sym(id, self.module);
            let var = self.body.get_or_insert_global(def);
            self.body
                .authz_flow_links
                .push((receiver.clone(), Variable::new(var)));
        }
    }

    /// Remember the function values among a call's arguments, whose bodies the
    /// lowering kept apart in `Environment::authz_closures`.
    pub(super) fn record_callbacks(&mut self, args: &[ExprOrSpread]) {
        let callbacks: SmallVec<[usize; 1]> = args
            .iter()
            .filter_map(|arg| {
                let span = match &*arg.expr {
                    Expr::Arrow(arrow) => arrow.span,
                    Expr::Fn(function) => function.function.span,
                    _ => return None,
                };
                self.res.authz_closure_index.get(&span).copied()
            })
            .collect();
        if !callbacks.is_empty() {
            let location = Location::new(
                self.block,
                self.body.blockbuilders[self.block].insts.len() as u32,
            );
            self.body.authz_callbacks.insert(location, callbacks);
        }
    }
}

impl FunctionAnalyzer<'_> {
    /// A catch handler is not part of the lowered control flow. Lower it as a body
    /// of its own so the flow analysis can follow what it reads and returns.
    pub(super) fn lower_catch(&mut self, handler: &swc_core::ecma::ast::CatchClause) {
        let owner = self
            .res
            .add_anonymous("__CATCH", AnonType::Closure, self.module);
        let params: Vec<Pat> = handler.param.iter().cloned().collect();
        let mut args = ArgDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body: Body::with_owner(owner),
            current_arg: Variable::default(),
        };
        args.visit_pats(&params);
        let mut locals = LocalDefiner {
            res: args.res,
            module: self.module,
            func: owner,
            body: args.body,
        };
        handler.body.visit_with(&mut locals);
        locals.body.authz_flow_gap = authz_lossy::flow_gap(&params, &handler.body);
        let mut analyzer = FunctionAnalyzer::new(
            locals.res,
            self.module,
            owner,
            self.secret_packages,
            locals.body,
            self.suspicious_remotes,
        );
        analyzer.lower_stmts(&handler.body.stmts);
        for bb in analyzer.body.iter_block_keys().collect::<Vec<_>>() {
            if !analyzer.body.block(bb).set_term_called {
                analyzer.body.set_terminator(bb, Terminator::Ret);
            }
        }
        let body = analyzer.body;
        let index = self.res.add_closure(handler.span, body);
        self.body.authz_catches.push(index);
    }
}
