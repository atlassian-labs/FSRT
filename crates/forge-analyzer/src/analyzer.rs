// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0

use std::iter;

use crate::utils::FxHashMap;
use swc_core::ecma::ast::{BindingIdent, CallExpr, Callee, Expr, FnDecl, Id, VarDeclarator};
use swc_core::ecma::visit::{noop_visit_type, Visit, VisitWith};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum AuthZVals {
    Authorize, // BOT
    Unauthorized,
    #[default]
    Noop, // TOP
    Unknown {
        // technically this is the real TOP
        needs_resolution: Vec<Id>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FunctionInfo {
    funcalls: Vec<Id>,
    status: AuthZVals,
}

impl FunctionInfo {
    pub fn new() -> Self {
        Self {
            funcalls: Vec::new(),
            status: AuthZVals::default(),
        }
    }
}

#[derive(Debug)]
struct FunctionCollector {
    functions: Vec<Id>,
}

#[derive(Debug)]
struct FunctionAnalyzer {
    call_stack: Vec<Id>,
    func_info: FxHashMap<Id, FunctionInfo>,
}

impl FunctionAnalyzer {
    fn with_functions<T>(functions: T) -> Self
    where
        T: IntoIterator<Item = Id>,
    {
        let func_info = functions
            .into_iter()
            .zip(iter::repeat_with(FunctionInfo::new))
            .collect();
        Self {
            func_info,
            call_stack: Vec::new(),
        }
    }
}

impl Visit for FunctionAnalyzer {
    noop_visit_type!();
    fn visit_call_expr(&mut self, n: &CallExpr) {
        let CallExpr { callee, .. } = n;
        if let Callee::Expr(expr) = callee {
            match &**expr {
                Expr::Ident(id) => self.call_stack.push(id.to_id()),
                _ => todo!(),
            }
        }
    }
}

impl Visit for FunctionCollector {
    noop_visit_type!();

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let id = n.ident.to_id();
        self.functions.push(id);
        n.function.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        if let Some(expr) = &n.init {
            match &**expr {
                Expr::Arrow(expr) => {
                    if let Some(BindingIdent { id, .. }) = n.name.as_ident() {
                        let id = id.to_id();
                        self.functions.push(id);
                        expr.visit_children_with(self);
                    }
                }
                Expr::Fn(expr) => {
                    if let Some(BindingIdent { id, .. }) = n.name.as_ident() {
                        let id = id.to_id();
                        self.functions.push(id);
                        expr.visit_children_with(self);
                    }
                }
                _ => {}
            }
        }
    }
}
