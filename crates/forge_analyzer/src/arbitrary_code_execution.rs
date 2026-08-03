use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
};

use swc_core::{
    common::{SourceMap, Span},
    ecma::{
        ast::{
            BindingIdent, CallExpr, Callee, ClassDecl, Expr, ExprOrSpread, FnDecl, Id, ImportDecl,
            ImportSpecifier, Lit, MemberExpr, MemberProp, Module, ModuleExportName, NewExpr,
            ObjectPat, ObjectPatProp, Pat, PropName, VarDecl, VarDeclKind,
        },
        visit::{Visit, VisitWith},
    },
};

use crate::reporter::{IntoVuln, Reporter, Severity, Vulnerability};

const CHILD_PROCESS_MODULES: [&str; 2] = ["child_process", "node:child_process"];

fn child_process_api(name: &str) -> Option<&'static str> {
    match name {
        "exec" => Some("exec"),
        "execFile" => Some("execFile"),
        "execSync" => Some("execSync"),
        "execFileSync" => Some("execFileSync"),
        "fork" => Some("fork"),
        "spawn" => Some("spawn"),
        "spawnSync" => Some("spawnSync"),
        _ => None,
    }
}

fn is_child_process_module(name: &str) -> bool {
    CHILD_PROCESS_MODULES.contains(&name)
}

fn module_export_name(name: &ModuleExportName) -> &str {
    match name {
        ModuleExportName::Ident(ident) => ident.sym.as_ref(),
        ModuleExportName::Str(value) => value.value.as_ref(),
    }
}

fn property_name(prop: &MemberProp) -> Option<&str> {
    match prop {
        MemberProp::Ident(ident) => Some(ident.sym.as_ref()),
        MemberProp::Computed(computed) => match computed.expr.as_ref() {
            Expr::Lit(Lit::Str(value)) => Some(value.value.as_ref()),
            _ => None,
        },
        MemberProp::PrivateName(_) => None,
    }
}

fn pattern_property_name(prop: &PropName) -> Option<&str> {
    match prop {
        PropName::Ident(ident) => Some(ident.sym.as_ref()),
        PropName::Str(value) => Some(value.value.as_ref()),
        _ => None,
    }
}

#[derive(Default)]
struct Bindings {
    child_process_namespaces: HashSet<Id>,
    child_process_functions: HashMap<Id, &'static str>,
    const_values: HashMap<Id, Box<Expr>>,
    local_bindings: HashSet<Id>,
    destructures: Vec<(ObjectPat, Box<Expr>)>,
}

impl Bindings {
    fn finish(&mut self) {
        for (pattern, init) in std::mem::take(&mut self.destructures) {
            if !self.is_child_process_expression(&init, &mut HashSet::new()) {
                continue;
            }

            for prop in pattern.props {
                match prop {
                    ObjectPatProp::Assign(assign) => {
                        if let Some(api) = child_process_api(assign.key.id.sym.as_ref()) {
                            self.child_process_functions
                                .insert(assign.key.id.to_id(), api);
                        }
                    }
                    ObjectPatProp::KeyValue(key_value) => {
                        let Some(api) =
                            pattern_property_name(&key_value.key).and_then(child_process_api)
                        else {
                            continue;
                        };
                        if let Pat::Ident(local) = key_value.value.as_ref() {
                            self.child_process_functions.insert(local.id.to_id(), api);
                        }
                    }
                    ObjectPatProp::Rest(_) => {}
                }
            }
        }
    }

    fn is_global_ident(&self, ident: &swc_core::ecma::ast::Ident, name: &str) -> bool {
        ident.sym == name && !self.local_bindings.contains(&ident.to_id())
    }

    fn is_require_of_child_process(&self, call: &CallExpr) -> bool {
        let Callee::Expr(callee) = &call.callee else {
            return false;
        };
        let Expr::Ident(require) = callee.as_ref() else {
            return false;
        };
        if !self.is_global_ident(require, "require") || call.args.len() != 1 {
            return false;
        }
        matches!(
            call.args[0].expr.as_ref(),
            Expr::Lit(Lit::Str(module)) if is_child_process_module(module.value.as_ref())
        )
    }

    fn is_child_process_expression(&self, expr: &Expr, seen: &mut HashSet<Id>) -> bool {
        match expr {
            Expr::Ident(ident) => {
                let id = ident.to_id();
                if self.child_process_namespaces.contains(&id) {
                    return true;
                }
                let Some(init) = self.const_values.get(&id) else {
                    return false;
                };
                if !seen.insert(id.clone()) {
                    return false;
                }
                let result = self.is_child_process_expression(init, seen);
                seen.remove(&id);
                result
            }
            Expr::Call(call) => self.is_require_of_child_process(call),
            Expr::Paren(paren) => self.is_child_process_expression(&paren.expr, seen),
            Expr::TsAs(ts) => self.is_child_process_expression(&ts.expr, seen),
            Expr::TsConstAssertion(ts) => self.is_child_process_expression(&ts.expr, seen),
            Expr::TsInstantiation(ts) => self.is_child_process_expression(&ts.expr, seen),
            Expr::TsNonNull(ts) => self.is_child_process_expression(&ts.expr, seen),
            Expr::TsSatisfies(ts) => self.is_child_process_expression(&ts.expr, seen),
            Expr::TsTypeAssertion(ts) => self.is_child_process_expression(&ts.expr, seen),
            _ => false,
        }
    }

    fn child_process_callee(&self, expr: &Expr, seen: &mut HashSet<Id>) -> Option<&'static str> {
        match expr {
            Expr::Ident(ident) => {
                let id = ident.to_id();
                if let Some(api) = self.child_process_functions.get(&id) {
                    return Some(*api);
                }
                let init = self.const_values.get(&id)?;
                if !seen.insert(id.clone()) {
                    return None;
                }
                let result = self.child_process_callee(init, seen);
                seen.remove(&id);
                result
            }
            Expr::Member(member) => {
                let api = property_name(&member.prop).and_then(child_process_api)?;
                self.is_child_process_expression(&member.obj, &mut HashSet::new())
                    .then_some(api)
            }
            Expr::Paren(paren) => self.child_process_callee(&paren.expr, seen),
            Expr::TsAs(ts) => self.child_process_callee(&ts.expr, seen),
            Expr::TsConstAssertion(ts) => self.child_process_callee(&ts.expr, seen),
            Expr::TsInstantiation(ts) => self.child_process_callee(&ts.expr, seen),
            Expr::TsNonNull(ts) => self.child_process_callee(&ts.expr, seen),
            Expr::TsSatisfies(ts) => self.child_process_callee(&ts.expr, seen),
            Expr::TsTypeAssertion(ts) => self.child_process_callee(&ts.expr, seen),
            _ => None,
        }
    }

    fn is_static_expression(&self, expr: &Expr, seen: &mut HashSet<Id>) -> bool {
        match expr {
            Expr::Lit(_) | Expr::Object(_) | Expr::Fn(_) | Expr::Arrow(_) | Expr::Class(_) => true,
            Expr::Array(array) => array.elems.iter().all(|element| {
                element.as_ref().is_none_or(|element| {
                    element.spread.is_none() && self.is_static_expression(&element.expr, seen)
                })
            }),
            Expr::Tpl(template) => template
                .exprs
                .iter()
                .all(|expr| self.is_static_expression(expr, seen)),
            Expr::Bin(binary) => {
                self.is_static_expression(&binary.left, seen)
                    && self.is_static_expression(&binary.right, seen)
            }
            Expr::Cond(cond) => {
                self.is_static_expression(&cond.cons, seen)
                    && self.is_static_expression(&cond.alt, seen)
            }
            Expr::Seq(sequence) => sequence
                .exprs
                .last()
                .is_none_or(|expr| self.is_static_expression(expr, seen)),
            Expr::Unary(unary) => self.is_static_expression(&unary.arg, seen),
            Expr::Await(await_expr) => self.is_static_expression(&await_expr.arg, seen),
            Expr::Paren(paren) => self.is_static_expression(&paren.expr, seen),
            Expr::TsAs(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::TsConstAssertion(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::TsInstantiation(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::TsNonNull(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::TsSatisfies(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::TsTypeAssertion(ts) => self.is_static_expression(&ts.expr, seen),
            Expr::Ident(ident) => {
                let id = ident.to_id();
                if let Some(init) = self.const_values.get(&id) {
                    if !seen.insert(id.clone()) {
                        return false;
                    }
                    let result = self.is_static_expression(init, seen);
                    seen.remove(&id);
                    return result;
                }
                !self.local_bindings.contains(&id)
                    && matches!(ident.sym.as_ref(), "undefined" | "NaN" | "Infinity")
            }
            _ => false,
        }
    }
}

impl Visit for Bindings {
    fn visit_binding_ident(&mut self, ident: &BindingIdent) {
        self.local_bindings.insert(ident.id.to_id());
    }

    fn visit_fn_decl(&mut self, function: &FnDecl) {
        self.local_bindings.insert(function.ident.to_id());
        function.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, class: &ClassDecl) {
        self.local_bindings.insert(class.ident.to_id());
        class.visit_children_with(self);
    }

    fn visit_import_decl(&mut self, import: &ImportDecl) {
        for specifier in &import.specifiers {
            self.local_bindings.insert(specifier.local().to_id());
        }

        if !is_child_process_module(import.src.value.as_ref()) {
            return;
        }

        for specifier in &import.specifiers {
            match specifier {
                ImportSpecifier::Named(named) => {
                    let imported = named
                        .imported
                        .as_ref()
                        .map(module_export_name)
                        .unwrap_or(named.local.sym.as_ref());
                    if let Some(api) = child_process_api(imported) {
                        self.child_process_functions
                            .insert(named.local.to_id(), api);
                    }
                }
                ImportSpecifier::Default(default) => {
                    self.child_process_namespaces.insert(default.local.to_id());
                }
                ImportSpecifier::Namespace(namespace) => {
                    self.child_process_namespaces
                        .insert(namespace.local.to_id());
                }
            }
        }
    }

    fn visit_var_decl(&mut self, declaration: &VarDecl) {
        if declaration.kind == VarDeclKind::Const {
            for declarator in &declaration.decls {
                let Some(init) = &declarator.init else {
                    continue;
                };
                match &declarator.name {
                    Pat::Ident(ident) => {
                        self.const_values.insert(ident.id.to_id(), init.clone());
                    }
                    Pat::Object(pattern) => {
                        self.destructures.push((pattern.clone(), init.clone()));
                    }
                    _ => {}
                }
            }
        }
        declaration.visit_children_with(self);
    }
}

#[derive(Debug)]
pub struct ArbitraryCodeExecutionVuln {
    sink: &'static str,
    file: PathBuf,
    line: usize,
    column: usize,
}

impl fmt::Display for ArbitraryCodeExecutionVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Potential arbitrary code execution through {}",
            self.sink
        )
    }
}

impl IntoVuln for ArbitraryCodeExecutionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.file.hash(&mut hasher);
        self.sink.hash(&mut hasher);
        self.line.hash(&mut hasher);
        self.column.hash(&mut hasher);

        let location = format!("{}:{}:{}", self.file.display(), self.line, self.column);
        Vulnerability {
            check_name: format!("Custom-Check-Arbitrary-Code-Execution-{}", hasher.finish()),
            description: format!(
                "Non-constant input is passed to {} at {}, which may allow arbitrary code execution.",
                self.sink, location
            ),
            recommendation: "Do not execute dynamically constructed code, commands, or arguments. Remove child-process execution where possible; otherwise use a strict allowlist and an isolated sandbox.",
            proof: format!(
                "Non-constant execution input reaches {} at {}",
                self.sink, location
            ),
            severity: Severity::Critical,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: "Requirement 10.2",
            date: reporter.current_date(),
        }
    }
}

pub struct ArbitraryCodeExecutionChecker {
    vulns: Vec<ArbitraryCodeExecutionVuln>,
}

impl ArbitraryCodeExecutionChecker {
    pub fn new() -> Self {
        Self { vulns: Vec::new() }
    }

    pub fn scan_module(&mut self, module: &Module, file: &Path, source_map: &SourceMap) {
        let mut bindings = Bindings::default();
        module.visit_with(&mut bindings);
        bindings.finish();

        let mut visitor = ExecutionVisitor {
            bindings: &bindings,
            source_map,
            file,
            vulns: &mut self.vulns,
        };
        module.visit_with(&mut visitor);
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = ArbitraryCodeExecutionVuln> {
        self.vulns
    }
}

impl Default for ArbitraryCodeExecutionChecker {
    fn default() -> Self {
        Self::new()
    }
}

struct ExecutionVisitor<'a> {
    bindings: &'a Bindings,
    source_map: &'a SourceMap,
    file: &'a Path,
    vulns: &'a mut Vec<ArbitraryCodeExecutionVuln>,
}

impl ExecutionVisitor<'_> {
    fn has_dynamic_argument<'a>(&self, args: impl IntoIterator<Item = &'a ExprOrSpread>) -> bool {
        args.into_iter().any(|argument| {
            argument.spread.is_some()
                || !self
                    .bindings
                    .is_static_expression(&argument.expr, &mut HashSet::new())
        })
    }

    fn add_vuln(&mut self, sink: &'static str, span: Span) {
        let location = self.source_map.try_lookup_char_pos(span.lo).ok();
        self.vulns.push(ArbitraryCodeExecutionVuln {
            sink,
            file: self.file.to_owned(),
            line: location.as_ref().map_or(0, |location| location.line),
            column: location.map_or(0, |location| location.col_display + 1),
        });
    }
}

impl Visit for ExecutionVisitor<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee {
            let eval_sink = match callee.as_ref() {
                Expr::Ident(ident) if self.bindings.is_global_ident(ident, "eval") => Some("eval"),
                Expr::Member(MemberExpr { obj, prop, .. })
                    if matches!(obj.as_ref(), Expr::Ident(ident) if self.bindings.is_global_ident(ident, "global") || self.bindings.is_global_ident(ident, "globalThis"))
                        && property_name(prop) == Some("eval") =>
                {
                    Some("eval")
                }
                _ => None,
            };

            if let Some(sink) = eval_sink {
                if call
                    .args
                    .first()
                    .is_some_and(|argument| self.has_dynamic_argument([argument]))
                {
                    self.add_vuln(sink, call.span);
                }
            } else if let Some(api) = self
                .bindings
                .child_process_callee(callee, &mut HashSet::new())
            {
                let relevant_arguments = match api {
                    "exec" | "execSync" => &call.args[..call.args.len().min(1)],
                    _ => &call.args[..call.args.len().min(2)],
                };
                if self.has_dynamic_argument(relevant_arguments) {
                    self.add_vuln(api, call.span);
                }
            }
        }

        call.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, expression: &NewExpr) {
        let sink = match expression.callee.as_ref() {
            Expr::Ident(ident) if self.bindings.is_global_ident(ident, "Function") => {
                Some("new Function")
            }
            Expr::Ident(ident) if ident.sym == "AsyncFunction" => Some("new AsyncFunction"),
            _ => None,
        };

        if let (Some(sink), Some(args)) = (sink, &expression.args)
            && self.has_dynamic_argument(args)
        {
            self.add_vuln(sink, expression.span);
        }

        expression.visit_children_with(self);
    }
}
