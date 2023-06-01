// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, mem};

use crate::ctx::{BasicBlockId, FunctionMeta, IrStmt, ModuleCtx, TerminatorKind, STARTING_BLOCK};
use crate::lattice::MeetSemiLattice;
use swc_core::ecma::ast::{
    ArrowExpr, BindingIdent, CallExpr, Callee, Expr, ExprOrSpread, FnDecl, FnExpr, Id, IfStmt,
    JSXElementName, JSXOpeningElement, Lit, MemberExpr, MemberProp, Pat, Stmt, Str, ThrowStmt,
    TplElement, VarDeclarator,
};
use swc_core::ecma::visit::{noop_visit_type, Visit, VisitWith};
use tracing::{debug, instrument};

use forge_utils::FxHashMap;

#[derive(Hash)]
pub enum ForgePermissions {
    WriteAuditLogsConfluence,
    ReadAuditLogsConfluence,
    WriteConfluenceContent,
    ReadConfluenceSpaceSummary,
    WriteConfluenceSpace,
    WriteConfluenceFile,
    ReadConfluenceProps,
    WriteConfluenceProps,
    ReadConfluenceContentAll,
    ReadConfluenceContentSummary,
    ReadInlineTaskConfluence,
    SearchConfluence,
    ReadConfluenceContentPermission,
    ReadConfluenceUser,
    ReadUserPropertyConfluence,
    ManageConfluenceConfiguration,
    ReadConfluenceGroups,
    WriteConfluenceGroups,
    WriteUserPropertyConfluence,
    ReadSpacePermissionConfluence,
    WriteSpacePermissionsConfluence,
    WriteInlineTaskConfluence,
    ReadOnlyContentAttachmentConfluence,
    ReadJiraUser,
    ReadJiraWork,
    WriteJiraWork,
    ManageJiraProject,
    ManageJiraConfiguration,
    ManageJiraWebhook,
    Unknown,
}

pub fn resolve_permission(permission: ForgePermissions) -> &'static str {
    match permission {
        ForgePermissions::ReadAuditLogsConfluence => "read:audit-log:confluence",
        ForgePermissions::WriteAuditLogsConfluence => "write:audit-log:confluence",
        ForgePermissions::WriteConfluenceContent => "wwrite:confluence-content",
        ForgePermissions::ReadConfluenceSpaceSummary => "read:confluence-space.summary",
        ForgePermissions::WriteConfluenceSpace => "write:confluence-space",
        ForgePermissions::WriteConfluenceFile => "write:confluence-file",
        ForgePermissions::WriteUserPropertyConfluence => "write:user.property:confluence",
        ForgePermissions::ReadConfluenceProps => "read:confluence-props",
        ForgePermissions::WriteConfluenceProps => "write:confluence-props",
        ForgePermissions::ManageConfluenceConfiguration => "manage:confluence-configuration",
        ForgePermissions::ReadConfluenceContentAll => "read:confluence-content.all",
        ForgePermissions::ReadConfluenceContentSummary => "read:confluence-content.summary",
        ForgePermissions::SearchConfluence => "search:confluence",
        ForgePermissions::ReadConfluenceContentPermission => "read:confluence-content.permission",
        ForgePermissions::ReadConfluenceUser => "read:confluence-user",
        ForgePermissions::ReadUserPropertyConfluence => "read:user.property:confluence",
        ForgePermissions::ReadConfluenceGroups => "read:confluence-content.permission",
        ForgePermissions::WriteConfluenceGroups => "write:confluence-groups",
        ForgePermissions::ReadSpacePermissionConfluence => "read:space.permission:confluence",
        ForgePermissions::WriteSpacePermissionsConfluence => "write:space.permission:confluence",
        ForgePermissions::ReadOnlyContentAttachmentConfluence => {
            "readonly:content.attachment:confluence"
        },
        ForgePermissions::ReadInlineTaskConfluence => "read:inlinetask:confluence",
        ForgePermissions::WriteInlineTaskConfluence => "write:inlinetask:confluence",
        ForgePermissions::ReadJiraUser => "read:jira-user",
        ForgePermissions::ReadJiraWork => "read:jira-work",
        ForgePermissions::WriteJiraWork => "write:jira-work",
        ForgePermissions::ManageJiraProject => "manage:jira-project",
        ForgePermissions::ManageJiraConfiguration => "manage:jira-configuration",
        ForgePermissions::ManageJiraWebhook => "manage:jira-webhook",
        ForgePermissions::Unknown => "unknown",
    }
}

#[instrument(level = "debug", skip_all)]
pub(crate) fn collect_functions<N>(node: &N, ctx: &mut ModuleCtx) -> FxHashMap<Id, FunctionMeta>
where
    for<'a> N: VisitWith<FunctionCollector<'a>>,
{
    let mut collector = FunctionCollector::new(ctx);
    node.visit_with(&mut collector);
    collector.functions
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthZVal {
    Authorize, // BOT
    Unauthorized,
    Noop,
    #[default]
    Unknown, // TOP
}

pub(crate) struct FunctionCollector<'ctx> {
    functions: FxHashMap<Id, FunctionMeta>,
    ctx: &'ctx mut ModuleCtx,
}

struct FunctionAnalyzer<'a> {
    ctx: &'a mut ModuleCtx,
    meta: FunctionMeta,
    curr_block: BasicBlockId,
}

// technically the HRTB is unnecessary, since we only need the lifetime from `ForgeImports`,
// however, I might add more lifetime params to [`FunctionAnalyzer`] in the future
fn analyze_functions<N>(body: &N, forge_imports: &mut ModuleCtx) -> FunctionMeta
where
    for<'a> N: VisitWith<FunctionAnalyzer<'a>>,
{
    let mut analyzer = FunctionAnalyzer::new(forge_imports);
    body.visit_children_with(&mut analyzer);
    analyzer.meta
}

struct CheckApiCalls {
    perms_related: bool,
    args: Vec<String>,
}

impl CheckApiCalls {
    pub(crate) fn new() -> CheckApiCalls {
        CheckApiCalls {
            perms_related: false,
            args: Vec::new(),
        }
    }
}

fn contains_perms_check<N: VisitWith<CheckApiCalls>>(node: &N) -> CheckApiCalls {
    let mut api_call_metadata = CheckApiCalls::new();
    node.visit_with(&mut api_call_metadata);
    return api_call_metadata;

    //TODO: these substrings seems to cover all the permissions related APIs, however, we might
    // want to make it more granular in the future.
    // could also use regex, but this isn't hot enough to matter
    impl Visit for CheckApiCalls {
        fn visit_str(&mut self, n: &Str) {
            self.args.push(n.value.to_string());
            if n.value.contains("perm") || n.value.contains("user") {
                self.perms_related = true;
            }
        }

        // NOTE: VARIABLES FOR FUNCTION HERE
        fn visit_tpl_element(&mut self, n: &TplElement) {
            self.args.push(n.raw.to_string());
            if n.raw.contains("perm") || n.raw.contains("user") {
                self.perms_related = true;
            }
        }
    }
}

impl<'ctx> FunctionCollector<'ctx> {
    #[inline]
    fn new(ctx: &'ctx mut ModuleCtx) -> Self {
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

impl<'a> FunctionAnalyzer<'a> {
    #[inline]
    fn new(ctx: &'a mut ModuleCtx) -> Self {
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

    #[inline]
    fn add_throw_stmt(&mut self) {
        self.meta
            .add_terminator(self.curr_block, TerminatorKind::Throw);
    }

    #[inline]
    fn create_block_succ(&mut self) -> BasicBlockId {
        self.meta.create_block_from(self.curr_block)
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
            JSXElementName::Ident(id) => self.add_ir_stmt(IrStmt::Call(id.into())),
            // FIXME: add cases for these
            JSXElementName::JSXMemberExpr(_) => {}
            JSXElementName::JSXNamespacedName(_) => {}
        }
    }

    fn visit_stmt(&mut self, n: &Stmt) {
        match n {
            Stmt::Throw(t) => {
                self.visit_throw_stmt(t);
                self.curr_block = self.meta.push_block();
            }
            Stmt::If(IfStmt {
                test, cons, alt, ..
            }) => {
                test.visit_children_with(self);
                let mut cons_id = self.create_block_succ();
                let mut alt_id = self.create_block_succ();
                let _save = mem::replace(&mut self.curr_block, cons_id);
                cons.visit_with(self);
                cons_id = mem::replace(&mut self.curr_block, alt_id);
                alt.visit_with(self);
                alt_id = self.curr_block;
                let new_block = self.meta.push_block();
                self.meta.add_edge(cons_id, new_block);
                self.meta.add_edge(alt_id, new_block);
                self.curr_block = new_block;
            }
            n => n.visit_children_with(self),
        }
    }

    fn visit_throw_stmt(&mut self, n: &ThrowStmt) {
        let expr = &*n.arg;
        expr.visit_with(self);
        self.add_throw_stmt();
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
                        IrStmt::Call(id.into())
                    };
                    self.add_ir_stmt(irstmt);
                }
                Expr::Member(MemberExpr { obj, prop, .. }) => match prop {
                    MemberProp::Ident(ident) => {
                        let ident = ident.to_id();
                        debug!(propname = ?&ident.0, "analyzing method call");
                        let mut api_call = ApiCallData {
                            args: Vec::new(),
                            function_name: ident.0.to_string(),
                        };
                        if &ident.0 == "requestJira" || &ident.0 == "requestConfluence" {
                            debug!(api = ?&ident.0, "found api call");
                            for arg in args.into_iter() {
                                let api_call_data = contains_perms_check(&arg.expr);
                                if api_call_data.perms_related {
                                    self.add_ir_stmt(IrStmt::Resolved(AuthZVal::Authorize));
                                } else if self.is_as_app_access(obj) {
                                    self.add_ir_stmt(IrStmt::Resolved(AuthZVal::Unauthorized));
                                }
                                api_call.args.extend_from_slice(&api_call_data.args.clone());
                            }
                            self.ctx.permissions_used.push(
                                resolve_permission(api_call.check_permission_used()).to_string(),
                            );
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

pub(crate) struct ApiCallData {
    function_name: String,
    args: Vec<String>,
}

impl ApiCallData {
    pub(crate) fn check_permission_used(&self) -> Vec<ForgePermissions> {
        /**
             *     WriteConfluenceContent,
        ReadConfluenceSpaceSummary,
        WriteConfluenceSpaceSummary,
        WriteConfluenceFile, *
        ReadConfluenceProps,
        ReadConfluenceContentAll, *
        ReadConfluenceContentSummary,
        SearchConfluence,
        ReadConfluenceContentPermission,
        ReadConfluenceUser,
        ReadConfluenceGroups,
        WriteConfluenceGroups,
        ReadOnlyContentAttachmentConfluence,
        ReadJiraUser,
        ReadJiraWork,
        WriteJiraWork,
        ManageJiraProject,
        ManageJiraConfiguration,
        ManageJiraWebhook,
        Unknown,
             */
        let mut used_permissions: Vec<ForgePermissions> = Vec::new();

        let joined_args = self.args.join("");

        let post_call = joined_args.contains("POST");
        let delete_call = joined_args.contains("DELTE");
        let put_call = joined_args.contains("PUT");

        let contains_audit = joined_args.contains("audit");
        let contains_issue = joined_args.contains("issue");
        let contains_content = joined_args.contains("content");
        let contains_user = joined_args.contains("user");
        let contains_property = joined_args.contains("property");
        let contains_theme = joined_args.contains("theme");
        let contains_template = joined_args.contains("template");
        let contains_space = joined_args.contains("space");
        let contains_analytics = joined_args.contains("analytics");
        let contains_cql = joined_args.contains("cql");
        let contains_history = joined_args.contains("history");
        let contains_attachment = joined_args.contains("attachment");
        let contains_data = joined_args.contains("data");
        let contains_contentbody = joined_args.contains("contentbody");
        let contians_permissions = joined_args.contains("permissions");
        let contains_property = joined_args.contains("property");
        let contains_page_tree = joined_args.contains("pageTree");
        let contains_group = joined_args.contains("group");
        let contains_inlinetasks = joined_args.contains("inlinetasks");
        let contains_relation = joined_args.contains("relation");
        let contains_settings = joined_args.contains("settings");
        let contains_permission = joined_args.contains("permission");
        let contains_download = joined_args.contains("download");
        let contains_descendants = joined_args.contains("descendants");
        let contains_comment = joined_args.contains("comment");
        let contains_label = joined_args.contains("contains_label");
        let contains_restriction = joined_args.contains("restriction");

        match self.function_name.as_str() {
            "requestJira" => {
                if post_call {
                    if contains_issue {
                        used_permissions.push(ForgePermissions::WriteJiraWork);
                    } else {
                        used_permissions.push(ForgePermissions::Unknown);
                    }
                } else {
                    if contains_issue {
                        used_permissions.push(ForgePermissions::ReadJiraWork);
                    } else {
                        used_permissions.push(ForgePermissions::Unknown);
                    }
                }
            }
            "requestConfluence" => {
                if post_call || delete_call || put_call {
                    if contains_content {
                        used_permissions.push(ForgePermissions::WriteConfluenceContent);
                    } else if contains_audit {
                        if post_call {
                            used_permissions.push(ForgePermissions::ReadAuditLogsConfluence);
                            used_permissions.push(ForgePermissions::WriteAuditLogsConfluence)
                        } else {
                            used_permissions.push(ForgePermissions::WriteAuditLogsConfluence)
                        }
                    } else if contains_content && contains_attachment { 
                        if put_call {
                            // review this more specifically
                            // /wiki/rest/api/content/{id}/child/attachment/{attachmentId}`,
                            used_permissions.push(ForgePermissions::WriteConfluenceFile);
                            used_permissions.push(ForgePermissions::WriteConfluenceProps)
                        } else {
                            used_permissions.push(ForgePermissions::WriteConfluenceFile)
                        }
                    } else if contains_contentbody {
                        used_permissions.push(ForgePermissions::ReadConfluenceContentAll)
                    } else if contains_content && contians_permissions {
                        used_permissions.push(ForgePermissions::ReadConfluenceContentPermission)
                    } else if contains_property {
                        used_permissions.push(ForgePermissions::WriteConfluenceProps)
                    } else if contains_content || contains_page_tree || contains_relation {
                        used_permissions.push(ForgePermissions::WriteConfluenceContent)
                    } else if contains_group {
                        used_permissions.push(ForgePermissions::WriteConfluenceGroups)
                    } else if contains_settings {
                        used_permissions.push(ForgePermissions::ManageConfluenceConfiguration)
                    } else if contains_space && contains_permission {
                        if !delete_call {
                            used_permissions.push(ForgePermissions::ReadSpacePermissionConfluence);
                        }
                        used_permissions.push(ForgePermissions::WriteSpacePermissionsConfluence)
                    } else if contains_space || contains_theme {
                        used_permissions.push(ForgePermissions::WriteConfluenceSpace);
                    } else if contains_template {
                        used_permissions.push(ForgePermissions::WriteConfluenceContent);
                    } else if contains_inlinetasks {
                        used_permissions.push(ForgePermissions::WriteInlineTaskConfluence)
                    } else if contains_user && contains_property {
                        used_permissions.push(ForgePermissions::WriteUserPropertyConfluence);
                    } else {
                        used_permissions.push(ForgePermissions::Unknown);
                    }
                } else {
                    if contains_issue {
                        used_permissions.push(ForgePermissions::ReadJiraWork);
                    } else if contains_audit {
                        used_permissions.push(ForgePermissions::ReadAuditLogsConfluence)
                    } else if contains_cql {
                        used_permissions.push(ForgePermissions::SearchConfluence)
                    } else if contains_attachment && contains_download {
                        used_permissions.push(ForgePermissions::ReadOnlyContentAttachmentConfluence)
                    } else if contains_content && contains_property {
                        used_permissions.push(ForgePermissions::ReadConfluenceProps);
                    } else if contains_content && (contains_comment || contains_descendants || contains_label) {
                        used_permissions.push(ForgePermissions::ReadConfluenceContentSummary);
                    } else if contains_content || contains_analytics {
                        used_permissions.push(ForgePermissions::ReadConfluenceContentAll);
                    } else {
                        used_permissions.push(ForgePermissions::Unknown);
                    }
                }
            }
            _ => {used_permissions.push(ForgePermissions::Unknown);}
        }
        used_permissions
    }
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

impl fmt::Display for AuthZVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthZVal::Authorize => write!(f, "Authorize"),
            AuthZVal::Unauthorized => write!(f, "Unauthorized"),
            AuthZVal::Noop => write!(f, "No-Op"),
            AuthZVal::Unknown => write!(f, "Unknown"),
        }
    }
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
