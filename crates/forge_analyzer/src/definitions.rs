#![allow(dead_code, unused)]

use std::{borrow::Borrow, fmt, mem};

use forge_file_resolver::{FileResolver, ForgeResolver};
use forge_utils::{create_newtype, FxHashMap};

use swc_core::{
    common::SyntaxContext,
    ecma::{
        ast::{
            ArrayLit, ArrowExpr, AssignExpr, AssignOp, AssignPat, AssignPatProp, AssignProp,
            AwaitExpr, BinExpr, BindingIdent, BlockStmt, BreakStmt, CallExpr, Callee, ClassDecl,
            ClassExpr, ComputedPropName, CondExpr, ContinueStmt, Decl, DefaultDecl, DoWhileStmt,
            ExportAll, ExportDecl, ExportDefaultDecl, ExportDefaultExpr, ExportNamedSpecifier,
            Expr, ExprOrSpread, ExprStmt, FnDecl, FnExpr, ForInStmt, ForOfStmt, ForStmt, Function,
            Id, Ident, IfStmt, ImportDecl, ImportDefaultSpecifier, ImportNamedSpecifier,
            ImportStarAsSpecifier, KeyValuePatProp, KeyValueProp, LabeledStmt, Lit, MemberExpr,
            MemberProp, MetaPropExpr, MethodProp, Module, ModuleDecl, ModuleExportName, ModuleItem,
            NewExpr, ObjectLit, ObjectPat, ObjectPatProp, OptCall, OptChainBase, OptChainExpr,
            ParenExpr, Pat, PatOrExpr, PrivateName, Prop, PropName, PropOrSpread, ReturnStmt,
            SeqExpr, Stmt, Str, Super, SuperProp, SuperPropExpr, SwitchStmt, TaggedTpl, ThisExpr,
            ThrowStmt, Tpl, TryStmt, TsAsExpr, TsConstAssertion, TsInstantiation, TsNonNullExpr,
            TsSatisfiesExpr, TsTypeAssertion, UnaryExpr, UpdateExpr, VarDecl, VarDeclarator,
            WhileStmt, WithStmt, YieldExpr,
        },
        atoms::JsWord,
        visit::{noop_visit_type, Visit, VisitWith},
    },
};
use tracing::{debug, info, instrument, warn};
use typed_index_collections::{TiSlice, TiVec};

use crate::{
    ctx::ModId,
    ir::{BasicBlockId, Body, Inst, Literal, Operand, Projection, Rvalue, Terminator, Variable},
};

create_newtype! {
    pub struct FuncId(u32);
}

create_newtype! {
    pub struct ObjId(u32);
}

create_newtype! {
    pub struct DefId(u32);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjKind {
    Class(ObjId),
    Lit(ObjId),
    Resolver(ObjId),
}

struct NormalizedExport {
    module: ModId,
    def: DefId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Symbol {
    module: ModId,
    id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolExport {
    module: ModId,
    name: JsWord,
}

#[derive(Debug, Clone, Default)]
struct ResolverTable {
    defs: TiVec<DefId, DefRes>,
    names: TiVec<DefId, JsWord>,
    symbol_to_id: FxHashMap<Symbol, DefId>,
    parent: FxHashMap<DefId, DefId>,
    owning_module: TiVec<DefId, ModId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnonType {
    Obj,
    Closure,
    Unknown,
}

struct ModuleDefs {
    symbols: FxHashMap<Id, DefId>,
    functions: Box<[DefId]>,
    globals: Box<[DefId]>,
    classes: Box<[DefId]>,
    exports: Box<[DefId]>,
}

#[instrument(skip(modules, file_resolver))]
pub fn run_resolver(
    modules: &TiSlice<ModId, Module>,
    file_resolver: &ForgeResolver,
) -> Environment {
    let mut resolver = Environment::new();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut export_collector = ExportCollector {
            res_table: &mut resolver.resolver,
            curr_mod,
            exports: vec![],
            default: None,
        };
        module.visit_children_with(&mut export_collector);
        let mod_id = resolver.exports.push_and_get_key(export_collector.exports);
        debug_assert_eq!(curr_mod, mod_id);
        if let Some(default) = export_collector.default {
            let def_id = resolver.default_exports.insert(curr_mod, default);
            debug_assert_eq!(def_id, None, "def_id shouldn't be set");
        }
    }

    let mut foreign = TiVec::default();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut import_collector = ImportCollector {
            resolver: &mut resolver,
            file_resolver,
            foreign_defs: &mut foreign,
            curr_mod,
            current_import: Default::default(),
            in_foreign_import: false,
        };
        module.visit_with(&mut import_collector);
    }

    let defs = Definitions::new(
        resolver
            .resolver
            .defs
            .iter_enumerated()
            .map(|(id, &d)| (id, d)),
        foreign,
    );
    resolver.defs = defs;
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut lowerer = Lowerer {
            res: &mut resolver,
            curr_mod,
            parents: vec![],
            curr_def: None,
        };
        module.visit_with(&mut lowerer);
    }

    for (curr_mod, module) in modules.iter_enumerated() {
        let mut collector = FunctionCollector {
            res: &mut resolver,
            module: curr_mod,
            parent: None,
        };
        module.visit_with(&mut collector);
    }

    resolver
}

/// this struct is a bit of a hack, because we also use it for
/// the definition of "global" scoped object literals, i.e.
///
/// ```javascript
/// const glbl = {
///   foo: () => { ... },
///   ...
/// }
///
/// export default {
///   f1, f2, f3
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Class {
    def: DefId,
    pub_members: Vec<(JsWord, DefId)>,
    constructor: Option<DefId>,
}

enum PropKind {
    Alias(DefId),
    Unknown,
    Setter(DefId),
}

enum ObjTy {
    Class { constructor: DefId },
    Lit,
    LitProp { parent: DefId },
    ResolverProp { parent: DefId },
    Resolver,
}

struct Object {
    def: DefId,
    pub_members: Vec<(JsWord, DefId)>,
    ty: ObjTy,
}

impl Class {
    fn new(def: DefId) -> Self {
        Self {
            def,
            pub_members: vec![],
            constructor: None,
        }
    }

    fn find_member(&self, name: &JsWord) -> Option<DefId> {
        self.pub_members
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| *d)
    }
}

create_newtype! {
    pub struct ForeignId(u32);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ImportKind {
    Star,
    Default,
    Named(JsWord),
}

#[derive(Debug, Clone)]
pub struct ForeignItem {
    kind: ImportKind,
    module_name: JsWord,
}

type DefKey = DefKind<FuncId, ObjId, ForeignId>;
type DefRef<'a> = DefKind<&'a Body, &'a Class, &'a ForeignItem>;
type DefMut<'a> = DefKind<&'a mut Body, &'a mut Class, &'a mut ForeignItem>;
type DefRes<I = ForeignId> = DefKind<(), (), I>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefKind<F, O, I> {
    Arg,
    Function(F),
    ExportAlias(DefId),
    GlobalObj(O),
    Class(O),
    Foreign(I),
    /// exported(usual) handler to the actual resolver definitions
    ///
    /// [`DefId`] should point to [`DefKind::Resolver`]
    ///
    /// # Example:
    ///
    /// ```javascript
    /// import Resolver from '@forge/resolver';
    ///
    /// const resolver = new Resolver();
    ///
    /// resolver.define('handlerFunc' ({ payload, context }) => {
    ///   console.log(`payload: ${payload}, ctx: ${context}`);
    /// });
    /// // the `handler` symbol resolves to a DefId for [`DefKind::ResolverHandler`]
    /// export const handler = resolver.getDefinitions();
    /// ```
    ResolverHandler(DefId),
    Resolver(O),
    ResolverDef(DefId),
    Closure(F),
    // Ex: `module` in import * as 'foo' from 'module'
    ModuleNs(ModId),
    Undefined,
}

impl<F, O, I> Default for DefKind<F, O, I> {
    fn default() -> Self {
        Self::Undefined
    }
}

impl<F, O, I> DefKind<F, O, I> {
    fn expect_body(self) -> F {
        match self {
            Self::Function(f) | Self::Closure(f) => f,
            _ => panic!("expected function"),
        }
    }

    fn expect_class(self) -> O {
        match self {
            Self::Class(c) | Self::GlobalObj(c) | Self::Resolver(c) => c,
            _ => panic!("expected class"),
        }
    }
}

impl PartialEq<DefKey> for DefRes {
    fn eq(&self, other: &DefKey) -> bool {
        match (*self, *other) {
            (DefKind::Function(()), DefKind::Function(_)) => true,
            (DefKind::ExportAlias(l0), DefKind::ExportAlias(r0)) => l0 == r0,
            (DefKind::GlobalObj(()), DefKind::GlobalObj(_)) => true,
            (DefKind::Class(()), DefKind::Class(_)) => true,
            (DefKind::Foreign(l0), DefKind::Foreign(r0)) => l0 == r0,
            (DefKind::ResolverHandler(l0), DefKind::ResolverHandler(r0)) => l0 == r0,
            (DefKind::Resolver(()), DefKind::Resolver(_)) => true,
            (DefKind::ResolverDef(l0), DefKind::ResolverDef(r0)) => l0 == r0,
            (DefKind::Closure(()), DefKind::Closure(_)) => true,
            (DefKind::ModuleNs(l0), DefKind::ModuleNs(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl PartialEq<DefRes> for DefKey {
    fn eq(&self, other: &DefRes) -> bool {
        match (*self, *other) {
            (DefKind::Function(_), DefKind::Function(())) => true,
            (DefKind::ExportAlias(l0), DefKind::ExportAlias(r0)) => l0 == r0,
            (DefKind::GlobalObj(_), DefKind::GlobalObj(())) => true,
            (DefKind::Class(_), DefKind::Class(())) => true,
            (DefKind::Foreign(l0), DefKind::Foreign(r0)) => l0 == r0,
            (DefKind::ResolverHandler(l0), DefKind::ResolverHandler(r0)) => l0 == r0,
            (DefKind::Resolver(_), DefKind::Resolver(())) => true,
            (DefKind::ResolverDef(l0), DefKind::ResolverDef(r0)) => l0 == r0,
            (DefKind::Closure(_), DefKind::Closure(())) => true,
            (DefKind::ModuleNs(l0), DefKind::ModuleNs(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Copy for DefKey {}
impl Copy for DefRes {}
impl Copy for DefRef<'_> {}

#[derive(Debug, Clone, Default)]
struct Definitions {
    defs: TiVec<DefId, DefKey>,
    funcs: TiVec<FuncId, Body>,
    classes: TiVec<ObjId, Class>,
    foreign: TiVec<ForeignId, ForeignItem>,
}

#[derive(Debug, Clone, Default)]
pub struct Environment {
    exports: TiVec<ModId, Vec<(JsWord, DefId)>>,
    defs: Definitions,
    default_exports: FxHashMap<ModId, DefId>,
    resolver: ResolverTable,
}

struct ImportCollector<'cx> {
    resolver: &'cx mut Environment,
    file_resolver: &'cx ForgeResolver,
    foreign_defs: &'cx mut TiVec<ForeignId, ForeignItem>,
    curr_mod: ModId,
    current_import: JsWord,
    in_foreign_import: bool,
}

struct ExportCollector<'cx> {
    res_table: &'cx mut ResolverTable,
    curr_mod: ModId,
    exports: Vec<(JsWord, DefId)>,
    default: Option<DefId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowerStage {
    Collect,
    Create,
}

struct Lowerer<'cx> {
    res: &'cx mut Environment,
    curr_mod: ModId,
    parents: Vec<DefId>,
    curr_def: Option<DefId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PropPath {
    Def(DefId),
    Str(JsWord),
    Unknown(Id),
    Expr,
    This,
    Super,
    Private(Id),
    Computed(Id),
}

fn normalize_callee_expr(
    callee: &Callee,
    res_table: &Environment,
    curr_mod: ModId,
) -> Vec<PropPath> {
    struct CalleeNormalizer<'cx> {
        res_table: &'cx Environment,
        curr_mod: ModId,
        path: Vec<PropPath>,
        in_prop: bool,
    }

    impl<'cx> CalleeNormalizer<'cx> {
        fn check_prop(&mut self, n: &MemberProp) {
            let old_prop = mem::replace(&mut self.in_prop, true);
            n.visit_with(self);
            self.in_prop = old_prop;
        }
    }

    impl Visit for CalleeNormalizer<'_> {
        fn visit_member_prop(&mut self, n: &MemberProp) {
            match n {
                MemberProp::Ident(n) => n.visit_with(self),
                MemberProp::PrivateName(PrivateName { id, .. }) => {
                    self.path.push(PropPath::Private(id.to_id()))
                }
                MemberProp::Computed(ComputedPropName { expr, .. }) => {
                    let old_prop = mem::replace(&mut self.in_prop, true);
                    expr.visit_with(self);
                    self.in_prop = old_prop;
                }
            }
        }

        fn visit_ident(&mut self, n: &Ident) {
            let id = n.to_id();
            if self.in_prop {
                self.path.push(PropPath::Computed(id));
            } else {
                let prop = self
                    .res_table
                    .sym_to_id(id.clone(), self.curr_mod)
                    .map_or(PropPath::Unknown(id), PropPath::Def);
                self.path.push(prop);
            }
        }

        fn visit_str(&mut self, n: &Str) {
            let str = n.value.clone();
            self.path.push(PropPath::Str(str));
        }

        fn visit_lit(&mut self, n: &Lit) {
            match n {
                Lit::Str(n) => n.visit_with(self),
                Lit::Bool(_)
                | Lit::Null(_)
                | Lit::Num(_)
                | Lit::BigInt(_)
                | Lit::Regex(_)
                | Lit::JSXText(_) => self.path.push(PropPath::Expr),
            }
        }

        fn visit_expr(&mut self, n: &Expr) {
            match n {
                Expr::Member(MemberExpr { obj, prop, .. }) if !self.in_prop => {
                    obj.visit_with(self);
                    prop.visit_with(self);
                }
                Expr::This(_) => {
                    if !self.path.is_empty() {
                        warn!("thisexpr in prop index: {}", self.path.len());
                    } else {
                        self.path.push(PropPath::This);
                    }
                }
                expr @ (Expr::Lit(_) | Expr::Paren(_) | Expr::Ident(_)) => {
                    expr.visit_children_with(self)
                }

                _ => self.path.push(PropPath::Expr),
            }
        }
    }
    if let Some(expr) = callee.as_expr() {
        let mut normalizer = CalleeNormalizer {
            res_table,
            curr_mod,
            path: vec![],
            in_prop: false,
        };
        normalizer.visit_expr(expr);
        normalizer.path
    } else {
        vec![]
    }
}

impl ResolverTable {
    #[inline]
    fn sym_id(&self, id: Id, module: ModId) -> Option<DefId> {
        self.symbol_to_id.get(&Symbol { module, id }).copied()
    }

    #[inline]
    fn sym_kind(&self, id: Id, module: ModId) -> Option<DefRes> {
        let def = self.sym_id(id, module)?;
        self.defs.get(def).copied()
    }

    #[inline]
    fn reserve_symbol(&mut self, id: Id, module: ModId) -> DefId {
        self.add_sym(DefRes::default(), id, module)
    }

    #[inline]
    fn get_or_insert_sym(&mut self, id: Id, module: ModId) -> DefId {
        self.sym_id(id.clone(), module)
            .unwrap_or_else(|| self.reserve_symbol(id, module))
    }

    fn reserve_def(&mut self, name: JsWord, module: ModId) -> DefId {
        self.defs.push_and_get_key(DefRes::default());
        self.names.push_and_get_key(name);
        self.owning_module.push_and_get_key(module)
    }

    fn add_anon(&mut self, def: DefRes, name: JsWord, module: ModId) -> DefId {
        let defid = self.defs.push_and_get_key(def);
        let defid2 = self.owning_module.push_and_get_key(module);
        debug_assert_eq!(
            defid, defid2,
            "inconsistent state while inserting {}",
            &*name
        );
        let defid3 = self.names.push_and_get_key(name);
        debug_assert_eq!(
            defid,
            defid3,
            "inconsistent state while inserting {}",
            self.names.last().unwrap()
        );
        defid
    }

    fn add_sym(&mut self, def: DefRes, id: Id, module: ModId) -> DefId {
        let defid = self.defs.push_and_get_key(def);
        let defid2 = self.owning_module.push_and_get_key(module);
        debug_assert_eq!(defid, defid2, "inconsistent state while inserting {}", id.0);
        let sym = id.0.clone();
        self.symbol_to_id.insert(Symbol { id, module }, defid2);
        let defid3 = self.names.push_and_get_key(sym);
        debug_assert_eq!(
            defid,
            defid3,
            "inconsistent state while inserting {}",
            self.names.last().unwrap()
        );
        defid
    }
}

struct FunctionCollector<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    parent: Option<DefId>,
}

struct FunctionAnalyzer<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    current_def: DefId,
    assigning_to: Option<Variable>,
    body: Body,
    block: BasicBlockId,
    operand_stack: Vec<Operand>,
    in_lhs: bool,
}

impl<'cx> FunctionAnalyzer<'cx> {
    #[inline]
    fn set_curr_terminator(&mut self, term: Terminator) {
        self.body.set_terminator(self.block, term);
    }

    #[inline]
    fn push_curr_inst(&mut self, inst: Inst) {
        self.body.push_inst(self.block, inst);
    }

    fn lower_member(&mut self, obj: &Expr, prop: &MemberProp) -> Operand {
        let obj = self.lower_expr(obj);
        let Operand::Var(mut var) = obj else {
            // FIXME: handle literals
            return obj;
        };
        match prop {
            MemberProp::Ident(id) | MemberProp::PrivateName(PrivateName { id, .. }) => {
                let id = id.to_id();
                var.projections.push(Projection::Known(id.0));
            }
            MemberProp::Computed(ComputedPropName { expr, .. }) => {
                let opnd = self.lower_expr(expr);
                var.projections
                    .push(self.body.resolve_prop(self.block, opnd));
            }
        }
        Operand::Var(var)
    }

    // TODO: This can probably be made into a trait
    fn lower_expr(&mut self, n: &Expr) -> Operand {
        match n {
            Expr::This(_) => Operand::Var(Variable::THIS),
            Expr::Array(ArrayLit { elems, .. }) => {
                let array_lit: Vec<_> = elems
                    .iter()
                    .map(|e| {
                        e.as_ref()
                            .map_or(Operand::UNDEF, |ExprOrSpread { spread, expr }| {
                                self.lower_expr(expr)
                            })
                    })
                    .collect();
                Operand::UNDEF
            }
            Expr::Object(ObjectLit { span, props }) => {
                // TODO: lower object literals
                Operand::UNDEF
            }
            Expr::Fn(_) => Operand::UNDEF,
            Expr::Unary(UnaryExpr { op, arg, .. }) => {
                let arg = self.lower_expr(arg);
                let tmp = self
                    .body
                    .push_tmp(self.block, Rvalue::Unary(op.into(), arg), None);
                Operand::with_var(tmp)
            }
            Expr::Update(UpdateExpr {
                op, prefix, arg, ..
            }) => {
                // FIXME: Handle op
                self.lower_expr(arg)
            }
            Expr::Bin(BinExpr {
                op, left, right, ..
            }) => {
                let left = self.lower_expr(left);
                let right = self.lower_expr(right);
                let tmp = self
                    .body
                    .push_tmp(self.block, Rvalue::Bin(op.into(), left, right), None);
                Operand::with_var(tmp)
            }

            Expr::SuperProp(SuperPropExpr { obj, prop, .. }) => {
                let mut super_var = Variable::SUPER;
                match prop {
                    SuperProp::Ident(id) => {
                        let id = id.to_id().0;
                        super_var.projections.push(Projection::Known(id));
                    }
                    SuperProp::Computed(ComputedPropName { expr, .. }) => {
                        let opnd = self.lower_expr(expr);
                        let prop = self.body.resolve_prop(self.block, opnd);
                        super_var.projections.push(prop);
                    }
                }
                Operand::Var(super_var)
            }
            Expr::Assign(AssignExpr {
                op, left, right, ..
            }) => match left {
                PatOrExpr::Expr(_) => todo!(),
                PatOrExpr::Pat(_) => todo!(),
            },
            Expr::Member(MemberExpr { obj, prop, .. }) => self.lower_member(obj, prop),
            Expr::Cond(CondExpr {
                test, cons, alt, ..
            }) => self.lower_expr(test),
            Expr::Call(n) => {
                let mut args = Vec::with_capacity(n.args.len());
                for ExprOrSpread { spread, expr } in &n.args {
                    let arg = self.lower_expr(expr);
                    args.push(arg);
                }
                let callee = match &n.callee {
                    Callee::Super(_) => Operand::Var(Variable::SUPER),
                    Callee::Import(_) => Operand::UNDEF,
                    Callee::Expr(expr) => self.lower_expr(expr),
                };
                let props = normalize_callee_expr(&n.callee, self.res, self.module);
                match props.first() {
                    Some(&PropPath::Def(id)) => {
                        debug!("call from: {}", self.res.def_name(id));
                        debug!("call expr: {:?}", props);
                    }
                    Some(PropPath::Unknown(id)) => {
                        debug!("call from: {}", id.0);
                        debug!("call expr: {:?}", props);
                    }
                    _ => (),
                }
                todo!()
            }
            Expr::New(NewExpr { callee, args, .. }) => Operand::UNDEF,
            Expr::Seq(SeqExpr { exprs, .. }) => {
                if let Some((last, rest)) = exprs.split_last() {
                    for expr in rest {
                        let opnd = self.lower_expr(expr);
                        self.body.push_expr(self.block, Rvalue::Read(opnd));
                    }
                    self.lower_expr(last)
                } else {
                    Literal::Undef.into()
                }
            }
            Expr::Ident(id) => {
                let id = id.to_id();
                let Some(def) = self.res.sym_to_id(id.clone(), self.module) else {
                    warn!("unknown symbol: {}", id.0);
                    return Literal::Undef.into();
                };
                let var = self.body.get_or_insert_global(def);
                Operand::with_var(var)
            }
            Expr::Lit(lit) => lit.clone().into(),
            Expr::Tpl(Tpl { exprs, quasis, .. }) => todo!(),
            Expr::TaggedTpl(TaggedTpl { tag, tpl, .. }) => todo!(),
            Expr::Arrow(_) => Operand::UNDEF,
            Expr::Class(_) => Operand::UNDEF,
            Expr::Yield(YieldExpr { arg, .. }) => arg
                .as_deref()
                .map_or(Operand::UNDEF, |expr| self.lower_expr(expr)),
            Expr::MetaProp(_) => Operand::UNDEF,
            Expr::Await(AwaitExpr { arg, .. }) => self.lower_expr(arg),
            Expr::Paren(ParenExpr { expr, .. }) => self.lower_expr(expr),
            Expr::JSXMember(_) => todo!(),
            Expr::JSXNamespacedName(_) => todo!(),
            Expr::JSXEmpty(_) => todo!(),
            Expr::JSXElement(_) => todo!(),
            Expr::JSXFragment(_) => todo!(),
            Expr::TsTypeAssertion(TsTypeAssertion { expr, .. })
            | Expr::TsConstAssertion(TsConstAssertion { expr, .. })
            | Expr::TsNonNull(TsNonNullExpr { expr, .. })
            | Expr::TsAs(TsAsExpr { expr, .. })
            | Expr::TsInstantiation(TsInstantiation { expr, .. })
            | Expr::TsSatisfies(TsSatisfiesExpr { expr, .. }) => self.lower_expr(expr),
            Expr::PrivateName(PrivateName { id, .. }) => todo!(),
            Expr::OptChain(OptChainExpr { base, .. }) => match base {
                OptChainBase::Call(OptCall { callee, args, .. }) => todo!(),
                OptChainBase::Member(MemberExpr { obj, prop, .. }) => {
                    // TODO: create separate basic blocks
                    self.lower_member(obj, prop)
                }
            },
            Expr::Invalid(_) => Operand::UNDEF,
        }
    }

    fn lower_stmt(&mut self, n: &Stmt) {
        match n {
            Stmt::Block(BlockStmt { stmts, .. }) => todo!(),
            Stmt::Empty(_) => todo!(),
            Stmt::Debugger(_) => todo!(),
            Stmt::With(WithStmt { obj, body, .. }) => todo!(),
            Stmt::Return(ReturnStmt { arg, .. }) => todo!(),
            Stmt::Labeled(LabeledStmt { label, body, .. }) => todo!(),
            Stmt::Break(BreakStmt { label, .. }) => todo!(),
            Stmt::Continue(ContinueStmt { label, .. }) => todo!(),
            Stmt::If(IfStmt {
                test, cons, alt, ..
            }) => todo!(),
            Stmt::Switch(SwitchStmt {
                discriminant,
                cases,
                ..
            }) => todo!(),
            Stmt::Throw(ThrowStmt { arg, .. }) => todo!(),
            Stmt::Try(stmt) => {
                let TryStmt {
                    block,
                    handler,
                    finalizer,
                    ..
                } = &**stmt;
                todo!()
            }
            Stmt::While(WhileStmt { test, body, .. }) => todo!(),
            Stmt::DoWhile(DoWhileStmt { test, body, .. }) => todo!(),
            Stmt::For(ForStmt {
                init,
                test,
                update,
                body,
                ..
            }) => todo!(),
            Stmt::ForIn(ForInStmt {
                left, right, body, ..
            }) => todo!(),
            Stmt::ForOf(ForOfStmt {
                left, right, body, ..
            }) => todo!(),
            Stmt::Decl(decl) => match decl {
                Decl::Class(_) => todo!(),
                Decl::Fn(_) => todo!(),
                Decl::Var(_) => todo!(),
                Decl::TsInterface(_) => todo!(),
                Decl::TsTypeAlias(_) => todo!(),
                Decl::TsEnum(_) => todo!(),
                Decl::TsModule(_) => todo!(),
            },
            Stmt::Expr(ExprStmt { expr, .. }) => todo!(),
        }
    }
}

impl Visit for FunctionAnalyzer<'_> {
    fn visit_stmt(&mut self, n: &Stmt) {
        match n {
            Stmt::Block(_) => todo!(),
            Stmt::Empty(_) => todo!(),
            Stmt::Debugger(_) => todo!(),
            Stmt::With(_) => todo!(),
            Stmt::Return(_) => todo!(),
            Stmt::Labeled(_) => todo!(),
            Stmt::Break(_) => todo!(),
            Stmt::Continue(_) => todo!(),
            Stmt::If(_) => todo!(),
            Stmt::Switch(_) => todo!(),
            Stmt::Throw(_) => todo!(),
            Stmt::Try(_) => todo!(),
            Stmt::While(_) => todo!(),
            Stmt::DoWhile(_) => todo!(),
            Stmt::For(_) => todo!(),
            Stmt::ForIn(_) => todo!(),
            Stmt::ForOf(_) => todo!(),
            Stmt::Decl(_) => todo!(),
            Stmt::Expr(_) => todo!(),
        }
    }
}

struct ArgDefiner<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    func: DefId,
    body: Body,
}

impl Visit for ArgDefiner<'_> {
    fn visit_ident(&mut self, n: &Ident) {
        let id = n.to_id();
        let defid = self
            .res
            .get_or_overwrite_sym(id.clone(), self.module, DefRes::Arg);
        self.res.add_parent(defid, self.func);
        self.body.add_arg(defid, id);
    }

    fn visit_object_pat_prop(&mut self, n: &ObjectPatProp) {
        match n {
            ObjectPatProp::KeyValue(KeyValuePatProp { key, .. }) => key.visit_with(self),
            ObjectPatProp::Assign(AssignPatProp { key, .. }) => self.visit_ident(key),
            ObjectPatProp::Rest(_) => {}
        }
    }

    fn visit_pat(&mut self, n: &Pat) {
        match n {
            Pat::Ident(_) | Pat::Array(_) => n.visit_children_with(self),
            Pat::Object(ObjectPat { props, .. }) => props.visit_children_with(self),
            Pat::Assign(AssignPat { left, .. }) => left.visit_with(self),
            Pat::Expr(id) => {
                if let Expr::Ident(id) = &**id {
                    id.visit_with(self);
                }
            }
            Pat::Invalid(_) => {}
            Pat::Rest(_) => {}
            Pat::Invalid(_) => {}
        }
    }
}

struct LocalDefiner<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    func: DefId,
    body: Body,
}

impl Visit for LocalDefiner<'_> {
    fn visit_ident(&mut self, n: &Ident) {
        let id = n.to_id();
        let defid = self.res.get_or_insert_sym(id.clone(), self.module);
        self.res.try_add_parent(defid, self.func);
        self.body.add_local_def(defid, id);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        n.name.visit_with(self);
    }

    fn visit_decl(&mut self, n: &Decl) {
        match n {
            Decl::Class(_) => {}
            Decl::Fn(FnDecl { ident, .. }) => {
                ident.visit_with(self);
            }
            Decl::Var(vars) => vars.visit_children_with(self),
            Decl::TsInterface(_) | Decl::TsTypeAlias(_) | Decl::TsEnum(_) | Decl::TsModule(_) => {}
        }
    }

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
    fn visit_fn_decl(&mut self, _: &FnDecl) {}
}

impl Visit for FunctionCollector<'_> {
    fn visit_function(&mut self, n: &Function) {
        n.visit_children_with(self);
        let owner = self.parent.unwrap_or_else(|| {
            self.res
                .add_anonymous("__UNKNOWN", AnonType::Closure, self.module)
        });
        let mut argdef = ArgDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body: Body::with_owner(owner),
        };
        n.params.visit_children_with(&mut argdef);
        let body = argdef.body;
        let mut localdef = LocalDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body,
        };
        n.body.visit_children_with(&mut localdef);
        let body = localdef.body;
        let mut analyzer = FunctionAnalyzer {
            res: self.res,
            module: self.module,
            current_def: owner,
            assigning_to: None,
            body,
            block: BasicBlockId::default(),
            operand_stack: vec![],
            in_lhs: false,
        };
        n.body.visit_with(&mut analyzer);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        n.visit_children_with(self);
        let Some(BindingIdent{id, ..}) = n.name.as_ident() else {
            return;
        };
        let id = id.to_id();
        match n.init.as_deref() {
            Some(Expr::Fn(f)) => {
                let defid = self
                    .res
                    .get_or_overwrite_sym(id, self.module, DefKind::Function(()));
                let old_parent = self.parent.replace(defid);
                f.visit_with(self);
                self.parent = old_parent;
            }
            Some(Expr::Arrow(f)) => {
                let defid = self
                    .res
                    .get_or_overwrite_sym(id, self.module, DefKind::Function(()));
                let old_parent = self.parent.replace(defid);
                f.visit_with(self);
                self.parent = old_parent;
            }
            _ => {}
        }
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        n.visit_children_with(self);
        if let Some((def_id, propname, expr)) = as_resolver_def(n, self.res, self.module) {
            info!("found possible resolver: {propname}");
            match self.res.lookup_prop(def_id, propname) {
                Some(def) => {
                    info!("analyzing resolver def: {def:?}");
                    let mut analyzer = FunctionAnalyzer {
                        res: self.res,
                        module: self.module,
                        current_def: def,
                        assigning_to: None,
                        body: Body::with_owner(def),
                        block: BasicBlockId::default(),
                        operand_stack: vec![],
                        in_lhs: false,
                    };
                    expr.visit_with(&mut analyzer);
                }
                None => {
                    warn!("resolver def not found");
                }
            }
        }
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let id = n.ident.to_id();
        let def = self.res.get_or_insert_sym(id, self.module);
        self.parent = Some(def);
        n.function.visit_with(self);
        self.parent = None;
    }
}

impl Lowerer<'_> {
    #[inline]
    fn defid_from_ident(&self, id: Id) -> Option<DefId> {
        self.res.sym_to_id(id, self.curr_mod)
    }

    #[inline]
    fn get_or_insert_sym(&mut self, id: Id) -> DefId {
        self.res.get_or_insert_sym(id, self.curr_mod)
    }

    fn res_from_ident(&self, id: Id) -> Option<DefRef<'_>> {
        self.res.sym_to_def(id, self.curr_mod)
    }

    fn as_foreign_import(&self, imported_sym: Id, module: &str) -> Option<&ImportKind> {
        match self.res_from_ident(imported_sym) {
            Some(DefRef::Foreign(item)) if item.module_name == *module => Some(&item.kind),
            _ => None,
        }
    }

    fn def_function(&mut self, id: Id) -> DefId {
        self.res
            .get_or_overwrite_sym(id, self.curr_mod, DefRes::Function(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ResolverDef {
    FnDef,
    Handler,
}

fn as_resolver(
    expr: &Expr,
    res_table: &Environment,
    module: ModId,
) -> Option<(DefId, ResolverDef)> {
    if let Expr::Member(MemberExpr {
        obj,
        prop: MemberProp::Ident(prop),
        ..
    }) = expr
    {
        let id = obj.as_ident()?;
        let def_id = res_table.sym_to_id(id.to_id(), module)?;
        let def = res_table.def_ref(def_id);
        if let DefKind::Resolver(obj) = def {
            match &*prop.sym {
                "getDefinitions" => return Some((def_id, ResolverDef::Handler)),
                "define" => return Some((def_id, ResolverDef::FnDef)),
                unknown => {
                    warn!("unknown prop: {unknown} on resolver: {}", &*id.sym);
                }
            }
        }
    }
    None
}

fn as_resolver_def<'a>(
    call: &'a CallExpr,
    res: &Environment,
    module: ModId,
) -> Option<(DefId, &'a JsWord, &'a Expr)> {
    let Some((objid, ResolverDef::FnDef)) = call
            .callee
            .as_expr()
            .and_then(|expr| as_resolver(expr, res, module)) else
    {
        return None;
    };
    let [ExprOrSpread { expr: name, .. }, ExprOrSpread { expr: args, .. }] = &*call.args else {
        return None;
    };
    match &**name {
        Expr::Lit(Lit::Str(Str { value, .. })) => Some((objid, value, args)),
        _ => None,
    }
}

impl Visit for Lowerer<'_> {
    noop_visit_type!();

    fn visit_call_expr(&mut self, n: &CallExpr) {
        if let Some(expr) = n.callee.as_expr() {
            if let Some((objid, ResolverDef::FnDef)) = as_resolver(expr, self.res, self.curr_mod) {
                if let [ExprOrSpread { expr: name, .. }, ExprOrSpread { expr: args, .. }] = &*n.args
                {
                    if let Expr::Lit(Lit::Str(Str { value, .. })) = &**name {
                        let fname = value.clone();
                        let class = self.res.def_mut(objid).expect_class();
                        class.pub_members.push((fname, self.curr_def.unwrap()));
                    }
                }
            }
        }
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        if let VarDeclarator {
            name: Pat::Ident(BindingIdent { id, .. }),
            init: Some(expr),
            ..
        } = n
        {
            let id = id.to_id();
            match &**expr {
                Expr::Arrow(expr) => {
                    let def_id = self.def_function(id);
                    let old_def = self.curr_def.replace(def_id);
                    expr.visit_children_with(self);
                    self.curr_def = old_def;
                }
                Expr::Fn(expr) => {
                    let def_id = self.def_function(id);
                    let old_def = self.curr_def.replace(def_id);
                    expr.visit_children_with(self);
                    self.curr_def = old_def;
                }
                Expr::Call(CallExpr {
                    callee: Callee::Expr(expr),
                    args,
                    ..
                }) => {
                    if let Some((objid, kind)) = as_resolver(expr, self.res, self.curr_mod) {
                        match kind {
                            ResolverDef::FnDef => {
                                if let [ExprOrSpread { expr: name, .. }, ExprOrSpread { expr: args, .. }] =
                                    &**args
                                {
                                    if let Expr::Lit(Lit::Str(Str { value, .. })) = &**expr {
                                        let fname = value.clone();
                                        println!("defining function: {}", &*fname);
                                        let member_def = match &**args {
                                            Expr::Fn(_) | Expr::Arrow(_) => self.res.add_anonymous(
                                                fname.clone(),
                                                AnonType::Closure,
                                                self.curr_mod,
                                            ),
                                            Expr::Ident(id) => self.get_or_insert_sym(id.to_id()),
                                            _ => {
                                                warn!("unknown function def: {:?}", args);
                                                self.res.add_anonymous(
                                                    fname.clone(),
                                                    AnonType::Unknown,
                                                    self.curr_mod,
                                                )
                                            }
                                        };
                                        let class = self.res.def_mut(objid).expect_class();
                                        class.pub_members.push((fname, member_def));
                                    }
                                }
                            }
                            ResolverDef::Handler => {
                                self.res.get_or_overwrite_sym(
                                    id,
                                    self.curr_mod,
                                    DefKind::ResolverHandler(objid),
                                );
                            }
                        }
                    }
                    expr.visit_children_with(self);
                }
                Expr::Object(ObjectLit { props, .. }) => {
                    let def_id =
                        self.res
                            .get_or_overwrite_sym(id, self.curr_mod, DefKind::GlobalObj(()));
                    let old_def = self.curr_def.replace(def_id);
                    // TODO:add parent
                    for prop in props {
                        match prop {
                            // TODO: track 'spreaded' objects
                            PropOrSpread::Spread(_) => {}
                            PropOrSpread::Prop(prop) => match &**prop {
                                Prop::Shorthand(id) => {
                                    let id = id.to_id();
                                    let sym = id.0.clone();
                                    let def_id = self.get_or_insert_sym(id);
                                    self.res
                                        .def_mut(def_id)
                                        .expect_class()
                                        .pub_members
                                        .push((sym, self.curr_def.unwrap()));
                                }
                                Prop::KeyValue(KeyValueProp { key, value }) => {
                                    if let sym @ Some(_) = key.as_symbol() {
                                        let defid = value.as_ident().map(|id| {
                                            self.res.get_or_insert_sym(id.to_id(), self.curr_mod)
                                        });
                                        let cls = self.res.def_mut(def_id).expect_class();
                                        cls.pub_members.extend(sym.zip(defid));
                                    }
                                }
                                Prop::Assign(AssignProp { key, .. }) => {
                                    let obj_sym = self.res.def_name(def_id);
                                    warn!("object {obj_sym} invalid assign prop {:?}", &key.sym);
                                }
                                /// TODO: track these
                                Prop::Getter(_) | Prop::Setter(_) => {}
                                Prop::Method(MethodProp { key, function }) => {
                                    function.body.visit_with(self);
                                    if let Some(sym) = key.as_symbol() {
                                        let def_id = self.res.add_anonymous(
                                            sym.clone(),
                                            AnonType::Closure,
                                            self.curr_mod,
                                        );
                                        self.res
                                            .def_mut(def_id)
                                            .expect_class()
                                            .pub_members
                                            .push((sym, def_id));
                                    }
                                }
                            },
                        }
                    }
                }
                Expr::New(NewExpr { callee, .. }) => {
                    let Some(callee_id) = callee.as_ident() else {
                        expr.visit_children_with(self);
                        return;
                    };
                    let callee_id = callee_id.to_id();
                    if Some(&ImportKind::Default)
                        == self.as_foreign_import(callee_id, "@forge/resolver")
                    {
                        self.res
                            .get_or_overwrite_sym(id, self.curr_mod, DefKind::Resolver(()));
                    }
                    expr.visit_children_with(self);
                }
                _ => {}
            }
        }
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let id = n.ident.to_id();
        let _defid = self.def_function(id);
    }
}

trait AsSymbol {
    fn expect_symbol(&self) -> JsWord {
        self.as_symbol().unwrap()
    }
    fn as_symbol(&self) -> Option<JsWord>;
}

impl AsSymbol for PropName {
    fn as_symbol(&self) -> Option<JsWord> {
        match self {
            PropName::Str(Str { value: sym, .. }) | PropName::Ident(Ident { sym, .. }) => {
                Some(sym.clone())
            }
            PropName::Num(_) | PropName::Computed(_) | PropName::BigInt(_) => None,
        }
    }
}

impl ExportCollector<'_> {
    fn add_export(&mut self, def: DefRes, id: Id) -> DefId {
        let exported_sym = id.0.clone();
        let defid = self.res_table.add_sym(def, id, self.curr_mod);
        self.exports.push((exported_sym, defid));
        defid
    }

    fn add_default(&mut self, def: DefRes, id: Option<Id>) {
        let defid = match id {
            Some(id) => self.res_table.add_sym(def, id, self.curr_mod),
            None => {
                self.res_table.names.push("default".into());
                self.res_table.owning_module.push(self.curr_mod);
                self.res_table.defs.push_and_get_key(def)
            }
        };
        self.default = Some(defid);
    }
}

impl Visit for ImportCollector<'_> {
    noop_visit_type!();

    fn visit_import_decl(&mut self, n: &ImportDecl) {
        let Str { value, .. } = &*n.src;
        let old_import = mem::replace(&mut self.current_import, value.clone());
        n.visit_children_with(self);
        self.current_import = old_import;
    }

    fn visit_import_named_specifier(&mut self, n: &ImportNamedSpecifier) {
        if n.is_type_only {
            return;
        }
        let ImportNamedSpecifier {
            local, imported, ..
        } = n;
        let local = local.to_id();
        let import_name = imported
            .as_ref()
            .map_or_else(|| local.0.clone(), export_name_to_jsword);

        match self
            .file_resolver
            .resolve_import(self.curr_mod.into(), &*self.current_import)
        {
            Ok(id) => {
                // TODO: find exported symbols
                if let Some(def_id) = self
                    .resolver
                    .resolve_local_export(ModId::from(id), &import_name)
                {
                    self.resolver.resolver.symbol_to_id.insert(
                        Symbol {
                            module: self.curr_mod,
                            id: local,
                        },
                        def_id,
                    );
                }
            }
            Err(_) => {
                let foreign_id = self.foreign_defs.push_and_get_key(ForeignItem {
                    kind: ImportKind::Named(import_name),
                    module_name: self.current_import.clone(),
                });
                self.resolver
                    .resolver
                    .add_sym(DefRes::Foreign(foreign_id), local, self.curr_mod);
            }
        }
    }

    fn visit_import_default_specifier(&mut self, n: &ImportDefaultSpecifier) {
        let local = n.local.to_id();
        match self
            .file_resolver
            .resolve_import(self.curr_mod.into(), &*self.current_import)
        {
            Ok(id) => {
                let mod_id = ModId::from(id);
                debug_assert_ne!(self.curr_mod, mod_id);
                match self.resolver.default_export(mod_id) {
                    Some(def) => {
                        self.resolver.resolver.symbol_to_id.insert(
                            Symbol {
                                module: self.curr_mod,
                                id: local,
                            },
                            def,
                        );
                    }
                    None => warn!("unable to find default import for {}", &self.current_import),
                }
            }
            Err(_) => {
                let foreign_id = self.foreign_defs.push_and_get_key(ForeignItem {
                    kind: ImportKind::Default,
                    module_name: self.current_import.clone(),
                });

                self.resolver
                    .resolver
                    .add_sym(DefRes::Foreign(foreign_id), local, self.curr_mod);
            }
        };
    }

    fn visit_import_star_as_specifier(&mut self, n: &ImportStarAsSpecifier) {
        let local = n.local.to_id();
        let defkind = match self
            .file_resolver
            .resolve_import(self.curr_mod.into(), &*self.current_import)
        {
            Ok(id) => {
                let mod_id = ModId::from(id);
                debug_assert_ne!(self.curr_mod, mod_id);
                DefRes::ModuleNs(mod_id)
            }
            Err(_) => {
                let foreign_id = self.foreign_defs.push_and_get_key(ForeignItem {
                    kind: ImportKind::Star,
                    module_name: self.current_import.clone(),
                });
                DefRes::Foreign(foreign_id)
            }
        };
        self.resolver
            .resolver
            .add_sym(defkind, local, self.curr_mod);
    }

    fn visit_module_item(&mut self, n: &ModuleItem) {
        if let ModuleItem::ModuleDecl(ModuleDecl::Import(n)) = n {
            n.visit_with(self);
        }
    }
}

impl Visit for ExportCollector<'_> {
    noop_visit_type!();
    fn visit_export_decl(&mut self, n: &ExportDecl) {
        match &n.decl {
            Decl::Class(ClassDecl { ident, .. }) => {
                let ident = ident.to_id();
                self.add_export(DefRes::Class(()), ident);
            }
            Decl::Fn(FnDecl { ident, .. }) => {
                let ident = ident.to_id();
                self.add_export(DefRes::Function(()), ident);
            }
            Decl::Var(vardecls) => {
                let VarDecl { decls, .. } = &**vardecls;
                decls.iter().for_each(|var| self.visit_var_declarator(var));
            }
            Decl::TsInterface(_) => {}
            Decl::TsTypeAlias(_) => {}
            Decl::TsEnum(_) => {}
            Decl::TsModule(_) => {}
        };
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        // TODO: handle other kinds of destructuring patterns
        if let Pat::Ident(BindingIdent { id, .. }) = &n.name {
            let id = id.to_id();
            self.add_export(DefRes::Undefined, id);
        }
    }

    fn visit_module_item(&mut self, n: &ModuleItem) {
        match n {
            ModuleItem::ModuleDecl(decl)
                if matches!(
                    decl,
                    ModuleDecl::ExportDecl(_)
                        | ModuleDecl::ExportDefaultDecl(_)
                        | ModuleDecl::ExportDefaultExpr(_)
                        | ModuleDecl::ExportAll(_)
                        | ModuleDecl::ExportNamed(_)
                ) =>
            {
                decl.visit_children_with(self)
            }
            _ => {}
        }
    }

    fn visit_export_all(&mut self, _: &ExportAll) {}

    fn visit_export_default_decl(&mut self, n: &ExportDefaultDecl) {
        match &n.decl {
            DefaultDecl::Class(ClassExpr { ident, .. }) => {
                self.add_default(DefRes::Class(()), ident.as_ref().map(Ident::to_id))
            }
            DefaultDecl::Fn(FnExpr { ident, .. }) => {
                self.add_default(DefRes::Function(()), ident.as_ref().map(Ident::to_id))
            }
            DefaultDecl::TsInterfaceDecl(_) => {}
        }
    }

    fn visit_export_named_specifier(&mut self, n: &ExportNamedSpecifier) {
        let orig_id = n.orig.as_id();
        let orig = self.add_export(DefRes::default(), orig_id);
        if let Some(id) = &n.exported {
            let exported_id = id.as_id();
            self.add_export(DefRes::ExportAlias(orig), exported_id);
        }
    }

    fn visit_export_default_expr(&mut self, _: &ExportDefaultExpr) {
        self.add_default(DefRes::Undefined, None);
    }
}

impl Environment {
    #[inline]
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn next_key(&self) -> DefId {
        self.resolver.defs.next_key()
    }

    #[inline]
    fn try_add_parent(&mut self, child: DefId, parent: DefId) {
        self.resolver.parent.entry(child).or_insert(parent);
    }

    #[inline]
    fn add_parent(&mut self, child: DefId, parent: DefId) {
        self.resolver.parent.insert(child, parent);
    }

    #[inline]
    fn get_or_insert_sym(&mut self, id: Id, module: ModId) -> DefId {
        let def_id = self.resolver.get_or_insert_sym(id, module);
        let def_id2 = self.defs.defs.get(def_id).copied().map_or_else(
            || self.defs.defs.push_and_get_key(DefKey::default()),
            |_| def_id,
        );
        debug_assert_eq!(def_id, def_id2);
        def_id
    }

    fn new_key_from_res(&mut self, id: DefId, res: DefRes) -> DefKey {
        match res {
            DefKind::Arg => DefKind::Arg,
            DefKind::Function(_) => {
                let func_id = self.defs.funcs.push_and_get_key(Body::with_owner(id));
                DefKind::Function(func_id)
            }
            DefKind::Closure(_) => {
                let closure_id = self.defs.funcs.push_and_get_key(Body::with_owner(id));
                DefKind::Closure(closure_id)
            }
            DefKind::GlobalObj(_) => {
                let obj_id = self.defs.classes.push_and_get_key(Class::new(id));
                DefKind::GlobalObj(obj_id)
            }
            DefKind::Class(_) => {
                let class_id = self.defs.classes.push_and_get_key(Class::new(id));
                DefKind::Class(class_id)
            }
            DefKind::Resolver(_) => {
                let obj_id = self.defs.classes.push_and_get_key(Class::new(id));
                DefKind::Resolver(obj_id)
            }
            DefKind::ExportAlias(i) => DefKind::ExportAlias(i),
            DefKind::Foreign(i) => DefKind::Foreign(i),
            DefKind::ResolverHandler(i) => DefKind::ResolverHandler(i),
            DefKind::ResolverDef(i) => DefKind::ResolverDef(i),
            DefKind::ModuleNs(i) => DefKind::ModuleNs(i),
            DefKind::Undefined => DefKind::Undefined,
        }
    }

    fn add_anonymous(&mut self, name: impl Into<JsWord>, kind: AnonType, module: ModId) -> DefId {
        match kind {
            AnonType::Obj => {
                let id = self
                    .resolver
                    .add_anon(DefRes::GlobalObj(()), name.into(), module);
                let obj_id = self.defs.classes.push_and_get_key(Class::new(id));
                let id2 = self.defs.defs.push_and_get_key(DefKind::GlobalObj(obj_id));
                debug_assert_eq!(id, id2);
                id
            }
            AnonType::Closure => {
                let id = self
                    .resolver
                    .add_anon(DefRes::Closure(()), name.into(), module);
                let func_id = self.defs.funcs.push_and_get_key(Body::with_owner(id));
                let id2 = self.defs.defs.push_and_get_key(DefKind::Closure(func_id));
                debug_assert_eq!(id, id2);
                id
            }
            AnonType::Unknown => {
                let id = self
                    .resolver
                    .add_anon(DefRes::Undefined, name.into(), module);
                let id2 = self.defs.defs.push_and_get_key(DefKind::Undefined);
                debug_assert_eq!(id, id2);
                id
            }
        }
    }

    fn module_export<I: PartialEq<str> + ?Sized>(
        &self,
        module: ModId,
        export_name: &I,
    ) -> Option<DefId> {
        if *export_name == *"default" {
            self.default_export(module)
        } else {
            self.exports[module]
                .iter()
                .find_map(|(ident, defid)| (*export_name == **ident).then_some(*defid))
        }
    }

    #[inline]
    fn get_or_overwrite_sym(&mut self, id: Id, module: ModId, kind: DefRes) -> DefId {
        let defid = self.resolver.get_or_insert_sym(id, module);
        self.resolver.defs[defid] = kind;
        match self.defs.defs.get(defid).copied() {
            Some(key) if key == kind => return defid,
            Some(_) => {
                let key = self.new_key_from_res(defid, kind);
                self.defs.defs[defid] = key;
            }
            None => {
                let key = self.new_key_from_res(defid, kind);
                let def2 = self.defs.defs.push_and_get_key(key);
                debug_assert_eq!(defid, def2);
            }
        }
        defid
    }

    #[inline]
    pub fn default_export(&self, module: ModId) -> Option<DefId> {
        self.default_exports.get(&module).copied()
    }

    #[inline]
    pub fn def_name(&self, def: DefId) -> &str {
        &self.resolver.names[def]
    }

    #[inline]
    pub fn module_exports(&self, module: ModId) -> impl Iterator<Item = (&str, DefId)> + '_ {
        self.exports[module].iter().map(|(k, v)| (&**k, *v))
    }

    #[inline]
    pub fn def_ref(&self, def: DefId) -> DefRef<'_> {
        match self.defs.defs[def] {
            DefKind::Arg => DefKind::Arg,
            DefKind::Function(f) => {
                let body = &self.defs.funcs[f];
                DefKind::Function(body)
            }
            DefKind::ExportAlias(d) => DefKind::ExportAlias(d),
            DefKind::GlobalObj(id) => {
                let class = &self.defs.classes[id];
                DefKind::GlobalObj(class)
            }
            DefKind::Class(id) => {
                let class = &self.defs.classes[id];
                DefKind::Class(class)
            }
            DefKind::Foreign(id) => {
                let foreign = &self.defs.foreign[id];
                DefKind::Foreign(foreign)
            }
            DefKind::ResolverHandler(id) => DefKind::ResolverHandler(id),
            DefKind::Resolver(id) => {
                let class = &self.defs.classes[id];
                DefKind::Resolver(class)
            }
            DefKind::ResolverDef(id) => DefKind::ResolverDef(id),
            DefKind::Closure(id) => {
                let body = &self.defs.funcs[id];
                DefKind::Closure(body)
            }
            DefKind::ModuleNs(id) => DefKind::ModuleNs(id),
            DefKind::Undefined => DefKind::Undefined,
        }
    }

    fn lookup_prop(&self, obj: DefId, prop: &JsWord) -> Option<DefId> {
        match self.def_ref(obj) {
            DefKind::GlobalObj(obj) | DefKind::Class(obj) | DefKind::Resolver(obj) => {
                obj.find_member(prop)
            }
            DefKind::ExportAlias(def) | DefKind::ResolverHandler(def) => {
                self.lookup_prop(def, prop)
            }
            DefKind::ModuleNs(mid) => self.module_export(mid, prop),
            // FIXME: fully resolve foreign items here as well
            DefKind::Foreign(_)
            | DefKind::Arg
            | DefKind::Function(_)
            | DefKind::Closure(_)
            | DefKind::ResolverDef(_)
            | DefKind::Undefined => None,
        }
    }

    #[inline]
    fn sym_to_id(&self, id: Id, module: ModId) -> Option<DefId> {
        let sym = Symbol { module, id };
        self.resolver.symbol_to_id.get(&sym).copied()
    }

    #[inline]
    fn sym_to_def(&self, id: Id, module: ModId) -> Option<DefRef<'_>> {
        self.resolver.sym_id(id, module).map(|id| self.def_ref(id))
    }

    #[inline]
    fn sym_to_def_mut(&mut self, id: Id, module: ModId) -> Option<DefMut<'_>> {
        self.resolver.sym_id(id, module).map(|id| self.def_mut(id))
    }

    #[inline]
    fn def_mut(&mut self, def: DefId) -> DefMut<'_> {
        match self.defs.defs[def] {
            DefKind::Arg => DefKind::Arg,
            DefKind::Function(f) => {
                let body = &mut self.defs.funcs[f];
                DefKind::Function(body)
            }
            DefKind::ExportAlias(d) => DefKind::ExportAlias(d),
            DefKind::GlobalObj(id) => {
                let class = &mut self.defs.classes[id];
                DefKind::GlobalObj(class)
            }
            DefKind::Class(id) => {
                let class = &mut self.defs.classes[id];
                DefKind::Class(class)
            }
            DefKind::Foreign(id) => {
                let foreign = &mut self.defs.foreign[id];
                DefKind::Foreign(foreign)
            }
            DefKind::ResolverHandler(id) => DefKind::ResolverHandler(id),
            DefKind::Resolver(id) => {
                let class = &mut self.defs.classes[id];
                DefKind::Resolver(class)
            }
            DefKind::ResolverDef(id) => DefKind::ResolverDef(id),
            DefKind::Closure(id) => {
                let body = &mut self.defs.funcs[id];
                DefKind::Closure(body)
            }
            DefKind::ModuleNs(id) => DefKind::ModuleNs(id),
            DefKind::Undefined => DefKind::Undefined,
        }
    }

    fn resolve_local_export(&self, module: ModId, name: &JsWord) -> Option<DefId> {
        match &**name {
            "default" => self.default_exports.get(&module).copied(),
            _ => self.exports.get(module).and_then(|exports| {
                exports
                    .iter()
                    .find_map(|&(ref export, def_id)| (*export == *name).then_some(def_id))
            }),
        }
    }
}

impl Definitions {
    fn new(
        res: impl IntoIterator<Item = (DefId, DefRes)>,
        foreign: TiVec<ForeignId, ForeignItem>,
    ) -> Self {
        let mut funcs = TiVec::new();
        let mut classes = TiVec::new();
        let defs: TiVec<_, _> = res
            .into_iter()
            .map(|(id, def)| match def {
                DefKind::Arg => DefKind::Arg,
                DefKind::Function(_) => {
                    let fid = funcs.push_and_get_key(Body::with_owner(id));
                    DefKind::Function(fid)
                }
                DefKind::ExportAlias(d) => DefKind::ExportAlias(d),
                DefKind::GlobalObj(_) => {
                    let objid = classes.push_and_get_key(Class::new(id));
                    DefKind::GlobalObj(objid)
                }
                DefKind::Class(_) => {
                    let objid = classes.push_and_get_key(Class::new(id));
                    DefKind::Class(objid)
                }
                DefKind::Foreign(d) => DefKind::Foreign(d),
                DefKind::ResolverHandler(d) => DefKind::ResolverHandler(d),
                DefKind::Resolver(_) => {
                    let objid = classes.push_and_get_key(Class::new(id));
                    DefKind::Resolver(objid)
                }
                DefKind::ResolverDef(d) => DefKind::ResolverDef(d),
                DefKind::Closure(_) => {
                    let fid = funcs.push_and_get_key(Body::with_owner(id));
                    DefKind::Closure(fid)
                }
                DefKind::ModuleNs(d) => DefKind::ModuleNs(d),
                DefKind::Undefined => DefKind::Undefined,
            })
            .collect();
        Self {
            defs,
            funcs,
            classes,
            foreign,
        }
    }
}

trait Database<K> {
    type Value;
    fn get(&self, key: K) -> Option<&Self::Value>;
    fn get_mut(&mut self, key: K) -> Option<&mut Self::Value>;
}

impl Database<ForeignId> for Definitions {
    type Value = ForeignItem;
    fn get(&self, key: ForeignId) -> Option<&Self::Value> {
        self.foreign.get(key)
    }

    fn get_mut(&mut self, key: ForeignId) -> Option<&mut Self::Value> {
        self.foreign.get_mut(key)
    }
}

trait AsId {
    fn as_id(&self) -> Id;
}

fn export_name_to_jsword(expname: &ModuleExportName) -> JsWord {
    match expname {
        ModuleExportName::Ident(ident) => ident.to_id().0,
        ModuleExportName::Str(str) => str.value.clone(),
    }
}

impl ObjKind {
    #[inline]
    fn into_inner(self) -> ObjId {
        match self {
            ObjKind::Lit(id) | ObjKind::Resolver(id) | ObjKind::Class(id) => id,
        }
    }

    #[inline]
    fn as_defkind(&self) -> DefKey {
        match *self {
            ObjKind::Class(id) => DefKey::Class(id),
            ObjKind::Lit(id) => DefKey::GlobalObj(id),
            ObjKind::Resolver(id) => DefKey::Resolver(id),
        }
    }
}

impl DefKey {
    #[inline]
    fn as_objkind(&self) -> Option<ObjKind> {
        match *self {
            DefKey::Class(id) => Some(ObjKind::Class(id)),
            DefKey::Resolver(id) => Some(ObjKind::Resolver(id)),
            DefKey::GlobalObj(id) => Some(ObjKind::Lit(id)),
            DefKey::Function(_)
            | DefKey::ResolverDef(_)
            | DefKey::Closure(_)
            | DefKey::Arg
            | DefKey::ExportAlias(_)
            | DefKey::ResolverHandler(_)
            | DefKey::ModuleNs(_)
            | DefKey::Foreign(_)
            | DefKey::Undefined => None,
        }
    }
}

impl<F, O, I> fmt::Display for DefKind<F, O, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefKind::Class(_) => write!(f, "class"),
            DefKind::ResolverDef(_) => write!(f, "resolver def"),
            DefKind::Resolver(_) => write!(f, "resolver"),
            DefKind::Arg => write!(f, "argument"),
            DefKind::GlobalObj(_) => write!(f, "object literal"),
            DefKind::Function(_) => write!(f, "function"),
            DefKind::Closure(_) => write!(f, "closure"),
            DefKind::ExportAlias(_) => write!(f, "export alias"),
            DefKind::ResolverHandler(_) => write!(f, "resolver handler"),
            DefKind::ModuleNs(_) => write!(f, "module namespace"),
            DefKind::Foreign(_) => write!(f, "foreign"),
            DefKind::Undefined => write!(f, "undefined"),
        }
    }
}

impl fmt::Display for ImportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportKind::Star => write!(f, "*"),
            ImportKind::Default => write!(f, "default"),
            ImportKind::Named(sym) => write!(f, "{}", &**sym),
        }
    }
}

impl fmt::Display for ForeignItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "import {} from {}", self.kind, &*self.module_name)
    }
}

impl From<ObjKind> for DefKey {
    #[inline]
    fn from(value: ObjKind) -> Self {
        value.as_defkind()
    }
}

impl AsId for ModuleExportName {
    fn as_id(&self) -> Id {
        match self {
            ModuleExportName::Ident(ident) => ident.to_id(),
            ModuleExportName::Str(str) => (str.value.clone(), SyntaxContext::empty()),
        }
    }
}
