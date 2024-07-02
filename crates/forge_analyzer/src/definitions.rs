#![allow(dead_code, unused)]

use std::{borrow::Borrow, fmt, mem};

use crate::utils::{calls_method, eq_prop_name};
use forge_file_resolver::{FileResolver, ForgeResolver};
use forge_utils::{create_newtype, FxHashMap};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use swc_core::ecma::ast::{MethodKind, PrivateMethod};
use swc_core::{
    common::{Span, SyntaxContext, DUMMY_SP},
    ecma::{
        ast::{
            ArrayLit, ArrayPat, ArrowExpr, AssignExpr, AssignOp, AssignPat, AssignPatProp,
            AssignProp, AssignTarget, AwaitExpr, BinExpr, BindingIdent, BlockStmt, BlockStmtOrExpr,
            BreakStmt, CallExpr, Callee, ClassDecl, ClassExpr, ClassMethod, ComputedPropName,
            CondExpr, Constructor, ContinueStmt, Decl, DefaultDecl, DoWhileStmt, ExportAll,
            ExportDecl, ExportDefaultDecl, ExportDefaultExpr, ExportNamedSpecifier,
            ExportSpecifier, Expr, ExprOrSpread, ExprStmt, FnDecl, FnExpr, ForHead, ForInStmt,
            ForOfStmt, ForStmt, Function, Id, Ident, IfStmt, Import, ImportDecl,
            ImportDefaultSpecifier, ImportNamedSpecifier, ImportStarAsSpecifier, JSXAttrName,
            JSXAttrOrSpread, JSXAttrValue, JSXElement, JSXElementChild, JSXElementName, JSXExpr,
            JSXExprContainer, JSXFragment, JSXMemberExpr, JSXNamespacedName, JSXObject,
            JSXSpreadChild, JSXText, KeyValuePatProp, KeyValueProp, LabeledStmt, Lit, MemberExpr,
            MemberProp, MetaPropExpr, MethodProp, Module, ModuleDecl, ModuleExportName, ModuleItem,
            NamedExport, NewExpr, Number, ObjectLit, ObjectPat, ObjectPatProp, OptCall,
            OptChainBase, OptChainExpr, Param, ParenExpr, Pat, PrivateName, Prop, PropName,
            PropOrSpread, RestPat, ReturnStmt, SeqExpr, SimpleAssignTarget, Stmt, Str, Super,
            SuperProp, SuperPropExpr, SwitchStmt, TaggedTpl, ThisExpr, ThrowStmt, Tpl, TplElement,
            TryStmt, TsAsExpr, TsConstAssertion, TsInstantiation, TsNonNullExpr, TsSatisfiesExpr,
            TsTypeAssertion, UnaryExpr, UpdateExpr, VarDecl, VarDeclOrExpr, VarDeclarator,
            WhileStmt, WithStmt, YieldExpr,
        },
        atoms::{Atom, JsWord},
        utils::{function, ident::IdentLike},
        visit::{noop_visit_type, Visit, VisitWith},
    },
};
use tracing::{debug, field::debug, info, instrument, warn};
use typed_index_collections::{TiSlice, TiVec};

use crate::ir::VarId;
use crate::{
    ctx::ModId,
    ir::{
        Base, BasicBlockId, Body, Inst, Intrinsic, Literal, Operand, Projection, Rvalue, Template,
        Terminator, VarKind, Variable, RETURN_VAR, STARTING_BLOCK,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Const {
    Literal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uninit,
    Unknown,
    Object(VarId),
    Const(Const),
    Phi(Vec<Const>),
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
pub struct ResolverTable {
    defs: TiVec<DefId, DefRes>,
    pub names: TiVec<DefId, JsWord>,
    pub global: TiVec<ModId, DefId>,
    recent_names: FxHashMap<(JsWord, ModId), DefId>,
    exported_names: FxHashMap<(JsWord, ModId), DefId>,
    default_export_names: FxHashMap<(JsWord, ModId), DefId>,
    symbol_to_id: FxHashMap<Symbol, DefId>,
    global_defid_to_value: FxHashMap<DefId, Value>,
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
    secret_packages: &[PackageData],
) -> Environment {
    let mut environment = Environment::new();

    for (curr_mod, module) in modules.iter_enumerated() {
        let mut export_collector = ExportCollector {
            res_table: &mut environment.resolver,
            curr_mod,
            exports: vec![],
            default: None,
        };
        module.visit_children_with(&mut export_collector);
        let mod_id = environment
            .exports
            .push_and_get_key(export_collector.exports);
        debug_assert_eq!(curr_mod, mod_id);
        if let Some(default) = export_collector.default {
            let def_id = environment.default_exports.insert(curr_mod, default);
            debug_assert_eq!(def_id, None, "def_id shouldn't be set");
        }
    }

    let mut foreign = TiVec::default();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut import_collector = ImportCollector {
            resolver: &mut environment,
            file_resolver,
            foreign_defs: &mut foreign,
            curr_mod,
            current_import: Default::default(),
            in_foreign_import: false,
        };
        module.visit_with(&mut import_collector);
    }

    let mut foreign = TiVec::default();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut import_collector = ImportCollector {
            resolver: &mut environment,
            file_resolver,
            foreign_defs: &mut foreign,
            curr_mod,
            current_import: Default::default(),
            in_foreign_import: false,
        };
        module.visit_with(&mut import_collector);
    }

    // check for required after Definitions pass
    let defs = Definitions::new(
        environment
            .resolver
            .defs
            .iter_enumerated()
            .map(|(id, &d)| (id, d)),
        foreign,
    );
    environment.defs = defs;
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut lowerer = Lowerer {
            res: &mut environment,
            curr_mod,
            curr_class: None,
            parents: vec![],
            curr_def: None,
        };
        module.visit_with(&mut lowerer);
    }
    for (curr_mod, module) in modules.iter_enumerated() {
        let global_id = environment.get_or_reserve_global_scope(curr_mod);
        let mut global_collector = GlobalCollector {
            res: &mut environment,
            global_id,
            secret_packages,
            module: curr_mod,
            parent: None,
        };
        module.visit_with(&mut global_collector);
    }
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut collector = FunctionCollector {
            res: &mut environment,
            file_resolver,
            curr_class: None,
            curr_function: None,
            secret_packages,
            module: curr_mod,
            parent: None,
        };
        module.visit_with(&mut collector);
    }

    environment
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Class {
    def: DefId,
    pub pub_members: Vec<(JsWord, DefId)>,
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
    pub fn new(def: DefId) -> Self {
        Self {
            def,
            pub_members: vec![],
            constructor: None,
        }
    }

    /// Locate a property on this object.
    ///
    /// Note that this does not look up the prototype chain.
    ///
    /// # Example
    ///
    /// ```javascript
    /// const obj = {
    ///   foo: 1,
    /// };
    /// ```
    ///
    /// ```rust
    /// use forge_analyzer::definitions::{Class, DefId};
    ///
    /// # fn foo(obj_id: DefId) {
    /// let obj = Class::new(obj_id);
    /// obj.find_member("foo");
    /// # }
    /// ```
    pub fn find_member<N: ?Sized>(&self, name: &N) -> Option<DefId>
    where
        JsWord: PartialEq<N>,
    {
        self.pub_members
            .iter()
            .find_map(|(n, d)| (*n == *name).then_some(*d))
    }
}

create_newtype! {
    pub struct ForeignId(u32);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportKind {
    Star,
    Default,
    Named(JsWord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The renamed [`DefId`]
    ///
    /// # Example
    ///
    /// ```javascript
    /// function foo() {}
    /// // The [`DefId`] of `foo` will be the field in [`ExportAlias`]
    /// // The [`DefKind`] of bar will be [`ExportAlias`]
    /// export { foo as bar };
    /// ```
    ExportAlias(DefId),
    GlobalObj(O),
    Class(O),
    /// any imports that are not from the current project
    Foreign(I),
    /// exported(usual) handler to the actual resolver definitions
    ///
    /// [`DefId`] should point to [`DefKind::Resolver`]
    ///
    /// # Example
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
    /// the actual resolver object
    ///
    /// # Example
    ///
    /// ```javascript
    /// import Resolver from '@forge/resolver';
    ///
    /// const resolver = new Resolver();
    /// // `resolver` resolves to a DefId pointing to [`DefKind::Resolver`]
    /// ```
    Resolver(O),
    /// function defined on a resolver object
    ///
    /// # Example
    ///
    /// ```javascript
    /// // the `handler` symbol resolves to a DefId for [`DefKind::ResolverHandler`]
    /// resolver.define('handlerFunc', ({ payload, context }) => {}
    /// ```
    ResolverDef(DefId),
    Closure(F),
    // Example: `module` in import * as 'foo' from 'module'
    // Local modules only.
    ModuleNs(ModId),
    Undefined,
}

impl<F, O, I> Default for DefKind<F, O, I> {
    fn default() -> Self {
        Self::Undefined
    }
}

impl<F, O, I> DefKind<F, O, I> {
    pub fn expect_body(self) -> F {
        match self {
            Self::Function(f) | Self::Closure(f) => f,
            k => panic!("expected function"),
        }
    }

    pub fn expect_class(self) -> O {
        match self {
            Self::Class(c) | Self::GlobalObj(c) | Self::Resolver(c) => c,
            _ => panic!("expected class"),
        }
    }

    pub fn as_body(&self) -> Option<&F> {
        match self {
            Self::Function(f) | Self::Closure(f) => Some(f),
            _ => None,
        }
    }

    pub fn to_body(self) -> Option<F> {
        match self {
            Self::Function(f) | Self::Closure(f) => Some(f),
            _ => None,
        }
    }

    pub fn as_handler(&self) -> Option<DefId> {
        match *self {
            Self::ResolverHandler(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_resolver(&self) -> Option<&O> {
        match self {
            Self::Resolver(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_resolver_def(&self) -> Option<DefId> {
        match *self {
            Self::ResolverDef(id) => Some(id),
            _ => None,
        }
    }

    pub fn is_resolver_handler(&self) -> bool {
        matches!(self, Self::ResolverHandler(_))
    }
}

impl PartialEq<DefKey> for DefRes {
    fn eq(&self, other: &DefKey) -> bool {
        *other == *self
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
            (DefKind::Arg, DefKind::Arg) => true,
            (DefKind::Undefined, DefKind::Undefined) => true,
            (
                DefKind::Function(_)
                | DefKind::Arg
                | DefKind::Undefined
                | DefKind::ExportAlias(_)
                | DefKind::GlobalObj(_)
                | DefKind::Class(_)
                | DefKind::Foreign(_)
                | DefKind::Resolver(_)
                | DefKind::ResolverHandler(_)
                | DefKind::ResolverDef(_)
                | DefKind::Closure(_)
                | DefKind::ModuleNs(_),
                _,
            ) => false,
        }
    }
}

impl Copy for DefKey {}
impl Copy for DefRes {}
impl Copy for DefRef<'_> {}

#[derive(Debug, Clone, Default)]
pub struct Definitions {
    pub defs: TiVec<DefId, DefKey>,
    funcs: TiVec<FuncId, Body>,
    pub classes: TiVec<ObjId, Class>,
    foreign: TiVec<ForeignId, ForeignItem>,
}

#[derive(Debug, Clone, Default)]
pub struct Environment {
    exports: TiVec<ModId, Vec<(JsWord, DefId)>>,
    pub global: TiVec<ModId, DefId>,
    pub defs: Definitions,
    default_exports: FxHashMap<ModId, DefId>,
    pub resolver: ResolverTable,
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

struct GlobalCollector<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    global_id: DefId,
    secret_packages: &'cx [PackageData],
    parent: Option<DefId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowerStage {
    Collect,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntrinsicName {
    RequestConfluence,
    RequestJira,
    Other,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Eq)]
pub struct PackageData {
    pub package_name: String,
    pub identifier: String,
    pub method: Option<String>,
    pub secret_position: u8,
}

struct Lowerer<'cx> {
    res: &'cx mut Environment,
    curr_mod: ModId,
    curr_class: Option<DefId>,
    parents: Vec<DefId>,
    curr_def: Option<DefId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PropPath {
    Def(DefId),
    Static(JsWord),
    MemberCall(JsWord),
    Unknown(Id),
    Expr,
    This,
    Super,
    Private(Id),
    Computed(Id),
}

fn normalize_callee_expr(
    callee: CalleeRef<'_>,
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
                MemberProp::Ident(n) => {
                    self.path.push(PropPath::Static(n.sym.clone()));
                }
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
            self.path.push(PropPath::Static(str));
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
                Expr::Call(CallExpr { callee, .. }) => {
                    let Some(expr) = callee.as_expr() else {
                        self.path.push(PropPath::Expr);
                        return;
                    };
                    match &**expr {
                        Expr::Member(MemberExpr {
                            obj,
                            prop: MemberProp::Ident(ident),
                            ..
                        }) => {
                            obj.visit_with(self);
                            self.path.push(PropPath::MemberCall(ident.sym.clone()));
                        }
                        _ => {
                            self.path.push(PropPath::Expr);
                        }
                    }
                }

                _ => self.path.push(PropPath::Expr),
            }
        }
    }
    match callee {
        CalleeRef::Expr(expr) => {
            let mut normalizer = CalleeNormalizer {
                res_table,
                curr_mod,
                path: vec![],
                in_prop: false,
            };
            normalizer.visit_expr(expr);
            normalizer.path
        }
        CalleeRef::Import => vec![],
        CalleeRef::Super => vec![PropPath::Super],
    }
}

impl ResolverTable {
    #[inline]
    fn sym_id(&self, id: Id, module: ModId) -> Option<DefId> {
        self.symbol_to_id.get(&Symbol { module, id }).copied()
    }

    #[inline]
    fn recent_sym(&self, sym: JsWord, module: ModId) -> Option<DefId> {
        self.recent_names.get(&(sym, module)).copied()
    }

    #[inline]
    fn get_default(&self, module: ModId) -> Option<DefId> {
        for (defid, sym) in self.names.iter_enumerated() {
            if sym == "default" && self.owning_module.contains(&module) {
                return Some(defid);
            }
        }
        None
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
        let defid = self
            .sym_id(id.clone(), module)
            .unwrap_or_else(|| self.reserve_symbol(id.clone(), module));
        self.recent_names.insert((id.0, module), defid);
        defid
    }

    #[inline]
    fn get_sym(&mut self, id: Id, module: ModId) -> Option<DefId> {
        self.sym_id(id.clone(), module)
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
            "inconsistent state while inserting 1 {}",
            &*name
        );
        let defid3 = self.names.push_and_get_key(name);
        debug_assert_eq!(
            defid,
            defid3,
            "inconsistent state while inserting 2 {}",
            self.names.last().unwrap()
        );
        defid
    }

    fn add_sym(&mut self, def: DefRes, id: Id, module: ModId) -> DefId {
        let defid = self.defs.push_and_get_key(def);
        let defid2 = self.owning_module.push_and_get_key(module);
        debug_assert_eq!(
            defid, defid2,
            "inconsistent state while inserting 3 {}",
            id.0
        );
        let sym = id.0.clone();
        self.symbol_to_id.insert(Symbol { id, module }, defid2);
        self.recent_names.insert((sym.clone(), module), defid2);
        let defid3 = self.names.push_and_get_key(sym);
        debug_assert_eq!(
            defid,
            defid3,
            "inconsistent state while inserting 4 {}",
            self.names.last().unwrap()
        );
        defid
    }
}

struct FunctionCollector<'cx> {
    res: &'cx mut Environment,
    file_resolver: &'cx ForgeResolver,
    module: ModId,
    curr_class: Option<DefId>,
    curr_function: Option<DefId>,
    secret_packages: &'cx [PackageData],
    parent: Option<DefId>,
}

struct FunctionAnalyzer<'cx> {
    pub res: &'cx mut Environment,
    module: ModId,
    current_def: DefId,
    assigning_to: Option<Variable>,
    pub body: Body,
    block: BasicBlockId,
    secret_packages: &'cx [PackageData],
    operand_stack: Vec<Operand>,
    in_lhs: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalleeRef<'a> {
    Expr(&'a Expr),
    Import,
    Super,
}

impl<'a> From<&'a Callee> for CalleeRef<'a> {
    fn from(value: &'a Callee) -> Self {
        match value {
            Callee::Super(_) => Self::Super,
            Callee::Import(_) => Self::Import,
            Callee::Expr(expr) => Self::Expr(expr),
        }
    }
}

impl<'a> From<&'a Expr> for CalleeRef<'a> {
    fn from(value: &'a Expr) -> Self {
        Self::Expr(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum ApiCallKind {
    #[default]
    Unknown,
    Fields,
    CustomField,
    Trivial,
    Authorize,
}

fn classify_api_call(expr: &Expr) -> ApiCallKind {
    use regex::Regex;
    use std::cell::OnceCell;

    // FIXME: this should be done as a dataflow analysis instead of on the AST.
    fn trivial_regex(route: &str) -> bool {
        thread_local! {
            static TRIVIAL: OnceCell<Regex> = const { OnceCell::new() }
        }
        TRIVIAL.with(move |r| {
            r.get_or_init(|| {
                Regex::new(r"user|instance|avatar|license|preferences|server[iI]nfo").unwrap()
            })
            .is_match(route)
        })
    }

    #[derive(Default)]
    struct ApiCallClassifier {
        kind: ApiCallKind,
    }

    impl ApiCallClassifier {
        fn check(&mut self, name: &str) {
            if name.contains("permission") {
                self.kind = self.kind.max(ApiCallKind::Authorize);
            } else if trivial_regex(name) || name.contains("group") {
                self.kind = self.kind.max(ApiCallKind::Trivial);
            } else if name == "/rest/api/3/field" || name == "/rest/api/2/field" {
                self.kind = ApiCallKind::Fields;
            } else if name.contains("field") {
                self.kind = self.kind.max(ApiCallKind::CustomField);
            }
        }
    }

    impl Visit for ApiCallClassifier {
        fn visit_tpl_element(&mut self, n: &TplElement) {
            self.check(&n.raw);
        }

        fn visit_str(&mut self, s: &Str) {
            self.check(&s.value);
        }
    }

    let mut classifier = ApiCallClassifier::default();
    expr.visit_with(&mut classifier);
    classifier.kind
}

impl<'cx> FunctionAnalyzer<'cx> {
    #[inline]
    fn set_curr_terminator(&mut self, term: Terminator) {
        self.body.set_terminator(self.block, term);
    }

    fn as_intrinsic(&self, callee: &[PropPath], first_arg: Option<&Expr>) -> Option<Intrinsic> {
        fn is_storage_read(prop: &JsWord) -> bool {
            *prop == *"get" || *prop == *"getSecret" || *prop == *"query"
        }

        match *callee {
            [PropPath::Unknown((ref name, ..))] if *name == *"fetch" => Some(Intrinsic::Fetch),
            [PropPath::Def(def), ref authn @ .., PropPath::Static(ref last)]
                if (*last == *"requestJira" || *last == *"requestConfluence")
                    && Some(&ImportKind::Default)
                        == self.res.is_imported_from(def, "@forge/api") =>
            {
                let function_name = if *last == "requestJira" {
                    IntrinsicName::RequestJira
                } else {
                    IntrinsicName::RequestConfluence
                };
                let first_arg = first_arg?;
                let is_as_app = authn.first() == Some(&PropPath::MemberCall("asApp".into()));
                match classify_api_call(first_arg) {
                    ApiCallKind::Unknown => {
                        if is_as_app {
                            Some(Intrinsic::ApiCall(IntrinsicName::Other))
                        } else {
                            Some(Intrinsic::SafeCall(function_name))
                        }
                    }
                    ApiCallKind::CustomField => {
                        if is_as_app {
                            Some(Intrinsic::ApiCustomField)
                        } else {
                            Some(Intrinsic::SafeCall(function_name))
                        }
                    }
                    ApiCallKind::Fields => {
                        if is_as_app {
                            Some(Intrinsic::ApiCustomField)
                        } else {
                            Some(Intrinsic::UserFieldAccess)
                        }
                    }
                    ApiCallKind::Trivial => Some(Intrinsic::SafeCall(IntrinsicName::Other)),
                    ApiCallKind::Authorize => Some(Intrinsic::Authorize(IntrinsicName::Other)),
                }
            }

            [PropPath::Def(def), PropPath::Static(ref s), ..] if is_storage_read(s) => {
                match self.res.is_imported_from(def, "@forge/api") {
                    Some(ImportKind::Named(ref name)) if *name == *"storage" => {
                        Some(Intrinsic::StorageRead)
                    }
                    _ => None,
                }
            }
            [PropPath::Def(def), ..] if self.res.is_imported_from(def, "@forge/api").is_some() => {
                if let Some(ImportKind::Named(ref name)) =
                    self.res.is_imported_from(def, "@forge/api")
                {
                    if *name == *"authorize" {
                        return Some(Intrinsic::Authorize(IntrinsicName::Other));
                    } else if *name == *"fetch" {
                        return Some(Intrinsic::Fetch);
                    }
                }
                None
            }
            //[PropPath::Def(def), PropPath::Static(a), PropPath::Static(b)]
            // 1. Star, identifier, method
            [PropPath::Def(def), PropPath::Static(ref identifier), PropPath::Static(ref method)] => {
                // case where function requires object to be invoked first
                // example: import * as cryptoJS from 'crypto-js';
                // var aes = cryptoJS.AES.encrypt('Secret message', 'secret password');
                let (package_name, import_kind) = self.res.as_foreign_import(def)?;
                let package_found = self.secret_packages.iter().find(|&package_data| {
                    if let Some(package_method) = &package_data.method {
                        package_name == package_data.package_name
                            && import_kind == ImportKind::Star
                            && identifier == &package_data.identifier
                            && *method == *package_method
                    } else {
                        false
                    }
                });

                package_found.map(|package| Intrinsic::SecretFunction(package.clone()))
            }
            // [Def, Static]
            // [PropPath::Def(def), PropPath::Static(atom)]
            // 1. Star, identifier (NO METHOD)
            // 2. Named/Default => import kind matches idenntifier and static(atom) matches method
            [PropPath::Def(def), PropPath::Static(ref method_name)] => {
                let (package_name, import_kind) = self.res.as_foreign_import(def)?;
                // Star imports that don't have any object call to invoke function
                // import * as atlassian_jwt from "atlassian-jwt";
                // atlassian_jwt.encode(blah, blah);
                if import_kind == ImportKind::Star {
                    let package_found = self.secret_packages.iter().find(|&package_data| {
                        package_name == package_data.package_name
                            && *method_name == package_data.identifier
                            && package_data.method.is_none()
                    });
                    package_found.map(|package| Intrinsic::SecretFunction(package.clone()))
                } else {
                    // Named or default imports that
                    // import AES from "crypto-js";
                    // import {AES} from "crypto-js"
                    // Aes.encrypt(blah, blah);
                    let package_found = self.secret_packages.iter().find(|&package_data| {
                        if let Some(method) = &package_data.method {
                            package_name == package_data.package_name
                                && import_kind == *package_data.identifier
                                && *method_name == *method
                        } else {
                            package_name == package_data.package_name
                                && *method_name == *package_data.identifier
                                && import_kind == ImportKind::Default
                        }
                    });
                    package_found.map(|package| Intrinsic::SecretFunction(package.clone()))
                }
            }
            // [Def, .., Static] star
            // [Def, .., Static] named/default
            // [PropPath::Def(def)]
            // 1. Named/Default => package matches imported from and ident is the same, (NO METHOD)
            [PropPath::Def(def)] => {
                let (package_name, import_kind) = self.res.as_foreign_import(def)?;
                let package = self.secret_packages.iter().find(|&package_data| {
                    *package_name == *package_data.package_name
                        && import_kind == *package_data.identifier
                        && package_data.method.is_none()
                });
                package.cloned().map(Intrinsic::SecretFunction)
            }

            _ => None,
        }
    }

    /// Sets the current block to `block` and returns the previous block.
    #[inline]
    fn goto_block(&mut self, block: BasicBlockId) -> BasicBlockId {
        self.set_curr_terminator(Terminator::Goto(block));
        mem::replace(&mut self.block, block)
    }

    #[inline]
    fn push_curr_inst(&mut self, inst: Inst) {
        self.body.push_inst(self.block, inst);
    }

    fn lower_member(&mut self, obj: &Expr, prop: &MemberProp) -> Operand {
        if obj.as_ident().is_some_and(|ident| *ident.sym == *"process") && eq_prop_name(prop, "env")
        {
            // FIXME: Store the exact environment variable in the IR and don't create duplicate IR instructions.
            self.push_curr_inst(Inst::Expr(Rvalue::Intrinsic(
                Intrinsic::EnvRead,
                smallvec![],
            )));
        }

        let obj = self.lower_expr(obj, None);
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
                let opnd = self.lower_expr(expr, None);
                var.projections
                    .push(self.body.resolve_prop(self.block, opnd));
            }
        }
        Operand::Var(var)
    }

    fn bind_pats_helper(&mut self, n: &Pat, rhs: Variable) {
        match n {
            Pat::Ident(BindingIdent { id, .. }) => {
                let id = id.to_id();
                let def = self.res.get_or_insert_sym(id, self.module);
                let var = self.body.get_or_insert_global(def);
                self.push_curr_inst(Inst::Assign(
                    Variable::new(var),
                    Rvalue::Read(Operand::Var(rhs)),
                ));
            }
            Pat::Array(ArrayPat { elems, .. }) => {
                for (i, elem) in elems.iter().enumerate() {
                    if let Some(elem) = elem {
                        let prop = Projection::Known(i.to_string().into());
                        let mut var = rhs.clone();
                        var.projections.push(prop);
                        self.bind_pats_helper(elem, var);
                    }
                }
            }
            Pat::Rest(RestPat { arg, .. }) => self.bind_pats_helper(arg, rhs),
            Pat::Object(obj) => {
                for prop in &obj.props {
                    let mut rhs = rhs.clone();
                    match prop {
                        ObjectPatProp::KeyValue(KeyValuePatProp { key, value }) => match key {
                            PropName::Ident(Ident { sym: prop, .. })
                            | PropName::Str(Str { value: prop, .. }) => {
                                let prop = Projection::Known(prop.clone());
                                rhs.projections.push(prop);
                                self.bind_pats_helper(value, rhs);
                            }
                            PropName::Num(Number { value: num, .. }) => {
                                // FIXME: derive Eq and Hash for Projection so we can use floats
                                // (Yes, I know ^ is cringe, but it matches JS semantics)
                                let prop = Projection::Known(num.to_string().into());
                                rhs.projections.push(prop);
                                self.bind_pats_helper(value, rhs);
                            }
                            PropName::Computed(ComputedPropName { expr, .. }) => {
                                let opnd = self.lower_expr(expr, None);
                                let proj = self.body.resolve_prop(self.block, opnd);
                                rhs.projections.push(proj);
                                self.bind_pats_helper(value, rhs);
                            }
                            PropName::BigInt(bigint) => {
                                let proj = Projection::Known(bigint.value.to_string().into());
                                rhs.projections.push(proj);
                                self.bind_pats_helper(value, rhs);
                            }
                        },
                        ObjectPatProp::Assign(AssignPatProp { key, value, .. }) => {
                            let id = key.to_id();
                            rhs.projections.push(Projection::Known(id.0.clone()));
                            let def = self.res.get_or_insert_sym(id, self.module);
                            let var = self.body.get_or_insert_global(def);
                            self.push_curr_inst(Inst::Assign(
                                Variable::new(var),
                                Rvalue::Read(Operand::Var(rhs)),
                            ));
                        }
                        ObjectPatProp::Rest(rest) => self.bind_pats_helper(&rest.arg, rhs),
                    }
                }
            }
            Pat::Assign(AssignPat { left, right, .. }) => self.bind_pats_helper(left, rhs),
            Pat::Invalid(_) => {}
            Pat::Expr(_) => {}
        }
    }

    fn lower_jsx_member(&mut self, n: &JSXMemberExpr) -> Operand {
        let mut var = match &n.obj {
            JSXObject::JSXMemberExpr(obj) => self.lower_jsx_member(obj),
            JSXObject::Ident(ident) => self.lower_ident(ident),
        };
        if let Operand::Var(var) = &mut var {
            var.projections.push(Projection::Known(n.prop.sym.clone()));
        }
        var
    }

    fn resolve_class_prop(&self, ident: &Ident) -> Option<&Class> {
        if let Some(defid) = self.res.sym_to_id(ident.to_id(), self.module) {
            if let Some(potential_class) = self.body.class_instantiations.get(&defid) {
                if let Some(DefKind::Class(class_id)) = self.res.defs.defs.get(*potential_class) {
                    return self.res.defs.classes.get(*class_id);
                }
            }
        }
        None
    }

    fn get_operand_for_call(&mut self, expr: &Expr) -> Operand {
        if let Expr::Ident(ident) = expr {
            if let Some(DefKind::Class(class)) = self.res.sym_to_def(ident.to_id(), self.module) {
                let id = ident.to_id();
                if let Some((_, def_constructor)) = class
                    .pub_members
                    .iter()
                    .find(|(name, defid)| name == "constructor")
                {
                    let var = self.body.get_or_insert_global(*def_constructor);
                    return Operand::with_var(var);
                }
            }
        }
        if let Expr::Member(MemberExpr { obj, prop, .. }) = expr {
            if let Expr::Ident(ident) = &**obj {
                if let Some(class) = self.resolve_class_prop(ident) {
                    if let MemberProp::Ident(ident) = prop {
                        if let Some((_, def_constructor)) = class
                            .pub_members
                            .iter()
                            .find(|(name, defid)| name == &ident.sym)
                        {
                            let var = self.body.get_or_insert_global(*def_constructor);
                            return Operand::with_var(var);
                        }
                    }
                }
            }
        }
        self.lower_expr(expr, None)
    }

    fn lower_call(&mut self, callee: CalleeRef<'_>, args: &[ExprOrSpread]) -> Operand {
        // debug!("in da lower call");
        let props = normalize_callee_expr(callee, self.res, self.module);
        if let Some(&PropPath::Def(id)) = props.first() {
            if self.res.is_imported_from(id, "@forge/ui").map_or(
                false,
                |imp| matches!(imp, ImportKind::Named(s) if *s == *"useState" || *s == *"useEffect"),
            ) || calls_method(callee, "then")
                || calls_method(callee, "map")
                || calls_method(callee, "foreach")
                || calls_method(callee, "filter")
                || calls_method(callee, "catch")
            {
                if let [ExprOrSpread { expr, .. }] = args {
                    match &**expr {
                        Expr::Arrow(ArrowExpr { body, .. }) => match &**body {
                            BlockStmtOrExpr::BlockStmt(stmt) => {
                                self.lower_stmts(&stmt.stmts);
                                return Operand::UNDEF;
                            }
                            BlockStmtOrExpr::Expr(expr) => {
                                return self.lower_expr(expr, None);
                            }
                        },
                        Expr::Fn(FnExpr { ident: _, function }) => {
                            if let Some(body) = &function.body {
                                self.lower_stmts(&body.stmts);
                                return Operand::UNDEF;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let lowered_args = args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let defid =
                    self.res
                        .add_anonymous(format!("{i}argument"), AnonType::Unknown, self.module);
                self.lower_expr(&arg.expr, Some(defid))
            })
            .collect();

        let callee = match callee {
            CalleeRef::Super => Operand::Var(Variable::SUPER),
            CalleeRef::Import => Operand::UNDEF,
            CalleeRef::Expr(expr) => self.get_operand_for_call(expr),
        };
        let first_arg = args.first().map(|expr| &*expr.expr);
        let intrinsic = self.as_intrinsic(&props, first_arg);
        let call = match intrinsic {
            Some(int) => Rvalue::Intrinsic(int, lowered_args),
            None => Rvalue::Call(callee, lowered_args),
        };
        let res = self.body.push_tmp(self.block, call, None);
        Operand::with_var(res)
    }

    fn bind_pats(&mut self, n: &Pat, val: Rvalue) {
        match n {
            Pat::Ident(BindingIdent { id, .. }) => {
                let id = id.to_id();
                let def = self.res.get_or_insert_sym(id, self.module);
                let var = self.body.get_or_insert_global(def);
                self.push_curr_inst(Inst::Assign(Variable::new(var), val));
            }
            Pat::Array(ArrayPat { elems, .. }) => {
                let lval = self.body.push_tmp(self.block, val, None);
                self.bind_pats_helper(n, Variable::new(lval));
            }
            Pat::Rest(RestPat { arg, .. }) => self.bind_pats(arg, val),
            Pat::Object(ObjectPat { props, .. }) => {
                let lval = self.body.push_tmp(self.block, val, None);
                self.bind_pats_helper(n, Variable::new(lval));
            }
            Pat::Assign(AssignPat { left, right, .. }) => {
                // TODO: handle default
                self.bind_pats(left, val);
            }
            Pat::Invalid(_) => {}
            Pat::Expr(expr) => {
                let opnd = self.lower_expr(expr, None);
                self.body.coerce_to_lval(self.block, opnd, None);
            }
        }
    }

    fn lower_tpl(&mut self, n: &Tpl) -> Template {
        let exprs = n
            .exprs
            .iter()
            .map(|expr| self.lower_expr(expr, None))
            .collect::<Vec<_>>();
        let quasis = n
            .quasis
            .iter()
            .map(|quasi| quasi.raw.clone())
            .collect::<Vec<_>>();
        Template {
            exprs,
            quasis,
            ..Default::default()
        }
    }

    fn lower_jsx_attr(&mut self, n: &JSXElement) {
        n.opening.attrs.iter().for_each(|attr| match attr {
            JSXAttrOrSpread::JSXAttr(jsx_attr) => {
                if let JSXAttrName::Ident(ident_value) = &jsx_attr.name {
                    if let Some(JSXAttrValue::JSXExprContainer(jsx_expr)) = &jsx_attr.value {
                        self.lower_jsx_handler(jsx_expr, ident_value);
                    }
                }
            }
            JSXAttrOrSpread::SpreadElement(_) => {}
        });
    }

    fn lower_jsx_handler(&mut self, n: &JSXExprContainer, ident_value: &Ident) {
        if let JSXExpr::Expr(expr) = &n.expr {
            // FIXME: Add entry point for the functions that are called as part of the handlers
            self.lower_expr(expr, None);
            match &**expr {
                // JSX handler names should start with "on[A-Z]"
                _ if !matches!(ident_value.sym.as_bytes(), [b'o', b'n', b'A'..=b'Z', ..]) => {}
                Expr::Arrow(arrow_expr) => {
                    if let BlockStmtOrExpr::Expr(expr) = &*arrow_expr.body {
                        self.lower_expr(expr, None);
                    }
                }
                Expr::Ident(ident) => {
                    let defid = self.res.sym_to_id(ident.to_id(), self.module);
                    let varid = self.body.get_or_insert_global(defid.unwrap());
                    self.body.push_tmp(
                        self.block,
                        Rvalue::Call(Operand::Var(Variable::from(varid)), SmallVec::default()),
                        None,
                    );
                }
                _ => {}
            }
        }
    }

    fn lower_jsx_child(&mut self, n: &JSXElementChild) -> Operand {
        match n {
            JSXElementChild::JSXText(JSXText { value, .. }) => {
                Operand::Lit(Literal::Str(value.clone()))
            }
            JSXElementChild::JSXExprContainer(JSXExprContainer { expr, .. }) => match expr {
                JSXExpr::JSXEmptyExpr(_) => Operand::UNDEF,
                JSXExpr::Expr(expr) => self.lower_expr(expr, None),
            },
            JSXElementChild::JSXSpreadChild(JSXSpreadChild { expr, .. }) => {
                self.lower_expr(expr, None)
            }
            JSXElementChild::JSXElement(elem) => {
                self.lower_jsx_attr(elem);
                self.lower_jsx_elem(elem)
            }
            JSXElementChild::JSXFragment(JSXFragment { children, .. }) => {
                for child in children {
                    self.lower_jsx_child(child);
                }
                Operand::UNDEF
            }
        }
    }

    fn lower_ident(&mut self, ident: &Ident) -> Operand {
        let id = ident.to_id();
        let Some(def) = self.res.sym_to_id(id.clone(), self.module) else {
            warn!("unknown symbol: {}", id.0);
            return Literal::Undef.into();
        };
        let var = self.body.get_or_insert_global(def);
        Operand::with_var(var)
    }

    fn lower_jsx_elem(&mut self, n: &JSXElement) -> Operand {
        let args = n
            .children
            .iter()
            .map(|child| self.lower_jsx_child(child))
            .collect();

        self.lower_jsx_attr(n);

        let callee = match &n.opening.name {
            JSXElementName::Ident(ident) => {
                let id = ident.to_id();
                let Some(def) = self.res.sym_to_id(id.clone(), self.module) else {
                    warn!("unknown symbol: {}", id.0);
                    return Literal::Undef.into();
                };
                let var = self.body.get_or_insert_global(def);
                Operand::with_var(var)
            }
            JSXElementName::JSXMemberExpr(mem) => self.lower_jsx_member(mem),
            JSXElementName::JSXNamespacedName(JSXNamespacedName { ns, name }) => {
                let ns = ns.to_id();
                let Some(def) = self.res.sym_to_id(ns.clone(), self.module) else {
                    warn!("unknown symbol: {}", ns.0);
                    return Literal::Undef.into();
                };
                let var = self.body.get_or_insert_global(def);
                let mut var = Variable::new(var);
                var.projections.push(Projection::Known(name.sym.clone()));
                Operand::Var(var)
            }
        };
        let call = Rvalue::Call(callee, args);
        Operand::with_var(self.body.push_tmp(self.block, call, None))
    }

    // TODO: This can probably be made into a trait
    fn lower_expr(&mut self, n: &Expr, parent: Option<DefId>) -> Operand {
        match n {
            Expr::This(_) => Operand::Var(Variable::THIS),
            Expr::Array(ArrayLit { elems, .. }) => {
                let array_lit: Vec<_> = elems
                    .iter()
                    .map(|e| {
                        e.as_ref()
                            .map_or(Operand::UNDEF, |ExprOrSpread { spread, expr }| {
                                self.lower_expr(expr, None)
                            })
                    })
                    .collect();
                Operand::UNDEF
            }
            Expr::Object(ObjectLit { span, props }) => {
                let def_id = self
                    .res
                    .add_anonymous("__UNKNOWN", AnonType::Obj, self.module);
                let class_var_id = self.body.add_var(VarKind::LocalDef(def_id));
                if let DefKind::GlobalObj(class_id) = self.res.defs.defs[def_id] {
                    props.iter().for_each(|prop_or_spread| {
                        let mut var = Variable::new(class_var_id);
                        match prop_or_spread {
                            PropOrSpread::Prop(prop) => match &**prop {
                                Prop::Shorthand(ident) => {
                                    let id = ident.to_id();
                                    let new_def =
                                        self.res.get_or_insert_sym(id.clone(), self.module);
                                    let var_id = self.body.get_or_insert_global(new_def);
                                    var.projections.push(Projection::Known(ident.sym.clone()));
                                    self.res
                                        .def_mut(def_id)
                                        .expect_class()
                                        .pub_members
                                        .push((id.0, new_def));
                                    self.body.push_inst(
                                        self.block,
                                        Inst::Assign(var, Rvalue::Read(Operand::with_var(var_id))),
                                    );
                                }
                                Prop::KeyValue(KeyValueProp { key, value }) => {
                                    let lowered_value = self.lower_expr(value, None);
                                    let lowered_var = self.body.coerce_to_lval(
                                        self.block,
                                        lowered_value.clone(),
                                        None,
                                    );

                                    let rval = Rvalue::Read(lowered_value);
                                    if let Base::Var(var_id) = lowered_var.base {
                                        match key {
                                            PropName::Str(str) => {
                                                let def_id_prop = self.res.add_anonymous(
                                                    str.value.clone(),
                                                    AnonType::Unknown,
                                                    self.module,
                                                );
                                                let cls = self.res.def_mut(def_id).expect_class();
                                                cls.pub_members
                                                    .push((key.as_symbol().unwrap(), def_id_prop));
                                                var.projections
                                                    .push(Projection::Known(str.value.clone()));
                                            }
                                            PropName::Ident(ident) => {
                                                let def_id_prop = self
                                                    .res
                                                    .get_or_insert_sym(ident.to_id(), self.module);
                                                let cls = self.res.def_mut(def_id).expect_class();
                                                cls.pub_members
                                                    .push((key.as_symbol().unwrap(), def_id_prop));
                                                var.projections
                                                    .push(Projection::Known(ident.sym.clone()));
                                            }
                                            _ => {}
                                        }
                                        self.body.push_inst(self.block, Inst::Assign(var, rval));
                                    }
                                }
                                _ => {}
                            },
                            PropOrSpread::Spread(spread) => {}
                        }
                    })
                }
                Operand::Var(Variable::new(class_var_id))
            }
            Expr::Fn(_) => Operand::UNDEF,
            Expr::Unary(UnaryExpr { op, arg, .. }) => {
                let arg = self.lower_expr(arg, None);
                let tmp = self
                    .body
                    .push_tmp(self.block, Rvalue::Unary(op.into(), arg), None);
                Operand::with_var(tmp)
            }
            Expr::Update(UpdateExpr {
                op, prefix, arg, ..
            }) => {
                // FIXME: Handle op
                self.lower_expr(arg, None)
            }
            Expr::Bin(BinExpr {
                op, left, right, ..
            }) => {
                let left = self.lower_expr(left, None);
                let right = self.lower_expr(right, None);

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
                        let opnd = self.lower_expr(expr, None);
                        let prop = self.body.resolve_prop(self.block, opnd);
                        super_var.projections.push(prop);
                    }
                }
                Operand::Var(super_var)
            }
            Expr::Assign(AssignExpr {
                op, left, right, ..
            }) => {
                let rhs = self.lower_expr(right, None);
                match left {
                    AssignTarget::Pat(pat) => {
                        self.bind_pats(&pat.clone().into(), Rvalue::Read(rhs.clone()));
                    }
                    AssignTarget::Simple(expr) => match expr {
                        SimpleAssignTarget::Ident(BindingIdent { id, .. }) => {
                            let lval = self.lower_ident(id);
                            let lval = self.body.coerce_to_lval(self.block, lval, None);
                            self.push_curr_inst(Inst::Assign(lval, Rvalue::Read(rhs.clone())));
                        }
                        SimpleAssignTarget::Member(MemberExpr { obj, prop, .. }) => {
                            let lval = self.lower_member(obj, prop);
                            let lval = self.body.coerce_to_lval(self.block, lval, None);
                            self.push_curr_inst(Inst::Assign(lval, Rvalue::Read(rhs.clone())));
                        }
                        SimpleAssignTarget::SuperProp(_) => {
                            // FIXME: handle super assignees
                        }
                        SimpleAssignTarget::Paren(ParenExpr { expr, .. }) => {
                            let lval = self.lower_expr(expr, None);
                            let lval = self.body.coerce_to_lval(self.block, lval, None);
                            self.push_curr_inst(Inst::Assign(lval, Rvalue::Read(rhs.clone())));
                        }
                        SimpleAssignTarget::OptChain(OptChainExpr { optional, base, .. }) => {
                            match &**base {
                                OptChainBase::Call(OptCall { callee, args, .. }) => {
                                    let callee = self.lower_call(callee.as_ref().into(), args);
                                    let lval = self.body.coerce_to_lval(self.block, callee, None);
                                    self.push_curr_inst(Inst::Assign(
                                        lval,
                                        Rvalue::Read(rhs.clone()),
                                    ));
                                }
                                OptChainBase::Member(MemberExpr { obj, prop, .. }) => {
                                    let lval = self.lower_member(obj, prop);
                                    let lval = self.body.coerce_to_lval(self.block, lval, None);
                                    self.push_curr_inst(Inst::Assign(
                                        lval,
                                        Rvalue::Read(rhs.clone()),
                                    ));
                                }
                            }
                        }
                        SimpleAssignTarget::TsAs(_)
                        | SimpleAssignTarget::TsSatisfies(_)
                        | SimpleAssignTarget::TsNonNull(_)
                        | SimpleAssignTarget::TsTypeAssertion(_)
                        | SimpleAssignTarget::TsInstantiation(_)
                        | SimpleAssignTarget::Invalid(_) => {}
                    },
                };
                rhs
            }
            Expr::Member(MemberExpr { obj, prop, .. }) => self.lower_member(obj, prop),
            Expr::Cond(CondExpr {
                test, cons, alt, ..
            }) => {
                let cond = self.lower_expr(test, None);
                let curr = self.block;
                let rest = self.body.new_block();
                let cons_block = self.body.new_block();
                let alt_block = self.body.new_block();
                self.set_curr_terminator(Terminator::If {
                    cond,
                    cons: cons_block,
                    alt: alt_block,
                });
                self.block = cons_block;
                let cons = self.lower_expr(cons, None);
                let cons_phi = self.body.push_tmp(self.block, Rvalue::Read(cons), None);
                self.set_curr_terminator(Terminator::Goto(rest));
                self.block = alt_block;
                let alt = self.lower_expr(alt, None);
                let alt_phi = self.body.push_tmp(self.block, Rvalue::Read(alt), None);
                self.set_curr_terminator(Terminator::Goto(rest));
                self.block = rest;
                let phi = self.body.push_tmp(
                    self.block,
                    Rvalue::Phi(vec![(cons_phi, cons_block), (alt_phi, alt_block)]),
                    None,
                );
                Operand::with_var(phi)
            }
            Expr::Call(CallExpr { callee, args, .. }) => self.lower_call(callee.into(), args),
            Expr::New(NewExpr { callee, args, .. }) => {
                if let Expr::Ident(ident) = &**callee {
                    // remove the clone
                    return self.lower_call(
                        CalleeRef::Expr(callee),
                        args.clone().unwrap_or_default().as_slice(),
                    );
                }

                Operand::UNDEF
            }
            Expr::Seq(SeqExpr { exprs, .. }) => {
                if let Some((last, rest)) = exprs.split_last() {
                    for expr in rest {
                        let opnd = self.lower_expr(expr, None);
                        self.body.push_expr(self.block, Rvalue::Read(opnd));
                    }
                    self.lower_expr(last, None)
                } else {
                    Literal::Undef.into()
                }
            }
            Expr::Ident(id) => {
                let id = id.to_id();
                let Some(def) = self.res.sym_to_id(id.clone(), self.module) else {
                    warn!("3 unknown symbol: {}", id.0);
                    return Literal::Undef.into();
                };
                let var = self.body.get_or_insert_global(def);
                Operand::with_var(var)
            }
            Expr::Lit(lit) => lit.clone().into(),
            Expr::Tpl(tpl) => {
                let tpl = self.lower_tpl(tpl);
                Operand::with_var(
                    self.body
                        .push_tmp(self.block, Rvalue::Template(tpl), parent),
                )
            }
            Expr::TaggedTpl(TaggedTpl { tag, tpl, .. }) => {
                let tag = Some(self.lower_expr(tag, parent));
                let tpl = Template {
                    tag,
                    ..self.lower_tpl(tpl)
                };
                Operand::with_var(
                    self.body
                        .push_tmp(self.block, Rvalue::Template(tpl), parent),
                )
            }
            Expr::Arrow(_) => Operand::UNDEF,
            Expr::Class(_) => Operand::UNDEF,
            Expr::Yield(YieldExpr { arg, .. }) => arg
                .as_deref()
                .map_or(Operand::UNDEF, |expr| self.lower_expr(expr, None)),
            Expr::MetaProp(_) => Operand::UNDEF,
            Expr::Await(AwaitExpr { arg, .. }) => self.lower_expr(arg, None),
            Expr::Paren(ParenExpr { expr, .. }) => self.lower_expr(expr, None),
            Expr::JSXMember(mem) => self.lower_jsx_member(mem),
            Expr::JSXNamespacedName(JSXNamespacedName { ns, name, .. }) => {
                let mut ident = self.lower_ident(ns);
                if let Operand::Var(var) = &mut ident {
                    var.projections.push(Projection::Known(name.sym.clone()));
                }
                ident
            }
            Expr::JSXEmpty(_) => Operand::UNDEF,
            Expr::JSXElement(elem) => self.lower_jsx_elem(elem),
            Expr::JSXFragment(JSXFragment {
                opening,
                children,
                closing,
                ..
            }) => {
                for child in children {
                    self.lower_jsx_child(child);
                }
                Operand::UNDEF
            }
            Expr::TsTypeAssertion(TsTypeAssertion { expr, .. })
            | Expr::TsConstAssertion(TsConstAssertion { expr, .. })
            | Expr::TsNonNull(TsNonNullExpr { expr, .. })
            | Expr::TsAs(TsAsExpr { expr, .. })
            | Expr::TsInstantiation(TsInstantiation { expr, .. })
            | Expr::TsSatisfies(TsSatisfiesExpr { expr, .. }) => self.lower_expr(expr, None),
            Expr::PrivateName(PrivateName { id, .. }) => todo!(),
            Expr::OptChain(OptChainExpr { base, .. }) => match &**base {
                OptChainBase::Call(OptCall { callee, args, .. }) => {
                    self.lower_call(callee.as_ref().into(), args)
                }
                OptChainBase::Member(MemberExpr { obj, prop, .. }) => {
                    // TODO: create separate basic blocks
                    self.lower_member(obj, prop)
                }
            },
            Expr::Invalid(_) => Operand::UNDEF,
        }
    }

    fn lower_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.lower_stmt(stmt);
        }
    }

    fn lower_stmt(&mut self, n: &Stmt) {
        match n {
            Stmt::Block(BlockStmt { stmts, .. }) => self.lower_stmts(stmts),
            Stmt::Empty(_) => {}
            Stmt::Debugger(_) => {}
            Stmt::With(WithStmt { obj, body, .. }) => {
                let opnd = self.lower_expr(obj, None);
                self.body.push_expr(self.block, Rvalue::Read(opnd));
                self.lower_stmt(body);
            }
            Stmt::Return(ReturnStmt { arg, .. }) => {
                if let Some(arg) = arg {
                    let opnd = self.lower_expr(arg, None);
                    self.body
                        .push_inst(self.block, Inst::Assign(RETURN_VAR, Rvalue::Read(opnd)));
                }
                self.body.set_terminator(self.block, Terminator::Ret);
            }
            Stmt::Labeled(LabeledStmt { label, body, .. }) => {
                self.lower_stmt(body);
            }
            Stmt::Break(BreakStmt { label, .. }) => {}
            Stmt::Continue(ContinueStmt { label, .. }) => {}
            Stmt::If(IfStmt {
                test, cons, alt, ..
            }) => {
                let [cons_block, cont] = self.body.new_blocks();
                let alt_block = if let Some(alt) = alt {
                    let alt_block = self.body.new_block();
                    let old_block = mem::replace(&mut self.block, alt_block);
                    self.lower_stmt(alt);
                    self.set_curr_terminator(Terminator::Goto(cont));
                    self.block = old_block;
                    alt_block
                } else {
                    cont
                };
                let cond = self.lower_expr(test, None);
                self.set_curr_terminator(Terminator::If {
                    cond,
                    cons: cons_block,
                    alt: alt_block,
                });
                self.block = cons_block;
                self.lower_stmt(cons);
                self.goto_block(cont);
            }
            Stmt::Switch(SwitchStmt {
                discriminant,
                cases,
                ..
            }) => {
                let opnd = self.lower_expr(discriminant, None);
                // TODO: lower switch
            }
            Stmt::Throw(ThrowStmt { arg, .. }) => {
                let opnd = self.lower_expr(arg, None);
                self.body.push_expr(self.block, Rvalue::Read(opnd));
                self.body.set_terminator(self.block, Terminator::Throw);
            }
            Stmt::Try(stmt) => {
                let TryStmt {
                    block: BlockStmt { stmts, .. },
                    handler,
                    finalizer,
                    ..
                } = &**stmt;
                self.lower_stmts(stmts);
                if let Some(BlockStmt { stmts, .. }) = finalizer {
                    self.lower_stmts(stmts);
                }
            }
            Stmt::While(WhileStmt { test, body, .. }) => {
                let [check, cont, body_id] = self.body.new_blocks();
                self.set_curr_terminator(Terminator::Goto(check));
                self.block = check;
                let cond = self.lower_expr(test, None);
                self.set_curr_terminator(Terminator::If {
                    cond,
                    cons: body_id,
                    alt: cont,
                });
                let check = mem::replace(&mut self.block, body_id);
                self.lower_stmt(body);
                self.set_curr_terminator(Terminator::Goto(check));
                self.block = cont;
            }
            Stmt::DoWhile(DoWhileStmt { test, body, .. }) => {
                let [check, cont, body_id] = self.body.new_blocks();
                self.set_curr_terminator(Terminator::Goto(body_id));
                self.block = body_id;
                self.lower_stmt(body);
                self.set_curr_terminator(Terminator::Goto(check));
                self.block = check;
                let cond = self.lower_expr(test, None);
                self.set_curr_terminator(Terminator::If {
                    cond,
                    cons: body_id,
                    alt: cont,
                });
                self.block = cont;
            }
            Stmt::For(ForStmt {
                init,
                test,
                update,
                body,
                ..
            }) => {
                match init {
                    Some(VarDeclOrExpr::VarDecl(decl)) => {
                        self.lower_var_decl(decl);
                    }
                    Some(VarDeclOrExpr::Expr(expr)) => {
                        self.lower_expr(expr, None);
                    }
                    None => {}
                }
                let [check, cont, body_id] = self.body.new_blocks();
                self.goto_block(check);
                if let Some(test) = test {
                    let cond = self.lower_expr(test, None);
                    self.set_curr_terminator(Terminator::If {
                        cond,
                        cons: body_id,
                        alt: cont,
                    });
                } else {
                    self.set_curr_terminator(Terminator::Goto(body_id));
                }
                self.block = body_id;
                self.lower_stmt(body);
                if let Some(update) = update {
                    self.lower_expr(update, None);
                }
                self.set_curr_terminator(Terminator::Goto(check));
                self.goto_block(cont);
            }
            Stmt::ForIn(ForInStmt {
                left, right, body, ..
            }) => self.lower_loop(left, right, body),
            Stmt::ForOf(ForOfStmt {
                left, right, body, ..
            }) => self.lower_loop(left, right, body),
            Stmt::Decl(decl) => match decl {
                Decl::Class(_) => {}
                Decl::Fn(_) => {}
                Decl::Var(var) => {
                    self.lower_var_decl(var);
                }
                Decl::Using(_) => {}
                Decl::TsInterface(_)
                | Decl::TsTypeAlias(_)
                | Decl::TsEnum(_)
                | Decl::TsModule(_) => {}
            },
            Stmt::Expr(ExprStmt { expr, .. }) => {
                let opnd = self.lower_expr(expr, None);
                self.body.push_expr(self.block, Rvalue::Read(opnd));
            }
        }
    }

    fn lower_loop(&mut self, left: &ForHead, right: &Expr, body: &Stmt) {
        // FIXME: don't assume loops are infinite
        let opnd = self.lower_expr(right, None);
        match left {
            ForHead::VarDecl(var) => self.lower_var_decl(var),
            ForHead::Pat(pat) => self.bind_pats(pat, Rvalue::Read(opnd)),
            ForHead::UsingDecl(_) => {
                //FIXME: investigate this case
            }
        }
        self.lower_stmt(body);
    }

    fn lower_var_decl(&mut self, var: &VarDecl) {
        for decl in &var.decls {
            if let Pat::Ident(id) = &decl.name {
                let id = id.to_id();
                let def = self.res.get_or_insert_sym(id, self.module);
                let opnd = decl
                    .init
                    .as_deref()
                    .map_or(Operand::UNDEF, |init| self.lower_expr(init, Some(def)));
                self.bind_pats(&decl.name, Rvalue::Read(opnd));
            } else {
                let opnd = decl
                    .init
                    .as_deref()
                    .map_or(Operand::UNDEF, |init| self.lower_expr(init, None));
                self.bind_pats(&decl.name, Rvalue::Read(opnd));
            }
        }
    }
}

struct ArgDefiner<'cx> {
    res: &'cx mut Environment,
    module: ModId,
    func: DefId,
    body: Body,
    current_arg: Variable,
}

impl Visit for ArgDefiner<'_> {
    noop_visit_type!();
    fn visit_ident(&mut self, n: &Ident) {
        let id = n.to_id();
        let defid = self
            .res
            .get_or_overwrite_sym(id.clone(), self.module, DefRes::Arg);
        self.res.add_parent(defid, self.func);
        let var = self.body.get_or_insert_global(defid);
        self.body.push_assign(
            STARTING_BLOCK,
            var.into(),
            Rvalue::Read(Operand::Var(self.current_arg.clone())),
        );
    }

    fn visit_object_pat_prop(&mut self, n: &ObjectPatProp) {
        match n {
            ObjectPatProp::KeyValue(KeyValuePatProp { key, value }) => {
                match key {
                    PropName::Ident(ident) => {
                        self.current_arg
                            .projections
                            .push(Projection::Known(ident.sym.clone()));
                    }
                    PropName::Str(str) => {
                        self.current_arg
                            .projections
                            .push(Projection::Known(str.value.clone()));
                    }
                    PropName::Num(num) => {
                        self.current_arg
                            .projections
                            .push(Projection::Known(num.value.to_string().into()));
                    }
                    PropName::BigInt(bigint) => {
                        self.current_arg
                            .projections
                            .push(Projection::Known(bigint.value.to_string().into()));
                    }
                    PropName::Computed(ComputedPropName { expr, .. }) => {
                        // TODO: handle this case
                        return;
                    }
                }
                value.visit_with(self);
            }
            ObjectPatProp::Assign(AssignPatProp { key, .. }) => {
                self.current_arg
                    .projections
                    .push(Projection::Known(key.sym.clone()));
                key.visit_with(self);
            }
            ObjectPatProp::Rest(_) => return,
        }
        self.current_arg.projections.pop();
    }

    fn visit_pat(&mut self, n: &Pat) {
        match n {
            Pat::Ident(_) | Pat::Array(_) => n.visit_children_with(self),
            Pat::Object(ObjectPat { props, .. }) => props.visit_children_with(self),
            Pat::Assign(AssignPat { left, .. }) => left.visit_with(self),
            // This is syntactically invalid in arguments
            Pat::Expr(id) => {}
            Pat::Invalid(_) => {}
            Pat::Rest(_) => {}
        }
    }

    fn visit_pats(&mut self, n: &[Pat]) {
        for (pos, pat) in n.iter().enumerate() {
            let (defid, id) = if let Some(id) = pat.as_ident().map(BindingIdent::to_id) {
                let defid = self
                    .res
                    .get_or_overwrite_sym(id.clone(), self.module, DefRes::Arg);
                self.res.add_parent(defid, self.func);
                self.res.add_parent(defid, self.func);
                continue;
            } else {
                //FIXME: clean up unnecessary allocations
                let id = format!("{pos}argument");
                let defid = self.res.add_anonymous(id, AnonType::Unknown, self.module);
                let id = Atom::from(self.res.def_name(defid)).to_id();
                (defid, id)
            };
            let var_id = self.body.add_arg(defid, id);
            // FIXME: use clone_from once we specialize
            self.current_arg = Variable::new(var_id);
            self.visit_pat(pat);
        }
    }

    fn visit_params(&mut self, n: &[Param]) {
        let pats = n.iter().map(|param| param.pat.clone()).collect::<Vec<_>>();
        self.visit_pats(&pats);
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
        if let Some(Expr::New(new_expr)) = n.init.as_deref() {
            if let Pat::Ident(ident) = &n.name {
                if let Some(defid_variable) = self.res.sym_to_id(ident.to_id(), self.module) {
                    if let Expr::Ident(ident) = &*new_expr.callee {
                        if let Some(DefKind::Class(class)) =
                            self.res.sym_to_def(ident.to_id(), self.module)
                        {
                            if let Some(defid_class) =
                                self.res.sym_to_id(ident.to_id(), self.module)
                            {
                                self.body
                                    .class_instantiations
                                    .insert(defid_variable, defid_class);
                            }
                        }
                    }
                }
            }
        }
    }

    fn visit_decl(&mut self, n: &Decl) {
        match n {
            Decl::Class(_) => {}
            Decl::Fn(FnDecl { ident, .. }) => {
                ident.visit_with(self);
            }
            Decl::Var(vars) => vars.visit_children_with(self),
            Decl::Using(_)
            | Decl::TsInterface(_)
            | Decl::TsTypeAlias(_)
            | Decl::TsEnum(_)
            | Decl::TsModule(_) => {}
        }
    }

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
    fn visit_fn_decl(&mut self, _: &FnDecl) {}
}

impl Visit for FunctionCollector<'_> {
    fn visit_export_default_decl(&mut self, n: &ExportDefaultDecl) {
        if let Some(defid) = self.res.default_export(self.module) {
            // we don't need to check that it is either a class or a function because
            // it will get caught by the respective methods.
            self.curr_class = Some(defid);
            self.curr_function = Some(defid);
        }
        n.visit_children_with(self);

        self.curr_class = None;
        self.curr_function = None;
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        if let Some(ident) = ident_from_assign_expr(n) {
            if ident.sym == "module" {
                if let Some(mem_expr) = mem_expr_from_assign(n) {
                    if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                        if ident_property.sym == "exports" {
                            match &*n.right {
                                Expr::Fn(FnExpr { ident, function }) => self.handle_function(
                                    function,
                                    self.res.default_export(self.module),
                                ),
                                Expr::Class(ClassExpr { ident, class }) => {
                                    self.curr_class = self.res.default_export(self.module)
                                }
                                // do not worry about idents here ...
                                _ => {}
                            }
                        }
                    }
                }
            } else if ident.sym == "exports" {
                if let Some(mem_expr) = mem_expr_from_assign(n) {
                    if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                        match &*n.right {
                            Expr::Fn(n) => {
                                if let Some(defid) =
                                    self.res.get_sym(ident_property.to_id(), self.module)
                                {
                                    self.handle_function(&n.function, Some(defid));
                                }
                            }
                            Expr::Class(class) => {
                                if let Some(defid) =
                                    self.res.get_sym(ident_property.to_id(), self.module)
                                {
                                    self.curr_class = Some(defid);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, n: &ClassDecl) {
        if let Some(defid) = self
            .res
            .resolver
            .exported_names
            .get(&(n.ident.clone().sym, self.module))
            .cloned()
        {
            self.curr_class = Some(defid);
        } else if let Some(DefKind::Class(class)) =
            self.res.sym_to_def(n.ident.to_id(), self.module)
        {
            self.curr_class = Some(class.def); // sets the current class so that mehtods are assigned to the proper class
        }
        n.visit_children_with(self);
    }

    fn visit_constructor(&mut self, n: &Constructor) {
        if let Some(class_def) = self.curr_class {
            if let DefKind::Class(class) = self.res.clone().def_ref(class_def) {
                if let Some((_, owner)) = &class
                    .pub_members
                    .iter()
                    .find(|(name, defid)| name == "constructor")
                {
                    let mut argdef = ArgDefiner {
                        res: self.res,
                        module: self.module,
                        func: *owner,
                        body: Body::with_owner(*owner),
                        current_arg: Default::default(),
                    };
                    n.params.visit_with(&mut argdef);
                    let body = argdef.body;
                    let mut localdef = LocalDefiner {
                        res: self.res,
                        module: self.module,
                        func: *owner,
                        body,
                    };
                    n.body.visit_children_with(&mut localdef);
                    let body = localdef.body;
                    let mut analyzer = FunctionAnalyzer {
                        res: self.res,
                        module: self.module,
                        current_def: *owner,
                        assigning_to: None,
                        secret_packages: self.secret_packages,
                        body,
                        block: BasicBlockId::default(),
                        operand_stack: vec![],
                        in_lhs: false,
                    };
                    if let Some(BlockStmt { stmts, .. }) = &n.body {
                        analyzer.lower_stmts(stmts);
                        let body = analyzer.body;
                        *self.res.def_mut(*owner).expect_body() = body;
                    }
                }
            }
        }
    }

    fn visit_class_method(&mut self, n: &ClassMethod) {
        if let Some(class_def) = self.curr_class {
            if let DefKind::Class(class) = self.res.clone().def_ref(class_def) {
                if let Some((_, owner)) = &class.pub_members.iter().find(|(name, defid)| {
                    if let PropName::Ident(ident) = &n.key {
                        return name == &ident.sym;
                    }
                    false
                }) {
                    let mut argdef = ArgDefiner {
                        res: self.res,
                        module: self.module,
                        func: *owner,
                        body: Body::with_owner(*owner),
                        current_arg: Default::default(),
                    };
                    n.function.params.visit_with(&mut argdef);
                    let body = argdef.body;
                    let mut localdef = LocalDefiner {
                        res: self.res,
                        module: self.module,
                        func: *owner,
                        body,
                    };
                    n.function.body.visit_children_with(&mut localdef);
                    let body = localdef.body;
                    let mut analyzer = FunctionAnalyzer {
                        res: self.res,
                        module: self.module,
                        current_def: *owner,
                        secret_packages: self.secret_packages,
                        assigning_to: None,
                        body,
                        block: BasicBlockId::default(),
                        operand_stack: vec![],
                        in_lhs: false,
                    };
                    if let Some(BlockStmt { stmts, .. }) = &n.function.body {
                        analyzer.lower_stmts(stmts);
                        let body = analyzer.body;
                        *self.res.def_mut(*owner).expect_body() = body;
                    }
                }
            }
        }
    }

    fn visit_arrow_expr(
        &mut self,
        ArrowExpr {
            body: func_body,
            params,
            ..
        }: &ArrowExpr,
    ) {
        let owner = self.parent.unwrap_or_else(|| {
            self.res
                .add_anonymous("__UNKNOWN", AnonType::Closure, self.module)
        });
        let old_parent = self.parent.replace(owner);
        func_body.visit_with(self);
        let mut argdef = ArgDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body: Body::with_owner(owner),
            current_arg: Default::default(),
        };
        params.visit_with(&mut argdef);
        let body = argdef.body;
        let mut localdef = LocalDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body,
        };
        func_body.visit_children_with(&mut localdef);
        let body = localdef.body;
        let mut analyzer = FunctionAnalyzer {
            res: self.res,
            module: self.module,
            current_def: owner,
            assigning_to: None,
            secret_packages: self.secret_packages,
            body,
            block: BasicBlockId::default(),
            operand_stack: vec![],
            in_lhs: false,
        };
        match &**func_body {
            BlockStmtOrExpr::BlockStmt(BlockStmt { stmts, .. }) => {
                analyzer.lower_stmts(stmts);
            }
            BlockStmtOrExpr::Expr(e) => {
                let opnd = analyzer.lower_expr(e, None);
                analyzer
                    .body
                    .push_inst(analyzer.block, Inst::Assign(RETURN_VAR, Rvalue::Read(opnd)));
            }
        }
        *self.res.def_mut(owner).expect_body() = analyzer.body;
        self.parent = old_parent;
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        n.visit_children_with(self);
        let Some(BindingIdent { id, .. }) = n.name.as_ident() else {
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
            Some(Expr::Arrow(arrow)) => {
                let owner = self
                    .res
                    .get_or_overwrite_sym(id, self.module, DefKind::Function(()));
                let old_parent = self.parent.replace(owner);
                self.visit_arrow_expr(arrow);
                self.parent = old_parent;
            }
            Some(Expr::Call(CallExpr {
                callee: Callee::Expr(expr),
                args,
                ..
            })) => {
                if let Expr::Ident(ident) = &**expr {
                    let callee_ident = ident.to_id();
                    if callee_ident.0 == "require"
                        && self.res.sym_to_id(callee_ident, self.module).is_none()
                        && args.len() == 1
                    {
                        match args.first() {
                            Some(ExprOrSpread { spread, expr: lit }) => {
                                // TODO: handle local module imports
                                if let Expr::Lit(Lit::Str(Str { value, .. })) = &**lit {
                                    let package_to_check = self
                                        .secret_packages
                                        .iter()
                                        .find(|package| package.package_name == **value);

                                    if let Some(package) = package_to_check {
                                        match self.file_resolver.resolve_import(
                                            self.module.into(),
                                            &package.package_name,
                                        ) {
                                            Ok(id) => {
                                                debug!("Imported package already tracked");
                                            }
                                            Err(_) => {
                                                let foreign_id =
                                                    self.res.defs.foreign.push_and_get_key(
                                                        ForeignItem {
                                                            kind: ImportKind::Star,
                                                            module_name: value.clone(),
                                                        },
                                                    );
                                                let lhs = self.res.get_or_overwrite_sym(
                                                    id,
                                                    self.module,
                                                    DefKind::Foreign(foreign_id),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            None => debug!("No argument passed in"),
                        }
                    } else {
                        let ident_to_id = ident.to_id();
                        let Some(def) = self.res.sym_to_id(ident_to_id, self.module) else {
                            debug!("No id found for symbol");
                            return;
                        };
                        if matches!(self.res.is_imported_from(def, "@forge/ui"), Some(ImportKind::Named(imp)) if *imp == *"render")
                        {
                            let owner = self.res.get_or_overwrite_sym(
                                id,
                                self.module,
                                DefKind::Function(()),
                            );
                            let Some(ExprOrSpread { expr, .. }) = &args.first() else {
                                return;
                            };
                            let old_parent = self.parent.replace(owner);
                            let mut analyzer = FunctionAnalyzer {
                                res: self.res,
                                module: self.module,
                                current_def: owner,
                                assigning_to: None,
                                secret_packages: self.secret_packages,
                                body: Body::with_owner(owner),
                                block: BasicBlockId::default(),
                                operand_stack: vec![],
                                in_lhs: false,
                            };
                            let opnd = analyzer.lower_expr(expr, None);
                            analyzer.body.push_inst(
                                analyzer.block,
                                Inst::Assign(RETURN_VAR, Rvalue::Read(opnd)),
                            );
                            *self.res.def_mut(owner).expect_body() = analyzer.body;
                            self.parent = old_parent;
                        }
                    }
                }
            }
            Some(Expr::Object(object_lit)) => {
                object_lit.props.iter().for_each(|prop| {
                    if let PropOrSpread::Prop(prop) = prop {
                        if let Prop::Method(MethodProp { key, function }) = &**prop {
                            if let Some(key_ident) = key.as_ident() {
                                let former_parent = self.parent;
                                self.parent = self.res.get_prop_from_ident(
                                    self.module,
                                    id.to_id(),
                                    key_ident,
                                );
                                self.handle_function(function, None);
                                self.parent = former_parent;
                            }
                        }
                    }
                });
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
                    //self.res.overwrite_def(def, DefKind::Function(()));
                    info!("analyzing resolver def: {def:?}");
                    let old_parent = self.parent.replace(def);
                    match expr {
                        Expr::Fn(f) => {
                            debug!("visitng this one for require!");
                            f.visit_with(self);
                        }
                        Expr::Arrow(arrow) => self.visit_arrow_expr(arrow),
                        _ => {}
                    }
                    self.parent = old_parent;
                }
                None => {
                    warn!("resolver def not found");
                }
            }
        }
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        let id = n.ident.to_id();
        if let Some(defid) = self
            .res
            .resolver
            .exported_names
            .get(&(n.ident.clone().sym, self.module))
            .cloned()
        {
            self.res.resolver.defs[defid] = DefRes::Function(());
            self.res.overwrite_def(defid, DefRes::Function(()));
            self.curr_function = Some(defid);
            self.handle_function(&n.function, Some(defid));
        } else {
            let def = self
                .res
                .get_or_overwrite_sym(id, self.module, DefKind::Function(()));

            let former_parent = self.parent;
            self.parent = Some(def);
            n.function.visit_with(self);
            self.parent = former_parent;
        }
    }

    fn visit_function(&mut self, n: &Function) {
        n.visit_children_with(self);
        self.handle_function(n, None);
    }
}

impl FunctionCollector<'_> {
    fn handle_function(&mut self, n: &Function, owner: Option<DefId>) {
        let owner = self.parent.unwrap_or_else(|| {
            if let Some(def_id) = owner {
                def_id
            } else if let Some(def_id) = self.curr_function {
                def_id
            } else {
                self.res
                    .add_anonymous("__UNKNOWN", AnonType::Closure, self.module)
            }
        });
        let mut argdef = ArgDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body: Body::with_owner(owner),
            current_arg: Default::default(),
        };
        n.params.visit_with(&mut argdef);
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
            secret_packages: self.secret_packages,
            block: BasicBlockId::default(),
            operand_stack: vec![],
            in_lhs: false,
        };
        if let Some(BlockStmt { stmts, .. }) = &n.body {
            analyzer.lower_stmts(stmts);
            let body = analyzer.body;
            *self.res.def_mut(owner).expect_body() = body;
        }
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
        .and_then(|expr| as_resolver(expr, res, module))
    else {
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

    fn visit_export_default_decl(&mut self, n: &ExportDefaultDecl) {
        if let Some(defid) = self.res.default_export(self.curr_mod) {
            self.curr_class = Some(defid);
        }
        n.visit_children_with(self);
        self.curr_class = None;
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        if let Some(ident) = ident_from_assign_expr(n) {
            if ident.sym == "module" {
                if let Some(mem_expr) = mem_expr_from_assign(n) {
                    if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                        if ident_property.sym == "exports" {
                            if let Expr::Class(ClassExpr { ident, class }) = &*n.right {
                                if let Some(defid) = self.res.default_export(self.curr_mod) {
                                    self.curr_class = Some(defid);
                                }
                                n.visit_children_with(self);
                                self.curr_class = None;
                            }
                        }
                    }
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, n: &ClassDecl) {
        if let Some(defid) = self
            .res
            .resolver
            .exported_names
            .get(&(n.ident.clone().sym, self.curr_mod))
            .cloned()
        {
            self.res.resolver.defs[defid] = DefRes::Class(());
            self.res.overwrite_def(defid, DefRes::Class(()));
            self.curr_class = Some(defid);
        } else if let Some(DefKind::Class(class)) =
            self.res.sym_to_def(n.ident.to_id(), self.curr_mod)
        {
            // sets the current class so that mehtods are assigned to the proper class
            self.curr_class = Some(class.def);
        }
        n.visit_children_with(self);
    }

    fn visit_constructor(&mut self, n: &Constructor) {
        n.visit_children_with(self);
        if let Some(class_def) = self.curr_class {
            if let DefKind::Class(class) = self.res.def_mut(class_def) {
                if let PropName::Ident(ident) = &n.key {
                    let owner =
                        self.res
                            .add_anonymous("__CONSTRUCTOR", AnonType::Closure, self.curr_mod);
                    self.res.add_class_method(n.key.clone(), class_def, owner);
                }
            }
        }
    }

    fn visit_class_method(&mut self, n: &ClassMethod) {
        n.visit_children_with(self);
        if let Some(class_def) = self.curr_class {
            if let DefKind::Class(class) = self.res.def_mut(class_def) {
                if let PropName::Ident(ident) = &n.key {
                    let owner =
                        self.res
                            .add_anonymous("__CLASSMETHOD", AnonType::Closure, self.curr_mod);
                    self.res.add_class_method(n.key.clone(), class_def, owner);
                }
            }
        }
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        if let Some(expr) = n.callee.as_expr() {
            if let Some((objid, ResolverDef::FnDef)) = as_resolver(expr, self.res, self.curr_mod) {
                if let [ExprOrSpread { expr: name, .. }, ExprOrSpread { expr: args, .. }] = &*n.args
                {
                    if let Expr::Lit(Lit::Str(Str { value, .. })) = &**name {
                        let fname = value.clone();
                        let new_def =
                            self.res
                                .add_anonymous(fname.clone(), AnonType::Closure, self.curr_mod);
                        let class = self.res.def_mut(objid).expect_class();
                        class.pub_members.push((fname, new_def));
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
                Expr::Lit(lit) => {}
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
                                    let new_def = self.get_or_insert_sym(id);
                                    self.res
                                        .def_mut(def_id)
                                        .expect_class()
                                        .pub_members
                                        .push((sym, new_def));
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
                                    if let Some(sym) = key.as_symbol() {
                                        let def_id_function = self.res.add_anonymous(
                                            sym.clone(),
                                            AnonType::Closure,
                                            self.curr_mod,
                                        );
                                        self.res
                                            .def_mut(def_id)
                                            .expect_class()
                                            .pub_members
                                            .push((sym, def_id_function));
                                    }
                                    self.visit_function(function);
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

    fn add_default(&mut self, def: DefRes, id: Option<Id>) -> DefId {
        let defid = match id {
            Some(id) => self.res_table.add_sym(def, id, self.curr_mod),
            None => {
                self.res_table.names.push("default".into());
                self.res_table.owning_module.push(self.curr_mod);
                self.res_table.defs.push_and_get_key(def)
            }
        };
        self.default = Some(defid);
        defid
    }

    fn add_default_with_id(&mut self, def: DefRes, defid: DefId) {
        self.res_table.names.push("default".into());
        self.res_table.owning_module.push(self.curr_mod);
        self.default = Some(defid);
    }
}

// Import collector for run_resolver
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

impl Visit for GlobalCollector<'_> {
    fn visit_function(&mut self, _: &Function) {}

    fn visit_class(&mut self, _: &swc_core::ecma::ast::Class) {}

    fn visit_module(&mut self, n: &Module) {
        // we encouter 2 statements, so the defid gets reassigned every time

        let owner = self.global_id;
        let mut localdef = LocalDefiner {
            res: self.res,
            module: self.module,
            func: owner,
            body: Body::with_owner(owner),
        };
        n.visit_children_with(&mut localdef);
        let body = localdef.body;
        let mut analyzer = FunctionAnalyzer {
            res: self.res,
            module: self.module,
            current_def: owner,
            assigning_to: None,
            secret_packages: self.secret_packages,
            body,
            block: BasicBlockId::default(),
            operand_stack: vec![],
            in_lhs: false,
        };

        let mut all_module_items = Vec::new();

        for item in &n.body {
            if let ModuleItem::Stmt(stmt) = item {
                all_module_items.push(stmt.clone());
            }
        }
        analyzer.lower_stmts(all_module_items.as_slice());
        let body = analyzer.body;

        *self.res.def_mut(owner).expect_body() = body;
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
                //decls.iter().for_each(|var| self.visit_var_declarator(var));
            }
            Decl::Using(_)
            | Decl::TsInterface(_)
            | Decl::TsTypeAlias(_)
            | Decl::TsEnum(_)
            | Decl::TsModule(_) => {}
        };
        n.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        if let Some(ident) = ident_from_assign_expr(n) {
            if ident.sym == "module" {
                if let Some(mem_expr) = mem_expr_from_assign(n) {
                    if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                        if ident_property.sym == "exports" {
                            match &*n.right {
                                Expr::Fn(FnExpr { ident, function }) => {
                                    self.add_default(
                                        DefRes::Function(()),
                                        ident.as_ref().map(Ident::to_id),
                                    );
                                }
                                Expr::Class(ClassExpr { ident, class }) => {
                                    self.add_default(
                                        DefRes::Class(()),
                                        ident.as_ref().map(Ident::to_id),
                                    );
                                }
                                Expr::Ident(ident) => {
                                    let default_id = self.add_default(DefRes::Undefined, None);
                                    // adding the default export, so we can resolve it during the lowering
                                    self.res_table
                                        .exported_names
                                        .insert((ident.sym.clone(), self.curr_mod), default_id);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            } else if ident.sym == "exports" {
                if let Some(mem_expr) = mem_expr_from_assign(n) {
                    if let MemberProp::Ident(ident_property) = &mem_expr.prop {
                        match &*n.right {
                            Expr::Fn(FnExpr { ident, function }) => {
                                self.add_export(DefRes::Function(()), ident_property.to_id());
                            }
                            Expr::Class(_) => {
                                self.add_export(DefRes::Class(()), ident_property.to_id());
                            }
                            Expr::Ident(ident) => {
                                let export_defid =
                                    self.add_export(DefRes::Undefined, ident_property.to_id());
                                self.res_table
                                    .exported_names
                                    .insert((ident.sym.clone(), self.curr_mod), export_defid);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        n.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        // TODO: handle other kinds of destructuring patterns
        if let Pat::Ident(BindingIdent { id, .. }) = &n.name {
            let id = id.to_id();
            self.add_export(DefRes::Undefined, id);
        }
        n.visit_children_with(self);
    }

    fn visit_named_export(&mut self, n: &NamedExport) {
        if n.type_only {
            return;
        }
        for export in &n.specifiers {
            match export {
                ExportSpecifier::Namespace(_) => {}
                ExportSpecifier::Default(_) => {}
                ExportSpecifier::Named(n) => {}
            }
        }
    }

    fn visit_export_all(&mut self, _: &ExportAll) {}

    fn visit_export_default_decl(&mut self, n: &ExportDefaultDecl) {
        match &n.decl {
            DefaultDecl::Class(ClassExpr { ident, .. }) => {
                self.add_default(DefRes::Class(()), ident.as_ref().map(Ident::to_id));
            }
            DefaultDecl::Fn(FnExpr { ident, .. }) => {
                self.add_default(DefRes::Function(()), ident.as_ref().map(Ident::to_id));
            }
            DefaultDecl::TsInterfaceDecl(_) => {}
        }
        n.decl.visit_children_with(self);
    }

    fn visit_export_named_specifier(&mut self, n: &ExportNamedSpecifier) {
        if let ModuleExportName::Ident(ident) = &n.orig {
            let export_defid = self.add_export(DefRes::Undefined, ident.to_id());
            self.res_table
                .exported_names
                .insert((ident.sym.clone(), self.curr_mod), export_defid);
        } else {
            let orig_id = n.orig.as_id();
            let orig = self.add_export(DefRes::default(), orig_id);
            if let Some(id) = &n.exported {
                let exported_id = id.as_id();
                self.add_export(DefRes::ExportAlias(orig), exported_id);
            }
            n.visit_children_with(self)
        }
    }

    fn visit_export_default_expr(&mut self, n: &ExportDefaultExpr) {
        if let Expr::Ident(ident) = &*n.expr {
            let default_id = self.add_default(DefRes::Undefined, None);
            // adding the default export, so we can resolve it during the lowering
            self.res_table
                .exported_names
                .insert((ident.sym.clone(), self.curr_mod), default_id);
        }
    }
}

fn ident_from_assign_expr(n: &AssignExpr) -> Option<Ident> {
    if let Some(mem_expr) = mem_expr_from_assign(n) {
        if let Expr::Ident(ident) = &*mem_expr.obj {
            return Some(ident.clone());
        }
    }
    None
}

fn mem_expr_from_assign(n: &AssignExpr) -> Option<&MemberExpr> {
    n.left.as_simple()?.as_member()
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

    fn overwrite_def(&mut self, def: DefId, res: DefRes) {
        let key = self.new_key_from_res(def, res);
        self.defs.defs[def] = key;
    }

    #[inline]
    pub fn bodies(&self) -> impl Iterator<Item = &Body> + '_ {
        self.defs.funcs.iter()
    }

    #[inline]
    pub fn get_object(&self, mod_id: ModId, object_id: Id) -> Option<&Class> {
        let def_id = self.get_sym(object_id, mod_id)?;
        let def_key = self.defs.defs[def_id];
        if let DefKey::Class(class) = def_key {
            return Some(&self.defs.classes[class]);
        } else if let DefKind::GlobalObj(global_obj) = def_key {
            return Some(&self.defs.classes[global_obj]);
        }
        None
    }

    #[inline]
    pub fn get_prop_from_ident(
        &self,
        mod_id: ModId,
        class_id: Id,
        method_name_ident: &Ident,
    ) -> Option<DefId> {
        let class = self.get_object(mod_id, class_id.to_id())?;
        Some(
            class
                .pub_members
                .iter()
                .find(|(name, defid)| *name == method_name_ident.sym)?
                .1,
        )
    }

    #[inline]
    #[cfg_attr(debug_assertions, track_caller)]
    fn get_or_insert_sym(&mut self, id: Id, module: ModId) -> DefId {
        let def_id = self.resolver.get_or_insert_sym(id, module);
        let def_id2 = self.defs.defs.get(def_id).copied().map_or_else(
            || self.defs.defs.push_and_get_key(DefKey::default()),
            |_| def_id,
        );
        debug_assert_eq!(def_id, def_id2, "resolver and defs out of sync");
        def_id
    }

    #[inline]
    fn get_sym(&self, id: Id, module: ModId) -> Option<DefId> {
        self.resolver.sym_id(id, module)
    }

    #[inline]
    fn recent_sym(&self, sym: JsWord, module: ModId) -> Option<DefId> {
        self.resolver.recent_sym(sym, module)
    }

    #[inline]
    pub fn get_all_functions(&self) -> Vec<DefId> {
        self.defs.get_all_functions()
    }

    #[inline]
    fn reserve_global_scope(&mut self, module: ModId) -> DefId {
        let defid = self.add_anonymous("__GLOBAL", AnonType::Closure, module);
        self.global.insert(module, defid);
        defid
    }

    #[inline]
    fn get_or_reserve_global_scope(&mut self, module: ModId) -> DefId {
        if let Some(defid) = self.global.get(module) {
            *defid
        } else {
            self.reserve_global_scope(module)
        }
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

    fn add_class_method(&mut self, n: PropName, class_def: DefId, owner: DefId) {
        if let DefKind::Class(class) = self.def_mut(class_def) {
            if let PropName::Ident(ident) = &n {
                class.pub_members.push((ident.sym.to_owned(), owner));
            }
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
                let name = name.into();
                let id = self.resolver.add_anon(DefRes::Closure(()), name, module);
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

    pub fn module_export<I: PartialEq<str> + ?Sized>(
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

    // takes in Definition ID and returns tuple with import module and type of import
    pub fn as_foreign_import(&self, def: DefId) -> Option<(JsWord, ImportKind)> {
        let DefKind::Foreign(f) = self.def_ref(def) else {
            return None;
        };
        Some((f.module_name.clone(), f.kind.clone()))
    }

    /// Check if def is exported from the foreign module specified in `module_name`.
    pub fn is_imported_from(&self, def: DefId, module_name: &str) -> Option<&ImportKind> {
        match self.def_ref(def) {
            DefKind::Foreign(f) if f.module_name == *module_name => Some(&f.kind),
            _ => None,
        }
    }

    pub fn resolve_alias(&self, def: DefId) -> DefId {
        match self.def_ref(def) {
            DefKind::Arg
            | DefKind::GlobalObj(_)
            | DefKind::Class(_)
            | DefKind::Foreign(_)
            | DefKind::Resolver(_)
            | DefKind::ModuleNs(_)
            | DefKind::Undefined
            | DefKind::Closure(_)
            | DefKind::Function(_) => def,
            DefKind::ExportAlias(def)
            | DefKind::ResolverDef(def)
            | DefKind::ResolverHandler(def) => self.resolve_alias(def),
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub fn resolver_defs(&self, def: DefId) -> Vec<(JsWord, DefId)> {
        let def = {
            let new_def = self.resolve_alias(def);
            #[cfg(debug_assertions)]
            if new_def != def {
                debug!(new = ?new_def, old = ?def, "resolved alias");
            }
            new_def
        };
        // TODO: return an iterator instead of a Vec
        let defkind = self.def_ref(def);
        if let DefKind::Resolver(class) = defkind {
            class
                .pub_members
                .iter()
                .map(|(k, v)| (k.clone(), self.resolve_alias(*v)))
                .collect()
        } else {
            debug!(?defkind, "not a resolver");
            vec![]
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

    pub fn get_all_functions(&self) -> Vec<DefId> {
        self.defs
            .iter_enumerated()
            .filter(|(defid, defkind)| defkind == &&DefKind::Function(()))
            .map(|(defid, defkind)| defid)
            .collect_vec()
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

impl DefId {
    #[inline]
    pub(crate) fn new(raw: u32) -> Self {
        Self(raw)
    }
}

impl PartialEq<str> for ImportKind {
    fn eq(&self, other: &str) -> bool {
        match self {
            ImportKind::Star => false,
            ImportKind::Default => other == "default",
            ImportKind::Named(name) => name == other,
        }
    }
}
