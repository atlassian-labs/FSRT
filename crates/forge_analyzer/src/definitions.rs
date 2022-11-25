#![allow(dead_code, unused)]

use std::{borrow::Borrow, fmt, mem};

use forge_file_resolver::{FileResolver, ForgeResolver};
use forge_utils::{create_newtype, FxHashMap};

use swc_core::{
    common::SyntaxContext,
    ecma::{
        ast::{
            AssignProp, BindingIdent, CallExpr, Callee, ClassDecl, ClassExpr, ComputedPropName,
            Decl, DefaultDecl, ExportAll, ExportDecl, ExportDefaultDecl, ExportDefaultExpr,
            ExportNamedSpecifier, Expr, ExprOrSpread, FnDecl, FnExpr, Id, Ident, ImportDecl,
            ImportDefaultSpecifier, ImportNamedSpecifier, ImportStarAsSpecifier, KeyValueProp, Lit,
            MemberExpr, MemberProp, MethodProp, Module, ModuleDecl, ModuleExportName, ModuleItem,
            NewExpr, ObjectLit, Pat, PrivateName, Prop, PropName, PropOrSpread, Str, VarDecl,
            VarDeclarator,
        },
        atoms::JsWord,
        visit::{noop_visit_type, Visit, VisitWith},
    },
};
use tracing::warn;
use typed_index_collections::{TiSlice, TiVec};

use crate::{ctx::ModId, ir::Body};

create_newtype! {
    pub struct GlobalId(u32);
}

create_newtype! {
    pub struct FuncId(u32);
}

create_newtype! {
    pub struct ObjId(u32);
}

create_newtype! {
    pub struct DefId(u32);
}

const INVALID_FUNC: FuncId = FuncId(u32::MAX);

const INVALID_CLASS: ObjId = ObjId(u32::MAX);

const INVALID_GLOBAL: GlobalId = GlobalId(u32::MAX);

trait DefinitionDb {
    fn possible_funcalls(&self, proj: &[Option<DefId>]) -> &[DefId];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefKind {
    Function(FuncId),
    Global(GlobalId),
    Class(ObjId),
    ExportAlias(DefId),
    /// exported(usuall) handler to the actual resolver definitions
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
    Resolver(ObjId),
    // to account for the common pattern of object literals being used to organize
    // functions
    ObjLit(ObjId),
    // Ex: `module` in import * as 'foo' from 'module'
    ModuleNs(ModId),
    Foreign(ForeignId),
    // should only be set by the initial exporter
    Undefined,
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
    defs: TiVec<DefId, DefKind>,
    names: TiVec<DefId, JsWord>,
    symbol_to_id: FxHashMap<Symbol, DefId>,
    parent: FxHashMap<DefId, DefId>,
    owning_module: TiVec<DefId, ModId>,
}

struct ModuleDefs {
    symbols: FxHashMap<Id, DefId>,
    functions: Box<[DefId]>,
    globals: Box<[DefId]>,
    classes: Box<[DefId]>,
    exports: Box<[DefId]>,
}

pub fn run_resolver(
    modules: &TiSlice<ModId, Module>,
    file_resolver: &ForgeResolver,
) -> (Resolver, TiVec<ForeignId, ForeignItem>) {
    let mut resolver = Resolver::new();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut export_collector = ExportCollector {
            res_table: &mut resolver.res_table,
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

    let mut foreign_defs = TiVec::default();
    for (curr_mod, module) in modules.iter_enumerated() {
        let mut import_collector = ImportCollector {
            resolver: &mut resolver,
            file_resolver,
            foreign_defs: &mut foreign_defs,
            curr_mod,
            current_import: Default::default(),
            in_foreign_import: false,
        };
        module.visit_with(&mut import_collector);
    }
    (resolver, foreign_defs)
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
struct Class {
    def: DefId,
    pub_members: Vec<(JsWord, DefId)>,
    constructor: Option<DefId>,
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

#[derive(Debug, Clone)]
struct Definitions {
    funcs: TiVec<FuncId, Body>,
    globals: TiVec<GlobalId, Body>,
    classes: TiVec<ObjId, Class>,
    foreign: TiVec<ForeignId, ForeignItem>,
}

#[derive(Debug, Clone, Default)]
pub struct Resolver {
    exports: TiVec<ModId, Vec<(JsWord, DefId)>>,
    default_exports: FxHashMap<ModId, DefId>,
    res_table: ResolverTable,
}

struct ImportCollector<'cx> {
    resolver: &'cx mut Resolver,
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
    res_table: &'cx mut ResolverTable,
    defs: &'cx mut Definitions,
    curr_mod: ModId,
    stage: LowerStage,
    parents: Vec<DefId>,
    curr_def: Option<DefId>,
}

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

fn normalize_callee_expr(callee: &Callee, res_table: &ResolverTable, curr_mod: ModId) {
    struct CalleeNormalizer<'cx> {
        res_table: &'cx ResolverTable,
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
                self.path.push(PropPath::Unknown(id));
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
    }
}

impl ResolverTable {
    #[inline]
    fn sym_id(&self, id: Id, module: ModId) -> Option<DefId> {
        self.symbol_to_id.get(&Symbol { module, id }).copied()
    }

    #[inline]
    fn sym_kind(&self, id: Id, module: ModId) -> Option<DefKind> {
        let def = self.sym_id(id, module)?;
        self.defs.get(def).copied()
    }

    #[inline]
    fn reserve_symbol(&mut self, id: Id, module: ModId) -> DefId {
        self.add_sym(DefKind::Undefined, id, module)
    }

    #[inline]
    fn get_or_insert_sym(&mut self, id: Id, module: ModId) -> DefId {
        self.sym_id(id.clone(), module)
            .unwrap_or_else(|| self.reserve_symbol(id, module))
    }

    fn reserve_def(&mut self, name: JsWord, module: ModId) -> DefId {
        self.defs.push_and_get_key(DefKind::Undefined);
        self.names.push_and_get_key(name);
        self.owning_module.push_and_get_key(module)
    }

    fn add_prop(&mut self, def: DefKind, prop: JsWord, module: ModId) -> DefId {
        let defid = self.defs.push_and_get_key(def);
        let defid2 = self.owning_module.push_and_get_key(module);
        debug_assert_eq!(
            defid, defid2,
            "inconsistent state while inserting {}",
            &*prop
        );
        let defid3 = self.names.push_and_get_key(prop);
        debug_assert_eq!(
            defid,
            defid3,
            "inconsistent state while inserting {}",
            self.names.last().unwrap()
        );
        defid
    }

    fn add_sym(&mut self, def: DefKind, id: Id, module: ModId) -> DefId {
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
    res: &'cx mut ResolverTable,
    defs: &'cx mut Definitions,
    module: ModId,
    parent: Option<DefId>,
}

impl Lowerer<'_> {
    fn defid_from_ident(&self, id: Id) -> Option<DefId> {
        let sym = Symbol {
            module: self.curr_mod,
            id,
        };
        self.res_table.symbol_to_id.get(&sym).copied()
    }

    #[inline]
    fn reserve_symbol(&mut self, id: Id) -> DefId {
        self.res_table.get_or_insert_sym(id, self.curr_mod)
    }

    fn defkind_from_ident(&self, id: Id) -> Option<DefKind> {
        let cid = id.clone();
        let defid = self.defid_from_ident(id)?;
        let defkind = self.res_table.defs.get(defid).copied();
        if defkind.is_none() {
            warn!(
                module = ?self.curr_mod,
                "resolver table has unknown defid: {defid:?} for id: {cid:?}"
            );
        }
        defkind
    }

    fn as_foreign_import(&self, imported_sym: Id, module: &str) -> Option<&ImportKind> {
        match self.defkind_from_ident(imported_sym) {
            Some(DefKind::Foreign(fid)) => self
                .defs
                .foreign
                .get(fid)
                .filter(|&item| item.module_name == *module)
                .map(|item| &item.kind),
            _ => None,
        }
    }

    #[inline]
    fn next_key(&self) -> DefId {
        self.res_table.defs.next_key()
    }

    fn def_objlike(&mut self, id: Id, f: impl FnOnce(ObjId) -> ObjKind) -> (DefId, ObjId) {
        let idlookup = id.clone();
        match self.defid_from_ident(idlookup) {
            Some(def) => {
                let defkind = self.res_table.defs[def];
                (def, defkind.as_objkind().unwrap().into_inner())
            }
            None => {
                let next_key = self.next_key();
                let objid = self.defs.classes.push_and_get_key(Class::new(next_key));
                let objkind = f(objid);
                self.res_table
                    .add_sym(objkind.as_defkind(), id, self.curr_mod);
                (next_key, objkind.into_inner())
            }
        }
    }

    fn add_sym_or_else(&mut self, id: Id, f: impl FnOnce(&mut Self, DefId) -> DefKind) -> DefId {
        self.defid_from_ident(id.clone()).unwrap_or_else(|| {
            let next_key = self.next_key();
            let defkind = f(self, next_key);
            self.res_table.add_sym(defkind, id, self.curr_mod)
        })
    }

    fn def_method(&mut self, sym: JsWord) -> DefId {
        let func_id = self.defs.funcs.push_and_get_key(Body::default());
        self.res_table
            .add_prop(DefKind::Function(func_id), sym, self.curr_mod)
    }

    fn def_function(&mut self, id: Id) -> DefId {
        self.defid_from_ident(id.clone()).unwrap_or_else(|| {
            let funcid = self.defs.funcs.push_and_get_key(Body::default());
            self.res_table
                .add_sym(DefKind::Function(funcid), id, self.curr_mod)
        })
    }
}

enum ResolverDef {
    FnDef,
    Handler,
}

fn as_resolver(
    expr: &Expr,
    res_table: &ResolverTable,
    module: ModId,
) -> Option<(ObjId, ResolverDef)> {
    if let Expr::Member(MemberExpr {
        obj,
        prop: MemberProp::Ident(prop),
        ..
    }) = expr
    {
        let id = obj.as_ident()?;
        let def = res_table.sym_kind(id.to_id(), module)?;
        if let DefKind::Resolver(obj) = def {
            match &*prop.sym {
                "getDefinitions" => return Some((obj, ResolverDef::Handler)),
                "define" => return Some((obj, ResolverDef::FnDef)),
                unknown => {
                    warn!("unknown prop: {unknown} on resolver: {}", &*id.sym);
                }
            }
        }
    }
    None
}

impl Visit for Lowerer<'_> {
    noop_visit_type!();

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
                    if let Some((objid, kind)) = as_resolver(expr, self.res_table, self.curr_mod) {
                        match kind {
                            ResolverDef::FnDef => {
                                if let [ExprOrSpread { expr: name, .. }, ExprOrSpread { expr: args, .. }] =
                                    &**args
                                {
                                    if let Expr::Lit(Lit::Str(Str { value, .. })) = &**expr {
                                        let fname = value.clone();
                                        let class = &mut self.defs.classes[objid];
                                        class.pub_members.push((fname, self.curr_def.unwrap()));
                                    }
                                }
                            }
                            ResolverDef::Handler => todo!(),
                        }
                    }
                    expr.visit_children_with(self);
                }
                Expr::Object(ObjectLit { props, .. }) => {
                    let (def_id, obj_id) = self.def_objlike(id, ObjKind::Lit);
                    let old_def = self.curr_def.replace(def_id);
                    for prop in props {
                        match prop {
                            // TODO: track 'spreaded' objects
                            PropOrSpread::Spread(_) => {}
                            PropOrSpread::Prop(prop) => match &**prop {
                                Prop::Shorthand(id) => {
                                    let id = id.to_id();
                                    let sym = id.0.clone();
                                    let def_id = self.reserve_symbol(id);
                                    self.defs.classes[obj_id].pub_members.push((sym, def_id));
                                }
                                Prop::KeyValue(KeyValueProp { key, value }) => {
                                    let cls = &mut self.defs.classes[obj_id];
                                    if let sym @ Some(_) = key.as_symbol() {
                                        let defid = value.as_ident().map(|id| {
                                            self.res_table
                                                .get_or_insert_sym(id.to_id(), self.curr_mod)
                                        });
                                        cls.pub_members.extend(sym.zip(defid));
                                    }
                                }
                                Prop::Assign(AssignProp { key, .. }) => {
                                    let obj_sym = &self.res_table.names[def_id];
                                    warn!("object {obj_sym:?} invalid assign prop {:?}", &key.sym);
                                }
                                /// TODO: track these
                                Prop::Getter(_) | Prop::Setter(_) => {}
                                Prop::Method(MethodProp { key, function }) => {
                                    function.body.visit_with(self);
                                    if let Some(sym) = key.as_symbol() {
                                        let def_id = self.def_method(sym.clone());
                                        let cls = &mut self.defs.classes[obj_id];
                                        cls.pub_members.push((sym, def_id));
                                    }
                                }
                            },
                        }
                    }
                }
                Expr::New(NewExpr { callee, .. }) => {
                    let Some(id) = callee.as_ident() else {
                        expr.visit_children_with(self);
                        return;
                    };
                    let id = id.to_id();
                    if Some(&ImportKind::Default)
                        == self.as_foreign_import(id.clone(), "@forge/resolver")
                    {
                        self.add_sym_or_else(id, |this, to_insert| {
                            let obj_id = this.defs.classes.push_and_get_key(Class::new(to_insert));
                            DefKind::Resolver(obj_id)
                        });
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
    fn add_export(&mut self, def: DefKind, id: Id) -> DefId {
        let exported_sym = id.0.clone();
        let defid = self.res_table.add_sym(def, id, self.curr_mod);
        self.exports.push((exported_sym, defid));
        defid
    }

    fn add_default(&mut self, def: DefKind, id: Option<Id>) {
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
                    self.resolver.res_table.symbol_to_id.insert(
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
                    .res_table
                    .add_sym(DefKind::Foreign(foreign_id), local, self.curr_mod);
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
                        self.resolver.res_table.symbol_to_id.insert(
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
                    .res_table
                    .add_sym(DefKind::Foreign(foreign_id), local, self.curr_mod);
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
                DefKind::ModuleNs(mod_id)
            }
            Err(_) => {
                let foreign_id = self.foreign_defs.push_and_get_key(ForeignItem {
                    kind: ImportKind::Star,
                    module_name: self.current_import.clone(),
                });
                DefKind::Foreign(foreign_id)
            }
        };
        self.resolver
            .res_table
            .add_sym(defkind, local, self.curr_mod);
    }

    fn visit_module_item(&mut self, n: &ModuleItem) {
        if let ModuleItem::ModuleDecl(ModuleDecl::Import(n)) = n {
            n.visit_with(self);
        }
    }
}

impl<'cx> Visit for ExportCollector<'cx> {
    noop_visit_type!();
    fn visit_export_decl(&mut self, n: &ExportDecl) {
        match &n.decl {
            Decl::Class(ClassDecl { ident, .. }) => {
                let ident = ident.to_id();
                self.add_export(DefKind::Class(INVALID_CLASS), ident);
            }
            Decl::Fn(FnDecl { ident, .. }) => {
                let ident = ident.to_id();
                self.add_export(DefKind::Function(INVALID_FUNC), ident);
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
            self.add_export(DefKind::Undefined, id);
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
            DefaultDecl::Class(ClassExpr { ident, .. }) => self.add_default(
                DefKind::Class(INVALID_CLASS),
                ident.as_ref().map(Ident::to_id),
            ),
            DefaultDecl::Fn(FnExpr { ident, .. }) => self.add_default(
                DefKind::Function(INVALID_FUNC),
                ident.as_ref().map(Ident::to_id),
            ),
            DefaultDecl::TsInterfaceDecl(_) => {}
        }
    }

    fn visit_export_named_specifier(&mut self, n: &ExportNamedSpecifier) {
        let orig_id = n.orig.as_id();
        let orig = self.add_export(DefKind::Undefined, orig_id);
        if let Some(id) = &n.exported {
            let exported_id = id.as_id();
            self.add_export(DefKind::ExportAlias(orig), exported_id);
        }
    }

    fn visit_export_default_expr(&mut self, _: &ExportDefaultExpr) {
        self.add_default(DefKind::Undefined, None);
    }
}

impl Resolver {
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn default_export(&self, module: ModId) -> Option<DefId> {
        self.default_exports.get(&module).copied()
    }

    #[inline]
    pub fn def_name(&self, def: DefId) -> &str {
        &self.res_table.names[def]
    }

    #[inline]
    pub fn module_exports(&self, module: ModId) -> impl Iterator<Item = (&str, DefId)> + '_ {
        self.exports[module].iter().map(|(k, v)| (&**k, *v))
    }

    #[inline]
    pub fn def_kind(&self, def: DefId) -> DefKind {
        self.res_table.defs[def]
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
    fn as_defkind(&self) -> DefKind {
        match *self {
            ObjKind::Class(id) => DefKind::Class(id),
            ObjKind::Lit(id) => DefKind::ObjLit(id),
            ObjKind::Resolver(id) => DefKind::Resolver(id),
        }
    }
}

impl DefKind {
    #[inline]
    fn as_objkind(&self) -> Option<ObjKind> {
        match *self {
            DefKind::Class(id) => Some(ObjKind::Class(id)),
            DefKind::Resolver(id) => Some(ObjKind::Resolver(id)),
            DefKind::ObjLit(id) => Some(ObjKind::Lit(id)),
            DefKind::Function(_)
            | DefKind::Global(_)
            | DefKind::ExportAlias(_)
            | DefKind::ResolverHandler(_)
            | DefKind::ModuleNs(_)
            | DefKind::Foreign(_)
            | DefKind::Undefined => None,
        }
    }
}

impl fmt::Display for DefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefKind::Class(_) => write!(f, "class"),
            DefKind::Resolver(_) => write!(f, "resolver"),
            DefKind::ObjLit(_) => write!(f, "object literal"),
            DefKind::Function(_) => write!(f, "function"),
            DefKind::Global(_) => write!(f, "global"),
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

impl From<ObjKind> for DefKind {
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

impl fmt::Display for GlobalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@G{}", self.0)
    }
}
