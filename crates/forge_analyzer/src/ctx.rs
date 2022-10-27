use std::iter::repeat;
use std::{borrow::Borrow, hash::Hash, path::PathBuf};

use forge_utils::create_newtype;
use once_cell::unsync::OnceCell;
use petgraph::prelude::NodeIndex;
use petgraph::stable_graph::DefaultIx;
use rustc_hash::FxHashMap;
use smallvec::smallvec;
use smallvec::SmallVec;
use swc_core::ecma::ast::{Id, Ident, Module};
use tracing::{debug, instrument};
use typed_index_collections::TiVec;

use crate::{
    analyzer::AuthZVal, lattice::MeetSemiLattice, lower_module, Exports, ForgeImports, ImportKind,
};

create_newtype! {
    pub struct ModId(u32);
}

create_newtype! {
    pub struct StmtId(u32);
}

create_newtype! {
    pub struct BasicBlockId(u32);
}

impl BasicBlockId {
    #[inline]
    pub(crate) fn to_bits(self) -> u32 {
        self.0
    }
}

impl From<BasicBlockId> for NodeIndex<DefaultIx> {
    fn from(value: BasicBlockId) -> Self {
        Self::new(value.to_bits() as usize)
    }
}

pub const UNKNOWN_MODULE: ModId = ModId(u32::MAX);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModItem {
    pub mod_id: ModId,
    pub ident: Id,
}

impl ModItem {
    pub fn with_unknown_ident(ident: Id) -> Self {
        Self {
            mod_id: UNKNOWN_MODULE,
            ident,
        }
    }

    pub fn as_unknown_ident(&self) -> Option<&Id> {
        match *self {
            ModItem {
                mod_id: UNKNOWN_MODULE,
                ref ident,
            } => Some(ident),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IrStmt {
    Call(ModItem),
    Resolved(AuthZVal),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum TerminatorKind {
    #[default]
    Ret,
    Throw,
    Branch(SmallVec<[BasicBlockId; 2]>),
}

#[derive(Debug, Default, Clone)]
pub struct BasicBlock {
    pub(crate) stmts: TiVec<StmtId, IrStmt>,
    pub(crate) terminator: TerminatorKind,
}

pub const STARTING_BLOCK: BasicBlockId = BasicBlockId(0);
pub const ENTRY_STMT: StmtId = StmtId(0);

#[derive(Default, Debug, Clone)]
pub(crate) struct FunctionMeta {
    pub(crate) blocks: TiVec<BasicBlockId, BasicBlock>,
    pub(crate) succ: FxHashMap<BasicBlockId, SmallVec<[BasicBlockId; 2]>>,
    pub(crate) pred: FxHashMap<BasicBlockId, SmallVec<[BasicBlockId; 1]>>,
    out: TiVec<BasicBlockId, AuthZVal>,
    res: OnceCell<AuthZVal>,
}

#[derive(Default, Debug, Clone)]
pub struct ModuleCtx {
    // module identifier -> imports
    pub(crate) imports: FxHashMap<Id, SmallVec<[ImportKind; 8]>>,
    pub(crate) forge_imports: ForgeImports,
    pub(crate) ident_to_import: FxHashMap<Id, Id>,
    pub(crate) exports: Option<Exports>,
    pub(crate) functions: FxHashMap<Id, FunctionMeta>,
}

#[derive(Default, Clone, Debug)]
pub struct AppCtx {
    // Map from import Id -> module name
    pub(crate) import_ids: FxHashMap<Id, Id>,

    pub(crate) path_ids: FxHashMap<PathBuf, ModId>,
    pub(crate) modules: TiVec<ModId, Module>,
    pub(crate) modctx: TiVec<ModId, ModuleCtx>,
}

impl AppCtx {
    #[inline]
    pub fn new() -> Self {
        Self {
            import_ids: FxHashMap::default(),
            path_ids: FxHashMap::default(),
            modules: TiVec::default(),
            modctx: TiVec::default(),
        }
    }

    #[instrument(level = "debug", skip(self, module))]
    pub fn load_module(&mut self, path: PathBuf, module: Module) -> ModId {
        let modctx = lower_module(&module);
        let mod_id = self.modules.push_and_get_key(module);
        self.modctx.insert(mod_id, modctx);
        self.path_ids.insert(path, mod_id);
        mod_id
    }

    #[inline]
    pub fn block(&self, func: &ModItem, block: BasicBlockId) -> Option<&BasicBlock> {
        self.func(func)?.blocks.get(block)
    }

    #[inline]
    pub fn block_mut(&mut self, func: &ModItem, block: BasicBlockId) -> Option<&mut BasicBlock> {
        self.func_mut(func)?.blocks.get_mut(block)
    }

    #[inline]
    pub fn modid_from_path<P>(&self, path: &P) -> Option<ModId>
    where
        PathBuf: Borrow<P>,
        P: Hash + Eq,
    {
        self.path_ids.get(path).copied()
    }

    // TODO: move this to the engine
    pub(crate) fn meet(
        &mut self,
        func: &ModItem,
        block: BasicBlockId,
        start: Option<AuthZVal>,
    ) -> (Option<ModItem>, bool) {
        debug!("meet from {func:?}");
        let funcs = match self.func(func) {
            Some(f) => f,
            None => return (None, true),
        };
        debug!("starting transfer function");

        // if &*func.0 == "SecureGlance" {
        //     dbg!(&funcs);
        // }

        let start = start.unwrap_or_default();

        // meet over pred blocks
        let mut input = funcs.pred.get(&block).map_or(start, |pred| {
            pred.iter().fold(AuthZVal::Unknown, |mut res, &id| {
                res.meet(funcs.out.get(id).copied().unwrap_or_default());
                res
            })
        });
        debug!(?input, "transfer in");
        let next = funcs.blocks[block].stmts.iter_enumerated().fold(
            (None, false),
            |(call, curr), (_stmt_id, val)| match val {
                IrStmt::Call(ref call_id) => {
                    if let Some(meta) = self.func(call_id) {
                        debug!("calling: {meta:#?}");
                        let cached = meta.res.get().copied();
                        let authz = cached.as_ref().copied().unwrap_or(AuthZVal::Unknown);
                        let func = cached.is_none().then(|| call_id.clone());
                        (call.or(func), input.meet(authz))
                    } else {
                        (call, curr)
                    }
                }
                IrStmt::Resolved(val) => {
                    debug!(?val, "resolved IR statement");
                    (call, input.meet(*val))
                }
            },
        );
        debug!(?next, "transfer out");
        let funcs = self.func_mut(func).unwrap();
        funcs.out[block].meet(input);
        debug!(output = ?funcs.out[block], ?input, "result of transfer");
        if funcs.succ.get(&block).is_none() {
            let res = &mut funcs.res;
            match res.get_mut() {
                Some(val) => {
                    debug!(previous = ?val, current = ?input, "setting output");
                    val.meet(input);
                }
                None => {
                    let _ = res.set(input);
                }
            };
            debug!(calling = ?next.0, finish = true, "last block");
            return (next.0, true);
        }
        debug!(calling = ?next.0, finish = next.1, "contining to next block");
        next
    }

    #[inline]
    pub(crate) fn func_mut(&mut self, func: &ModItem) -> Option<&mut FunctionMeta> {
        self.modctx
            .get_mut(func.mod_id)?
            .functions
            .get_mut(&func.ident)
    }
    #[inline]
    pub(crate) fn func(&self, func: &ModItem) -> Option<&FunctionMeta> {
        self.modctx.get(func.mod_id)?.functions.get(&func.ident)
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) fn resolve_export(&self, mod_id: ModId, func: &Id) -> Option<(ModId, Id)> {
        let import = self.modctx.get(mod_id)?.ident_to_import.get(func)?;
        let pat: &str = &import.0;
        debug!(import = pat, "found import");
        let pat = pat.strip_prefix("./").unwrap_or(pat);
        let module = self
            .path_ids
            .iter()
            .find_map(|(path, &mod_id)| path.to_string_lossy().contains(pat).then_some(mod_id))?;
        debug!(?module, "found module");
        let exported_func = self.modctx.get(module)?.exports.as_ref()?.find_orig(func);
        debug!(?exported_func, "function");
        Some(module).zip(exported_func)
    }

    #[inline]
    pub fn export(&self, mod_id: ModId, func: &str) -> Option<Id> {
        self.modctx
            .get(mod_id)?
            .exports
            .as_ref()?
            .orig_from_str(func)
    }

    pub(crate) fn func_res(&self, func: &ModItem) -> AuthZVal {
        self.func(func)
            .and_then(|f| f.res.get().copied())
            .unwrap_or(AuthZVal::Unknown)
    }

    #[inline]
    pub(crate) fn succ(
        &self,
        func: &ModItem,
        block: BasicBlockId,
    ) -> Option<impl Iterator<Item = BasicBlockId> + DoubleEndedIterator + '_> {
        self.func(func)
            .and_then(|f| Some(f.succ.get(&block)?.into_iter().copied()))
    }

    #[inline]
    pub fn module_ids(
        &self,
    ) -> impl Iterator<Item = ModId> + DoubleEndedIterator + ExactSizeIterator + '_ {
        self.modules.keys()
    }
}

impl FunctionMeta {
    #[inline]
    pub(crate) fn new() -> Self {
        let blocks = vec![BasicBlock::new()].into();
        let out = vec![AuthZVal::Unknown].into();
        Self {
            blocks,
            out,
            ..Default::default()
        }
    }

    #[inline]
    pub(crate) fn add_stmt(&mut self, id: BasicBlockId, stmt: IrStmt) {
        self.blocks[id].push(stmt);
    }

    #[inline]
    pub(crate) fn add_terminator(&mut self, id: BasicBlockId, term: TerminatorKind) {
        self.blocks[id].terminator = term
    }

    #[inline]
    pub(crate) fn push_block(&mut self) -> BasicBlockId {
        self.out.push(AuthZVal::Unknown);
        self.blocks.push_and_get_key(BasicBlock::default())
    }

    #[inline]
    pub(crate) fn add_terminator_to_last(&mut self, term: TerminatorKind) {
        self.blocks.last_mut().unwrap().terminator = term;
    }

    #[inline]
    pub(crate) fn add_edge(&mut self, from: BasicBlockId, to: BasicBlockId) {
        self.succ.entry(from).or_default().push(to);
        self.pred.entry(to).or_default().push(from);
    }

    #[inline]
    pub(crate) fn create_block_from(&mut self, pred: BasicBlockId) -> BasicBlockId {
        let id = self.blocks.push_and_get_key(BasicBlock::default());
        self.out.push(AuthZVal::Unknown);
        match &mut self.blocks[pred].terminator {
            TerminatorKind::Branch(branches) => branches.push(id),
            term => *term = TerminatorKind::Branch(smallvec![id]),
        }
        self.add_edge(pred, id);
        id
    }

    #[inline]
    pub(crate) fn iter_stmts(&self) -> impl Iterator<Item = &IrStmt> {
        self.blocks.iter().flat_map(|bb| &bb.stmts)
    }

    #[inline]
    pub(crate) fn iter_stmts_mut(&mut self) -> impl Iterator<Item = &mut IrStmt> + '_ {
        self.blocks.iter_mut().flat_map(|bb| &mut bb.stmts)
    }

    #[inline]
    pub(crate) fn iter_stmts_enumerated_mut(
        &mut self,
    ) -> impl Iterator<Item = (BasicBlockId, StmtId, &mut IrStmt)> + '_ {
        self.blocks.iter_mut_enumerated().flat_map(|(id, bb)| {
            repeat(id)
                .zip(bb.stmts.iter_mut_enumerated())
                .map(|(id, (idx, stmt))| (id, idx, stmt))
        })
    }
}

impl ModuleCtx {
    // check if the `ident` matches `funcname` imported` from `path`
    pub(crate) fn has_import(&self, ident: &Id, path: &str, funcname: &str) -> bool {
        let import = self.ident_to_import.get(ident);
        debug!(module = ?import, id = ?ident, "checking if import exists");
        import
            .filter(|modname| path == &modname.0)
            .and_then(|modname| {
                self.imports
                    .get(modname)?
                    .iter()
                    .find(|func| func.equal_funcname(funcname))
            })
            .is_some()
    }

    #[inline]
    pub(crate) fn is_api(&self, id: &Id) -> bool {
        self.forge_imports.is_api(id)
    }

    #[inline]
    pub(crate) fn is_authorize(&self, id: &Id) -> bool {
        self.forge_imports.is_authorize(id)
    }

    #[inline]
    pub(crate) fn is_as_app(&self, id: &Id) -> bool {
        self.forge_imports.is_as_app(id)
    }
}

impl BasicBlock {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            stmts: TiVec::new(),
            terminator: Default::default(),
        }
    }

    #[inline]
    fn push(&mut self, stmt: IrStmt) {
        self.stmts.push(stmt);
    }
}

impl From<AuthZVal> for IrStmt {
    #[inline]
    fn from(val: AuthZVal) -> Self {
        IrStmt::Resolved(val)
    }
}

impl From<Id> for ModItem {
    #[inline]
    fn from(ident: Id) -> Self {
        ModItem::with_unknown_ident(ident)
    }
}

impl From<Ident> for ModItem {
    #[inline]
    fn from(ident: Ident) -> Self {
        ModItem::with_unknown_ident(ident.to_id())
    }
}

impl From<&Ident> for ModItem {
    #[inline]
    fn from(ident: &Ident) -> Self {
        ModItem::with_unknown_ident(ident.to_id())
    }
}

impl From<ModItem> for IrStmt {
    #[inline]
    fn from(value: ModItem) -> Self {
        IrStmt::Call(value)
    }
}

impl ModItem {
    #[inline]
    pub fn new(mod_id: ModId, ident: Id) -> Self {
        Self { mod_id, ident }
    }
}
