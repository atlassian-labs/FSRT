#![allow(dead_code, unused_imports)]

// TODO: Use [`SSA`] instead
// [`SSA`]: https://pfalcon.github.io/ssabook/latest/book-full.pdf

use core::fmt;
use std::collections::BTreeSet;
use std::hash;
use std::hash::Hash;
use std::mem;

use forge_utils::create_newtype;
use forge_utils::FxHashMap;
use smallvec::smallvec;
use smallvec::SmallVec;
use swc_core::ecma::atoms::JsWord;
use swc_core::ecma::{ast::Id, atoms::Atom};
use typed_index_collections::TiVec;

use crate::ctx::ModId;
use crate::definitions::DefId;

create_newtype! {
    pub struct BasicBlockId(u32);
}

#[derive(Clone, Debug)]
pub(crate) struct BranchTargets {
    compare: SmallVec<[Operand; 1]>,
    branch: SmallVec<[BasicBlockId; 2]>,
}

#[derive(Clone, Debug, Default)]
pub(crate) enum Terminator {
    #[default]
    Ret,
    Goto(BasicBlockId),
    Throw,
    Call {
        callee: Operand,
        args: Vec<Operand>,
        ret: Option<Variable>,
    },
    Branch {
        scrutinee: Operand,
        targets: BranchTargets,
    },
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum Intrinsic {
    Authorize,
    Fetch,
    ApiCall,
    EnvRead,
    StorageOp,
}

#[derive(Clone, Debug)]
pub(crate) enum Rvalue {
    Unary(UnOp, Operand),
    Bin(BinOp, Operand, Operand),
    Read(Operand),
    Intrinsics(Intrinsic),
    Template {
        quasis: Vec<Atom>,
        exprs: Vec<Operand>,
        // TODO: make this more memory efficient
        tag: Option<Operand>,
    },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BasicBlock {
    insts: Vec<Inst>,
    term: Terminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Location {
    block: BasicBlockId,
    stmt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum VarKind {
    UserDef(DefId),
    Temp(DefId),
    Arg(DefId),
    Ret,
}

#[derive(Clone, Debug)]
pub struct Body {
    owner: Option<DefId>,
    blocks: TiVec<BasicBlockId, BasicBlock>,
    local_vars: TiVec<VarId, VarKind>,
    id_to_local: FxHashMap<Id, VarId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiCall {
    Authorize,
    Unauthorized,
    Noop,
}

#[derive(Clone, Debug)]
pub(crate) enum Inst {
    // maybe just use assign with a dummy VARIABLE for these?
    Expr(Rvalue),
    Assign(Variable, Rvalue),
}

#[derive(Clone, Debug, Default)]
pub(crate) enum Literal {
    Str(Id),
    Bool(bool),
    Null,
    #[default]
    Undef, // what a bunk language
    Number(f64),
    BigInt(num_bigint::BigInt),
    // regexp, flags
    RegExp(Atom, Atom),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinOp {
    Lt,
    Gt,
    EqEq,
    Neq,
    EqEqEq,
    Ge,
    Le,
    Add,
    Sub,
    Mul,
    Div,
    Exp,
    Mod,
    Or,
    And,
    BitOr,
    BitAnd,
    BitXor,
    Lshift,
    Rshift,
    RshiftLogical,
    In,
    InstanceOf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnOp {
    Neg,
    Not,
    BitNot,
    Plus,
    TypeOf,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Operand {
    Var(Variable),
    Lit(Literal),
}

create_newtype! {
    pub struct Label(u32);
}

create_newtype! {
    pub struct VarId(u32);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Variable {
    var: VarId,
    projections: SmallVec<[Projection; 1]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Projection {
    Known(JsWord),
    Computed(VarId),
}

impl fmt::Display for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.var)?;
        for proj in &self.projections {
            match proj {
                Projection::Known(lit) => write!(f, "[\"{lit}\"]")?,
                Projection::Computed(id) => write!(f, "[{id}]")?,
            }
        }
        Ok(())
    }
}

impl Body {
    #[inline]
    fn new() -> Self {
        let local_vars = vec![VarKind::Ret].into();
        Self {
            local_vars,
            owner: None,
            blocks: Default::default(),
            id_to_local: Default::default(),
        }
    }

    #[inline]
    pub(crate) fn with_owner(owner: DefId) -> Self {
        Self {
            owner: Some(owner),
            ..Self::new()
        }
    }

    #[inline]
    pub(crate) fn add_local_def(&mut self, def: DefId, id: Id) {
        self.id_to_local
            .insert(id, self.local_vars.push_and_get_key(VarKind::UserDef(def)));
    }

    #[inline]
    pub(crate) fn add_arg(&mut self, def: DefId, id: Id) {
        self.local_vars.push(VarKind::Arg(def));
        self.id_to_local
            .insert(id, VarId((self.local_vars.len() - 1) as u32));
    }

    #[inline]
    pub(crate) fn new_block(&mut self) -> BasicBlockId {
        self.blocks.push_and_get_key(BasicBlock::default())
    }

    #[inline]
    pub(crate) fn new_block_with_terminator(&mut self, term: Terminator) -> BasicBlockId {
        self.blocks.push_and_get_key(BasicBlock {
            term,
            ..Default::default()
        })
    }

    #[inline]
    pub(crate) fn set_terminator(&mut self, bb: BasicBlockId, term: Terminator) -> Terminator {
        mem::replace(&mut self.blocks[bb].term, term)
    }

    #[inline]
    pub(crate) fn push_inst(&mut self, bb: BasicBlockId, inst: Inst) {
        self.blocks[bb].insts.push(inst);
    }

    #[inline]
    pub(crate) fn push_assign(&mut self, bb: BasicBlockId, var: Variable, val: Rvalue) {
        self.blocks[bb].insts.push(Inst::Assign(var, val));
    }

    #[inline]
    pub(crate) fn push_expr(&mut self, bb: BasicBlockId, val: Rvalue) {
        self.blocks[bb].insts.push(Inst::Expr(val));
    }
}

impl Default for Body {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Literal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(l0), Self::Str(r0)) => l0 == r0,
            (Self::Bool(l0), Self::Bool(r0)) => l0 == r0,
            (Self::Number(l0), Self::Number(r0)) => l0 == r0,
            (Self::RegExp(l0, l1), Self::RegExp(r0, r1)) => l0 == r0 && l1 == r1,
            (Self::BigInt(l0), Self::BigInt(r0)) => l0 == r0,
            (l0, r0) => mem::discriminant(l0) == mem::discriminant(r0),
        }
    }
}

// I don't like it either, but in JS NaNs are compared bitwise
impl Eq for Literal {}

impl Hash for Literal {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        mem::discriminant(self).hash(state);
        match self {
            Literal::Str(s) => s.hash(state),
            Literal::Bool(b) => b.hash(state),
            Literal::Null | Literal::Undef => {}
            Literal::Number(n) => n.to_bits().hash(state),
            Literal::BigInt(bn) => bn.hash(state),
            Literal::RegExp(s, t) => (s, t).hash(state),
        }
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Literal::Str((ref s, _)) => write!(f, "\"{s}\""),
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::Null => write!(f, "[null]"),
            Literal::Undef => write!(f, "[undefined]"),
            Literal::Number(n) => write!(f, "{n}"),
            Literal::BigInt(ref n) => write!(f, "{n}"),
            Literal::RegExp(ref regex, ref flags) => write!(f, "/{regex}/{flags}"),
        }
    }
}

impl Rvalue {
    pub(crate) fn with_literal(lit: Literal) -> Self {
        Rvalue::Read(Operand::Lit(lit))
    }

    pub(crate) fn with_name(name: VarId) -> Self {
        Rvalue::Read(Operand::Var(Variable::new(name)))
    }
}

impl Variable {
    #[inline]
    pub(crate) fn new(var: VarId) -> Self {
        Self {
            var,
            projections: smallvec![],
        }
    }

    #[inline]
    pub(crate) fn add_computed(&mut self, var: VarId) {
        self.projections.push(Projection::Computed(var));
    }

    #[inline]
    pub(crate) fn add_known(&mut self, lit: JsWord) {
        self.projections.push(Projection::Known(lit));
    }
}
