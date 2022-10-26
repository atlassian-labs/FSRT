#![allow(dead_code, unused_imports)]

// TODO: Use [`SSA`] instead
// [`SSA`]: https://pfalcon.github.io/ssabook/latest/book-full.pdf

use std::collections::BTreeSet;

use forge_utils::create_newtype;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use swc_core::ecma::{ast::Id, atoms::Atom};
use typed_index_collections::TiVec;

use crate::ctx::ModId;

create_newtype! {
    pub struct BasicBlockId(u32);
}

#[derive(Clone, Debug)]
struct BranchTargets {
    compare: SmallVec<[Operand; 1]>,
    branch: SmallVec<[BasicBlockId; 2]>,
}

#[derive(Clone, Debug)]
enum Terminator {
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

#[derive(Clone, Debug)]
enum Rvalue {
    Unary(UnOp, Operand),
    Bin(BinOp, Operand, Operand),
    Read(Variable),
    Template {
        quasis: Vec<Atom>,
        exprs: Vec<Operand>,
        // TODO: make this more memory efficient
        tag: Option<Operand>,
    },
}

#[derive(Clone, Debug)]
struct BasicBlock {
    stmts: Vec<Stmt>,
    term: Terminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Location {
    block: BasicBlockId,
    stmt: u32,
}

#[derive(Clone, Default, Debug)]
struct Function {
    blocks: TiVec<BasicBlockId, BasicBlock>,
    vars: TiVec<VarId, Id>,
    id_to_var: FxHashMap<Id, VarId>,
    predecessors: BTreeSet<(BasicBlockId, BasicBlockId)>,
    successors: BTreeSet<(BasicBlockId, BasicBlockId)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiCall {
    Authorize,
    Unauthorized,
    Noop,
}

#[derive(Clone, Debug)]
enum Stmt {
    // maybe just use assign with a dummy VARIABLE for these?
    Expr(Rvalue),
    Assign(Variable, Rvalue),
}

#[derive(Clone, Debug, PartialEq)]
enum Literal {
    Str(Id),
    Bool(bool),
    Null,
    Undef, // what a bunk language
    Number(f64),
    BigInt,
    // regexp, flags
    RegExp(Atom, Atom),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinOp {
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
enum UnOp {
    Neg,
    Not,
    BitNot,
    Plus,
    TypeOf,
    Delete,
}

#[derive(Clone, Debug, PartialEq)]
enum Operand {
    Var(Variable),
    Lit(Literal),
    Global(ModId, Id),
}

create_newtype! {
    pub struct Label(u32);
}

create_newtype! {
    pub struct VarId(u32);
}

#[derive(Clone, Debug, PartialEq)]
struct Variable {
    var: VarId,
    projections: SmallVec<[Projection; 1]>,
}

#[derive(Clone, Debug, PartialEq)]
enum Projection {
    Lit(Literal),
    Var(VarId),
}

impl Function {
    fn new() -> Self {
        Function::default()
    }
}
