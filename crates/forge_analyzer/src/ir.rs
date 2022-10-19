#![allow(dead_code, unused_imports)]

// TODO: Use [`SSA`] instead
// [`SSA`]: https://pfalcon.github.io/ssabook/latest/book-full.pdf

use forge_utils::create_newtype;
use swc_core::ecma::ast::Id;

use crate::ctx::ModId;

enum Rvalue {
    Unary(UnOp, Operand),
    Bin(BinOp, Operand, Operand),
    Read(Variable),
}

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

enum UnOp {
    Neg,
    Not,
    BitNot,
    Plus,
    TypeOf,
    Delete,
}

enum StmtKind {
    Expr,
    Assign,
    Ret,
    Loop,
    Goto,
}

enum Literal {
    Str,
    Bool(bool),
    Null,
    Undef, // what a bunk language
    Number(f64),
    RegExp,
}

enum Operand {
    Var(Variable),
    Lit(Literal),
}

create_newtype! {
    pub struct VarId(u32);
}

struct Variable {
    var: VarId,
    projections: Vec<Projection>,
}

enum Projection {
    Lit(Literal),
    Var(VarId),
}
