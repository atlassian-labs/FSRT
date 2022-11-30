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
use smallvec::smallvec_inline;
use smallvec::SmallVec;
use swc_core::ecma::ast;
use swc_core::ecma::ast::BinaryOp;
use swc_core::ecma::ast::JSXText;
use swc_core::ecma::ast::Lit;
use swc_core::ecma::ast::Null;
use swc_core::ecma::ast::Number;
use swc_core::ecma::ast::UnaryOp;
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
    Switch {
        scrutinee: Operand,
        targets: BranchTargets,
    },
    If {
        cond: Operand,
        cons: BasicBlockId,
        alt: BasicBlockId,
    },
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum Intrinsic {
    Authorize,
    Fetch,
    ApiCall,
    EnvRead,
    StorageRead,
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
    LocalDef(DefId),
    GlobalRef(DefId),
    Temp { parent: Option<DefId> },
    AnonClosure(DefId),
    Arg(DefId),
    Ret,
}

#[derive(Clone, Debug)]
pub struct Body {
    owner: Option<DefId>,
    blocks: TiVec<BasicBlockId, BasicBlock>,
    vars: TiVec<VarId, VarKind>,
    ident_to_local: FxHashMap<Id, VarId>,
    def_id_to_vars: FxHashMap<DefId, VarId>,
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
    Str(JsWord),
    JSXText(Atom),
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
    NeqEq,
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
    NullishCoalesce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnOp {
    Neg,
    Not,
    BitNot,
    Plus,
    TypeOf,
    Delete,
    Void,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Operand {
    Var(Variable),
    Lit(Literal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Base {
    This,
    Super,
    Var(VarId),
}

create_newtype! {
    pub struct Label(u32);
}

create_newtype! {
    pub struct VarId(u32);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Variable {
    pub(crate) base: Base,
    pub(crate) projections: SmallVec<[Projection; 1]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Projection {
    Known(JsWord),
    Computed(Base),
}

impl fmt::Display for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        for proj in &self.projections {
            match proj {
                Projection::Known(lit) => write!(f, "[\"{lit}\"]")?,
                Projection::Computed(id) => write!(f, "[{id}]")?,
            }
        }
        Ok(())
    }
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Base::This => write!(f, "this"),
            Base::Super => write!(f, "super"),
            Base::Var(id) => write!(f, "{}", id),
        }
    }
}

impl Body {
    #[inline]
    fn new() -> Self {
        let local_vars = vec![VarKind::Ret].into();
        Self {
            vars: local_vars,
            owner: None,
            blocks: Default::default(),
            ident_to_local: Default::default(),
            def_id_to_vars: Default::default(),
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
        self.ident_to_local
            .insert(id, self.vars.push_and_get_key(VarKind::LocalDef(def)));
    }

    #[inline]
    pub(crate) fn add_arg(&mut self, def: DefId, id: Id) {
        self.vars.push(VarKind::Arg(def));
        self.ident_to_local
            .insert(id, VarId((self.vars.len() - 1) as u32));
    }

    #[inline]
    pub(crate) fn get_or_insert_global(&mut self, def: DefId) -> VarId {
        *self
            .def_id_to_vars
            .entry(def)
            .or_insert_with(|| self.vars.push_and_get_key(VarKind::GlobalRef(def)))
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

    pub(crate) fn resolve_prop(&mut self, bb: BasicBlockId, opnd: Operand) -> Projection {
        match opnd {
            Operand::Lit(lit) => Projection::Known(lit.as_jsword()),
            Operand::Var(var) if var.projections.is_empty() => Projection::Computed(var.base),
            Operand::Var(_) => {
                Projection::Computed(Base::Var(self.push_tmp(bb, Rvalue::Read(opnd), None)))
            }
        }
    }

    pub(crate) fn push_tmp(
        &mut self,
        bb: BasicBlockId,
        val: Rvalue,
        parent: Option<DefId>,
    ) -> VarId {
        let var = self.vars.push_and_get_key(VarKind::Temp { parent });
        self.push_inst(bb, Inst::Assign(Variable::new(var), val));
        var
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
            Literal::JSXText(r) => r.hash(state),
        }
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Literal::Str(ref s) => write!(f, "\"{s}\""),
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::Null => write!(f, "[null]"),
            Literal::Undef => write!(f, "[undefined]"),
            Literal::Number(n) => write!(f, "{n}"),
            Literal::BigInt(ref n) => write!(f, "{n}"),
            Literal::RegExp(ref regex, ref flags) => write!(f, "/{regex}/{flags}"),
            Literal::JSXText(ref r) => write!(f, "JSX: \"{r}\""),
        }
    }
}

impl Literal {
    fn as_jsword(&self) -> JsWord {
        match self {
            Literal::Str(s) => s.clone(),
            Literal::Bool(b) => b.to_string().into(),
            Literal::Null => "null".into(),
            Literal::Undef => "undefined".into(),
            Literal::Number(n) => n.to_string().into(),
            Literal::BigInt(n) => n.to_string().into(),
            Literal::RegExp(regex, flags) => format!("/{regex}/{flags}").into(),
            Literal::JSXText(r) => r.to_string().into(),
        }
    }
}

impl Rvalue {
    pub(crate) fn with_literal(lit: Literal) -> Self {
        Rvalue::Read(Operand::Lit(lit))
    }

    pub(crate) fn with_var(name: VarId) -> Self {
        Rvalue::Read(Operand::Var(Variable::new(name)))
    }
}

impl Operand {
    pub(crate) const UNDEF: Self = Self::Lit(Literal::Undef);

    #[inline]
    pub(crate) fn with_literal(lit: Literal) -> Self {
        Self::Lit(lit)
    }

    #[inline]
    pub(crate) const fn with_var(name: VarId) -> Self {
        Self::Var(Variable::new(name))
    }
}

impl From<Literal> for Operand {
    #[inline]
    fn from(value: Literal) -> Self {
        Self::Lit(value)
    }
}

impl From<Lit> for Operand {
    fn from(value: Lit) -> Self {
        Self::Lit(value.into())
    }
}

impl From<UnaryOp> for UnOp {
    fn from(value: UnaryOp) -> Self {
        match value {
            UnaryOp::Minus => Self::Neg,
            UnaryOp::Plus => Self::Plus,
            UnaryOp::Bang => Self::Not,
            UnaryOp::Tilde => Self::BitNot,
            UnaryOp::TypeOf => Self::TypeOf,
            UnaryOp::Void => Self::Void,
            UnaryOp::Delete => Self::Delete,
        }
    }
}

impl From<&UnaryOp> for UnOp {
    fn from(value: &UnaryOp) -> Self {
        Self::from(*value)
    }
}

impl From<Lit> for Literal {
    fn from(value: Lit) -> Self {
        match value {
            Lit::Str(value) => Self::Str(value.value),
            Lit::Bool(b) => Self::Bool(b.value),
            Lit::Null(_) => Self::Null,
            Lit::Num(Number { value, .. }) => Self::Number(value),
            Lit::BigInt(ast::BigInt { value, .. }) => Self::BigInt(*value),
            Lit::Regex(ast::Regex { exp, flags, .. }) => Self::RegExp(exp, flags),
            Lit::JSXText(JSXText { value, .. }) => Self::JSXText(value),
        }
    }
}

impl From<BinaryOp> for BinOp {
    fn from(value: BinaryOp) -> Self {
        match value {
            BinaryOp::EqEq => Self::EqEq,
            BinaryOp::NotEq => Self::Neq,
            BinaryOp::EqEqEq => Self::EqEqEq,
            BinaryOp::NotEqEq => Self::NeqEq,
            BinaryOp::Lt => Self::Lt,
            BinaryOp::LtEq => Self::Le,
            BinaryOp::Gt => Self::Gt,
            BinaryOp::GtEq => Self::Ge,
            BinaryOp::LShift => Self::Lshift,
            BinaryOp::RShift => Self::Rshift,
            BinaryOp::ZeroFillRShift => Self::RshiftLogical,
            BinaryOp::Add => Self::Add,
            BinaryOp::Sub => Self::Sub,
            BinaryOp::Mul => Self::Mul,
            BinaryOp::Div => Self::Div,
            BinaryOp::Mod => Self::Mod,
            BinaryOp::BitOr => Self::BitOr,
            BinaryOp::BitXor => Self::BitXor,
            BinaryOp::BitAnd => Self::BitAnd,
            BinaryOp::LogicalOr => Self::Or,
            BinaryOp::LogicalAnd => Self::And,
            BinaryOp::In => Self::In,
            BinaryOp::InstanceOf => Self::InstanceOf,
            BinaryOp::Exp => Self::Exp,
            BinaryOp::NullishCoalescing => Self::NullishCoalesce,
        }
    }
}

impl From<&BinaryOp> for BinOp {
    fn from(value: &BinaryOp) -> Self {
        Self::from(*value)
    }
}

impl Variable {
    pub(crate) const THIS: Self = Self {
        base: Base::This,
        projections: SmallVec::new_const(),
    };

    pub(crate) const SUPER: Self = Self {
        base: Base::Super,
        projections: SmallVec::new_const(),
    };

    #[inline]
    pub(crate) const fn new(var: VarId) -> Self {
        Self {
            base: Base::Var(var),
            projections: SmallVec::new_const(),
        }
    }

    #[inline]
    pub(crate) fn add_computed_var(&mut self, var: VarId) {
        self.projections.push(Projection::Computed(Base::Var(var)));
    }

    #[inline]
    pub(crate) fn add_known(&mut self, lit: JsWord) {
        self.projections.push(Projection::Known(lit));
    }
}
