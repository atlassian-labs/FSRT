#![allow(dead_code, unused_imports)]

// TODO: Use [`SSA`] instead
// [`SSA`]: https://pfalcon.github.io/ssabook/latest/book-full.pdf

use core::fmt;
use std::array;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::hash;
use std::hash::Hash;
use std::mem;
use std::num::NonZeroUsize;
use std::slice;

use forge_utils::create_newtype;
use forge_utils::FxHashMap;
use once_cell::unsync::OnceCell;
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
use crate::definitions::Class;
use crate::definitions::DefId;
use crate::definitions::DefKind;
use crate::definitions::Environment;
use crate::definitions::IntrinsicName;
use crate::definitions::PackageData;
use crate::definitions::Value;

pub const STARTING_BLOCK: BasicBlockId = BasicBlockId(0);

create_newtype! {
    pub struct BasicBlockId(u32);
}

#[derive(Clone, Debug)]
pub struct BranchTargets {
    compare: SmallVec<[Operand; 1]>,
    branch: SmallVec<[BasicBlockId; 2]>,
}

#[derive(Clone, Debug, Default)]
pub enum Terminator {
    #[default]
    Ret,
    Goto(BasicBlockId),
    Throw,
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

// FIXME: ideally we should record the API call expression in the IR and the `UserFieldAccess` and `ApiCustomField` variants
// should be removed and the type of the API call should be determined during dataflow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Intrinsic {
    Authorize(IntrinsicName),
    Fetch,
    UserFieldAccess,
    ApiCustomField,
    ApiCall(IntrinsicName),
    SafeCall(IntrinsicName),
    SecretFunction(PackageData),
    EnvRead,
    StorageRead,
}

#[derive(Clone, Debug, Default)]
pub struct Template {
    pub(crate) quasis: Vec<Atom>,
    pub(crate) exprs: Vec<Operand>,
    // TODO: make this more memory efficient
    // the semantics of this operation can probably be moved to call
    pub(crate) tag: Option<Operand>,
}

#[derive(Clone, Debug)]
pub enum Rvalue {
    Unary(UnOp, Operand),
    Bin(BinOp, Operand, Operand),
    Read(Operand),
    Call(Operand, SmallVec<[Operand; 4]>),
    Intrinsic(Intrinsic, SmallVec<[Operand; 4]>),
    Phi(Vec<(VarId, BasicBlockId)>),
    Template(Template),
}

#[derive(Clone, Debug, Default)]
pub struct BasicBlock {
    pub insts: Vec<Inst>,
    pub term: Terminator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Location {
    pub block: BasicBlockId,
    pub stmt: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarKind {
    LocalDef(DefId),
    GlobalRef(DefId),
    Temp { parent: Option<DefId> },
    AnonClosure(DefId),
    Arg(DefId),
    Ret,
}

pub(crate) const RETURN_VAR: Variable = Variable {
    base: Base::Var(VarId(0)),
    projections: SmallVec::new_const(),
};

#[derive(Clone, Debug)]
pub struct Body {
    owner: Option<DefId>,
    pub blocks: TiVec<BasicBlockId, BasicBlock>,
    pub vars: TiVec<VarId, VarKind>,
    pub values: FxHashMap<DefId, Value>,
    ident_to_local: FxHashMap<Id, VarId>,
    pub def_id_to_vars: FxHashMap<DefId, VarId>,
    pub class_instantiations: HashMap<DefId, DefId>,
    predecessors: OnceCell<TiVec<BasicBlockId, SmallVec<[BasicBlockId; 2]>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiCall {
    Authorize,
    Unauthorized,
    Noop,
}

#[derive(Clone, Debug)]
pub enum Inst {
    // maybe just use assign with a dummy VARIABLE for these?
    Expr(Rvalue),
    Assign(Variable, Rvalue),
}

#[derive(Clone, Debug, Default)]
pub enum Literal {
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
pub enum BinOp {
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
pub enum UnOp {
    Neg,
    Not,
    BitNot,
    Plus,
    TypeOf,
    Delete,
    Void,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Operand {
    Var(Variable),
    Lit(Literal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Base {
    #[default]
    This,
    Super,
    Var(VarId),
}

create_newtype! {
    pub struct Label(u32);
}

create_newtype! {
    pub struct VarId(pub u32);
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Variable {
    pub(crate) base: Base,
    pub(crate) projections: SmallVec<[Projection; 1]>,
}

impl From<VarId> for Variable {
    fn from(varid: VarId) -> Variable {
        Variable {
            base: Base::Var(varid),
            projections: SmallVec::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Projection {
    Known(JsWord),
    Computed(Base),
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub(crate) enum Successors {
    Return,
    One(BasicBlockId),
    Two(BasicBlockId, BasicBlockId),
}

impl BasicBlock {
    #[inline]
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &Inst> + ExactSizeIterator {
        self.insts.iter()
    }

    pub(crate) fn successors(&self) -> Successors {
        match self.term {
            Terminator::Ret => Successors::Return,
            Terminator::Goto(bb) => Successors::One(bb),
            Terminator::Throw => Successors::Return,
            Terminator::Switch { ref targets, .. } => {
                if targets.branch.len() == 1 {
                    Successors::One(targets.branch[0])
                } else {
                    Successors::Two(targets.branch[0], targets.branch[1])
                }
            }
            Terminator::If { cons, alt, .. } => Successors::Two(cons, alt),
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
            blocks: vec![BasicBlock::default()].into(),
            values: FxHashMap::default(),
            class_instantiations: Default::default(),
            ident_to_local: Default::default(),
            def_id_to_vars: Default::default(),
            predecessors: Default::default(),
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
    pub(crate) fn iter_vars(&self) -> impl Iterator<Item = &VarKind> {
        self.vars.iter()
    }

    #[inline]
    pub(crate) fn iter_vars_enumerated(&self) -> impl Iterator<Item = (VarId, &VarKind)> {
        self.vars.iter_enumerated()
    }

    pub(crate) fn iter_block_keys(
        &self,
    ) -> impl ExactSizeIterator<Item = BasicBlockId> + DoubleEndedIterator + '_ {
        self.blocks.iter_enumerated().map(|(bb, _)| bb)
    }

    #[inline]
    pub(crate) fn iter_blocks_enumerated(
        &self,
    ) -> impl ExactSizeIterator<Item = (BasicBlockId, &BasicBlock)> + DoubleEndedIterator {
        self.blocks.iter_enumerated()
    }

    #[inline]
    pub(crate) fn owner(&self) -> Option<DefId> {
        self.owner
    }

    #[inline]
    pub(crate) fn add_var(&mut self, kind: VarKind) -> VarId {
        self.vars.push_and_get_key(kind)
    }

    #[inline]
    pub(crate) fn add_local_def(&mut self, def: DefId, id: Id) {
        self.ident_to_local
            .insert(id, self.vars.push_and_get_key(VarKind::LocalDef(def)));
    }

    #[inline]
    pub(crate) fn add_arg(&mut self, def: DefId, id: Id) -> VarId {
        let var_id = self.vars.push_and_get_key(VarKind::Arg(def));
        self.ident_to_local
            .insert(id, VarId((self.vars.len() - 1) as u32));
        var_id
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

    pub(crate) fn new_blocks<const NUM: usize>(&mut self) -> [BasicBlockId; NUM] {
        array::from_fn(|_| self.new_block())
    }

    #[inline]
    pub(crate) fn new_block_with_terminator(&mut self, term: Terminator) -> BasicBlockId {
        self.blocks.push_and_get_key(BasicBlock {
            term,
            ..Default::default()
        })
    }

    pub(crate) fn predecessors(&self, block: BasicBlockId) -> &[BasicBlockId] {
        &self.predecessors.get_or_init(|| {
            let mut preds: TiVec<_, _> = vec![SmallVec::new(); self.blocks.len()].into();
            for (bb, block) in self.iter_blocks_enumerated() {
                match block.successors() {
                    Successors::Return => {}
                    Successors::One(s) => preds[s].push(bb),
                    Successors::Two(s1, s2) => {
                        preds[s1].push(bb);
                        preds[s2].push(bb);
                    }
                }
            }
            preds
        })[block]
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

    pub fn resolve_call<'cx>(
        &self,
        env: &'cx Environment,
        callee: &Operand,
    ) -> Option<(DefId, &'cx Body)> {
        match callee {
            Operand::Var(Variable {
                base: Base::Var(var),
                projections,
            }) => match self.vars[*var] {
                VarKind::LocalDef(def) | VarKind::GlobalRef(def) => {
                    let def = env.resolve_alias(def);
                    match env.def_ref(def) {
                        DefKind::Function(f) | DefKind::Closure(f) => Some((def, f)),
                        DefKind::GlobalObj(o) | DefKind::Class(o) => {
                            let [Projection::Known(ref mem)] = **projections else {
                                return None;
                            };
                            let mem_def = o.find_member(mem);
                            mem_def.zip(env.def_ref(mem_def?).as_body().copied())
                        }
                        DefKind::ModuleNs(n) => {
                            let [Projection::Known(ref mem)] = **projections else {
                                return None;
                            };
                            let module_export = env.module_export(n, mem);
                            module_export.zip(env.def_ref(module_export?).as_body().copied())
                        }
                        DefKind::ExportAlias(_)
                        | DefKind::Foreign(_)
                        | DefKind::ResolverHandler(_)
                        | DefKind::Resolver(_)
                        | DefKind::ResolverDef(_)
                        | DefKind::Undefined
                        | DefKind::Arg => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn coerce_to_lval(
        &mut self,
        bb: BasicBlockId,
        val: Operand,
        parent_key: Option<DefId>,
    ) -> Variable {
        match val {
            Operand::Var(var) => var,
            Operand::Lit(_) => Variable {
                base: Base::Var({
                    let var = self
                        .vars
                        .push_and_get_key(VarKind::Temp { parent: parent_key });
                    self.push_inst(bb, Inst::Assign(Variable::new(var), Rvalue::Read(val)));
                    var
                }),
                projections: Default::default(),
            },
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

    #[inline]
    pub(crate) fn block(&self, bb: BasicBlockId) -> &BasicBlock {
        &self.blocks[bb]
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

    pub(crate) fn as_var_id(&self) -> Option<VarId> {
        match self.base {
            Base::Var(var) => Some(var),
            _ => None,
        }
    }

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

    pub(crate) fn as_call(&self) -> Option<(&Operand, &[Operand])> {
        match self {
            Rvalue::Call(callee, args) => Some((callee, args)),
            _ => None,
        }
    }

    pub(crate) fn as_var(&self) -> Option<&Variable> {
        match self {
            Rvalue::Read(Operand::Var(var)) => Some(var),
            _ => None,
        }
    }
}

impl Location {
    #[inline]
    pub fn new(block: BasicBlockId, stmt: u32) -> Self {
        Self { block, stmt }
    }
}

impl Inst {
    pub(crate) fn rvalue(&self) -> &Rvalue {
        match self {
            Inst::Assign(_, r) | Inst::Expr(r) => r,
        }
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

impl<'a> IntoIterator for &'a BasicBlock {
    type Item = &'a Inst;

    type IntoIter = slice::Iter<'a, Inst>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.insts.iter()
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
            Base::Var(id) => write!(f, "{id}"),
        }
    }
}

impl fmt::Display for BasicBlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Var(v) => write!(f, "{v}"),
            Operand::Lit(l) => write!(f, "{l}"),
        }
    }
}

impl fmt::Display for Terminator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Terminator::Ret => write!(f, "return"),
            Terminator::Goto(bb) => write!(f, "goto {bb}"),
            Terminator::Throw => write!(f, "throw"),
            Terminator::Switch { .. } => write!(f, "switch"),
            Terminator::If { cond, cons, alt } => {
                write!(f, "if ({cond}) then goto {cons} else goto {alt}")
            }
        }
    }
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for inst in &self.insts {
            writeln!(f, "    {inst}")?;
        }
        write!(f, "    {}", &self.term)
    }
}

impl fmt::Display for UnOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            UnOp::Neg => write!(f, "-"),
            UnOp::Not => write!(f, "!"),
            UnOp::BitNot => write!(f, "~"),
            UnOp::Plus => write!(f, "+"),
            UnOp::TypeOf => write!(f, "typeof"),
            UnOp::Delete => write!(f, "delete"),
            UnOp::Void => write!(f, "void"),
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            BinOp::Lt => write!(f, "<"),
            BinOp::Gt => write!(f, ">"),
            BinOp::EqEq => write!(f, "=="),
            BinOp::Neq => write!(f, "!="),
            BinOp::NeqEq => write!(f, "!=="),
            BinOp::EqEqEq => write!(f, "==="),
            BinOp::Ge => write!(f, ">="),
            BinOp::Le => write!(f, "<="),
            BinOp::Add => write!(f, "+"),
            BinOp::Sub => write!(f, "-"),
            BinOp::Mul => write!(f, "*"),
            BinOp::Div => write!(f, "/"),
            BinOp::Exp => write!(f, "**"),
            BinOp::Mod => write!(f, "%"),
            BinOp::Or => write!(f, "||"),
            BinOp::And => write!(f, "&&"),
            BinOp::BitOr => write!(f, "|"),
            BinOp::BitAnd => write!(f, "&"),
            BinOp::BitXor => write!(f, "^"),
            BinOp::Lshift => write!(f, "<<"),
            BinOp::Rshift => write!(f, ">>"),
            BinOp::RshiftLogical => write!(f, ">>>"),
            BinOp::In => write!(f, "in"),
            BinOp::InstanceOf => write!(f, "instanceof"),
            BinOp::NullishCoalesce => write!(f, "??"),
        }
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`")?;
        let mut exprs = self.exprs.iter();
        for quasi in &self.quasis {
            write!(f, "{quasi}")?;
            if let Some(expr) = exprs.next() {
                write!(f, "{{{}}}", expr)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Inst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inst::Expr(rval) => write!(f, "_ = {rval}"),
            Inst::Assign(lval, rval) => write!(f, "{lval} = {rval}"),
        }
    }
}

impl fmt::Display for Intrinsic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Intrinsic::Fetch => write!(f, "fetch"),
            Intrinsic::Authorize(_) => write!(f, "authorize"),
            Intrinsic::SecretFunction(_) => write!(f, "secret function"),
            Intrinsic::ApiCall(_) => write!(f, "api call"),
            Intrinsic::ApiCustomField => write!(f, "accessing custom field route asApp"),
            Intrinsic::UserFieldAccess => write!(f, "accessing which fields a user can access"),
            Intrinsic::SafeCall(_) => write!(f, "safe api call"),
            Intrinsic::EnvRead => write!(f, "env read"),
            Intrinsic::StorageRead => write!(f, "forge storage read"),
        }
    }
}

impl fmt::Display for Rvalue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Rvalue::Unary(op, ref opnd) => write!(f, "{op} {opnd}"),
            Rvalue::Bin(op, ref lhs, ref rhs) => write!(f, "{lhs} {op} {rhs}"),
            Rvalue::Call(ref op, ref args) => {
                write!(f, "{op}(")?;
                for arg in args {
                    write!(f, "{arg}, ")?;
                }
                write!(f, ")")
            }
            Rvalue::Intrinsic(ref intrinsic, ref args) => {
                write!(f, "{intrinsic}(")?;
                for arg in args {
                    write!(f, "{arg}, ")?;
                }
                write!(f, ")")
            }
            Rvalue::Read(ref opnd) => write!(f, "{opnd}"),
            Rvalue::Phi(ref phis) => {
                write!(f, "phi(")?;
                for &(var, block) in phis {
                    write!(f, "{block}: {var}, ")?;
                }
                write!(f, ")")
            }
            Rvalue::Template(ref template) => write!(f, "{template}"),
        }
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
impl Default for Body {
    #[inline]
    fn default() -> Self {
        Self::new()
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
}

impl PartialEq for Literal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Str(l0), Self::Str(r0)) => *l0 == *r0,
            (Self::Bool(l0), Self::Bool(r0)) => *l0 == *r0,
            (Self::Number(l0), Self::Number(r0)) => *l0 == *r0,
            (Self::RegExp(l0, l1), Self::RegExp(r0, r1)) => *l0 == *r0 && *l1 == *r1,
            (Self::BigInt(l0), Self::BigInt(r0)) => *l0 == *r0,
            (Self::JSXText(l0), Self::JSXText(r0)) => *l0 == *r0,
            (Self::Null, Self::Null) | (Self::Undef, Self::Undef) => true,
            // We intentionally list out every possibility instead of using [`std::mem::discriminant`] to trigger a compile error
            // in the event that a new variant with a field is added.
            (
                Self::Bool(_)
                | Self::Str(_)
                | Self::JSXText(_)
                | Self::BigInt(_)
                | Self::Number(_)
                | Self::RegExp(_, _)
                | Self::Null
                | Self::Undef,
                _,
            ) => false,
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
