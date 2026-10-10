//! Reusable, forward may-taint analysis over the lowered IR.
//!
//! Policies define sources, property-read propagation and sinks. A policy's sink
//! predicate sees the state *before* each instruction. Only positive sink locations
//! are retained, rather than a full variable-state snapshot at every instruction.
//! Function inputs and returns are joined to a fixed point, including loops and
//! recursion. Values are tracked per function and variable and, for policies that
//! opt in, per known property path. Object properties and external calls are
//! conservatively treated as propagators unless a policy opts out; function
//! summaries are shared only by equivalent bounded entry contexts. A capped
//! overflow context joins additional inputs conservatively. Source provenance
//! and policy facts are independent, and a pending return is not a clean value.
//! lodash's `omit`, `pick` and `get` with literal paths select properties instead.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::{Bound, ControlFlow},
    rc::Rc,
};

use itertools::Itertools;
use smallvec::SmallVec;
use swc_core::ecma::atoms::Atom;

mod state;
mod value;
use state::{FieldMap, Fields};
pub use state::{FlowState, TrackedValue};
pub use value::{FlowFacts, FlowValue};

use crate::{
    definitions::{DefId, Environment, ImportKind},
    interp::{Dataflow, EntryKind, Interp, JoinSemiLattice, Runner},
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Body, Inst, Intrinsic, Literal, Location, Operand,
        Projection, Rvalue, STARTING_BLOCK, Successors, UnOp, VarId, VarKind,
    },
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub enum Taint {
    #[default]
    No,
    /// May carry a source. Each policy's sink decides whether it reports this.
    Unknown,
    /// A known source always survives a join with an unknown value.
    Yes,
}

impl JoinSemiLattice for Taint {
    const BOTTOM: Self = Self::No;

    fn join_changed(&mut self, other: &Self) -> bool {
        let old = *self;
        *self = self.join(other);
        old != *self
    }

    fn join(&self, other: &Self) -> Self {
        (*self).max(*other)
    }
}

impl<D: JoinSemiLattice + Clone> JoinSemiLattice for Vec<D> {
    const BOTTOM: Self = vec![];

    fn join_changed(&mut self, other: &Self) -> bool {
        let mut changed = self.len() < other.len();
        self.resize_with(self.len().max(other.len()), || D::BOTTOM);
        for (left, right) in self.iter_mut().zip(other) {
            changed |= left.join_changed(right);
        }
        changed
    }

    fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.join_changed(other);
        result
    }
}

/// Add sources and sinks for another scanner without duplicating the propagation
/// engine. A runner passes its configured policy to `TaintDataflow::new` from
/// `Runner::dataflow`.
pub trait TaintPolicy: Sized {
    type Facts: FlowFacts;
    /// Whether resolver request arguments are sources for this policy.
    const TAINT_RESOLVER_INPUT: bool = false;

    fn intrinsic_value(&self, intrinsic: &Intrinsic) -> FlowValue<Self::Facts>;
    /// Observe the state before the instruction, never a joined function exit.
    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool;
    /// Track writes and copies of known property paths independently.
    fn tracks_fields(&self) -> bool {
        false
    }
    /// Read an untracked property from its nearest known ancestor. Only the
    /// final name is supplied; `None` denotes a computed property. This transfer
    /// must be monotone and preserve the absence of source data in clean values.
    fn property_value(
        &self,
        base: FlowValue<Self::Facts>,
        _name: Option<&str>,
    ) -> FlowValue<Self::Facts> {
        base
    }

    fn binary_value(
        &self,
        op: BinOp,
        left: FlowValue<Self::Facts>,
        right: FlowValue<Self::Facts>,
    ) -> FlowValue<Self::Facts> {
        match op {
            BinOp::Or | BinOp::And | BinOp::NullishCoalesce => left.join(&right),
            _ if binary_taint(op, Taint::Yes, Taint::Yes) == Taint::No => left
                .combine(&right)
                .with_facts(Self::Facts::from_taint(Taint::No)),
            _ => left.combine(&right),
        }
    }

    /// Classify undeclared globals using the complete property path, so a rule
    /// for a builtin does not also match an unrelated method with the same name.
    fn global_call_value(
        &self,
        _name: &str,
        _path: &[Projection],
    ) -> Option<FlowValue<Self::Facts>> {
        None
    }
    /// Classify an unresolved call. Returning `None` combines receiver and
    /// arguments. A safety guarantee must hold for every input alternative.
    fn method_value(
        &self,
        _call: &UnresolvedCall<'_, Self::Facts>,
    ) -> Option<FlowValue<Self::Facts>> {
        None
    }
}

/// An unmodelled call, as `TaintPolicy::method_value` sees it.
pub struct UnresolvedCall<'a, F> {
    /// The last property name for a method call, or the bound name for a bare
    /// call to a global or imported binding.
    pub method: &'a str,
    pub receiver: FlowValue<F>,
    pub args: &'a [FlowValue<F>],
    callee: &'a Operand,
    operands: &'a [Operand],
    env: &'a Environment,
    body: &'a Body,
    layout: &'a Bindings,
    def: DefId,
    location: Location,
}

/// A string index, counted from the start or back from the end.
#[derive(Clone, Copy)]
enum Index {
    Start(f64),
    End(f64),
}

impl Index {
    /// `slice` and `substr` count a negative index back from the end.
    fn signed(self) -> Self {
        match self {
            Self::Start(index) if index < 0.0 => Self::End(-index),
            index => index,
        }
    }
}

impl<F> UnresolvedCall<'_, F> {
    /// The calling function and the call's location in it.
    pub fn site(&self) -> (DefId, Location) {
        (self.def, self.location)
    }

    pub fn function(&self) -> &str {
        self.env.def_name(self.def)
    }

    /// The most characters a `slice`, `substring` or `substr` method call can
    /// return, when its bounds are literals or offsets from the receiver's own
    /// `length`: `key.slice(-4)` and `key.substring(key.length - 4)` return at
    /// most 4, while `key.slice(7)` is unbounded. Arrays share `slice`.
    pub fn max_substring_len(&self) -> Option<f64> {
        let Operand::Var(callee) = self.callee else {
            return None;
        };
        let (Projection::Known(method), receiver) = callee.projections.split_last()? else {
            return None;
        };
        // A missing start returns the whole string; a missing end is the end.
        let start = self.index(callee.base, receiver, self.operands.first()?)?;
        let end = || match self.operands.get(1) {
            Some(operand) => self.index(callee.base, receiver, operand),
            None => Some(Index::End(0.0)),
        };
        let len = match &**method {
            "slice" => match (start.signed(), end()?.signed()) {
                (Index::End(start), Index::End(end)) => (start - end).max(0.0),
                (Index::End(start), Index::Start(_)) => start,
                (Index::Start(start), Index::Start(end)) => (end - start).max(0.0),
                (Index::Start(_), Index::End(_)) => return None,
            },
            // `substring` clamps negative indexes to 0 and swaps reversed bounds.
            "substring" => match (start, end()?) {
                (Index::Start(start), Index::Start(end)) => (end.max(0.0) - start.max(0.0)).abs(),
                (Index::End(start), Index::End(end)) => (start - end).abs(),
                _ => return None,
            },
            "substr" => match self.operands.get(1) {
                Some(len) => self.number(len)?.max(0.0),
                None => match start.signed() {
                    Index::End(start) => start,
                    Index::Start(_) => return None,
                },
            },
            _ => return None,
        };
        len.is_finite().then_some(len)
    }

    /// A literal index, or the receiver's `length` less a literal.
    fn index(&self, base: Base, receiver: &[Projection], operand: &Operand) -> Option<Index> {
        let is_length = |operand: &Operand| {
            matches!(operand, Operand::Var(var)
            if self.same_binding(var.base, base)
                && var.projections.split_last().is_some_and(|(last, rest)| {
                    matches!(last, Projection::Known(name) if *name == *"length")
                        && rest == receiver
                }))
        };
        if let Some(index) = self.number(operand) {
            return Some(Index::Start(index));
        }
        if is_length(operand) {
            return Some(Index::End(0.0));
        }
        match self.layout.definition(self.body, operand)? {
            Rvalue::Bin(BinOp::Sub, length, offset) if is_length(length) => self
                .number(offset)
                .filter(|&offset| offset >= 0.0)
                .map(Index::End),
            _ => None,
        }
    }

    fn number(&self, operand: &Operand) -> Option<f64> {
        match operand {
            Operand::Lit(Literal::Number(n)) => Some(*n).filter(|n| n.is_finite()),
            Operand::Lit(_) => None,
            Operand::Var(_) => match self.layout.definition(self.body, operand)? {
                Rvalue::Unary(UnOp::Neg, operand) => self.number(operand).map(|n| -n),
                Rvalue::Read(operand) => self.number(operand),
                _ => None,
            },
        }
    }

    fn same_binding(&self, left: Base, right: Base) -> bool {
        match (left, right) {
            (Base::Var(left), Base::Var(right)) => {
                left == right
                    || variable_def(&self.body.vars[left])
                        .is_some_and(|def| variable_def(&self.body.vars[right]) == Some(def))
            }
            _ => false,
        }
    }
}

/// Reads the state before an instruction the same way propagation does.
pub struct TaintReader<'a, P: TaintPolicy> {
    dataflow: &'a TaintDataflow<P>,
    frame: &'a FlowState<P::Facts>,
}

impl<P: TaintPolicy> TaintReader<'_, P> {
    /// The value read by `operand`, including property projection and facts.
    pub fn operand(&self, operand: &Operand) -> FlowValue<P::Facts> {
        self.dataflow.read(self.frame, operand)
    }

    /// A whole-variable read, including data held in its tracked properties.
    pub fn var(&self, id: VarId) -> FlowValue<P::Facts> {
        self.frame.value(id).aggregate()
    }
}

fn method_name(callee: &Operand) -> Option<&str> {
    match callee {
        Operand::Var(var) => match var.projections.last()? {
            Projection::Known(name) => Some(name),
            Projection::Computed(_) => None,
        },
        Operand::Lit(_) => None,
    }
}

/// The name a policy's `method_taint` sees for an unresolved call: the last
/// property name for a method call (`obj.method()`), or the bound name for a
/// bare call to a global or imported binding (`fetch()`), since both shapes
/// can equally be a well-known function a policy wants to recognize.
fn callee_name<'cx>(
    env: &'cx Environment,
    body: &'cx Body,
    callee: &'cx Operand,
) -> Option<&'cx str> {
    method_name(callee).or_else(|| {
        let Operand::Var(var) = callee else {
            return None;
        };
        if !var.projections.is_empty() {
            return None;
        }
        let def = variable_def(&body.vars[var.as_var_id()?])?;
        Some(env.def_name(def))
    })
}

fn argument_vars(body: &Body) -> impl Iterator<Item = (VarId, DefId)> + '_ {
    body.vars.iter_enumerated().filter_map(|(id, kind)| {
        if let VarKind::Arg(def) = kind {
            Some((id, *def))
        } else {
            None
        }
    })
}

fn variable_def(kind: &VarKind) -> Option<DefId> {
    match kind {
        VarKind::Arg(def) | VarKind::GlobalRef(def) | VarKind::LocalDef(def) => Some(*def),
        _ => None,
    }
}

/// A call must use the callee's inputs, never the caller's variable indices.
pub fn visit_taint_call<'cx, C: Runner<'cx, State = Vec<Taint>>>(
    checker: &mut C,
    interp: &Interp<'cx, C>,
    callee: &Operand,
    block: BasicBlockId,
    state: &[Taint],
) -> ControlFlow<(), Vec<Taint>> {
    if let Some((def, body)) = interp.body().resolve_call(interp.env(), callee)
        && !interp
            .runner_visited
            .borrow()
            .contains(&(def, STARTING_BLOCK))
    {
        interp.push_frame(def, block);
        let result = checker.visit_body(interp, def, body, &Vec::new());
        interp.pop_frame();
        result?;
    }
    ControlFlow::Continue(state.to_vec())
}

pub struct TaintDataflow<P> {
    policy: P,
}

impl<P> TaintDataflow<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
}

/// Zero is a root invocation. One is reserved for entirely clean calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct ContextId(usize);
const MAX_CONTEXTS: usize = 8;
const OVERFLOW: ContextId = ContextId(MAX_CONTEXTS + 1);

type CallInput<F> = (Vec<TrackedValue<F>>, BTreeMap<DefId, TrackedValue<F>>);

#[derive(Default)]
struct Queue {
    pending: VecDeque<(DefId, ContextId, BasicBlockId)>,
    queued: BTreeSet<(DefId, ContextId, BasicBlockId)>,
}

impl Queue {
    fn push(&mut self, key: (DefId, ContextId, BasicBlockId)) {
        if self.queued.insert(key) {
            self.pending.push_back(key);
        }
    }

    fn pop(&mut self) -> Option<(DefId, ContextId, BasicBlockId)> {
        let key = self.pending.pop_front()?;
        self.queued.remove(&key);
        Some(key)
    }
}

/// Known property names along a path, such as `["auth", "password"]`.
type FieldPath = SmallVec<[Atom; 2]>;

/// Deeper writes are summarized by their prefix, which bounds self-referential
/// writes such as `node.next = node` in a loop.
const MAX_FIELD_DEPTH: usize = 4;

fn known_prefix(projections: &[Projection]) -> FieldPath {
    projections
        .iter()
        .map_while(|projection| match projection {
            Projection::Known(name) => Some(name.clone()),
            Projection::Computed(_) => None,
        })
        .collect()
}

/// The tracked properties under `prefix`, keyed relative to it.
fn fields_under<F: FlowFacts>(source: &FieldMap<F>, prefix: &[Atom]) -> Option<Fields<F>> {
    let copied: FieldMap<F> = source
        .range::<[Atom], _>((Bound::Excluded(prefix), Bound::Unbounded))
        .take_while(|(path, _)| path.starts_with(prefix))
        .map(|(path, value)| (FieldPath::from(&path[prefix.len()..]), value.clone()))
        .collect();
    (!copied.is_empty()).then(|| Rc::new(copied))
}

struct Bindings {
    aliases: BTreeMap<DefId, SmallVec<[VarId; 2]>>,
    args: Vec<VarId>,
    /// The location of each temporary's only whole assignment, so literal
    /// arguments such as `-4` can be read back out of the IR.
    temps: BTreeMap<VarId, Option<Location>>,
    /// Array literals of strings, such as `['token']`, which lower to index
    /// writes like `%a["0"] = "token"` to a fresh local that is never assigned
    /// whole. `None` once any other write is seen.
    strings: BTreeMap<VarId, Option<SmallVec<[Atom; 2]>>>,
}

impl Bindings {
    fn new(body: &Body) -> Self {
        let mut aliases = BTreeMap::<_, SmallVec<_>>::new();
        for (id, kind) in body.vars.iter_enumerated() {
            if let Some(binding) = variable_def(kind) {
                aliases.entry(binding).or_default().push(id);
            }
        }
        let mut temps = BTreeMap::new();
        let mut strings = BTreeMap::<_, Option<SmallVec<_>>>::new();
        for (bb, block) in body.iter_blocks_enumerated() {
            for (idx, inst) in block.iter().enumerate() {
                let Inst::Assign(var, rvalue) = inst else {
                    continue;
                };
                let Base::Var(id) = var.base else {
                    continue;
                };
                let temp = matches!(body.vars[id], VarKind::Temp { .. });
                if !temp && !matches!(body.vars[id], VarKind::LocalDef(_)) {
                    continue;
                }
                match (&*var.projections, rvalue) {
                    ([], _) => {
                        if temp {
                            temps
                                .entry(id)
                                .and_modify(|location| *location = None)
                                .or_insert(Some(Location::new(bb, idx as u32)));
                        }
                        strings.insert(id, None);
                    }
                    (
                        [Projection::Known(index)],
                        Rvalue::Read(Operand::Lit(Literal::Str(element))),
                    ) if index.parse::<usize>().is_ok() => {
                        if let Some(elements) =
                            strings.entry(id).or_insert_with(|| Some(SmallVec::new()))
                        {
                            elements.push(element.clone());
                        }
                    }
                    _ => {
                        strings.insert(id, None);
                    }
                }
            }
        }
        Self {
            aliases,
            args: argument_vars(body).map(|(id, _)| id).collect(),
            temps,
            strings,
        }
    }

    /// The value assigned to a temporary read whole by `operand`.
    fn definition<'b>(&self, body: &'b Body, operand: &Operand) -> Option<&'b Rvalue> {
        let Operand::Var(var) = operand else {
            return None;
        };
        if !var.projections.is_empty() {
            return None;
        }
        let location = (*self.temps.get(&var.as_var_id()?)?)?;
        Some(body.block(location.block).insts[location.stmt as usize].rvalue())
    }

    /// The elements of an array literal of strings read whole by `operand`.
    fn strings(&self, operand: &Operand) -> Option<&[Atom]> {
        let Operand::Var(var) = operand else {
            return None;
        };
        if !var.projections.is_empty() {
            return None;
        }
        self.strings.get(&var.as_var_id()?)?.as_deref()
    }

    /// lodash path arguments: each a dotted string such as `'auth.token'`, or an
    /// array literal of them. `None` for any other argument, or a path deeper
    /// than tracked properties.
    fn lodash_paths(&self, operands: &[Operand]) -> Option<Vec<FieldPath>> {
        let mut paths = Vec::new();
        for operand in operands {
            match operand {
                Operand::Lit(Literal::Str(path)) => paths.push(lodash_path(path)?),
                _ => {
                    for path in self.strings(operand)? {
                        paths.push(lodash_path(path)?);
                    }
                }
            }
        }
        paths
            .iter()
            .all(|path| path.len() <= MAX_FIELD_DEPTH)
            .then_some(paths)
    }

    /// `get`'s path: a dotted string, or an array literal of property names.
    fn lodash_get_path(&self, operand: &Operand) -> Option<FieldPath> {
        match operand {
            Operand::Lit(Literal::Str(path)) => lodash_path(path),
            _ => Some(self.strings(operand)?.iter().cloned().collect()),
        }
    }

    fn frame<F: FlowFacts>(
        &self,
        env: &Environment,
        def: DefId,
        mut captures: BTreeMap<DefId, TrackedValue<F>>,
    ) -> FlowState<F> {
        // Recursive calls get fresh locals; only outer bindings are inherited.
        captures.retain(|binding, _| env.binding_owner(*binding) != Some(def));
        let body = env.def_ref(def).expect_body();
        let mut frame = FlowState {
            vars: Rc::new(
                body.vars
                    .iter()
                    .map(|kind| {
                        if matches!(kind, VarKind::Temp { .. } | VarKind::Ret) {
                            TrackedValue::BOTTOM
                        } else {
                            TrackedValue::default()
                        }
                    })
                    .collect(),
            ),
            reachable: true,
            ..FlowState::default()
        };
        for (binding, ids) in &self.aliases {
            let value = captures.get(binding).cloned().or_else(|| {
                // An initializer in another module may still be pending.
                // Functions are resolved from the IR independently of values.
                env.binding_owner(*binding)
                    .filter(|&owner| owner != def && env.global.contains(&owner))
                    .map(|_| TrackedValue::BOTTOM)
            });
            if let Some(value) = value {
                for &id in ids {
                    frame.set(id, value.clone());
                }
            }
        }
        frame.captures = captures;
        frame
    }

    fn captures_at_call<F: FlowFacts>(
        &self,
        state: &FlowState<F>,
        captured: &BTreeSet<DefId>,
    ) -> BTreeMap<DefId, TrackedValue<F>> {
        let mut captures = BTreeMap::new();
        for &binding in captured {
            let value = self
                .aliases
                .get(&binding)
                .map(|ids| state.value(ids[0]))
                .or_else(|| state.captures.get(&binding).cloned());
            if let Some(value) = value {
                captures.insert(binding, value);
            }
        }
        captures
    }
}

/// A dotted lodash path such as `'auth.token'`. Bracketed indexes are not parsed.
fn lodash_path(path: &str) -> Option<FieldPath> {
    if path.contains(['[', ']']) {
        return None;
    }
    path.split('.')
        .map(|name| (!name.is_empty()).then(|| Atom::from(name)))
        .collect()
}

/// The lodash function `callee` names: imported by name or through the default
/// or namespace import of `lodash` or `lodash-es`, or as the default import of a
/// per-method package such as `lodash/omit` or `lodash.omit`. `lodash/fp`
/// reorders arguments, so it never matches.
fn lodash_function<'cx>(
    env: &'cx Environment,
    body: &Body,
    callee: &'cx Operand,
) -> Option<&'cx str> {
    let Operand::Var(var) = callee else {
        return None;
    };
    let def = variable_def(&body.vars[var.as_var_id()?])?;
    let (module, import) = env.foreign_import(def)?;
    let whole = matches!(module, "lodash" | "lodash-es");
    match (import, &*var.projections) {
        (ImportKind::Named(name), []) if whole => Some(name),
        (ImportKind::Default | ImportKind::Star, [Projection::Known(name)]) if whole => Some(name),
        (ImportKind::Default, []) => ["lodash/", "lodash-es/", "lodash."]
            .into_iter()
            .find_map(|prefix| module.strip_prefix(prefix)),
        _ => None,
    }
}

fn unary_taint(op: UnOp, taint: Taint) -> Taint {
    match op {
        UnOp::Not | UnOp::TypeOf | UnOp::Delete | UnOp::Void => Taint::No,
        UnOp::Neg | UnOp::Plus | UnOp::BitNot => taint,
    }
}

pub(crate) fn binary_taint(op: BinOp, left: Taint, right: Taint) -> Taint {
    match op {
        // These operators return only boolean metadata, never either value.
        BinOp::Lt
        | BinOp::Gt
        | BinOp::EqEq
        | BinOp::Neq
        | BinOp::NeqEq
        | BinOp::EqEqEq
        | BinOp::Ge
        | BinOp::Le
        | BinOp::In
        | BinOp::InstanceOf => Taint::No,
        // Arithmetic can encode a secret; logical operators return an operand.
        BinOp::Add
        | BinOp::Sub
        | BinOp::Mul
        | BinOp::Div
        | BinOp::Exp
        | BinOp::Mod
        | BinOp::Or
        | BinOp::And
        | BinOp::BitOr
        | BinOp::BitAnd
        | BinOp::BitXor
        | BinOp::Lshift
        | BinOp::Rshift
        | BinOp::RshiftLogical
        | BinOp::NullishCoalesce => left.join(&right),
    }
}

impl<P: TaintPolicy> TaintDataflow<P> {
    fn project(&self, base: FlowValue<P::Facts>, rest: &[Projection]) -> FlowValue<P::Facts> {
        if !base.reachable {
            return base;
        }
        match rest.last() {
            None => base,
            Some(Projection::Known(name)) => self.policy.property_value(base, Some(name)),
            Some(Projection::Computed(_)) => self.policy.property_value(base, None),
        }
    }

    fn subtree(&self, object: &TrackedValue<P::Facts>, path: &[Atom]) -> TrackedValue<P::Facts> {
        let fields = object.fields.as_deref();
        let (base, rest) = (1..=path.len())
            .rev()
            .find_map(|len| Some((fields?.get(&path[..len])?.clone(), &path[len..])))
            .unwrap_or((object.root.clone(), path));
        let root = rest.last().map_or(base.clone(), |name| {
            if base.reachable {
                self.policy.property_value(base.clone(), Some(name))
            } else {
                base.clone()
            }
        });
        TrackedValue {
            root,
            fields: fields.and_then(|fields| fields_under(fields, path)),
        }
    }

    fn value(&self, frame: &FlowState<P::Facts>, operand: &Operand) -> TrackedValue<P::Facts> {
        let Operand::Var(var) = operand else {
            return TrackedValue::default();
        };
        let Some(id) = var.as_var_id() else {
            return TrackedValue::default();
        };
        let object = frame.value(id);
        let prefix = known_prefix(&var.projections);
        if prefix.len() == var.projections.len() {
            return self.subtree(&object, &prefix);
        }
        let base = self.subtree(&object, &prefix).aggregate();
        self.project(base, &var.projections[prefix.len()..]).into()
    }

    fn read(&self, frame: &FlowState<P::Facts>, operand: &Operand) -> FlowValue<P::Facts> {
        self.value(frame, operand).aggregate()
    }

    fn receiver_value(&self, frame: &FlowState<P::Facts>, callee: &Operand) -> FlowValue<P::Facts> {
        if let Operand::Var(var) = callee
            && !var.projections.is_empty()
        {
            let mut receiver = var.clone();
            receiver.projections.pop();
            self.read(frame, &Operand::Var(receiver))
        } else {
            self.read(frame, callee)
        }
    }

    fn lodash_call(
        &self,
        env: &Environment,
        body: &Body,
        layout: &Bindings,
        frame: &FlowState<P::Facts>,
        callee: &Operand,
        args: &[Operand],
    ) -> Option<TrackedValue<P::Facts>> {
        let function = lodash_function(env, body, callee)?;
        let (object, rest) = args.split_first()?;
        let object = self.value(frame, object);
        match function {
            "omit" => {
                let paths = layout.lodash_paths(rest)?;
                let fields = object.fields.as_ref().map(|fields| {
                    Rc::new(
                        fields
                            .iter()
                            .filter(|(field, _)| !paths.iter().any(|path| field.starts_with(path)))
                            .map(|(path, value)| (path.clone(), value.clone()))
                            .collect::<FieldMap<_>>(),
                    )
                });
                Some(TrackedValue {
                    root: object.root,
                    fields: fields.filter(|fields| !fields.is_empty()),
                })
            }
            "pick" => {
                let paths = layout.lodash_paths(rest)?;
                let mut picked = TrackedValue::default();
                for path in paths {
                    let value = self.subtree(&object, &path);
                    if self.policy.tracks_fields() {
                        let fields = Rc::make_mut(picked.fields.get_or_insert_default());
                        let root = if value
                            .fields
                            .iter()
                            .flat_map(|fields| fields.keys())
                            .any(|field| path.len() + field.len() > MAX_FIELD_DEPTH)
                        {
                            value.aggregate()
                        } else {
                            value.root.clone()
                        };
                        fields.insert(path.clone(), root);
                        for (field, value) in value.fields.iter().flat_map(|fields| fields.iter()) {
                            if path.len() + field.len() <= MAX_FIELD_DEPTH {
                                fields.insert(
                                    path.iter().chain(field).cloned().collect(),
                                    value.clone(),
                                );
                            }
                        }
                    } else {
                        picked.root = picked.root.combine(&value.aggregate());
                    }
                }
                Some(picked)
            }
            "get" => {
                let (path, default) = rest.split_first()?;
                let mut value = self.subtree(&object, &layout.lodash_get_path(path)?);
                if let Some(default) = default.first() {
                    self.join_tracked(&mut value, &self.value(frame, default));
                }
                Some(value)
            }
            _ => None,
        }
    }

    fn assign(
        &self,
        frame: &mut FlowState<P::Facts>,
        id: VarId,
        projections: &[Projection],
        value: TrackedValue<P::Facts>,
    ) {
        if projections.is_empty() {
            frame.set(id, value);
            return;
        }
        let mut object = frame.value(id);
        // Object/array literals are lowered to writes to a fresh temporary.
        if !object.root.reachable {
            object.root = FlowValue::default();
        }
        if !self.policy.tracks_fields() {
            object.root = object.root.combine(&value.aggregate());
            frame.set(id, object);
            return;
        }
        let mut path = known_prefix(projections);
        let exact = path.len() == projections.len() && path.len() <= MAX_FIELD_DEPTH;
        path.truncate(MAX_FIELD_DEPTH);
        let fields = Rc::make_mut(object.fields.get_or_insert_default());
        if exact {
            fields.retain(|field, _| !field.starts_with(&path));
            // Summarize truncated descendants in the copied root, so the
            // depth bound can lose precision but never discard a source.
            let root = if value
                .fields
                .iter()
                .flat_map(|fields| fields.keys())
                .any(|field| path.len() + field.len() > MAX_FIELD_DEPTH)
            {
                value.aggregate()
            } else {
                value.root.clone()
            };
            fields.insert(path.clone(), root);
            for (field, value) in value.fields.iter().flat_map(|fields| fields.iter()) {
                if path.len() + field.len() <= MAX_FIELD_DEPTH {
                    fields.insert(path.iter().chain(field).cloned().collect(), value.clone());
                }
            }
        } else {
            // Unknown/deep writes may add data anywhere below the prefix.
            let written = value.aggregate();
            for (field, value) in fields.iter_mut() {
                if field.starts_with(&path) {
                    *value = value.combine(&written);
                }
            }
            if path.is_empty() {
                object.root = object.root.combine(&written);
            } else {
                let old = self.subtree(&object, &path).aggregate();
                Rc::make_mut(object.fields.as_mut().unwrap()).insert(path, old.combine(&written));
            }
        }
        frame.set(id, object);
    }

    fn join_tracked(
        &self,
        into: &mut TrackedValue<P::Facts>,
        from: &TrackedValue<P::Facts>,
    ) -> bool {
        if *into == *from {
            return false;
        }
        if !from.root.reachable {
            return false;
        }
        if !into.root.reachable {
            *into = from.clone();
            return true;
        }
        let empty = FieldMap::new();
        let left = into.fields.as_deref().unwrap_or(&empty);
        let right = from.fields.as_deref().unwrap_or(&empty);
        let fields: FieldMap<_> = left
            .keys()
            .merge(right.keys())
            .dedup()
            .map(|path| {
                // Join the value at this path, without aggregating descendants twice.
                (
                    path.clone(),
                    self.subtree(into, path)
                        .root
                        .join(&self.subtree(from, path).root),
                )
            })
            .collect();
        let joined = TrackedValue {
            root: into.root.join(&from.root),
            fields: (!fields.is_empty()).then(|| Rc::new(fields)),
        };
        let changed = *into != joined;
        *into = joined;
        changed
    }

    fn join_frames(&self, into: &mut FlowState<P::Facts>, from: &FlowState<P::Facts>) -> bool {
        if !from.reachable {
            return false;
        }
        if !into.reachable {
            *into = from.clone();
            return true;
        }
        let mut changed = false;
        if !Rc::ptr_eq(&into.vars, &from.vars) {
            for (index, value) in from.vars.iter().enumerate() {
                let mut current = into.value(VarId::from(index));
                if self.join_tracked(&mut current, value) {
                    into.set(VarId::from(index), current);
                    changed = true;
                }
            }
        }
        for (&binding, value) in &from.captures {
            changed |= self.join_tracked(
                into.captures.entry(binding).or_insert(TrackedValue::BOTTOM),
                value,
            );
        }
        changed
    }
}

impl<'cx, P: TaintPolicy + Default> Dataflow<'cx> for TaintDataflow<P> {
    type State = Vec<Taint>;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self::new(P::default())
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        state: Self::State,
        _operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        state
    }

    fn analyze<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        entry: DefId,
    ) -> bool {
        let env = interp.env();
        let mut inputs = BTreeMap::<(DefId, ContextId, BasicBlockId), FlowState<P::Facts>>::new();
        // Absence means no returning execution has been discovered, not clean.
        let mut returns = BTreeMap::<(DefId, ContextId), TrackedValue<P::Facts>>::new();
        let mut contexts = BTreeMap::<DefId, Vec<CallInput<P::Facts>>>::new();
        let mut overflowed = BTreeSet::new();
        let mut findings = BTreeMap::new();
        let mut edges = BTreeMap::<
            (DefId, ContextId, BasicBlockId),
            BTreeMap<Location, (DefId, ContextId)>,
        >::new();
        let mut callers =
            BTreeMap::<(DefId, ContextId), BTreeSet<(DefId, ContextId, BasicBlockId)>>::new();
        let mut globals = BTreeMap::<DefId, TrackedValue<P::Facts>>::new();
        let mut queue = Queue::default();
        // One checkpoint per blocked block. Invalidate it whenever an input
        // or a previously consumed return changes; otherwise resume at the call.
        let mut suspended = BTreeMap::new();
        interp.instruction_findings.clear();

        let bindings: BTreeMap<_, _> = env
            .bodies()
            .filter_map(|body| body.owner().map(|def| (def, Bindings::new(body))))
            .collect();
        let captured: BTreeSet<_> = bindings
            .iter()
            .flat_map(|(&def, bindings)| {
                bindings.aliases.keys().copied().filter(move |binding| {
                    env.binding_owner(*binding)
                        .is_some_and(|owner| owner != def)
                })
            })
            .collect();
        // A helper needs only its own free bindings and those used by its
        // callees. Passing the entire caller environment creates spurious
        // contexts and quadratic copying in functions with many helpers.
        let mut capture_needs: BTreeMap<_, BTreeSet<_>> = bindings
            .iter()
            .map(|(&def, layout)| {
                (
                    def,
                    layout
                        .aliases
                        .keys()
                        .copied()
                        .filter(|&binding| {
                            env.binding_owner(binding).is_some_and(|owner| owner != def)
                        })
                        .collect(),
                )
            })
            .collect();
        let mut dependents = BTreeMap::<_, BTreeSet<_>>::new();
        for &def in bindings.keys() {
            let body = env.def_ref(def).expect_body();
            for (_, block) in body.iter_blocks_enumerated() {
                for inst in block.iter() {
                    if let Rvalue::Call(callee, _) = inst.rvalue()
                        && let Some((target, _)) = body.resolve_call(env, callee)
                    {
                        dependents.entry(target).or_default().insert(def);
                    }
                }
            }
        }
        let mut pending: VecDeque<_> = bindings.keys().copied().collect();
        while let Some(target) = pending.pop_front() {
            if let Some(callers) = dependents.get(&target) {
                for &caller in callers {
                    let inherited: Vec<_> = capture_needs[&target]
                        .iter()
                        .copied()
                        .filter(|&binding| env.binding_owner(binding) != Some(caller))
                        .collect();
                    let needed = capture_needs.get_mut(&caller).unwrap();
                    let before = needed.len();
                    needed.extend(inherited);
                    if before != needed.len() {
                        pending.push_back(caller);
                    }
                }
            }
        }
        let global_bodies: BTreeSet<_> = env.global.iter().copied().collect();
        let mut roots = env.global.clone();
        roots.push(entry);
        if interp.call_uncalled {
            roots.extend(env.get_all_functions_and_closures());
        }
        let root_frame = |def, globals: &BTreeMap<DefId, TrackedValue<P::Facts>>| {
            let captures = globals
                .iter()
                .filter(|(binding, _)| capture_needs[&def].contains(binding))
                .map(|(&binding, value)| (binding, value.clone()))
                .collect();
            let mut initial = bindings[&def].frame(env, def, captures);
            if def == entry
                && P::TAINT_RESOLVER_INPUT
                && matches!(interp.entry.kind, EntryKind::Resolver(..))
                && let Some(&id) = bindings[&def].args.first()
            {
                initial.set(id, FlowValue::from_taint(Taint::Yes).into());
            }
            initial
        };
        // Module IDs are not dependency ordered. Solve their captured values
        // together before seeding entrypoints; missing globals remain bottom.
        for &def in &env.global {
            let key = (def, ContextId(0), STARTING_BLOCK);
            inputs.insert(key, root_frame(def, &globals));
            queue.push(key);
        }
        let mut pending_roots = roots.iter().skip(env.global.len());
        loop {
            let Some((def, ctx, bb)) = queue.pop() else {
                let Some(&def) = pending_roots.next() else {
                    break;
                };
                let key = (def, ContextId(0), STARTING_BLOCK);
                inputs.insert(key, root_frame(def, &globals));
                queue.push(key);
                continue;
            };
            let body = env.def_ref(def).expect_body();
            let block = body.block(bb);
            let block_key = (def, ctx, bb);
            let resume = suspended.remove(&block_key);
            let previous_edges = edges.remove(&block_key).unwrap_or_default();
            let previous_findings = findings.remove(&block_key).unwrap_or_default();
            let (mut block_edges, mut block_findings, previous_targets) = if resume.is_some() {
                (previous_edges, previous_findings, BTreeSet::new())
            } else {
                let targets = previous_edges.values().copied().collect();
                (BTreeMap::new(), BTreeSet::new(), targets)
            };
            let (start, mut frame) = resume.unwrap_or_else(|| (0, inputs[&block_key].clone()));
            let layout = &bindings[&def];
            let mut returning = true;
            for (idx, inst) in block.iter().enumerate().skip(start) {
                let location = (def, Location::new(bb, idx as u32));
                let values = TaintReader {
                    dataflow: self,
                    frame: &frame,
                };
                if self.policy.is_violation(inst, &values) {
                    block_findings.insert(location.1);
                }
                let read = |operand| self.read(&frame, operand);
                let value: TrackedValue<P::Facts> = match inst.rvalue() {
                    Rvalue::Read(op) => self.value(&frame, op),
                    Rvalue::Unary(op, operand) => {
                        let value = read(operand);
                        if unary_taint(*op, Taint::Yes) == Taint::No {
                            value.with_facts(P::Facts::from_taint(Taint::No)).into()
                        } else {
                            value.into()
                        }
                    }
                    Rvalue::Bin(op, left, right) => self
                        .policy
                        .binary_value(*op, read(left), read(right))
                        .into(),
                    Rvalue::Phi(vars) => {
                        vars.iter()
                            .fold(TrackedValue::BOTTOM, |mut value, (id, _)| {
                                self.join_tracked(&mut value, &frame.value(*id));
                                value
                            })
                    }
                    Rvalue::Template(template) => template
                        .exprs
                        .iter()
                        .fold(FlowValue::default(), |value, op| value.combine(&read(op)))
                        .into(),
                    Rvalue::Intrinsic(intrinsic, _) => {
                        self.policy.intrinsic_value(intrinsic).into()
                    }
                    Rvalue::Call(callee, args) => {
                        if let Some((callee_def, _)) = body.resolve_call(env, callee) {
                            let callee_layout = &bindings[&callee_def];
                            // Capture the values visible at this call, including
                            // clean overwrites. Never join a binding's lifetime.
                            let mut callee_frame = callee_layout.frame(
                                env,
                                callee_def,
                                layout.captures_at_call(&frame, &capture_needs[&callee_def]),
                            );
                            for (&id, arg) in callee_layout.args.iter().zip(args) {
                                callee_frame.set(id, self.value(&frame, arg));
                            }
                            let signature = (
                                callee_layout
                                    .args
                                    .iter()
                                    .map(|&id| callee_frame.value(id))
                                    .collect::<Vec<_>>(),
                                callee_frame.captures.clone(),
                            );
                            let clean = signature
                                .0
                                .iter()
                                .chain(signature.1.values())
                                .all(|value| value.aggregate() == FlowValue::default());
                            let callee_ctx = if clean {
                                ContextId(1)
                            } else {
                                let keys = contexts.entry(callee_def).or_default();
                                if let Some(index) = keys.iter().position(|key| key == &signature) {
                                    ContextId(index + 2)
                                } else if keys.len() < MAX_CONTEXTS - 1 {
                                    keys.push(signature);
                                    ContextId(keys.len() + 1)
                                } else {
                                    if overflowed.insert(callee_def) {
                                        tracing::debug!(
                                            function = env.def_name(callee_def),
                                            "taint context budget exhausted; merging additional inputs"
                                        );
                                    }
                                    OVERFLOW
                                }
                            };
                            callers
                                .entry((callee_def, callee_ctx))
                                .or_default()
                                .insert((def, ctx, bb));
                            block_edges.insert(location.1, (callee_def, callee_ctx));
                            let key = (callee_def, callee_ctx, STARTING_BLOCK);
                            let is_new = !inputs.contains_key(&key);
                            if self.join_frames(inputs.entry(key).or_default(), &callee_frame)
                                || is_new
                            {
                                suspended.remove(&key);
                                queue.push(key);
                            }
                            let Some(value) = returns.get(&(callee_def, callee_ctx)) else {
                                suspended.insert(block_key, (idx, frame.clone()));
                                returning = false;
                                break;
                            };
                            value.clone()
                        } else if let Some(value) =
                            self.lodash_call(env, body, layout, &frame, callee, args)
                        {
                            value
                        } else {
                            // Preserve data through unmodelled transformations,
                            // including methods called on a tainted receiver.
                            let receiver = self.receiver_value(&frame, callee);
                            let taints: SmallVec<[FlowValue<P::Facts>; 4]> =
                                args.iter().map(read).collect();
                            let global_result = match callee {
                                Operand::Var(var) => var
                                    .as_var_id()
                                    .and_then(|id| variable_def(&body.vars[id]))
                                    .filter(|&def| env.is_undeclared_global(def))
                                    .and_then(|def| {
                                        self.policy
                                            .global_call_value(env.def_name(def), &var.projections)
                                    }),
                                Operand::Lit(_) => None,
                            };
                            let mut result = global_result
                                .or_else(|| {
                                    callee_name(env, body, callee).and_then(|method| {
                                        self.policy.method_value(&UnresolvedCall {
                                            method,
                                            receiver: receiver.clone(),
                                            args: &taints,
                                            callee,
                                            operands: args,
                                            env,
                                            body,
                                            layout,
                                            def,
                                            location: location.1,
                                        })
                                    })
                                })
                                .unwrap_or_else(|| {
                                    taints
                                        .iter()
                                        .fold(receiver.clone(), |value, arg| value.combine(arg))
                                });
                            // Policy facts may sanitize a value without erasing
                            // its provenance. Bottom is strict across calls.
                            let inputs = taints
                                .iter()
                                .fold(receiver, |value, arg| value.combine(arg));
                            if !inputs.reachable {
                                result = FlowValue::BOTTOM;
                            } else {
                                result.provenance.join_changed(&inputs.provenance);
                            }
                            result.into()
                        }
                    }
                };
                if let Inst::Assign(var, _) = inst
                    && let Base::Var(id) = var.base
                {
                    self.assign(&mut frame, id, &var.projections, value);
                    if let Some(var_def) = variable_def(&body.vars[id]) {
                        // Index aliases once per body instead of scanning all
                        // variables at every assignment.
                        let value = frame.value(id);
                        for &alias in &layout.aliases[&var_def] {
                            frame.set(alias, value.clone());
                        }
                    }
                }
            }

            if !block_findings.is_empty() {
                findings.insert(block_key, block_findings);
            }
            if !previous_targets.is_empty() {
                let targets: BTreeSet<_> = block_edges.values().copied().collect();
                for target in previous_targets.difference(&targets) {
                    if let Some(dependents) = callers.get_mut(target) {
                        dependents.remove(&block_key);
                    }
                }
            }
            edges.insert(block_key, block_edges);
            if !returning {
                continue;
            }
            let successors: SmallVec<[BasicBlockId; 2]> = match block.successors() {
                Successors::Return => {
                    let returned = body
                        .vars
                        .iter_enumerated()
                        .filter(|(_, kind)| matches!(kind, VarKind::Ret))
                        .fold(TrackedValue::BOTTOM, |mut value, (id, _)| {
                            self.join_tracked(&mut value, &frame.value(id));
                            value
                        });
                    // An implicit return is public undefined. An explicit
                    // return whose operand is bottom is still pending.
                    let explicit_return = block.iter().any(|inst| matches!(inst,
                        Inst::Assign(var, _) if var.as_var_id().is_some_and(|id| matches!(body.vars[id], VarKind::Ret))));
                    if !returned.root.reachable && explicit_return {
                        continue;
                    }
                    let returned = if returned.root.reachable {
                        returned
                    } else {
                        TrackedValue::default()
                    };
                    let is_new = !returns.contains_key(&(def, ctx));
                    if (self.join_tracked(
                        returns.entry((def, ctx)).or_insert(TrackedValue::BOTTOM),
                        &returned,
                    ) || is_new)
                        && let Some(dependents) = callers.get(&(def, ctx))
                    {
                        for &key in dependents {
                            if let Some((start, _)) = suspended.get(&key) {
                                let waiting_at = Location::new(key.2, *start as u32);
                                let calls = &edges[&key];
                                let changed = (def, ctx);
                                if calls.get(&waiting_at) != Some(&changed)
                                    || calls
                                        .range(..waiting_at)
                                        .any(|(_, target)| *target == changed)
                                {
                                    suspended.remove(&key);
                                }
                            }
                            queue.push(key);
                        }
                    }
                    // Entrypoints inherit completed module initializers, not
                    // every historical assignment made while initializing them.
                    if global_bodies.contains(&def) {
                        let mut changed = false;
                        for (&binding, ids) in &layout.aliases {
                            if captured.contains(&binding)
                                && env.binding_owner(binding) == Some(def)
                            {
                                changed |= self.join_tracked(
                                    globals.entry(binding).or_insert(TrackedValue::BOTTOM),
                                    &frame.value(ids[0]),
                                );
                            }
                        }
                        if changed {
                            for &root in &env.global {
                                let key = (root, ContextId(0), STARTING_BLOCK);
                                if self.join_frames(
                                    inputs.entry(key).or_default(),
                                    &root_frame(root, &globals),
                                ) {
                                    suspended.remove(&key);
                                    queue.push(key);
                                }
                            }
                        }
                    }
                    SmallVec::new()
                }
                Successors::One(succ) => smallvec::smallvec![succ],
                Successors::Two(left, right) => smallvec::smallvec![left, right],
            };
            for succ in successors {
                let key = (def, ctx, succ);
                let is_new = !inputs.contains_key(&key);
                if self.join_frames(inputs.entry(key).or_default(), &frame) || is_new {
                    suspended.remove(&key);
                    queue.push(key);
                }
            }
        }
        // Only final call edges establish reachable contexts. Evidence from
        // preliminary invocations must not survive after their callers move on.
        let mut adjacency = BTreeMap::<_, BTreeSet<_>>::new();
        for ((def, ctx, _), calls) in edges {
            adjacency
                .entry((def, ctx))
                .or_default()
                .extend(calls.into_values());
        }
        let mut live = BTreeSet::new();
        let mut pending: VecDeque<_> = roots.iter().map(|&def| (def, ContextId(0))).collect();
        while let Some(context) = pending.pop_front() {
            if live.insert(context)
                && let Some(targets) = adjacency.get(&context)
            {
                pending.extend(targets);
            }
        }
        interp.instruction_findings = findings
            .into_iter()
            .filter(|((def, ctx, _), _)| live.contains(&(*def, *ctx)))
            .flat_map(|((def, _, _), locations)| locations.into_iter().map(move |loc| (def, loc)))
            .collect();
        // The legacy reporting traversal uses a context-erased compatibility
        // view. Sink decisions have already been made on precise local states.
        let mut blocks = BTreeMap::<(DefId, BasicBlockId), Vec<Taint>>::new();
        for ((def, ctx, bb), frame) in inputs {
            if live.contains(&(def, ctx)) {
                let values = frame
                    .vars
                    .iter()
                    .map(|value| value.aggregate().provenance)
                    .collect();
                blocks.entry((def, bb)).or_default().join_changed(&values);
            }
        }
        interp.set_block_states(blocks);
        let mut summaries = BTreeMap::<DefId, Vec<Taint>>::new();
        for ((def, ctx), value) in returns {
            if live.contains(&(def, ctx)) {
                summaries
                    .entry(def)
                    .or_default()
                    .join_changed(&vec![value.aggregate().provenance]);
            }
        }
        interp.replace_func_states(summaries);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_join_preserves_sources_and_reports_changes() {
        let mut taint = Taint::No;
        assert!(!taint.join_changed(&Taint::No));
        assert!(taint.join_changed(&Taint::Unknown));
        assert!(taint.join_changed(&Taint::Yes));
        assert!(!taint.join_changed(&Taint::Unknown));
        assert_eq!(taint, Taint::Yes);
    }

    #[test]
    fn vector_join_preserves_unequal_lengths() {
        let left = vec![Taint::Yes];
        let right = vec![Taint::No, Taint::Yes];
        assert_eq!(left.join(&right), right.join(&left));
        let mut state = Vec::BOTTOM;
        assert!(state.join_changed(&right));
        assert_eq!(state, right);
        assert!(!state.join_changed(&right));
        assert!(state.join_changed(&left));
        assert_eq!(state, vec![Taint::Yes, Taint::Yes]);
    }
}
