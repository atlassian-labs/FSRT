//! Reusable, forward may-taint analysis over the lowered IR.
//!
//! Policies define sources, property-read propagation and sinks. A policy's sink
//! predicate sees the state *before* each instruction. Only positive sink locations
//! are retained, rather than a full variable-state snapshot at every instruction.
//! Function inputs and returns are joined to a fixed point, including loops and
//! recursion. Values are tracked per function and variable and, for policies that
//! opt in, per known property path. Object properties and external calls are
//! conservatively treated as propagators unless a policy opts out; function
//! summaries are context insensitive (shared across call sites). lodash's
//! `omit`, `pick` and `get` with literal paths select properties instead.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::{Bound, ControlFlow},
    rc::Rc,
};

use itertools::Itertools;
use smallvec::SmallVec;
use swc_core::ecma::atoms::Atom;

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
    /// Whether resolver request arguments are sources for this policy.
    const TAINT_RESOLVER_INPUT: bool = false;

    fn intrinsic_taint(&self, intrinsic: &Intrinsic) -> Taint;

    /// Whether `inst` is a sink reached by a reportable value.
    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool;

    /// Whether writes through known property paths are tracked, so that reading a
    /// written property yields that property's own taint.
    fn tracks_fields(&self) -> bool {
        false
    }

    /// The taint of reading an untracked property from a value with taint `base`.
    /// Only the last property of a chain is passed (`None` for a computed key);
    /// `base` is the taint of the nearest tracked value before it, and a clean
    /// `base` must stay clean. Writing a tainted property still taints the whole
    /// object, and a method call still inherits its receiver's taint.
    fn property_taint(&self, base: Taint, _name: Option<&str>) -> Taint {
        base
    }

    /// Override result propagation for policy-specific operator semantics.
    fn binary_taint(&self, op: BinOp, left: Taint, right: Taint) -> Taint {
        binary_taint(op, left, right)
    }

    /// Classify a call rooted at an undeclared global binding. The full
    /// projection path prevents unrelated methods from matching a builtin.
    fn global_call_taint(&self, _name: &str, _path: &[Projection]) -> Option<Taint> {
        None
    }

    /// The result of an unmodelled call, given its receiver and argument taints.
    /// Policies recognize their sanitizers and known non-propagating calls here;
    /// `None` joins them all.
    fn method_taint(&self, _call: &UnresolvedCall<'_>) -> Option<Taint> {
        None
    }
}

/// An unmodelled call, as `TaintPolicy::method_taint` sees it.
pub struct UnresolvedCall<'a> {
    /// The last property name for a method call, or the bound name for a bare
    /// call to a global or imported binding.
    pub method: &'a str,
    pub receiver: Taint,
    pub args: &'a [Taint],
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

impl UnresolvedCall<'_> {
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
pub struct TaintReader<'a, P> {
    dataflow: &'a TaintDataflow<P>,
    frame: &'a FrameState,
}

impl<P: TaintPolicy> TaintReader<'_, P> {
    /// The taint of the value read by `operand`, including any property read.
    pub fn operand(&self, operand: &Operand) -> Taint {
        self.dataflow.read(self.frame, operand)
    }

    /// The taint of a variable itself, ignoring its properties.
    pub fn var(&self, id: VarId) -> Taint {
        var_taint(&self.frame.vars, id)
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

fn var_taint(state: &[Taint], id: VarId) -> Taint {
    state.get(id.0 as usize).copied().unwrap_or(Taint::No)
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

#[derive(Default)]
struct Queue {
    pending: VecDeque<(DefId, BasicBlockId)>,
    queued: BTreeSet<(DefId, BasicBlockId)>,
}

impl Queue {
    fn push(&mut self, key: (DefId, BasicBlockId)) {
        if self.queued.insert(key) {
            self.pending.push_back(key);
        }
    }

    fn pop(&mut self) -> Option<(DefId, BasicBlockId)> {
        let key = self.pending.pop_front()?;
        self.queued.remove(&key);
        Some(key)
    }
}

/// Known property names along a path, such as `["auth", "password"]`.
type FieldPath = SmallVec<[Atom; 2]>;

/// Taints of properties written through a known path. A path absent here reads
/// from its nearest tracked prefix, or from the variable itself.
type FieldMap = BTreeMap<FieldPath, Taint>;

/// Frames share tracked properties until one of them writes.
type Fields = Rc<FieldMap>;

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
fn fields_under(source: &FieldMap, prefix: &[Atom]) -> Option<Fields> {
    let copied: FieldMap = source
        .range::<[Atom], _>((Bound::Excluded(prefix), Bound::Unbounded))
        .take_while(|(path, _)| path.starts_with(prefix))
        .map(|(path, &taint)| (FieldPath::from(&path[prefix.len()..]), taint))
        .collect();
    (!copied.is_empty()).then(|| Rc::new(copied))
}

/// A value's taint, with the taints of its tracked properties.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Tracked {
    taint: Taint,
    fields: Option<Fields>,
}

impl From<Taint> for Tracked {
    fn from(taint: Taint) -> Self {
        Self {
            taint,
            fields: None,
        }
    }
}

// Block inputs retain ordinary variable vectors, plus tracked properties for
// policies that opt in. Captures also carry bindings through helpers that do not
// themselves read them (but call a closure that does).
#[derive(Clone, Default)]
struct FrameState {
    vars: Vec<Taint>,
    /// Indexed like `vars`, and empty until a property is tracked.
    fields: Vec<Option<Fields>>,
    captures: BTreeMap<DefId, Tracked>,
}

impl FrameState {
    fn fields(&self, id: VarId) -> Option<&Fields> {
        self.fields.get(id.0 as usize)?.as_ref()
    }

    fn set_fields(&mut self, id: VarId, fields: Option<Fields>) {
        let index = id.0 as usize;
        match fields.filter(|fields| !fields.is_empty()) {
            Some(fields) => {
                if self.fields.len() <= index {
                    self.fields.resize(self.vars.len().max(index + 1), None);
                }
                self.fields[index] = Some(fields);
            }
            None => {
                if let Some(slot) = self.fields.get_mut(index) {
                    *slot = None;
                }
            }
        }
    }

    fn value(&self, id: VarId) -> Tracked {
        Tracked {
            taint: var_taint(&self.vars, id),
            fields: self.fields(id).cloned(),
        }
    }

    fn set(&mut self, id: VarId, value: Tracked) {
        self.vars[id.0 as usize] = value.taint;
        self.set_fields(id, value.fields);
    }
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

    fn frame(
        &self,
        env: &Environment,
        def: DefId,
        mut captures: BTreeMap<DefId, Tracked>,
    ) -> FrameState {
        // Recursive calls get fresh locals; only outer bindings are inherited.
        captures.retain(|binding, _| env.binding_owner(*binding) != Some(def));
        let mut frame = FrameState {
            vars: vec![Taint::No; env.def_ref(def).expect_body().vars.len()],
            ..FrameState::default()
        };
        for (binding, ids) in &self.aliases {
            if let Some(value) = captures.get(binding) {
                for &id in ids {
                    frame.set(id, value.clone());
                }
            }
        }
        frame.captures = captures;
        frame
    }

    fn captures_at_call(
        &self,
        state: &FrameState,
        captured: &BTreeSet<DefId>,
    ) -> BTreeMap<DefId, Tracked> {
        let mut captures = state.captures.clone();
        for (binding, ids) in &self.aliases {
            if captured.contains(binding) {
                let value = state.value(ids[0]);
                if value.taint == Taint::No {
                    captures.remove(binding);
                } else {
                    captures.insert(*binding, value);
                }
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
    /// The taint of an untracked property chain read from a value with taint `base`.
    fn project(&self, base: Taint, rest: &[Projection]) -> Taint {
        match rest.last() {
            None => base,
            Some(Projection::Known(name)) => self.policy.property_taint(base, Some(name)),
            Some(Projection::Computed(_)) => self.policy.property_taint(base, None),
        }
    }

    /// The taint of reading `projections` from a variable, starting from the
    /// nearest tracked property on the path.
    fn read_path(&self, root: Taint, fields: Option<&Fields>, projections: &[Projection]) -> Taint {
        if let Some(fields) = fields {
            let known = known_prefix(projections);
            for len in (1..=known.len()).rev() {
                if let Some(&taint) = fields.get(&known[..len]) {
                    return self.project(taint, &projections[len..]);
                }
            }
        }
        self.project(root, projections)
    }

    /// `read_path` for a path of known property names.
    fn read_field(&self, root: Taint, fields: &FieldMap, path: &[Atom]) -> Taint {
        let (base, rest) = (1..=path.len())
            .rev()
            .find_map(|len| Some((*fields.get(&path[..len])?, &path[len..])))
            .unwrap_or((root, path));
        rest.last()
            .map_or(base, |name| self.policy.property_taint(base, Some(name)))
    }

    fn read(&self, frame: &FrameState, operand: &Operand) -> Taint {
        match operand {
            Operand::Var(var) => var.as_var_id().map_or(Taint::No, |id| {
                self.read_path(
                    var_taint(&frame.vars, id),
                    frame.fields(id),
                    &var.projections,
                )
            }),
            Operand::Lit(_) => Taint::No,
        }
    }

    /// A method call inherits the taint of its receiver, not of the method itself:
    /// `secret.trim()` reads `secret`, while `secret.token.trim()` reads `secret.token`.
    fn receiver_taint(&self, frame: &FrameState, callee: &Operand) -> Taint {
        if let Operand::Var(var) = callee
            && let Some(id) = var.as_var_id()
            && let Some((_, receiver)) = var.projections.split_last()
        {
            self.read_path(var_taint(&frame.vars, id), frame.fields(id), receiver)
        } else {
            self.read(frame, callee)
        }
    }

    /// The value read by `operand`, keeping the tracked properties of a copied
    /// variable or known property.
    fn value(&self, frame: &FrameState, operand: &Operand) -> Tracked {
        let taint = self.read(frame, operand);
        let mut fields = None;
        if let Operand::Var(var) = operand
            && let Some(id) = var.as_var_id()
            && let Some(source) = frame.fields(id)
        {
            let prefix = known_prefix(&var.projections);
            if var.projections.is_empty() {
                fields = Some(source.clone());
            } else if prefix.len() == var.projections.len() {
                fields = fields_under(source, &prefix);
            }
        }
        Tracked { taint, fields }
    }

    /// The value at a known path within `object`, as a property read sees it.
    fn subtree(&self, object: &Tracked, path: &[Atom]) -> Tracked {
        let empty = FieldMap::new();
        let fields = object.fields.as_deref().unwrap_or(&empty);
        Tracked {
            taint: self.read_field(object.taint, fields, path),
            fields: fields_under(fields, path),
        }
    }

    /// lodash's `omit`, `pick` and `get` with literal paths select properties,
    /// rather than propagating the whole object like other unresolved calls.
    fn lodash_call(
        &self,
        env: &Environment,
        body: &Body,
        layout: &Bindings,
        frame: &FrameState,
        callee: &Operand,
        args: &[Operand],
    ) -> Option<Tracked> {
        let function = lodash_function(env, body, callee)?;
        let (object, rest) = args.split_first()?;
        let object = self.value(frame, object);
        match function {
            "omit" => Some(self.omit(object, &layout.lodash_paths(rest)?)),
            "pick" => Some(self.pick(&object, &layout.lodash_paths(rest)?)),
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

    /// `object` without the properties under `paths`. When tracked properties
    /// account for all of the object's taint, as for an object literal, the rest
    /// reads like its remaining and untracked properties. Otherwise, such as for
    /// a secret read whole, the remaining properties are unknown and keep it.
    fn omit(&self, object: Tracked, paths: &[FieldPath]) -> Tracked {
        let Some(fields) = &object.fields else {
            return object;
        };
        let remaining: FieldMap = fields
            .iter()
            .filter(|(field, _)| !paths.iter().any(|path| field.starts_with(path)))
            .map(|(field, &taint)| (field.clone(), taint))
            .collect();
        if remaining.len() == fields.len() {
            return object;
        }
        let tracked = fields
            .values()
            .fold(Taint::No, |taint, field| taint.join(field));
        let taint = if object.taint <= tracked {
            remaining.values().fold(
                self.policy.property_taint(object.taint, None),
                |taint, field| taint.join(field),
            )
        } else {
            object.taint
        };
        Tracked {
            taint,
            fields: (!remaining.is_empty()).then(|| Rc::new(remaining)),
        }
    }

    /// A new object holding only the properties under `paths`.
    fn pick(&self, object: &Tracked, paths: &[FieldPath]) -> Tracked {
        let mut picked = Tracked::default();
        let mut fields = FieldMap::new();
        for path in paths {
            let value = self.subtree(object, path);
            picked.taint.join_changed(&value.taint);
            if !self.policy.tracks_fields() {
                continue;
            }
            for len in 1..=path.len() {
                fields
                    .entry(path[..len].into())
                    .or_default()
                    .join_changed(&value.taint);
            }
            for (field, taint) in value.fields.iter().flat_map(|fields| fields.iter()) {
                if path.len() + field.len() <= MAX_FIELD_DEPTH {
                    fields
                        .entry(path.iter().chain(field).cloned().collect())
                        .or_default()
                        .join_changed(taint);
                }
            }
        }
        picked.fields = (!fields.is_empty()).then(|| Rc::new(fields));
        picked
    }

    /// Writes `value` to a variable or one of its properties.
    fn assign(
        &self,
        frame: &mut FrameState,
        id: VarId,
        projections: &[Projection],
        value: Tracked,
    ) {
        if projections.is_empty() {
            frame.set(id, value);
            return;
        }
        // The object now holds the value, so reading it whole includes it.
        frame.vars[id.0 as usize].join_changed(&value.taint);
        if !self.policy.tracks_fields() {
            return;
        }
        let mut path = known_prefix(projections);
        let exact = path.len() == projections.len() && path.len() <= MAX_FIELD_DEPTH;
        path.truncate(MAX_FIELD_DEPTH);
        // Take the map out of the frame so an unshared one is updated in place.
        let mut tracked = frame
            .fields
            .get_mut(id.0 as usize)
            .and_then(Option::take)
            .unwrap_or_default();
        let fields = Rc::make_mut(&mut tracked);
        // Properties containing the written one now hold its value too.
        for len in 1..path.len() {
            if let Some(taint) = fields.get_mut(&path[..len]) {
                taint.join_changed(&value.taint);
            }
        }
        if exact {
            fields.retain(|field, _| !field.starts_with(&path));
            for (field, &taint) in value.fields.iter().flat_map(|fields| fields.iter()) {
                if path.len() + field.len() <= MAX_FIELD_DEPTH {
                    fields.insert(path.iter().chain(field).cloned().collect(), taint);
                }
            }
            fields.insert(path, value.taint);
        } else {
            // A computed key may overwrite any property under the known prefix.
            for (field, taint) in fields.iter_mut() {
                if field.starts_with(&path) {
                    taint.join_changed(&value.taint);
                }
            }
        }
        frame.set_fields(id, Some(tracked));
    }

    /// Joins tracked properties. A path tracked on only one side is joined with
    /// what the other side reads there, so tracking never lowers a read.
    fn join_fields(
        &self,
        into: &mut Option<Fields>,
        into_root: Taint,
        from: Option<&Fields>,
        from_root: Taint,
    ) -> bool {
        match (&*into, from) {
            (None, None) => return false,
            (Some(current), Some(from)) if Rc::ptr_eq(current, from) => return false,
            // A clean value reads as clean everywhere, so `from` stands as is.
            (None, Some(from)) if into_root == Taint::No => {
                *into = Some(from.clone());
                return true;
            }
            _ => {}
        }
        let empty = FieldMap::new();
        let current = into.as_deref().unwrap_or(&empty);
        let other = from.map_or(&empty, |from| &**from);
        let joined: Vec<(FieldPath, Taint)> = current
            .keys()
            .merge(other.keys())
            .dedup()
            .filter_map(|path| {
                let taint = self
                    .read_field(into_root, current, path)
                    .join(&self.read_field(from_root, other, path));
                (current.get(path) != Some(&taint)).then(|| (path.clone(), taint))
            })
            .collect();
        if joined.is_empty() {
            return false;
        }
        Rc::make_mut(into.get_or_insert_default()).extend(joined);
        true
    }

    fn join_tracked(&self, into: &mut Tracked, from: &Tracked) -> bool {
        let fields = self.join_fields(
            &mut into.fields,
            into.taint,
            from.fields.as_ref(),
            from.taint,
        );
        into.taint.join_changed(&from.taint) || fields
    }

    fn join_frames(&self, into: &mut FrameState, from: &FrameState) -> bool {
        let mut changed = false;
        for index in 0..into.fields.len().max(from.fields.len()) {
            let id = VarId::from(index);
            let other = from.fields(id);
            let same = match (into.fields(id), other) {
                (None, None) => true,
                (Some(left), Some(right)) => Rc::ptr_eq(left, right),
                _ => false,
            };
            if same {
                continue;
            }
            let into_root = var_taint(&into.vars, id);
            let mut fields = into.fields.get_mut(index).and_then(Option::take);
            changed |= self.join_fields(&mut fields, into_root, other, var_taint(&from.vars, id));
            into.set_fields(id, fields);
        }
        changed |= into.vars.join_changed(&from.vars);
        for (&binding, value) in &from.captures {
            changed |= self.join_tracked(into.captures.entry(binding).or_default(), value);
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
        let mut inputs = BTreeMap::<(DefId, BasicBlockId), FrameState>::new();
        let mut returns = BTreeMap::<DefId, Tracked>::new();
        let mut callers = BTreeMap::<DefId, BTreeSet<(DefId, BasicBlockId)>>::new();
        let mut globals = BTreeMap::<DefId, Tracked>::new();
        let mut queue = Queue::default();
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
        let global_bodies: BTreeSet<_> = env.global.iter().copied().collect();
        let mut roots = env.global.clone();
        roots.push(entry);
        if interp.call_uncalled {
            roots.extend(env.get_all_functions_and_closures());
        }
        let root_frame = |def, globals: &BTreeMap<DefId, Tracked>| {
            let mut initial = bindings[&def].frame(env, def, globals.clone());
            if def == entry
                && P::TAINT_RESOLVER_INPUT
                && matches!(interp.entry.kind, EntryKind::Resolver(..))
                && let Some(&id) = bindings[&def].args.first()
            {
                initial.vars[id.0 as usize] = Taint::Yes;
            }
            initial
        };
        for &def in &roots {
            inputs.insert((def, STARTING_BLOCK), root_frame(def, &globals));
            queue.push((def, STARTING_BLOCK));
        }

        while let Some((def, bb)) = queue.pop() {
            let body = env.def_ref(def).expect_body();
            let block = body.block(bb);
            let mut frame = inputs[&(def, bb)].clone();
            let layout = &bindings[&def];

            for (idx, inst) in block.iter().enumerate() {
                let location = (def, Location::new(bb, idx as u32));
                let values = TaintReader {
                    dataflow: self,
                    frame: &frame,
                };
                if self.policy.is_violation(inst, &values) {
                    interp.instruction_findings.insert(location);
                } else {
                    interp.instruction_findings.remove(&location);
                }
                let read = |operand| self.read(&frame, operand);
                let value: Tracked = match inst.rvalue() {
                    Rvalue::Read(op) => self.value(&frame, op),
                    Rvalue::Unary(op, operand) => unary_taint(*op, read(operand)).into(),
                    Rvalue::Bin(op, left, right) => self
                        .policy
                        .binary_taint(*op, read(left), read(right))
                        .into(),
                    Rvalue::Phi(vars) => {
                        vars.iter().fold(Tracked::default(), |mut value, (id, _)| {
                            self.join_tracked(&mut value, &frame.value(*id));
                            value
                        })
                    }
                    Rvalue::Template(template) => template
                        .exprs
                        .iter()
                        .fold(Taint::No, |taint, op| taint.join(&read(op)))
                        .into(),
                    Rvalue::Intrinsic(intrinsic, _) => {
                        self.policy.intrinsic_taint(intrinsic).into()
                    }
                    Rvalue::Call(callee, args) => {
                        if let Some((callee_def, _)) = body.resolve_call(env, callee) {
                            callers.entry(callee_def).or_default().insert((def, bb));
                            let callee_layout = &bindings[&callee_def];
                            // Capture the values visible at this call, including
                            // clean overwrites. Never join a binding's lifetime.
                            let mut callee_frame = callee_layout.frame(
                                env,
                                callee_def,
                                layout.captures_at_call(&frame, &captured),
                            );
                            for (&id, arg) in callee_layout.args.iter().zip(args) {
                                callee_frame.set(id, self.value(&frame, arg));
                            }
                            let key = (callee_def, STARTING_BLOCK);
                            let is_new = !inputs.contains_key(&key);
                            if self.join_frames(inputs.entry(key).or_default(), &callee_frame)
                                || is_new
                            {
                                queue.push(key);
                            }
                            returns.get(&callee_def).cloned().unwrap_or_default()
                        } else if let Some(value) =
                            self.lodash_call(env, body, layout, &frame, callee, args)
                        {
                            value
                        } else {
                            // Preserve data through unmodelled transformations,
                            // including methods called on a tainted receiver.
                            let receiver = self.receiver_taint(&frame, callee);
                            let taints: SmallVec<[Taint; 4]> = args.iter().map(read).collect();
                            let global_result = match callee {
                                Operand::Var(var) => var
                                    .as_var_id()
                                    .and_then(|id| variable_def(&body.vars[id]))
                                    .filter(|&def| env.is_undeclared_global(def))
                                    .and_then(|def| {
                                        self.policy
                                            .global_call_taint(env.def_name(def), &var.projections)
                                    }),
                                Operand::Lit(_) => None,
                            };
                            global_result
                                .or_else(|| {
                                    callee_name(env, body, callee).and_then(|method| {
                                        self.policy.method_taint(&UnresolvedCall {
                                            method,
                                            receiver,
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
                                    taints.iter().fold(receiver, |taint, arg| taint.join(arg))
                                })
                                .into()
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

            let successors: SmallVec<[BasicBlockId; 2]> = match block.successors() {
                Successors::Return => {
                    let returned = body
                        .vars
                        .iter_enumerated()
                        .filter(|(_, kind)| matches!(kind, VarKind::Ret))
                        .fold(Tracked::default(), |mut value, (id, _)| {
                            self.join_tracked(&mut value, &frame.value(id));
                            value
                        });
                    let is_new = !returns.contains_key(&def);
                    if (self.join_tracked(returns.entry(def).or_default(), &returned) || is_new)
                        && let Some(dependents) = callers.get(&def)
                    {
                        for &key in dependents {
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
                                    globals.entry(binding).or_default(),
                                    &frame.value(ids[0]),
                                );
                            }
                        }
                        if changed {
                            for &root in &roots {
                                let initial = root_frame(root, &globals);
                                let key = (root, STARTING_BLOCK);
                                if self.join_frames(inputs.entry(key).or_default(), &initial) {
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
                let key = (def, succ);
                let is_new = !inputs.contains_key(&key);
                if self.join_frames(inputs.entry(key).or_default(), &frame) || is_new {
                    queue.push(key);
                }
            }
        }
        interp.set_block_states(
            inputs
                .into_iter()
                .map(|(key, frame)| (key, frame.vars))
                .collect(),
        );
        interp.replace_func_states(
            returns
                .into_iter()
                .map(|(def, value)| (def, vec![value.taint])),
        );
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
