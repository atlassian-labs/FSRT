//! Reusable, forward may-taint analysis over the lowered IR.
//!
//! Policies define sources, property-read propagation and sinks. A policy's sink
//! predicate sees the state *before* each instruction. Only positive sink locations
//! are retained, rather than a full variable-state snapshot at every instruction.
//! Function inputs and returns are joined to a fixed point, including loops and
//! recursion. Values are tracked per function and variable and, for policies that
//! opt in, per known property path. Object properties and external calls are
//! conservatively treated as propagators unless a policy opts out; function
//! summaries are context insensitive (shared across call sites).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::{Bound, ControlFlow},
    rc::Rc,
};

use itertools::Itertools;
use smallvec::SmallVec;
use swc_core::ecma::atoms::Atom;

use crate::{
    definitions::{DefId, Environment},
    interp::{Dataflow, EntryKind, Interp, JoinSemiLattice, Runner},
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Body, Inst, Intrinsic, Location, Operand,
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

    /// The result of an unmodelled method call, given its receiver and argument
    /// taints. Policies recognize their sanitizers here; `None` joins them all.
    fn method_taint(&self, _method: &Atom, _receiver: Taint, _args: &[Taint]) -> Option<Taint> {
        None
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

fn method_name(callee: &Operand) -> Option<&Atom> {
    match callee {
        Operand::Var(var) => match var.projections.last()? {
            Projection::Known(name) => Some(name),
            Projection::Computed(_) => None,
        },
        Operand::Lit(_) => None,
    }
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
}

impl Bindings {
    fn new(body: &Body) -> Self {
        let mut aliases = BTreeMap::<_, SmallVec<_>>::new();
        for (id, kind) in body.vars.iter_enumerated() {
            if let Some(binding) = variable_def(kind) {
                aliases.entry(binding).or_default().push(id);
            }
        }
        Self {
            aliases,
            args: argument_vars(body).map(|(id, _)| id).collect(),
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

fn unary_taint(op: UnOp, taint: Taint) -> Taint {
    match op {
        UnOp::Not | UnOp::TypeOf | UnOp::Delete | UnOp::Void => Taint::No,
        UnOp::Neg | UnOp::Plus | UnOp::BitNot => taint,
    }
}

fn binary_taint(op: BinOp, left: Taint, right: Taint) -> Taint {
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
                let copied: FieldMap = source
                    .range::<[Atom], _>((Bound::Excluded(&prefix[..]), Bound::Unbounded))
                    .take_while(|(path, _)| path.starts_with(&prefix))
                    .map(|(path, &taint)| (FieldPath::from(&path[prefix.len()..]), taint))
                    .collect();
                fields = (!copied.is_empty()).then(|| Rc::new(copied));
            }
        }
        Tracked { taint, fields }
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
                    Rvalue::Bin(op, left, right) => {
                        binary_taint(*op, read(left), read(right)).into()
                    }
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
                        } else {
                            // Preserve data through unmodelled transformations,
                            // including methods called on a tainted receiver.
                            let receiver = self.receiver_taint(&frame, callee);
                            let args: SmallVec<[Taint; 4]> = args.iter().map(read).collect();
                            method_name(callee)
                                .and_then(|method| {
                                    self.policy.method_taint(method, receiver, &args)
                                })
                                .unwrap_or_else(|| {
                                    args.iter().fold(receiver, |taint, arg| taint.join(arg))
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
