//! Reusable, forward may-taint analysis over the lowered IR.
//!
//! Policies define sources; runners evaluate their sink predicate on the state
//! *before* each instruction. Only positive sink locations are retained, rather
//! than a full variable-state snapshot at every instruction. Function inputs and returns are joined to a fixed point,
//! including loops and recursion. Values are tracked per function and variable.
//! Object properties and external calls are conservatively treated as propagators
//! unless a policy opts out; function summaries are context insensitive (shared
//! across call sites).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    marker::PhantomData,
    ops::ControlFlow,
};

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

/// Add sources for another scanner without duplicating the propagation engine.
pub trait TaintPolicy {
    fn intrinsic_taint(intrinsic: &Intrinsic) -> Taint;

    /// Whether resolver request arguments are sources for this policy.
    const TAINT_RESOLVER_INPUT: bool = false;

    /// Whether reading a property yields its containing object's taint. Writing
    /// a tainted property still taints the whole object, and a method call still
    /// inherits its receiver's taint.
    const PROPERTY_READS_PROPAGATE: bool = true;

    /// The result of an unmodelled method call, given its receiver and argument
    /// taints. Policies recognize their sanitizers here; `None` joins them all.
    fn method_taint(_method: &Atom, _receiver: Taint, _args: &[Taint]) -> Option<Taint> {
        None
    }
}

pub struct ResolverTaint;

impl TaintPolicy for ResolverTaint {
    const TAINT_RESOLVER_INPUT: bool = true;

    fn intrinsic_taint(_intrinsic: &Intrinsic) -> Taint {
        Taint::No
    }
}

pub struct SecretTaint;

impl TaintPolicy for SecretTaint {
    // Taint is tracked per variable, not per field, so a secret stored in one
    // field would otherwise taint every sibling ID, URL and count. Until fields
    // are tracked separately, only logging a whole secret-bearing value reports.
    const PROPERTY_READS_PROPAGATE: bool = false;

    fn intrinsic_taint(intrinsic: &Intrinsic) -> Taint {
        if matches!(intrinsic, Intrinsic::SecretRead) {
            Taint::Yes
        } else {
            Taint::No
        }
    }

    // Splitting on or replacing the secret itself redacts it from the receiver:
    // `text.split(secret).join('[REDACTED]')` or `url.replace(key, '***')`. The
    // pattern never reaches the result, and the receiver is assumed to hold no
    // other secret.
    fn method_taint(method: &Atom, receiver: Taint, args: &[Taint]) -> Option<Taint> {
        let remaining = if args.first() == Some(&Taint::Yes) {
            Taint::No
        } else {
            receiver
        };
        match (&**method, args) {
            ("split", [_, ..]) => Some(remaining),
            ("replace" | "replaceAll", [_, replacement]) => Some(remaining.join(replacement)),
            _ => None,
        }
    }
}

/// The taint of the variable underlying `operand`, ignoring its projections.
pub fn operand_taint(state: &[Taint], operand: &Operand) -> Taint {
    match operand {
        Operand::Var(var) => var.as_var_id().map_or(Taint::No, |id| var_taint(state, id)),
        Operand::Lit(_) => Taint::No,
    }
}

/// The taint of the value read by `operand`, including any property read.
pub fn read_taint<P: TaintPolicy>(state: &[Taint], operand: &Operand) -> Taint {
    match operand {
        Operand::Var(var) if !P::PROPERTY_READS_PROPAGATE && !var.projections.is_empty() => {
            Taint::No
        }
        _ => operand_taint(state, operand),
    }
}

/// A method call inherits the taint of its receiver, not of the method itself:
/// `secret.trim()` is tainted, while `secret.token.trim()` reads a property.
fn receiver_taint<P: TaintPolicy>(state: &[Taint], callee: &Operand) -> Taint {
    match callee {
        Operand::Var(var) if !P::PROPERTY_READS_PROPAGATE && var.projections.len() > 1 => Taint::No,
        _ => operand_taint(state, callee),
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

pub struct TaintDataflow<P = ResolverTaint>(PhantomData<P>);

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

// Block inputs retain ordinary variable vectors. Captures also carry bindings
// through helpers that do not themselves read them (but call a closure that does).
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct FrameState {
    vars: Vec<Taint>,
    captures: BTreeMap<DefId, Taint>,
}

impl JoinSemiLattice for FrameState {
    const BOTTOM: Self = Self {
        vars: Vec::new(),
        captures: BTreeMap::new(),
    };

    fn join_changed(&mut self, other: &Self) -> bool {
        let mut changed = self.vars.join_changed(&other.vars);
        for (&binding, taint) in &other.captures {
            changed |= self
                .captures
                .entry(binding)
                .or_default()
                .join_changed(taint);
        }
        changed
    }

    fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.join_changed(other);
        result
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
        mut captures: BTreeMap<DefId, Taint>,
    ) -> FrameState {
        // Recursive calls get fresh locals; only outer bindings are inherited.
        captures.retain(|binding, _| env.binding_owner(*binding) != Some(def));
        let mut vars = vec![Taint::No; env.def_ref(def).expect_body().vars.len()];
        for (binding, ids) in &self.aliases {
            if let Some(&taint) = captures.get(binding) {
                for id in ids {
                    vars[id.0 as usize] = taint;
                }
            }
        }
        FrameState { vars, captures }
    }

    fn captures_at_call(
        &self,
        state: &FrameState,
        captured: &BTreeSet<DefId>,
    ) -> BTreeMap<DefId, Taint> {
        let mut captures = state.captures.clone();
        for (binding, ids) in &self.aliases {
            if captured.contains(binding) {
                let taint = var_taint(&state.vars, ids[0]);
                if taint == Taint::No {
                    captures.remove(binding);
                } else {
                    captures.insert(*binding, taint);
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

impl<'cx, P: TaintPolicy> Dataflow<'cx> for TaintDataflow<P> {
    type State = Vec<Taint>;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self(PhantomData)
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
        let mut returns = BTreeMap::<DefId, Vec<Taint>>::new();
        let mut callers = BTreeMap::<DefId, BTreeSet<(DefId, BasicBlockId)>>::new();
        let mut globals = BTreeMap::<DefId, Taint>::new();
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
        let root_frame = |def, globals: &BTreeMap<DefId, Taint>| {
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
                if C::instruction_has_violation(inst, &frame.vars) {
                    interp.instruction_findings.insert(location);
                } else {
                    interp.instruction_findings.remove(&location);
                }
                let state = &frame.vars;
                let read = |operand| read_taint::<P>(state, operand);
                let taint = match inst.rvalue() {
                    Rvalue::Read(op) => read(op),
                    Rvalue::Unary(op, operand) => unary_taint(*op, read(operand)),
                    Rvalue::Bin(op, left, right) => binary_taint(*op, read(left), read(right)),
                    Rvalue::Phi(vars) => vars.iter().fold(Taint::No, |taint, (id, _)| {
                        taint.join(&var_taint(state, *id))
                    }),
                    Rvalue::Template(template) => template
                        .exprs
                        .iter()
                        .fold(Taint::No, |taint, op| taint.join(&read(op))),
                    Rvalue::Intrinsic(intrinsic, _) => P::intrinsic_taint(intrinsic),
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
                                callee_frame.vars[id.0 as usize] = read(arg);
                            }
                            let key = (callee_def, STARTING_BLOCK);
                            let is_new = !inputs.contains_key(&key);
                            if inputs.entry(key).or_default().join_changed(&callee_frame) || is_new
                            {
                                queue.push(key);
                            }
                            returns
                                .get(&callee_def)
                                .map_or(Taint::No, |state| var_taint(state, VarId(0)))
                        } else {
                            // Preserve data through unmodelled transformations,
                            // including methods called on a tainted receiver.
                            let receiver = receiver_taint::<P>(state, callee);
                            let args: SmallVec<[Taint; 4]> = args.iter().map(read).collect();
                            method_name(callee)
                                .and_then(|method| P::method_taint(method, receiver, &args))
                                .unwrap_or_else(|| {
                                    args.iter().fold(receiver, |taint, arg| taint.join(arg))
                                })
                        }
                    }
                };
                if let Inst::Assign(var, _) = inst
                    && let Base::Var(id) = var.base
                {
                    let state = &mut frame.vars;
                    if var.projections.is_empty() {
                        state[id.0 as usize] = taint;
                    } else {
                        state[id.0 as usize].join_changed(&taint);
                    }
                    if let Some(var_def) = variable_def(&body.vars[id]) {
                        // Index aliases once per body instead of scanning all
                        // variables at every assignment.
                        for &alias in &layout.aliases[&var_def] {
                            state[alias.0 as usize] = state[id.0 as usize];
                        }
                    }
                }
            }

            let successors: SmallVec<[BasicBlockId; 2]> = match block.successors() {
                Successors::Return => {
                    let return_taint = body
                        .vars
                        .iter_enumerated()
                        .filter(|(_, kind)| matches!(kind, VarKind::Ret))
                        .fold(Taint::No, |taint, (id, _)| {
                            taint.join(&var_taint(&frame.vars, id))
                        });
                    let is_new = !returns.contains_key(&def);
                    if (returns
                        .entry(def)
                        .or_default()
                        .join_changed(&vec![return_taint])
                        || is_new)
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
                                changed |= globals
                                    .entry(binding)
                                    .or_default()
                                    .join_changed(&var_taint(&frame.vars, ids[0]));
                            }
                        }
                        if changed {
                            for &root in &roots {
                                let initial = root_frame(root, &globals);
                                let key = (root, STARTING_BLOCK);
                                if inputs.entry(key).or_default().join_changed(&initial) {
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
                if inputs.entry(key).or_default().join_changed(&frame) || is_new {
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
        interp.replace_func_states(returns);
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
