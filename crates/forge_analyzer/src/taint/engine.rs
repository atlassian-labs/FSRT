use super::{
    Classification, FlowState, FlowValue, PolicyFacts,
    semantics::*,
    sources::{FORGE_SOURCES, SourceContext, SourceDefinition},
};
use crate::{
    definitions::{Const, DefId, DefKind, Value},
    interp::{Dataflow, Interp, JoinSemiLattice, Runner},
    ir::{
        Base, BasicBlock, BasicBlockId, Inst, Intrinsic, Location, Operand, Projection, Rvalue,
        STARTING_BLOCK, Terminator, VarId, VarKind, Variable,
    },
    worklist::WorkList,
};
use smallvec::SmallVec;
use std::collections::{BTreeMap, HashMap, HashSet};

pub trait FlowPolicy: Sized {
    type Facts: PolicyFacts;
    fn sources() -> &'static [SourceDefinition] {
        &[]
    }
    fn source_classification(source: &SourceDefinition) -> Classification {
        source.classification
    }
    fn variable_facts<'cx, C: Runner<'cx, State = FlowState<Self::Facts>>>(
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _variable: &Variable,
        _state: &FlowState<Self::Facts>,
    ) -> Option<Self::Facts> {
        None
    }
    fn rvalue_facts<'cx, C: Runner<'cx, State = FlowState<Self::Facts>>>(
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _location: Location,
        _rvalue: &Rvalue,
    ) -> Option<Self::Facts> {
        None
    }
    fn branch_refinement<'cx, C: Runner<'cx, State = FlowState<Self::Facts>>>(
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _condition: &Operand,
    ) -> Option<(Variable, bool)> {
        None
    }
}

fn source_value<P: FlowPolicy>(context: &SourceContext<'_>) -> Option<FlowValue<P::Facts>> {
    P::sources()
        .iter()
        .chain(FORGE_SOURCES)
        .find(|source| (source.matches)(context))
        .map(|source| FlowValue::source(P::source_classification(source), source.origin(context)))
}
fn argument_value<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    argument: DefId,
) -> FlowValue<P::Facts> {
    source_value::<P>(&SourceContext {
        env: interp.env(),
        body: interp.body(),
        function: def,
        location: Location::new(STARTING_BLOCK, 0),
        is_resolver: matches!(interp.entry().kind, crate::interp::EntryKind::Resolver(..)),
        argument: Some((argument, variable)),
        intrinsic: None,
        call: None,
    })
    .unwrap_or_else(FlowValue::unknown)
}

pub fn classify_variable<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    state: &FlowState<P::Facts>,
) -> FlowValue<P::Facts> {
    classify_variable_inner::<P, C>(interp, def, variable, state, &mut HashSet::new())
}
fn classify_variable_inner<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    state: &FlowState<P::Facts>,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> FlowValue<P::Facts> {
    let mut value = classify_variable_base::<P, C>(interp, def, variable, state, visiting);
    if let Some(facts) = P::variable_facts(interp, def, variable, state) {
        value.facts = facts;
    }
    value
}
fn classify_variable_base<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    state: &FlowState<P::Facts>,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> FlowValue<P::Facts> {
    let state_taint = state.variable_with_aliases(interp.env(), interp.body(), def, variable);
    if let Some(value) = &state_taint
        && !value.facts.is_unknown()
    {
        return value.clone();
    }

    let Base::Var(var) = variable.base else {
        return FlowValue::unknown();
    };

    let key = (def, var, variable.projections.iter().cloned().collect());
    if !visiting.insert(key.clone()) {
        return state_taint.unwrap_or_else(FlowValue::unknown);
    }

    // The block worklist can encounter a phi before its predecessor blocks. Use
    // the SSA definitions as a second source of truth so a value is not frozen
    // as Unknown merely because of traversal order.
    let definitions = interp.body().assignments_to(variable).collect::<Vec<_>>();
    if !definitions.is_empty() {
        let result =
            definitions
                .into_iter()
                .fold(FlowValue::trusted(), |result, (location, rvalue)| {
                    result.join(&classify_rvalue_inner::<P, C>(
                        interp, def, location, rvalue, state, visiting,
                    ))
                });
        visiting.remove(&key);
        return result;
    }

    if let Some(kind) = interp.body().vars.get(var) {
        match kind {
            VarKind::Arg(arg_def) => {
                let result = argument_value::<P, C>(interp, def, variable, *arg_def);
                visiting.remove(&key);
                return result;
            }
            VarKind::GlobalRef(global_def) => {
                if matches!(interp.env().def_ref(*global_def), DefKind::Arg) {
                    let result = argument_value::<P, C>(interp, def, variable, *global_def);
                    visiting.remove(&key);
                    return result;
                }
                let resolved_global = interp.env().resolve_alias(*global_def);
                if global_is_proven_constant(interp.env(), resolved_global)
                    || matches!(
                        interp
                            .value_manager
                            .defid_to_value
                            .get(global_def)
                            .or_else(|| {
                                interp.value_manager.defid_to_value.get(&resolved_global)
                            }),
                        Some(Value::Const(_) | Value::Phi(_))
                    )
                {
                    visiting.remove(&key);
                    return FlowValue::trusted();
                }
            }
            _ => {}
        }
    }

    let result = match interp.get_value(def, var, Some(variable.projections.clone())) {
        Some(Value::Const(Const::Literal(_))) | Some(Value::Phi(_)) => FlowValue::trusted(),
        Some(Value::Object(object)) => state
            .variable(def, &Variable::new(*object))
            .unwrap_or_else(FlowValue::unknown),
        Some(Value::Unknown | Value::Uninit) | None => {
            state_taint.unwrap_or_else(FlowValue::unknown)
        }
    };
    visiting.remove(&key);
    result
}

pub fn classify_operand<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operand: &Operand,
    state: &FlowState<P::Facts>,
) -> FlowValue<P::Facts> {
    classify_operand_inner::<P, C>(interp, def, operand, state, &mut HashSet::new())
}
fn classify_operand_inner<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operand: &Operand,
    state: &FlowState<P::Facts>,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> FlowValue<P::Facts> {
    match operand {
        Operand::Lit(_) => FlowValue::trusted(),
        Operand::Var(variable) => {
            classify_variable_inner::<P, C>(interp, def, variable, state, visiting)
        }
    }
}
fn join_operands<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operands: impl IntoIterator<Item = Operand>,
    state: &FlowState<P::Facts>,
) -> FlowValue<P::Facts> {
    operands
        .into_iter()
        .fold(FlowValue::trusted(), |result, operand| {
            result.join(&classify_operand::<P, C>(interp, def, &operand, state))
        })
}
fn classify_rvalue_inner<'cx, P: FlowPolicy, C: Runner<'cx, State = FlowState<P::Facts>>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    location: Location,
    rvalue: &Rvalue,
    state: &FlowState<P::Facts>,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> FlowValue<P::Facts> {
    let classify = |operand: &Operand, visiting: &mut HashSet<_>| {
        classify_operand_inner::<P, C>(interp, def, operand, state, visiting)
    };
    let context = SourceContext {
        env: interp.env(),
        body: interp.body(),
        function: def,
        location,
        is_resolver: matches!(interp.entry().kind, crate::interp::EntryKind::Resolver(..)),
        argument: None,
        intrinsic: match rvalue {
            Rvalue::Intrinsic(intrinsic, _) => Some(intrinsic),
            _ => None,
        },
        call: rvalue.as_call(),
    };
    // A registered result source owns its initial trust and safety. Operation
    // fallbacks must not require a second edit when a new source is registered.
    if let Some(source) = source_value::<P>(&context) {
        return source;
    }
    let mut value = match rvalue {
        Rvalue::Read(operand) | Rvalue::Unary(_, operand) => classify(operand, visiting),
        Rvalue::Bin(_, left, right) => classify(left, visiting).join(&classify(right, visiting)),
        Rvalue::Array(elements) => elements
            .iter()
            .fold(FlowValue::trusted(), |value, operand| {
                value.join(&classify(operand, visiting))
            }),
        Rvalue::Template(template) => template
            .exprs
            .iter()
            .fold(FlowValue::trusted(), |value, operand| {
                value.join(&classify(operand, visiting))
            }),
        Rvalue::Phi(values) => values.iter().fold(FlowValue::trusted(), |value, (var, _)| {
            value.join(&classify_variable_inner::<P, C>(
                interp,
                def,
                &Variable::new(*var),
                state,
                visiting,
            ))
        }),
        Rvalue::Intrinsic(_, _) => FlowValue::unknown(),
        Rvalue::Call(callee, operands) => {
            if let Some((callee_def, callee_body)) =
                interp.body().resolve_call(interp.env(), callee)
            {
                interp
                    .func_state(callee_def)
                    .and_then(|final_state| {
                        callee_body
                            .vars
                            .iter_enumerated()
                            .find(|(_, kind)| matches!(kind, VarKind::Ret))
                            .and_then(|(ret, _)| {
                                final_state.variable(callee_def, &Variable::new(ret))
                            })
                    })
                    .unwrap_or_else(FlowValue::unknown)
            } else {
                let args = operands
                    .iter()
                    .fold(FlowValue::trusted(), |value, operand| {
                        value.join(&classify(operand, visiting))
                    });
                if is_numeric_builtin_call(interp, callee) {
                    // These proven JavaScript built-ins depend on their inputs;
                    // conversion itself is not an additional unknown source.
                    args
                } else if let Some((receiver, _)) = method_receiver(callee) {
                    classify_variable_inner::<P, C>(interp, def, &receiver, state, visiting)
                        .join(&args)
                } else {
                    FlowValue::unknown().join(&args)
                }
            }
        }
    };
    if let Some(facts) = P::rvalue_facts(interp, def, location, rvalue) {
        value.facts = facts;
    }
    value
}
pub struct TaintDataflow<P> {
    policy: std::marker::PhantomData<P>,
    needs_call: Vec<(DefId, bool)>,
    branch_refinements: HashMap<(DefId, BasicBlockId), Vec<Variable>>,
}

impl<P: FlowPolicy> TaintDataflow<P> {
    fn target_aliases<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        interp: &Interp<'cx, C>,
        target: &Variable,
    ) -> Vec<Variable> {
        FlowState::<P::Facts>::logical_name(interp.env(), interp.body(), target).map_or_else(
            || vec![target.clone()],
            |name| {
                interp
                    .body()
                    .vars
                    .iter_enumerated()
                    .filter_map(|(var, _)| {
                        let candidate = Variable::new(var);
                        (FlowState::<P::Facts>::logical_name(
                            interp.env(),
                            interp.body(),
                            &candidate,
                        ) == Some(name))
                        .then_some(candidate)
                    })
                    .collect()
            },
        )
    }

    fn insert_projections<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        target: &Variable,
        projections: BTreeMap<Vec<Projection>, FlowValue<P::Facts>>,
        state: &mut FlowState<P::Facts>,
    ) {
        for (suffix, value) in projections {
            for alias in Self::target_aliases(interp, target) {
                let mut projected_target = alias;
                projected_target.projections.extend(suffix.iter().cloned());
                state.insert_variable(def, &projected_target, value.clone());
            }
        }
    }

    fn classify_rvalue<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        location: Location,
        rvalue: &Rvalue,
        state: &FlowState<P::Facts>,
    ) -> FlowValue<P::Facts> {
        classify_rvalue_inner::<P, C>(interp, def, location, rvalue, state, &mut HashSet::new())
    }

    fn propagate_call_arguments<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        callee: &Operand,
        operands: &[Operand],
        state: &mut FlowState<P::Facts>,
    ) {
        let Some((callee_def, callee_body)) = interp.body().resolve_call(interp.env(), callee)
        else {
            return;
        };
        for (argument_def, operand) in callee_body.argument_defs.iter().zip(operands) {
            let taint = classify_operand::<P, C>(interp, def, operand, state);
            for (arg, kind) in callee_body.vars.iter_enumerated() {
                let binding = match kind {
                    VarKind::Arg(binding)
                    | VarKind::GlobalRef(binding)
                    | VarKind::LocalDef(binding) => Some(binding),
                    _ => None,
                };
                if binding == Some(argument_def) {
                    state.insert_var(callee_def, arg, taint.clone());
                    if let Operand::Var(source) = operand {
                        let projections = state.projections(def, source);
                        for (suffix, value) in projections {
                            let mut target = Variable::new(arg);
                            target.projections.extend(suffix);
                            state.insert_variable(callee_def, &target, value);
                        }
                    }
                }
            }
        }
        let changed = interp.join_block_state(callee_def, STARTING_BLOCK, state);
        self.needs_call.push((callee_def, changed));
    }

    fn propagate_call_return_projections<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &self,
        interp: &Interp<'cx, C>,
        caller_def: DefId,
        callee: &Operand,
        target: &Variable,
        state: &mut FlowState<P::Facts>,
    ) {
        let Some((callee_def, callee_body)) = interp.body().resolve_call(interp.env(), callee)
        else {
            return;
        };
        let Some(final_state) = interp.func_state(callee_def) else {
            return;
        };

        let mut projections = BTreeMap::<Vec<Projection>, FlowValue<P::Facts>>::new();
        for returned in returned_object_variables(callee_body) {
            let Base::Var(returned_var) = returned.base else {
                continue;
            };
            for ((owner, var, path), value) in &final_state.values {
                if *owner != callee_def
                    || *var != returned_var
                    || path.len() <= returned.projections.len()
                    || !path.starts_with(&returned.projections)
                {
                    continue;
                }
                let suffix = path[returned.projections.len()..].to_vec();
                projections
                    .entry(suffix)
                    .and_modify(|current| *current = current.join(value))
                    .or_insert_with(|| value.clone());
            }
        }

        Self::insert_projections(interp, caller_def, target, projections, state);
    }

    fn propagate_assignment_projections<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        source: &Variable,
        target: &Variable,
        state: &mut FlowState<P::Facts>,
    ) {
        let Base::Var(source_var) = source.base else {
            return;
        };
        let mut projections = BTreeMap::<Vec<Projection>, FlowValue<P::Facts>>::new();
        for ((owner, var, path), value) in &state.values {
            if *owner != def
                || *var != source_var
                || path.len() <= source.projections.len()
                || !path.starts_with(&source.projections)
            {
                continue;
            }
            let suffix = path[source.projections.len()..].to_vec();
            projections
                .entry(suffix)
                .and_modify(|current| *current = current.join(value))
                .or_insert_with(|| value.clone());
        }
        Self::insert_projections(interp, def, target, projections, state);
    }

    fn propagate_container_mutation<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        callee: &Operand,
        operands: &[Operand],
        state: &mut FlowState<P::Facts>,
    ) {
        let Some((receiver, "push")) = method_receiver(callee) else {
            return;
        };
        let taint = classify_variable::<P, C>(interp, def, &receiver, state).join(
            &join_operands::<P, C>(interp, def, operands.iter().cloned(), state),
        );
        state.insert_assignment(interp.env(), interp.body(), def, &receiver, taint);
    }
}

impl<'cx, P: FlowPolicy> Dataflow<'cx> for TaintDataflow<P> {
    type State = FlowState<P::Facts>;
    const REQUIRE_CALLEE_STATE_COVERS_CALLER: bool = false;
    const JOIN_FUNCTION_RETURN_STATES: bool = true;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self {
            policy: std::marker::PhantomData,
            needs_call: vec![],
            branch_refinements: HashMap::new(),
        }
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        inst: &'cx Inst,
        mut state: Self::State,
    ) -> Self::State {
        state.reachable = true;
        if let Inst::Assign(target, rvalue) = inst {
            if let Rvalue::Call(callee, operands) = rvalue {
                self.propagate_call_arguments(interp, def, callee, operands, &mut state);
                self.propagate_container_mutation(interp, def, callee, operands, &mut state);
            }
            // FlowState<P::Facts> owns SQL classification, argument propagation, and return
            // propagation. Populating the shared ValueManager as well duplicates
            // that work and makes projected object assignments dominate runtime
            // on large entrypoint graphs.
            let taint = self.classify_rvalue(interp, def, loc, rvalue, &state);
            state.insert_assignment(interp.env(), interp.body(), def, target, taint);
            match rvalue {
                Rvalue::Call(callee, _) => {
                    self.propagate_call_return_projections(interp, def, callee, target, &mut state);
                }
                Rvalue::Read(Operand::Var(source)) => {
                    self.propagate_assignment_projections(interp, def, source, target, &mut state);
                }
                _ => {}
            }
        } else if let Inst::Expr(Rvalue::Call(callee, operands)) = inst {
            self.propagate_call_arguments(interp, def, callee, operands, &mut state);
            self.propagate_container_mutation(interp, def, callee, operands, &mut state);
        }
        state
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
    ) -> Self::State {
        let mut state = initial_state;
        if let Some(candidates) = self.branch_refinements.get(&(def, bb)).cloned() {
            for candidate in candidates {
                state.mark_refined(interp.env(), interp.body(), def, &candidate);
            }
        }
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }
        state
    }

    fn join_term<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        if let Terminator::If { cond, cons, alt } = &block.term
            && let Some((candidate, allowed_when_true)) = P::branch_refinement(interp, def, cond)
        {
            let allowed_successor = if allowed_when_true { *cons } else { *alt };
            let rejected_successor = if allowed_when_true { *alt } else { *cons };
            if allowed_successor != rejected_successor
                && interp.body().predecessors(allowed_successor).len() == 1
            {
                let candidates = self
                    .branch_refinements
                    .entry((def, allowed_successor))
                    .or_default();
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                    // SWC numbers a conditional expression's join block before
                    // its alternatives. Analyze both alternatives first so a
                    // sink in the join block does not observe a partial phi.
                    worklist
                        .worklist
                        .retain(|work| *work != (def, *cons) && *work != (def, *alt));
                    worklist.worklist.push_front((def, *alt));
                    worklist.worklist.push_front((def, *cons));
                }
            }
        }
        self.super_join_term(interp, def, block, state, worklist);
        for (callee, changed) in self.needs_call.drain(..) {
            if !worklist.push_front_blocks(interp.env(), callee, interp.call_all) && changed {
                let blocks = interp
                    .env()
                    .def_ref(callee)
                    .expect_body()
                    .iter_block_keys()
                    .map(|block| (callee, block));
                worklist.extend(blocks);
            }
        }
    }
}
