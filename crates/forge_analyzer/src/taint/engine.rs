use super::{
    Classification, FlowState, FlowValue, InputShape, PolicyFacts,
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
    let mut value = source_value::<P>(&SourceContext {
        env: interp.env(),
        body: interp.body(),
        function: def,
        location: Location::new(STARTING_BLOCK, 0),
        is_resolver: matches!(interp.entry().kind, crate::interp::EntryKind::Resolver(..)),
        argument: Some((argument, variable)),
        intrinsic: None,
        call: None,
    })
    .unwrap_or_else(FlowValue::unknown);
    value.shape = InputShape::Unknown;
    value
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
    let state_taint = state.variable_with_aliases(interp.body(), def, variable);
    if let Some(value) = &state_taint
        && (!value.facts.is_unknown() || value.shape.is_authoritative())
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
                .fold(FlowValue::BOTTOM, |result, (location, rvalue)| {
                    result.join(&classify_rvalue_inner::<P, C>(
                        interp, def, location, rvalue, state, visiting,
                    ))
                });
        visiting.remove(&key);
        return result;
    }

    if !variable.projections.is_empty() {
        let root = Variable::new(var);
        let returned_fields = interp
            .body()
            .assignments_to(&root)
            .filter_map(|(_, rvalue)| {
                let Rvalue::Call(callee, _) = rvalue else {
                    return None;
                };
                let (callee_def, callee_body) = interp.body().resolve_call(interp.env(), callee)?;
                let final_state = interp.func_state(callee_def)?;
                Some(
                    returned_object_variables(callee_body)
                        .into_iter()
                        .map(|mut returned| {
                            returned
                                .projections
                                .extend(variable.projections.iter().cloned());
                            final_state
                                .variable(callee_def, &returned)
                                .unwrap_or_else(FlowValue::unknown)
                        })
                        .fold(FlowValue::BOTTOM, |left, right| left.join(&right)),
                )
            })
            .reduce(|left, right| left.join(&right));
        if let Some(value) = returned_fields {
            visiting.remove(&key);
            return value;
        }
        if interp.body().assignments_to(&root).next().is_some() {
            let root_value = classify_variable_inner::<P, C>(interp, def, &root, state, visiting);
            if matches!(root_value.shape, InputShape::Known { .. }) {
                visiting.remove(&key);
                return root_value.project(&variable.projections);
            }
        }
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
                if interp.env().global_is_proven_constant(resolved_global)
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
        .fold(FlowValue::BOTTOM, |result, operand| {
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
        Rvalue::Array(elements) => elements.iter().fold(FlowValue::BOTTOM, |value, operand| {
            value.join(&classify(operand, visiting))
        }),
        Rvalue::Template(template) => template
            .exprs
            .iter()
            .fold(FlowValue::BOTTOM, |value, operand| {
                value.join(&classify(operand, visiting))
            }),
        Rvalue::Phi(values) => values.iter().fold(FlowValue::BOTTOM, |value, (var, _)| {
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
                let args = operands.iter().fold(FlowValue::BOTTOM, |value, operand| {
                    value.join(&classify(operand, visiting))
                });
                if is_numeric_builtin_call(interp, callee) {
                    // These proven JavaScript built-ins depend on their inputs;
                    // conversion itself is not an additional unknown source.
                    args
                } else if let Some((receiver, _)) = method_receiver(callee) {
                    let receiver =
                        classify_variable_inner::<P, C>(interp, def, &receiver, state, visiting);
                    let result = receiver.join(&args);
                    if receiver.shape.is_authoritative() {
                        result.join(&FlowValue::unknown())
                    } else {
                        result
                    }
                } else {
                    FlowValue::unknown().join(&args)
                }
            }
        }
    };
    let preserves_shape = matches!(rvalue, Rvalue::Read(_) | Rvalue::Phi(_))
        || matches!(rvalue, Rvalue::Call(callee, _) if interp.body().resolve_call(interp.env(), callee).is_some());
    if !preserves_shape {
        value.shape = value.shape.without_schema();
        value.references.clear();
    }
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
        interp.body().binding_variables(target).map_or_else(
            || vec![target.clone()],
            |aliases| aliases.iter().copied().map(Variable::new).collect(),
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
                projected_target.projections = target.projections.clone();
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
        // Recursive calls must evaluate all supplied values in the caller's
        // state before replacing any callee bindings.
        let mut call_state = state.clone();
        for (position, argument_def) in callee_body.argument_defs.iter().enumerate() {
            let operand = operands.get(position).unwrap_or(&Operand::UNDEF);
            let mut taint = classify_operand::<P, C>(interp, def, operand, state);
            if callee_body.unsupported_arguments.contains(argument_def) {
                taint.shape = taint.shape.without_schema();
            }

            for (arg, kind) in callee_body.vars.iter_enumerated() {
                let binding = match kind {
                    VarKind::Arg(binding)
                    | VarKind::GlobalRef(binding)
                    | VarKind::LocalDef(binding) => Some(binding),
                    _ => None,
                };
                if binding == Some(argument_def) {
                    call_state.insert_assignment(
                        callee_body,
                        callee_def,
                        &Variable::new(arg),
                        taint.clone(),
                    );
                    if let Operand::Var(source) = operand {
                        let projections = state.projections(def, source);
                        for (suffix, value) in projections {
                            let mut target = Variable::new(arg);
                            target.projections.extend(suffix);
                            call_state.insert_variable(callee_def, &target, value);
                        }
                    }
                }
            }
        }
        let changed = interp.join_block_state(callee_def, STARTING_BLOCK, &call_state);
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

    fn invalidate_call_inputs<'cx, C: Runner<'cx, State = FlowState<P::Facts>>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        callee: &Operand,
        operands: &[Operand],
        state: &mut FlowState<P::Facts>,
    ) {
        let resolved = interp.body().resolve_call(interp.env(), callee);
        let mut roots = Vec::new();
        for (position, operand) in operands.iter().enumerate() {
            let input = classify_operand::<P, C>(interp, def, operand, state);
            if !resolved.is_some_and(|(callee, _)| {
                input_is_read_only(interp.env(), callee, position, &mut HashSet::new())
            }) {
                roots.extend(input.references);
            }
        }
        if resolved.is_none()
            && let Some((receiver, _)) = method_receiver(callee)
        {
            roots.extend(classify_variable::<P, C>(interp, def, &receiver, state).references);
        }
        for root in roots {
            state.invalidate_input(root, None);
        }
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
        state.insert_assignment(interp.body(), def, &receiver, taint);
    }
}

impl<'cx, P: FlowPolicy> Dataflow<'cx> for TaintDataflow<P> {
    type State = FlowState<P::Facts>;
    const REQUIRE_CALLEE_STATE_COVERS_CALLER: bool = false;
    const JOIN_FUNCTION_RETURN_STATES: bool = true;

    fn with_interp<C: Runner<'cx, State = Self::State>>(interp: &Interp<'cx, C>) -> Self {
        if let Some(root) = interp.entry().root
            && interp.body().owner() == Some(root)
        {
            let body = interp.body();
            let mut state = FlowState::BOTTOM;
            state.reachable = true;
            for (position, &argument) in body.argument_defs.iter().enumerate() {
                let mut value = super::sources::root_argument::<P::Facts>(
                    interp.entry().contract,
                    position,
                    root,
                    argument,
                );
                if interp.entry().contract == crate::interp::InvocationContract::ForgeFunction
                    && position == 0
                {
                    let source = match interp.entry().input_category {
                        crate::interp::InputCategory::WebRequest => "http.request",
                        crate::interp::InputCategory::ProductEvent => "forge.product.event",
                        crate::interp::InputCategory::Payload => "entry.payload",
                    };
                    if let InputShape::Known { root, .. } = &mut value.shape {
                        root.payload_source = source;
                        value.references.clear();
                        value.references.insert(*root);
                    }
                    value.taint.origins = super::Origins::EMPTY;
                    value.taint.origins.insert(super::SourceOrigin {
                        source,
                        function: root,
                        site: super::OriginSite::Argument(argument),
                    });
                }
                if body.unsupported_arguments.contains(&argument) {
                    value.shape = InputShape::Unknown;
                    if value.taint.classification != Classification::Untrusted {
                        value = FlowValue::unknown();
                        value.shape = InputShape::Unknown;
                    }
                }
                for (var, kind) in body.vars.iter_enumerated() {
                    if matches!(kind, VarKind::Arg(binding) | VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) if *binding == argument)
                    {
                        state.insert_var(root, var, value.clone());
                    }
                }
            }
            interp.join_block_state(root, STARTING_BLOCK, &state);
        }
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
        if let Inst::Assign(_, Rvalue::Intrinsic(_, operands))
        | Inst::Expr(Rvalue::Intrinsic(_, operands)) = inst
        {
            let roots = operands
                .iter()
                .flat_map(|operand| {
                    classify_operand::<P, C>(interp, def, operand, &state).references
                })
                .collect::<Vec<_>>();
            for root in roots {
                state.invalidate_input(root, None);
            }
        }
        if let Inst::Assign(target, rvalue) = inst {
            if let Rvalue::Call(callee, operands) = rvalue {
                self.invalidate_call_inputs(interp, def, callee, operands, &mut state);
                self.propagate_call_arguments(interp, def, callee, operands, &mut state);
                self.propagate_container_mutation(interp, def, callee, operands, &mut state);
            }
            // FlowState<P::Facts> owns SQL classification, argument propagation, and return
            // propagation. Populating the shared ValueManager as well duplicates
            // that work and makes projected object assignments dominate runtime
            // on large entrypoint graphs.
            let taint = self.classify_rvalue(interp, def, loc, rvalue, &state);
            let read_projections = match rvalue {
                Rvalue::Read(Operand::Var(source)) => Some(state.projections(def, source)),
                _ => None,
            };
            if !target.projections.is_empty() {
                let mut receiver = target.clone();
                let property = receiver.projections.pop().expect("projected assignment");
                let input = classify_variable::<P, C>(interp, def, &receiver, &state);
                let aliases = state.input_write_targets(input.shape, &property);
                for root in input.references {
                    state.invalidate_input(root, Some(&taint));
                }
                for (owner, alias) in aliases {
                    state.insert_variable(owner, &alias, taint.clone());
                }
            }
            state.insert_assignment(interp.body(), def, target, taint);
            match rvalue {
                Rvalue::Call(callee, _) => {
                    self.propagate_call_return_projections(interp, def, callee, target, &mut state);
                }
                Rvalue::Read(_) => {
                    if let Some(projections) = read_projections {
                        Self::insert_projections(interp, def, target, projections, &mut state);
                    }
                }
                _ => {}
            }
        } else if let Inst::Expr(Rvalue::Call(callee, operands)) = inst {
            self.invalidate_call_inputs(interp, def, callee, operands, &mut state);
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
                state.mark_refined(interp.body(), def, &candidate);
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

/// A deliberately conservative, bounded effect proof. Follow only reads and
/// aliases of an argument. A write or an escape anywhere in its reachable local
/// call graph rejects the proof. Cycles are allowed only if all their uses pass.
fn input_is_read_only(
    env: &crate::definitions::Environment,
    def: DefId,
    position: usize,
    visiting: &mut HashSet<(DefId, usize)>,
) -> bool {
    if visiting.len() >= 128 {
        return false;
    }
    if !visiting.insert((def, position)) {
        return true;
    }
    let definition = env.def_ref(def);
    let Some(body) = definition.as_body() else {
        return false;
    };
    let Some(argument) = body.argument_defs.get(position) else {
        return true;
    };
    let mut aliases: HashSet<VarId> = body.vars.iter_enumerated().filter_map(|(var, kind)| {
        matches!(kind, VarKind::Arg(binding) | VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) if binding == argument).then_some(var)
    }).collect();
    let is_alias = |variable: &Variable, aliases: &HashSet<VarId>| matches!(variable.base, Base::Var(var) if aliases.contains(&var));
    let mut contained = aliases.clone();
    loop {
        let count = (aliases.len(), contained.len());
        for (_, block) in body.iter_blocks_enumerated() {
            for inst in block.iter() {
                if let Inst::Assign(target, rvalue) = inst {
                    let flows = match rvalue {
                        Rvalue::Read(Operand::Var(source)) => {
                            is_alias(source, &aliases)
                                || (!source.projections.is_empty() && is_alias(source, &contained))
                        }
                        Rvalue::Phi(values) => values.iter().any(|(var, _)| aliases.contains(var)),
                        Rvalue::Call(_, args) => args.iter().any(
                            |arg| matches!(arg, Operand::Var(var) if is_alias(var, &contained)),
                        ),
                        _ => false,
                    };
                    let contains = flows
                        || match rvalue {
                            Rvalue::Read(Operand::Var(source)) => is_alias(source, &contained),
                            Rvalue::Phi(values) => {
                                values.iter().any(|(var, _)| contained.contains(var))
                            }
                            Rvalue::Array(args) => args.iter().any(
                                |arg| matches!(arg, Operand::Var(var) if is_alias(var, &contained)),
                            ),
                            _ => false,
                        };
                    if let Base::Var(var) = target.base {
                        if flows && target.projections.is_empty() {
                            aliases.insert(var);
                            if let Some(versions) = body.binding_variables(target) {
                                aliases.extend(versions);
                            }
                        }
                        if contains {
                            contained.insert(var);
                            if let Some(versions) = body.binding_variables(target) {
                                contained.extend(versions);
                            }
                        }
                    }
                }
            }
        }
        if (aliases.len(), contained.len()) == count {
            break;
        }
    }
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in block.iter() {
            let rvalue = match inst {
                Inst::Assign(target, value) => {
                    if (!target.projections.is_empty() && is_alias(target, &aliases))
                        || (target.projections.len() > 1 && is_alias(target, &contained))
                    {
                        return false;
                    }
                    value
                }
                Inst::Expr(value) => value,
            };
            if let Rvalue::Call(callee, args) = rvalue {
                let resolved = body.resolve_call(env, callee);
                if resolved.is_none()
                    && let Some((receiver, _)) = method_receiver(callee)
                    && is_alias(&receiver, &contained)
                {
                    return false;
                }
                for (index, arg) in args.iter().enumerate() {
                    if matches!(arg, Operand::Var(var) if is_alias(var, &contained))
                        && !resolved.is_some_and(|(callee, _)| {
                            input_is_read_only(env, callee, index, visiting)
                        })
                    {
                        return false;
                    }
                }
            } else if let Rvalue::Intrinsic(_, args) = rvalue
                && args
                    .iter()
                    .any(|arg| matches!(arg, Operand::Var(var) if is_alias(var, &contained)))
            {
                return false;
            }
        }
    }
    true
}
