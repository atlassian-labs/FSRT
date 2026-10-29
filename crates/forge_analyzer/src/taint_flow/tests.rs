use super::*;
use crate::{
    definitions::{DefId, Environment},
    interp::JoinSemiLattice,
    ir::{Body, Location, Projection, STARTING_BLOCK, VarId, VarKind, Variable},
};

fn origin(index: u32) -> SourceOrigin {
    SourceOrigin {
        source: "test.input",
        function: DefId::new(0),
        site: OriginSite::Instruction(Location::new(STARTING_BLOCK, index)),
    }
}
fn value(classification: Classification, indexes: &[u32]) -> TaintValue {
    let mut value = TaintValue::new(classification);
    for index in indexes {
        value.origins.insert(origin(*index));
    }
    value
}
#[test]
fn classification_and_provenance_obey_join_laws() {
    let values = [
        value(Classification::Trusted, &[]),
        value(Classification::Unknown, &[1]),
        value(Classification::Untrusted, &[2]),
        value(Classification::Trusted, &[3, 4, 5, 6, 7, 8, 9, 10, 11]),
    ];
    for a in &values {
        assert_eq!(a.join(a), *a);
        for b in &values {
            assert_eq!(a.join(b), b.join(a));
            for c in &values {
                assert_eq!(a.join(&b.join(c)), a.join(b).join(c));
            }
        }
    }
}
#[test]
fn bounded_origins_do_not_depend_on_insertion_order_or_reduce_trust() {
    let mut forward = value(Classification::Trusted, &[]);
    let mut reverse = forward.clone();
    for index in 0..32 {
        forward.origins.insert(origin(index));
    }
    for index in (0..32).rev() {
        reverse.origins.insert(origin(index));
    }
    assert_eq!(forward, reverse);
    assert_eq!(forward.origins.iter().count(), MAX_ORIGINS);
    let untrusted = value(Classification::Untrusted, &[50]);
    let result = forward.join(&untrusted);
    assert_eq!(result.classification, Classification::Untrusted);
    assert_eq!(result.origins, forward.origins);
}
#[test]
fn origin_only_changes_trigger_convergence_once() {
    let mut a = value(Classification::Untrusted, &[1]);
    let b = value(Classification::Untrusted, &[2]);
    assert!(a.join_changed(&b));
    assert!(!a.join_changed(&b));
}
#[test]
fn reachable_unknown_is_distinct_from_unreachable_bottom() {
    let mut state = FlowState::<NoFacts>::BOTTOM;
    let mut body = Body::with_owner(DefId::new(0));
    let var = body.vars.push_and_get_key(VarKind::Temp { parent: None });
    let mut reached = state.clone();
    reached.insert_assignment(
        &body,
        DefId::new(0),
        &Variable::new(var),
        FlowValue::unknown(),
    );
    assert!(state.join_changed(&reached));
    assert!(!state.join_changed(&FlowState::BOTTOM));
    assert_eq!(
        state
            .variable(DefId::new(0), &Variable::new(var))
            .unwrap()
            .taint
            .classification,
        Classification::Unknown
    );
    assert!(
        state
            .variable(DefId::new(0), &Variable::new(VarId(999)))
            .is_none()
    );
}
#[test]
fn strong_assignment_replaces_taint_and_origins() {
    let def = DefId::new(0);
    let mut body = Body::with_owner(def);
    let var = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
    let mut state = FlowState::<NoFacts>::BOTTOM;
    state.insert_assignment(
        &body,
        def,
        &var,
        FlowValue::source(Classification::Untrusted, origin(1)),
    );
    state.insert_assignment(&body, def, &var, FlowValue::trusted());
    assert_eq!(state.variable(def, &var), Some(FlowValue::trusted()));
}
#[test]
fn exact_projection_precedes_conservative_root_summary() {
    let def = DefId::new(0);
    let mut body = Body::with_owner(def);
    let root = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
    let mut field = root.clone();
    field.projections.push(Projection::Known("safe".into()));
    let mut other = root.clone();
    other.projections.push(Projection::Known("other".into()));
    let mut state = FlowState::<NoFacts>::BOTTOM;
    state.insert_assignment(
        &body,
        def,
        &root,
        FlowValue::source(Classification::Untrusted, origin(1)),
    );
    state.insert_assignment(&body, def, &field, FlowValue::trusted());
    assert_eq!(
        state.variable_with_aliases(&body, def, &field),
        Some(FlowValue::trusted())
    );
    assert_eq!(
        state.variable(def, &other).unwrap().taint.classification,
        Classification::Untrusted
    );
}
#[test]
fn state_joins_notice_new_origins_even_when_classification_and_policy_facts_match() {
    let def = DefId::new(0);
    let mut body = Body::with_owner(def);
    let var = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
    let mut first = FlowState::<NoFacts>::BOTTOM;
    let mut second = FlowState::<NoFacts>::BOTTOM;
    first.insert_assignment(
        &body,
        def,
        &var,
        FlowValue::source(Classification::Untrusted, origin(1)),
    );
    second.insert_assignment(
        &body,
        def,
        &var,
        FlowValue::source(Classification::Untrusted, origin(2)),
    );
    assert!(first.join_changed(&second));
    assert!(!first.join_changed(&second));
    assert_eq!(
        first
            .variable(def, &var)
            .unwrap()
            .taint
            .origins
            .iter()
            .count(),
        2
    );
}

#[test]
fn binding_alias_overwrites_clear_related_projections_and_refinements() {
    let def = DefId::new(0);
    let mut env = Environment::default();
    let binding = env.resolver.names.push_and_get_key("fragment".into());
    let mut body = Body::with_owner(def);
    let first = Variable::new(body.vars.push_and_get_key(VarKind::Arg(binding)));
    let alias = Variable::new(body.vars.push_and_get_key(VarKind::GlobalRef(binding)));
    let mut projected = first.clone();
    projected
        .projections
        .push(Projection::Known("field".into()));
    let mut state = FlowState::<NoFacts>::BOTTOM;
    state.insert_assignment(
        &body,
        def,
        &projected,
        FlowValue::source(Classification::Untrusted, origin(1)),
    );
    state.mark_refined(&body, def, &projected);
    state.insert_assignment(&body, def, &alias, FlowValue::trusted());
    assert_eq!(
        state.variable_with_aliases(&body, def, &projected),
        Some(FlowValue::trusted())
    );
    assert!(!state.is_refined(&body, def, &projected));
}

#[test]
fn branch_refinement_requires_all_reachable_predecessors() {
    let def = DefId::new(0);
    let mut body = Body::with_owner(def);
    let var = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
    let mut checked = FlowState::<NoFacts>::BOTTOM;
    checked.insert_assignment(&body, def, &var, FlowValue::unknown());
    let unchecked = checked.clone();
    checked.mark_refined(&body, def, &var);
    assert!(
        checked
            .join(&FlowState::BOTTOM)
            .is_refined(&body, def, &var)
    );
    assert!(!checked.join(&unchecked).is_refined(&body, def, &var));
}

#[test]
fn forge_source_definitions_have_unique_ids_and_labels() {
    let mut ids = std::collections::HashSet::new();
    for source in sources::FORGE_SOURCES {
        assert!(ids.insert(source.id), "duplicate source: {}", source.id);
        assert!(!source.label.is_empty());
    }
}

#[test]
fn indexed_ir_definitions_preserve_exact_projection_and_assignment_order() {
    use crate::ir::{Operand, Rvalue, Terminator};
    let def = DefId::new(0);
    let mut body = Body::with_owner(def);
    let root = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
    let mut projected = root.clone();
    projected
        .projections
        .push(Projection::Known("field".into()));
    body.push_assign(STARTING_BLOCK, root.clone(), Rvalue::Read(Operand::UNDEF));
    body.push_assign(
        STARTING_BLOCK,
        projected.clone(),
        Rvalue::Read(Operand::UNDEF),
    );
    body.push_assign(STARTING_BLOCK, root.clone(), Rvalue::Read(Operand::UNDEF));
    body.set_terminator(STARTING_BLOCK, Terminator::Ret);
    let roots = body
        .assignments_to(&root)
        .map(|(location, _)| location.stmt)
        .collect::<Vec<_>>();
    let fields = body
        .assignments_to(&projected)
        .map(|(location, _)| location.stmt)
        .collect::<Vec<_>>();
    assert_eq!(roots, vec![0, 2]);
    assert_eq!(fields, vec![1]);
    projected
        .projections
        .push(Projection::Known("missing".into()));
    assert_eq!(body.assignments_to(&projected).count(), 0);
}

#[test]
fn shadowed_bindings_do_not_share_values_or_refinements() {
    let def = DefId::new(0);
    let mut env = Environment::default();
    let outer_binding = env.resolver.names.push_and_get_key("query".into());
    let inner_binding = env.resolver.names.push_and_get_key("query".into());
    let mut body = Body::with_owner(def);
    let outer = Variable::new(body.vars.push_and_get_key(VarKind::LocalDef(outer_binding)));
    let inner = Variable::new(body.vars.push_and_get_key(VarKind::LocalDef(inner_binding)));
    let mut field = outer.clone();
    field.projections.push(Projection::Known("field".into()));
    let value = FlowValue::source(Classification::Untrusted, origin(1));
    let mut state = FlowState::<NoFacts>::BOTTOM;
    state.insert_assignment(&body, def, &field, value.clone());
    assert_eq!(state.variable_with_aliases(&body, def, &inner), None);
    state.mark_refined(&body, def, &outer);
    assert!(!state.is_refined(&body, def, &inner));
    state.insert_assignment(&body, def, &inner, FlowValue::trusted());
    assert_eq!(state.variable_with_aliases(&body, def, &field), Some(value));
    assert!(state.is_refined(&body, def, &outer));
}

#[test]
fn input_shapes_obey_join_laws_independently_of_bounded_evidence() {
    use crate::interp::InvocationContract;
    let context = sources::root_argument::<NoFacts>(
        InvocationContract::ForgeFunction,
        1,
        DefId::new(90),
        DefId::new(91),
    );
    let payload = sources::root_argument::<NoFacts>(
        InvocationContract::ForgeFunction,
        0,
        DefId::new(90),
        DefId::new(92),
    );
    let leaf = context.project(&[
        Projection::Known("principal".into()),
        Projection::Known("accountId".into()),
    ]);
    let mut invalidated = context.shape;
    if let InputShape::Known { invalid, .. } = &mut invalidated {
        *invalid = Classification::Unknown;
    }
    let mut overwritten = context.shape;
    if let InputShape::Known { invalid, .. } = &mut overwritten {
        *invalid = Classification::Untrusted;
    }
    let shapes = [
        invalidated,
        overwritten,
        InputShape::BOTTOM,
        InputShape::Absent,
        InputShape::Unknown,
        context.shape,
        payload.shape,
        leaf.shape,
    ];
    for a in shapes {
        assert_eq!(a.join(&InputShape::BOTTOM), a);
        assert_eq!(a.join(&a), a);
        for b in shapes {
            assert_eq!(a.join(&b), b.join(&a));
            for c in shapes {
                assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
            }
        }
    }
    let mut crowded = context.clone();
    for index in 0..32 {
        crowded.taint.origins.insert(origin(index));
    }
    assert_eq!(crowded.taint.origins.iter().count(), MAX_ORIGINS);
    assert_eq!(
        crowded
            .project(&[Projection::Known("installContext".into())])
            .taint
            .classification,
        Classification::Trusted
    );
    assert_eq!(crowded.shape, context.shape);
    assert_eq!(crowded.references, context.references);
    assert_eq!(
        context.join(&FlowValue::unknown()).references,
        context.references
    );
    let other_leaf = context.project(&[Projection::Known("installContext".into())]);
    assert_ne!(leaf.shape, other_leaf.shape);
    assert_eq!(leaf.join(&other_leaf).shape, InputShape::Unknown);
    assert_eq!(
        leaf.join(&other_leaf)
            .project(&[Projection::Known("accountId".into())])
            .taint
            .classification,
        Classification::Unknown
    );
    assert_eq!(
        context.join(&FlowValue::unknown()).shape,
        InputShape::Absent
    );
    assert_eq!(
        payload.join(&context).taint.classification,
        Classification::Untrusted
    );
}

#[test]
fn input_schema_does_not_drop_computed_paths_or_trust_descendants_of_leaves() {
    use crate::interp::InvocationContract;
    let context = sources::root_argument::<NoFacts>(
        InvocationContract::ForgeFunction,
        1,
        DefId::new(0),
        DefId::new(1),
    );
    for path in [
        vec![
            Projection::Known("principal".into()),
            Projection::Known("accountId".into()),
            Projection::Known("nested".into()),
        ],
        vec![
            Projection::Computed(crate::ir::Base::Var(VarId(5))),
            Projection::Known("accountId".into()),
        ],
    ] {
        assert_eq!(
            context.project(&path).taint.classification,
            Classification::Unknown
        );
    }
    let envelope = sources::root_argument::<NoFacts>(
        InvocationContract::ResolverCallback,
        0,
        DefId::new(0),
        DefId::new(1),
    );
    assert_eq!(
        envelope
            .project(&[Projection::Computed(crate::ir::Base::Var(VarId(5)))])
            .taint
            .classification,
        Classification::Untrusted
    );
}
