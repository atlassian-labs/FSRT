use super::*;
use crate::checkers::SecretChecker;

fn with_interp(test: impl FnOnce(&mut Interp<'_, SecretChecker>)) {
    let mut env = Environment::default();
    env.resolver.names.push("test".into());
    let body = Body::default();
    let permissions = PermissionHashMap::default();
    let regexes = HashMap::default();
    let compass = CompassPermissionResolver::new();
    let mut interp = Interp::new(
        &env,
        false,
        false,
        vec![],
        &permissions,
        &regexes,
        &permissions,
        &regexes,
        &permissions,
        &regexes,
        &permissions,
        &regexes,
        &permissions,
        &regexes,
        &permissions,
        &regexes,
        &compass,
    );
    interp.set_body(&body);
    test(&mut interp);
}

#[test]
fn object_alias_cycles_have_no_resolved_target() {
    with_interp(|interp| {
        let def = DefId::new(0);
        // Both a two-node cycle and a longer cycle with an incoming alias.
        for aliases in [&[(1, 2), (2, 1)][..], &[(1, 2), (2, 3), (3, 1), (4, 1)]] {
            interp.value_manager.varid_to_value.clear();
            for &(from, to) in aliases {
                interp.add_value(def, VarId(from), Value::Object(VarId(to)));
            }
            for &(from, _) in aliases {
                let var = VarId(from);
                assert_eq!(
                    interp.get_farthest_obj(def, var, ProjectionVec::new()),
                    None
                );
                assert_eq!(
                    interp.value_from_operand(def, Operand::Var(var.into())),
                    Value::Unknown
                );
                let projection = ProjectionVec::from_iter([Projection::Known("value".into())]);
                assert_eq!(interp.get_farthest_obj(def, var, projection.clone()), None);
                assert_eq!(interp.get_value(def, var, Some(projection)), None);
            }

            let before = interp.get_defs();
            let value = Value::Const(Const::Literal("new".into()));
            interp.add_value_with_projection(def, VarId(1), value, ProjectionVec::new());
            interp.add_value_to_definition(
                def,
                VarId(1).into(),
                Rvalue::Read(Operand::Lit(Literal::Str("new".into()))),
            );
            assert_eq!(
                interp.get_defs(),
                before,
                "cyclic writes must not pick an arbitrary alias"
            );
        }
    });
}

#[test]
fn object_alias_chain_preserves_root_and_properties() {
    with_interp(|interp| {
        let def = DefId::new(0);
        interp.add_value(def, VarId(1), Value::Object(VarId(2)));
        interp.add_value(def, VarId(2), Value::Object(VarId(3)));
        // Self-references are valid object roots, unlike multi-node cycles.
        interp.add_value(def, VarId(3), Value::Object(VarId(3)));
        assert_eq!(
            interp.get_farthest_obj(def, VarId(1), ProjectionVec::new()),
            Some((VarId(3), ProjectionVec::new()))
        );
        let projection = ProjectionVec::from_iter([Projection::Known("value".into())]);
        let value = Value::Const(Const::Literal("retained".into()));
        interp.add_value_with_projection(def, VarId(1), value.clone(), projection.clone());
        assert_eq!(
            interp.get_value(def, VarId(3), Some(projection.clone())),
            Some(&value)
        );
        assert_eq!(
            interp.value_from_operand(
                def,
                Operand::Var(Variable {
                    base: Base::Var(VarId(1)),
                    projections: projection
                })
            ),
            value
        );
    });
}

#[test]
fn object_alias_chain_can_end_at_a_value_or_uninitialized_root() {
    with_interp(|interp| {
        let def = DefId::new(0);
        interp.add_value(def, VarId(1), Value::Object(VarId(2)));
        assert_eq!(
            interp.get_farthest_obj(def, VarId(1), ProjectionVec::new()),
            Some((VarId(2), ProjectionVec::new()))
        );
        let value = Value::Const(Const::Literal("known".into()));
        interp.add_value(def, VarId(2), value.clone());
        assert_eq!(
            interp.value_from_operand(def, Operand::Var(VarId(1).into())),
            value
        );
    });
}
