//! Facts derived only from finalized IR. These lazy caches belong to the
//! environment, so resetting a resolver's taint state does not rebuild them.
//! Like Body's assignment index, they must not be queried during lowering or SSA
//! rewriting. No scanner policy, incoming arguments, or mutable flow facts belong
//! here. Index storage is linear in assignments; constant results are bounded by
//! the number of queried definitions.

use super::{Environment, FuncId};
use crate::{
    definitions::DefId,
    ir::{Base, Body, Inst, Location, Operand, Rvalue, VarId, VarKind, Variable},
};
use forge_utils::FxHashMap;
use std::{
    cell::{OnceCell, RefCell},
    collections::HashSet,
};

#[derive(Debug, Clone, Default)]
pub(super) struct ImmutableFacts {
    assignments: OnceCell<FxHashMap<DefId, Vec<(FuncId, Location)>>>,
    constants: RefCell<FxHashMap<DefId, bool>>,
}

impl Environment {
    /// Index all writes to each resolved definition, including projected writes
    /// and writes in other bodies, in the same order as the original IR walk.
    fn definition_assignments(&self, def: DefId) -> impl Iterator<Item = (&Body, &Rvalue)> {
        let index = self.immutable_facts.assignments.get_or_init(|| {
            let mut index = FxHashMap::<DefId, Vec<(FuncId, Location)>>::default();
            for (function, body) in self.defs.funcs.iter_enumerated() {
                for (block, data) in body.iter_blocks_enumerated() {
                    for (stmt, inst) in data.iter().enumerate() {
                        let Inst::Assign(target, _) = inst else {
                            continue;
                        };
                        let Base::Var(var) = target.base else {
                            continue;
                        };
                        let binding = match body.vars.get(var) {
                            Some(VarKind::GlobalRef(binding) | VarKind::LocalDef(binding)) => {
                                self.resolve_alias(*binding)
                            }
                            _ => continue,
                        };
                        index
                            .entry(binding)
                            .or_default()
                            .push((function, Location::new(block, stmt as u32)));
                    }
                }
            }
            index
        });
        index
            .get(&def)
            .into_iter()
            .flatten()
            .map(|(function, location)| {
                let body = &self.defs.funcs[*function];
                (
                    body,
                    body.block(location.block).insts[location.stmt as usize].rvalue(),
                )
            })
    }

    /// A conservative constant proof over finalized IR, independent of entrypoint state.
    /// Only completed top-level queries are cached; recursion guards are never
    /// published as intermediate results. Failed proofs are cached as well.
    pub(crate) fn global_is_proven_constant(&self, def: DefId) -> bool {
        fn operand_is_constant(
            env: &Environment,
            body: &crate::ir::Body,
            operand: &Operand,
            visiting_vars: &mut HashSet<VarId>,
            visiting_defs: &mut HashSet<DefId>,
        ) -> bool {
            match operand {
                Operand::Lit(_) => true,
                Operand::Var(variable) => {
                    let Base::Var(var) = variable.base else {
                        return false;
                    };
                    if !visiting_vars.insert(var) {
                        return false;
                    }
                    let mut definitions = body.assignments_to(variable).peekable();
                    let mut root = variable.clone();
                    root.projections.clear();
                    let definitions =
                        if definitions.peek().is_none() && !variable.projections.is_empty() {
                            body.assignments_to(&root).collect::<Vec<_>>()
                        } else {
                            definitions.collect::<Vec<_>>()
                        };
                    let result = if definitions.is_empty() {
                        match body.vars.get(var) {
                            Some(VarKind::GlobalRef(global) | VarKind::LocalDef(global)) => {
                                definition_is_constant(
                                    env,
                                    env.resolve_alias(*global),
                                    visiting_defs,
                                )
                            }
                            _ => false,
                        }
                    } else {
                        definitions.into_iter().all(|(_, rvalue)| {
                            rvalue_is_constant(env, body, rvalue, visiting_vars, visiting_defs)
                        })
                    };
                    visiting_vars.remove(&var);
                    result
                }
            }
        }

        fn rvalue_is_constant(
            env: &Environment,
            body: &crate::ir::Body,
            rvalue: &Rvalue,
            visiting_vars: &mut HashSet<VarId>,
            visiting_defs: &mut HashSet<DefId>,
        ) -> bool {
            match rvalue {
                Rvalue::Read(operand) | Rvalue::Unary(_, operand) => {
                    operand_is_constant(env, body, operand, visiting_vars, visiting_defs)
                }
                Rvalue::Array(elements) => elements.iter().all(|operand| {
                    operand_is_constant(env, body, operand, visiting_vars, visiting_defs)
                }),
                Rvalue::Bin(_, left, right) => {
                    operand_is_constant(env, body, left, visiting_vars, visiting_defs)
                        && operand_is_constant(env, body, right, visiting_vars, visiting_defs)
                }
                Rvalue::Template(template) => template.exprs.iter().all(|operand| {
                    operand_is_constant(env, body, operand, visiting_vars, visiting_defs)
                }),
                Rvalue::Phi(values) => values.iter().all(|(var, _)| {
                    operand_is_constant(
                        env,
                        body,
                        &Operand::Var(Variable::new(*var)),
                        visiting_vars,
                        visiting_defs,
                    )
                }),
                Rvalue::Call(_, _) | Rvalue::Intrinsic(_, _) => false,
            }
        }

        fn definition_is_constant(
            env: &Environment,
            def: DefId,
            visiting_defs: &mut HashSet<DefId>,
        ) -> bool {
            if !visiting_defs.insert(def) {
                return false;
            }
            let mut found = false;
            let result = env.definition_assignments(def).all(|(body, rvalue)| {
                found = true;
                rvalue_is_constant(env, body, rvalue, &mut HashSet::new(), visiting_defs)
            });
            visiting_defs.remove(&def);
            found && result
        }

        let def = self.resolve_alias(def);
        if let Some(result) = self.immutable_facts.constants.borrow().get(&def).copied() {
            return result;
        }
        let result = definition_is_constant(self, def, &mut HashSet::new());
        self.immutable_facts
            .constants
            .borrow_mut()
            .insert(def, result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        definitions::DefKind,
        ir::{Literal, Projection, STARTING_BLOCK},
    };

    fn definition(env: &mut Environment, name: &str) -> DefId {
        let def = env.defs.defs.push_and_get_key(DefKind::Undefined);
        assert_eq!(env.resolver.names.push_and_get_key(name.into()), def);
        def
    }

    fn reference(body: &mut Body, def: DefId) -> Variable {
        Variable::new(body.vars.push_and_get_key(VarKind::GlobalRef(def)))
    }

    fn assign(body: &mut Body, target: Variable, value: Rvalue) {
        body.blocks[STARTING_BLOCK]
            .insts
            .push(Inst::Assign(target, value));
    }

    fn literal() -> Rvalue {
        Rvalue::Read(Operand::Lit(Literal::Str("constant".into())))
    }

    fn unknown() -> Rvalue {
        Rvalue::Call(Operand::UNDEF, Default::default())
    }

    #[test]
    fn completed_constant_queries_cache_positive_negative_and_missing_results() {
        let mut env = Environment::default();
        let constant = definition(&mut env, "constant");
        let dynamic = definition(&mut env, "dynamic");
        let missing = definition(&mut env, "missing");
        let alias = definition(&mut env, "alias");
        env.defs.defs[alias] = DefKind::ExportAlias(constant);
        let mut body = Body::default();
        let target = reference(&mut body, constant);
        assign(&mut body, target, literal());
        let target = reference(&mut body, dynamic);
        assign(&mut body, target, unknown());
        env.defs.funcs.push(body);

        for _ in 0..3 {
            assert!(env.global_is_proven_constant(constant));
            assert!(env.global_is_proven_constant(alias));
            assert!(!env.global_is_proven_constant(dynamic));
            assert!(!env.global_is_proven_constant(missing));
        }
        assert_eq!(env.immutable_facts.constants.borrow().len(), 3);
        assert_eq!(
            env.immutable_facts.constants.borrow().get(&missing),
            Some(&false)
        );
    }

    #[test]
    fn global_index_includes_projected_writes_through_aliases_in_other_bodies() {
        let mut env = Environment::default();
        let global = definition(&mut env, "global");
        let alias = definition(&mut env, "alias");
        env.defs.defs[alias] = DefKind::ExportAlias(global);
        let mut first = Body::default();
        let target = reference(&mut first, global);
        assign(&mut first, target, literal());
        let mut second = Body::default();
        let mut field = reference(&mut second, alias);
        field.projections.push(Projection::Known("field".into()));
        assign(&mut second, field, unknown());
        env.defs.funcs.extend([first, second]);

        let writes = env.definition_assignments(global).collect::<Vec<_>>();
        assert_eq!(writes.len(), 2);
        assert!(matches!(writes[0].1, Rvalue::Read(_)));
        assert!(matches!(writes[1].1, Rvalue::Call(_, _)));
        assert!(!env.global_is_proven_constant(global));
        assert!(!env.global_is_proven_constant(alias));
    }

    #[test]
    fn cyclic_constant_dependencies_terminate_independently_of_query_order() {
        for reverse in [false, true] {
            let mut env = Environment::default();
            let a = definition(&mut env, "a");
            let b = definition(&mut env, "b");
            let constant = definition(&mut env, "constant");
            for (target, source) in [(a, b), (b, a)] {
                let mut body = Body::default();
                let target = reference(&mut body, target);
                let source = reference(&mut body, source);
                assign(&mut body, target, Rvalue::Read(Operand::Var(source)));
                env.defs.funcs.push(body);
            }
            let mut body = Body::default();
            let target = reference(&mut body, constant);
            assign(&mut body, target, literal());
            env.defs.funcs.push(body);
            let order = if reverse { [b, a] } else { [a, b] };
            for def in order.into_iter().cycle().take(4) {
                assert!(!env.global_is_proven_constant(def));
                assert!(env.global_is_proven_constant(constant));
            }
        }
    }

    #[test]
    fn constant_operand_reads_keep_exact_projection_precedence_and_root_fallback() {
        let mut env = Environment::default();
        let exact = definition(&mut env, "exact");
        let fallback = definition(&mut env, "fallback");
        let mut body = Body::default();
        let root = Variable::new(body.vars.push_and_get_key(VarKind::Temp { parent: None }));
        assign(&mut body, root.clone(), unknown());
        let mut field = root.clone();
        field.projections.push(Projection::Known("known".into()));
        assign(&mut body, field.clone(), literal());
        let target = reference(&mut body, exact);
        assign(&mut body, target, Rvalue::Read(Operand::Var(field)));
        let mut missing = root;
        missing
            .projections
            .push(Projection::Known("missing".into()));
        let target = reference(&mut body, fallback);
        assign(&mut body, target, Rvalue::Read(Operand::Var(missing)));
        env.defs.funcs.push(body);
        assert!(env.global_is_proven_constant(exact));
        assert!(!env.global_is_proven_constant(fallback));
    }

    #[test]
    fn immutable_facts_are_scoped_to_the_environment() {
        for expected in [true, false, true] {
            let mut env = Environment::default();
            let def = definition(&mut env, "same_id_and_name");
            let mut body = Body::default();
            let target = reference(&mut body, def);
            assign(
                &mut body,
                target,
                if expected { literal() } else { unknown() },
            );
            env.defs.funcs.push(body);
            assert_eq!(env.global_is_proven_constant(def), expected);
        }
    }

    #[test]
    fn binding_variables_preserve_identity_and_variable_order() {
        let mut env = Environment::default();
        let binding = definition(&mut env, "shared");
        let same_name = definition(&mut env, "shared");
        let synthetic = definition(&mut env, "__synthetic");
        let mut body = Body::default();
        let argument = body.vars.push_and_get_key(VarKind::Arg(binding));
        let global = body.vars.push_and_get_key(VarKind::GlobalRef(binding));
        let local = body.vars.push_and_get_key(VarKind::LocalDef(same_name));
        let generated = body.vars.push_and_get_key(VarKind::LocalDef(synthetic));
        let generated_ref = body.vars.push_and_get_key(VarKind::GlobalRef(synthetic));
        let temp = body.vars.push_and_get_key(VarKind::Temp { parent: None });
        let mut projected = Variable::new(argument);
        projected
            .projections
            .push(Projection::Known("field".into()));
        assert_eq!(
            body.binding_variables(&projected),
            Some([argument, global].as_slice())
        );
        assert_eq!(
            body.binding_variables(&Variable::new(local)),
            Some([local].as_slice())
        );
        assert_eq!(
            body.binding_variables(&Variable::new(generated)),
            Some([generated, generated_ref].as_slice())
        );
        assert_eq!(body.binding_variables(&Variable::new(temp)), None);
        let mut other = Body::default();
        let other_var = reference(&mut other, binding);
        assert_eq!(
            other.binding_variables(&other_var),
            Some([other_var.as_var_id().unwrap()].as_slice())
        );
    }
}
