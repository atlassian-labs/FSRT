use crate::{
    definitions::{DefId, DefKind, Environment},
    interp::{Interp, Runner},
    ir::{Base, Body, Inst, Location, Operand, Projection, Rvalue, VarId, VarKind, Variable},
};
use std::collections::{BTreeMap, HashSet};
pub(crate) fn is_proven_local_array_length<'cx, C: Runner<'cx>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
) -> bool {
    let Some(Projection::Known(property)) = variable.projections.last() else {
        return false;
    };
    if property != "length" {
        return false;
    }

    fn is_array<'cx, C: Runner<'cx>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        variable: &Variable,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> bool {
        let Base::Var(var) = variable.base else {
            return false;
        };
        if !visiting.insert((def, var)) {
            return false;
        }

        let definitions = variable_definitions_with_aliases(interp.env(), interp.body(), variable);
        let result = !definitions.is_empty()
            && definitions.into_iter().all(|(_, rvalue)| match rvalue {
                Rvalue::Array(_) => true,
                Rvalue::Read(Operand::Var(source)) => is_array(interp, def, source, visiting),
                Rvalue::Phi(values) => values
                    .iter()
                    .all(|(source, _)| is_array(interp, def, &Variable::new(*source), visiting)),
                Rvalue::Call(callee, _) => {
                    unresolved_global_named(interp.env(), interp.body(), callee, "Array")
                }
                _ => false,
            });
        visiting.remove(&(def, var));
        result
    }

    let mut receiver = variable.clone();
    receiver.projections.pop();
    is_array(interp, def, &receiver, &mut HashSet::new())
}

pub(crate) fn is_numeric_builtin_call<'cx, C: Runner<'cx>>(
    interp: &Interp<'cx, C>,
    callee: &Operand,
) -> bool {
    let Operand::Var(variable) = callee else {
        return false;
    };
    let Base::Var(var) = variable.base else {
        return false;
    };
    let Some(VarKind::GlobalRef(binding)) = interp.body().vars.get(var) else {
        return false;
    };
    let binding = interp.env().resolve_alias(*binding);
    if !matches!(interp.env().def_ref(binding), DefKind::Undefined) {
        return false;
    }

    let global = interp.env().def_name(binding);
    match variable.projections.as_slice() {
        [] => matches!(global, "Number" | "parseInt" | "parseFloat"),
        [Projection::Known(method)] if global == "Math" => matches!(
            method.as_ref(),
            "abs"
                | "acos"
                | "acosh"
                | "asin"
                | "asinh"
                | "atan"
                | "atan2"
                | "atanh"
                | "cbrt"
                | "ceil"
                | "clz32"
                | "cos"
                | "cosh"
                | "exp"
                | "expm1"
                | "floor"
                | "fround"
                | "hypot"
                | "imul"
                | "log"
                | "log10"
                | "log1p"
                | "log2"
                | "max"
                | "min"
                | "pow"
                | "random"
                | "round"
                | "sign"
                | "sin"
                | "sinh"
                | "sqrt"
                | "tan"
                | "tanh"
                | "trunc"
        ),
        _ => false,
    }
}

pub(crate) fn unresolved_global_named(
    env: &Environment,
    body: &crate::ir::Body,
    operand: &Operand,
    expected: &str,
) -> bool {
    let Operand::Var(variable) = operand else {
        return false;
    };
    let Base::Var(var) = variable.base else {
        return false;
    };
    if !variable.projections.is_empty() {
        return false;
    }
    let Some(VarKind::GlobalRef(binding)) = body.vars.get(var) else {
        return false;
    };
    let binding = env.resolve_alias(*binding);
    matches!(env.def_ref(binding), DefKind::Undefined) && env.def_name(binding) == expected
}

pub(crate) fn method_receiver(callee: &Operand) -> Option<(Variable, &str)> {
    let Operand::Var(variable) = callee else {
        return None;
    };
    let Projection::Known(method) = variable.projections.last()? else {
        return None;
    };
    let mut receiver = variable.clone();
    receiver.projections.pop();
    Some((receiver, method.as_ref()))
}

pub(crate) fn variable_definitions<'a>(
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    let exact = body.assignments_to(variable).collect::<Vec<_>>();
    if !exact.is_empty() || variable.projections.is_empty() {
        return exact;
    }
    let mut root = variable.clone();
    root.projections.clear();
    variable_definitions(body, &root)
}

pub(crate) fn projected_variable_definitions<'a>(
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    body.iter_blocks_enumerated()
        .flat_map(|(block_id, block)| {
            block
                .iter()
                .enumerate()
                .filter_map(move |(stmt, inst)| match inst {
                    Inst::Assign(target, rvalue)
                        if target.base == variable.base && !target.projections.is_empty() =>
                    {
                        Some((Location::new(block_id, stmt as u32), rvalue))
                    }
                    _ => None,
                })
        })
        .collect()
}

pub(crate) fn variable_definitions_with_aliases<'a>(
    env: &Environment,
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    let Some(aliases) = body.logical_aliases(env, variable) else {
        let definitions = variable_definitions(body, variable);
        if definitions.is_empty() && variable.projections.is_empty() {
            return projected_variable_definitions(body, variable);
        }
        return definitions;
    };
    let mut definitions = BTreeMap::new();
    for &var in aliases {
        let mut candidate = Variable::new(var);
        candidate.projections = variable.projections.clone();
        let mut candidate_definitions = variable_definitions(body, &candidate);
        if candidate_definitions.is_empty() && candidate.projections.is_empty() {
            candidate_definitions = projected_variable_definitions(body, &candidate);
        }
        for (location, rvalue) in candidate_definitions {
            definitions.entry(location).or_insert(rvalue);
        }
    }
    definitions.into_iter().collect()
}

pub(crate) fn returned_object_variables(body: &crate::ir::Body) -> Vec<Variable> {
    fn collect(
        body: &crate::ir::Body,
        variable: &Variable,
        visiting: &mut HashSet<VarId>,
        returned: &mut Vec<Variable>,
    ) {
        let Base::Var(var) = variable.base else {
            return;
        };
        if !visiting.insert(var) {
            return;
        }
        for (_, rvalue) in variable_definitions(body, variable) {
            match rvalue {
                Rvalue::Read(Operand::Var(source)) => returned.push(source.clone()),
                Rvalue::Phi(values) => {
                    for (source, _) in values {
                        collect(body, &Variable::new(*source), visiting, returned);
                    }
                }
                _ => {}
            }
        }
        visiting.remove(&var);
    }

    let mut returned = Vec::new();
    for (variable, kind) in body.vars.iter_enumerated() {
        if matches!(kind, VarKind::Ret) {
            collect(
                body,
                &Variable::new(variable),
                &mut HashSet::new(),
                &mut returned,
            );
        }
    }
    returned
}

pub(crate) fn originates_from_resolved_local_call(
    env: &Environment,
    body: &Body,
    variable: VarId,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    body.iter_blocks_enumerated().any(|(_, block)| {
        block.iter().any(|inst| match inst {
            Inst::Assign(
                Variable {
                    base: Base::Var(target),
                    projections,
                },
                Rvalue::Call(callee, _),
            ) if *target == variable && projections.is_empty() => {
                body.resolve_call(env, callee).is_some()
            }
            Inst::Assign(
                Variable {
                    base: Base::Var(target),
                    projections,
                },
                Rvalue::Read(Operand::Var(Variable {
                    base: Base::Var(source),
                    projections: source_projections,
                })),
            ) if *target == variable && projections.is_empty() && source_projections.is_empty() => {
                originates_from_resolved_local_call(env, body, *source, depth - 1)
            }
            _ => false,
        })
    })
}

/// Cache only immutable IR provenance; no entrypoint-specific trust is stored here.
/// Callers first identify an API candidate, avoiding whole-body walks for ordinary calls.
pub(crate) fn call_has_local_receiver(env: &Environment, facts: &crate::ir::CallFacts) -> bool {
    *facts.local_receiver.get_or_init(|| {
        facts.root.is_some_and(|root| {
            env.bodies().any(|body| {
                body.vars.iter_enumerated().any(|(var, kind)| {
                    matches!(kind, VarKind::GlobalRef(def) | VarKind::LocalDef(def) if *def == root)
                        && originates_from_resolved_local_call(env, body, var, 8)
                })
            })
        })
    })
}
