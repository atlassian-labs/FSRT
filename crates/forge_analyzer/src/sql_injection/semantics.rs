//! IR queries shared by the SQL-injection policy. They read finalized IR only and
//! never consult dataflow state.
use crate::{
    definitions::{DefKind, Environment},
    ir::{Base, Body, Inst, Location, Operand, Projection, Rvalue, VarKind, Variable},
};
use std::collections::BTreeMap;

pub(crate) fn unresolved_global_named(
    env: &Environment,
    body: &Body,
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
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    let Some(aliases) = body.binding_variables(variable) else {
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
