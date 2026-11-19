//! IR queries shared by the SQL-injection policy. They read finalized IR only and
//! never consult dataflow state.
use crate::{
    definitions::{DefKind, Environment},
    ir::{Base, Body, Inst, Location, Operand, Projection, Rvalue, VarKind, Variable},
};
use std::collections::BTreeMap;

/// The elements of the array literal that `variable` is, read whole.
///
/// Lowering writes `[a, b]` one index at a time to a fresh local named
/// `__ARRAY` (`__ARRAY["0"] = a`, `__ARRAY["1"] = b`), and no instruction says
/// "this is the list `[a, b]`". The SQL scanner's recognizers of placeholder
/// lists and allowlists need that view, so it is rebuilt here from the
/// per-index writes, and the IR every other scanner reads stays as it is.
///
/// `None` unless `variable` is such a local and every write to it is a
/// numbered element, so a local that something else writes to is not
/// mistaken for a literal. An element the literal skips (`[a, , b]`) is
/// `undefined`.
pub(crate) fn array_literal_elements(
    env: &Environment,
    body: &Body,
    variable: &Variable,
) -> Option<Vec<Operand>> {
    if !variable.projections.is_empty() {
        return None;
    }
    let Base::Var(var) = variable.base else {
        return None;
    };
    let Some(VarKind::LocalDef(def)) = body.vars.get(var) else {
        return None;
    };
    if env.def_name(*def) != ARRAY_LITERAL_NAME
        || !matches!(env.def_ref(*def), DefKind::GlobalObj(_))
    {
        return None;
    }
    let mut elements = BTreeMap::new();
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in block.iter() {
            let Inst::Assign(target, rvalue) = inst else {
                continue;
            };
            if target.base != variable.base {
                continue;
            }
            let ([Projection::Known(index)], Rvalue::Read(element)) =
                (&*target.projections, rvalue)
            else {
                return None;
            };
            elements.insert(index.parse::<usize>().ok()?, element.clone());
        }
    }
    let length = elements.keys().next_back().map_or(0, |last| last + 1);
    Some(
        (0..length)
            .map(|index| elements.remove(&index).unwrap_or(Operand::UNDEF))
            .collect(),
    )
}

/// The name lowering gives the local that holds an array literal.
const ARRAY_LITERAL_NAME: &str = "__ARRAY";

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
