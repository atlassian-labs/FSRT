use crate::{
    definitions::DefKind,
    interp::{Interp, Runner},
    ir::{Base, Location, Operand, Projection, Rvalue, VarId, VarKind, Variable},
};
use std::collections::HashSet;
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
