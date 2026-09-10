use crate::interp::ProjectionVec;
use crate::ir::Projection;
use crate::{
    definitions::{CalleeRef, Const, DefId, Value},
    ir::{Literal, Operand, VarKind},
};
use forge_permission_resolver::permissions_resolver::RequestType;
use itertools::Itertools;
use swc_core::ecma::ast::{Expr, Lit, MemberProp};

pub fn calls_method(n: CalleeRef<'_>, name: &str) -> bool {
    if let CalleeRef::Expr(Expr::Member(mem)) = &n
        && let MemberProp::Ident(ident) = &mem.prop
    {
        return ident.sym == *name;
    }
    false
}

pub fn get_defid_from_varkind(varkind: &VarKind) -> Option<DefId> {
    match *varkind {
        VarKind::GlobalRef(defid)
        | VarKind::LocalDef(defid)
        | VarKind::Arg(defid)
        | VarKind::AnonClosure(defid) => Some(defid),
        VarKind::Temp { parent } => parent,
        VarKind::Ret => None,
    }
}

pub fn convert_operand_to_raw(operand: &Operand) -> Option<String> {
    if let Operand::Lit(lit) = operand {
        convert_lit_to_raw(lit)
    } else {
        None
    }
}

pub fn projvec_from_str(str: &str) -> ProjectionVec {
    ProjectionVec::from([Projection::Known(str.into())])
}

pub fn projvec_from_proj(proj: Projection) -> ProjectionVec {
    ProjectionVec::from([proj])
}

pub fn projvec_from_projvec(projs: &[Projection]) -> ProjectionVec {
    ProjectionVec::from(projs)
}

pub fn convert_lit_to_raw(lit: &Literal) -> Option<String> {
    match lit {
        Literal::BigInt(bigint) => Some(bigint.to_string()),
        Literal::Number(num) => Some(num.to_string()),
        Literal::Str(str) => Some(str.to_string()),
        _ => None,
    }
}

pub fn translate_request_type(request_type: Option<&str>) -> RequestType {
    if let Some(request_type) = request_type {
        match request_type {
            "PATCH" => RequestType::Patch,
            "PUT" => RequestType::Put,
            "DELETE" => RequestType::Delete,
            "POST" => RequestType::Post,
            _ => RequestType::Get,
        }
    } else {
        RequestType::Get
    }
}

pub fn get_str_from_operand(operand: &Operand) -> Option<String> {
    if let Operand::Lit(Literal::Str(str)) = operand {
        Some(str.to_string())
    } else {
        None
    }
}

pub fn add_elements_to_intrinsic_struct(value: &Value, args: &mut Vec<String>) {
    match value {
        Value::Const(Const::Literal(literal)) => {
            args.push(literal.clone());
        }
        Value::Phi(phi_value) => {
            args.extend(
                phi_value
                    .iter()
                    .map(|Const::Literal(literal)| literal.clone()),
            );
        }
        _ => {}
    }
}

pub fn return_combinations_phi(exprs: Vec<Value>) -> Value {
    let exprs: Vec<Vec<String>> = exprs
        .iter()
        .map(|expr| match expr {
            Value::Phi(value_vec) => value_vec
                .iter()
                .map(|Const::Literal(string)| string.clone())
                .collect(),
            Value::Const(Const::Literal(string)) => vec![string.clone()],
            _ => vec![],
        })
        .collect();

    let mut combinations = vec![String::new()];

    for list in exprs {
        let mut new_combinations = Vec::new();
        for combo in &combinations {
            for item in &list {
                new_combinations.push(format!("{combo}{item}"));
            }
        }
        combinations = new_combinations;
    }

    Value::Phi(
        combinations
            .iter()
            .map(|value| Const::Literal(value.clone()))
            .collect_vec(),
    )
}

pub fn eq_prop_name(n: &MemberProp, name: &str) -> bool {
    match n {
        MemberProp::Ident(ident) => ident.sym == *name,
        MemberProp::Computed(expr) => match expr.expr.as_ref() {
            Expr::Lit(Lit::Str(lit)) => *lit.value == *name,
            _ => false,
        },
        _ => false,
    }
}
