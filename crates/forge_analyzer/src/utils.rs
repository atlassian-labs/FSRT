use crate::{
    definitions::{CalleeRef, Const, DefId, Value},
    ir::{Base, Literal, Operand, VarId, VarKind, Variable},
};
use forge_permission_resolver::permissions_resolver::RequestType;
use itertools::Itertools;
use swc_core::ecma::ast::{Expr, Lit, MemberProp};

pub fn calls_method(n: CalleeRef<'_>, name: &str) -> bool {
    if let CalleeRef::Expr(Expr::Member(mem)) = &n {
        if let MemberProp::Ident(ident) = &mem.prop {
            return ident.sym == *name;
        }
    }
    false
}

pub fn resolve_var_from_operand(operand: &Operand) -> Option<(Variable, VarId)> {
    if let Operand::Var(var) = operand {
        if let Base::Var(varid) = var.base {
            return Some((var.clone(), varid));
        }
    }
    None
}

pub fn add_const_to_val_vec(val: &Value, const_val: &Const, vals: &mut Vec<String>) {
    match val {
        Value::Const(Const::Literal(lit)) => {
            if let Const::Literal(lit2) = const_val {
                vals.push(format!("{lit}{lit2}"));
            }
        }
        Value::Phi(phi_val2) => phi_val2.iter().for_each(|val2| {
            if let (Const::Literal(lit1), Const::Literal(lit2)) = (&const_val, val2) {
                vals.push(format!("{lit1}{lit2}"));
            }
        }),
        _ => {}
    }
}

pub fn get_defid_from_varkind(varkind: &VarKind) -> Option<DefId> {
    match varkind {
        VarKind::GlobalRef(defid) => Some(defid.clone()),
        VarKind::LocalDef(defid) => Some(defid.clone()),
        VarKind::Arg(defid) => Some(defid.clone()),
        VarKind::AnonClosure(defid) => Some(defid.clone()),
        VarKind::Temp { parent } => parent.clone(),
        _ => None,
    }
}

pub fn convert_operand_to_raw(operand: &Operand) -> Option<String> {
    if let Operand::Lit(lit) = operand {
        convert_lit_to_raw(lit)
    } else {
        None
    }
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
        return RequestType::Get;
    }
}

pub fn get_str_from_operand(operand: &Operand) -> Option<String> {
    if let Operand::Lit(lit) = operand {
        if let Literal::Str(str) = lit {
            return Some(str.to_string());
        }
    }
    None
}

pub fn add_elements_to_intrinsic_struct(value: &Value, args: &mut Option<Vec<String>>) {
    match value {
        Value::Const(const_value) => {
            if let Const::Literal(literal) = const_value {
                args.as_mut().unwrap().push(literal.clone());
            }
        }
        Value::Phi(phi_value) => {
            for value in phi_value {
                if let Const::Literal(literal) = value {
                    args.as_mut().unwrap().push(literal.clone());
                }
            }
        }
        _ => {}
    }
}

pub fn get_prev_value(value: Option<&Value>) -> Option<Vec<Const>> {
    if let Some(value) = value {
        return match value {
            Value::Const(const_value) => Some(vec![const_value.clone()]),
            Value::Phi(phi_value) => Some(phi_value.clone()),
            _ => None,
        };
    }
    None
}

pub fn return_value_from_string(values: Vec<String>) -> Value {
    // assert!(values.len() > 0);
    if values.len() == 1 {
        return Value::Const(Const::Literal(values.get(0).unwrap().clone()));
    } else {
        return Value::Phi(
            values
                .iter()
                .map(|val_string| Const::Literal(val_string.clone()))
                .collect_vec(),
        );
    }
}

pub fn trnaslate_request_type(request_type: Option<&str>) -> RequestType {
    if let Some(request_type) = request_type {
        match request_type {
            "PATCH" => RequestType::Patch,
            "PUT" => RequestType::Put,
            "DELETE" => RequestType::Delete,
            "POST" => RequestType::Post,
            _ => RequestType::Get,
        }
    } else {
        return RequestType::Get;
    }
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

const RED_ZONE: usize = 100 * 1024;

const STACK_SIZE: usize = 1024 * 1024;

#[inline]
pub(crate) fn ensure_sufficient_stack<T>(f: impl FnOnce() -> T) -> T {
    stacker::maybe_grow(RED_ZONE, STACK_SIZE, f)
}
