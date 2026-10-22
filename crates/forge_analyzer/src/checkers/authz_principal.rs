//! Root-specific reachability using only immutable boolean formal arguments.
//! No return-value, heap, identity, or general taint modelling is needed here.
//! Unknown inputs keep both branches; all call contexts contribute to the union.
//! Defaults apply only to resolved helper calls; host entry arguments stay unknown.
//! Mutation, dynamic code, and exhausted budgets fall back to existing reporting.
use crate::{
    definitions::{DefId, Environment},
    ir::{
        Base, BasicBlockId, BinOp, Body, Inst, Literal, Location, Operand, Rvalue, STARTING_BLOCK,
        Successors, Terminator, UnOp, VarId, VarKind,
    },
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Argument {
    Unknown,
    Undefined,
    Bool(bool),
}

#[derive(Default)]
pub(super) struct Reachability {
    functions: BTreeSet<DefId>,
    blocks: BTreeSet<(DefId, BasicBlockId)>,
}

impl Reachability {
    pub(super) fn excludes(&self, def: DefId, block: BasicBlockId) -> bool {
        self.functions.contains(&def) && !self.blocks.contains(&(def, block))
    }
}

struct Facts<'a> {
    body: &'a Body,
    params: BTreeMap<DefId, bool>,
    temps: BTreeMap<VarId, &'a Rvalue>,
}

impl Facts<'_> {
    fn boolean(&self, operand: &Operand, depth: usize, truthiness: bool) -> Option<bool> {
        if depth > 32 {
            return None;
        }
        match operand {
            Operand::Lit(Literal::Bool(value)) => Some(*value),
            Operand::Var(var) if var.projections.is_empty() => {
                let Base::Var(id) = var.base else { return None };
                match self.body.vars.get(id)? {
                    VarKind::Arg(binding)
                    | VarKind::GlobalRef(binding)
                    | VarKind::LocalDef(binding) => self.params.get(binding).copied(),
                    VarKind::Temp { .. } => match self.temps.get(&id)? {
                        Rvalue::Read(value) => self.boolean(value, depth + 1, truthiness),
                        Rvalue::Unary(UnOp::Not, value) => {
                            self.boolean(value, depth + 1, true).map(|v| !v)
                        }
                        Rvalue::Bin(op, left, right) => {
                            let logical_truthiness =
                                truthiness && matches!(op, BinOp::And | BinOp::Or);
                            let left = self.boolean(left, depth + 1, logical_truthiness);
                            let right = self.boolean(right, depth + 1, logical_truthiness);
                            match (op, left, right) {
                                (BinOp::And, Some(false), _) | (BinOp::And, _, Some(false))
                                    if truthiness =>
                                {
                                    Some(false)
                                }
                                (BinOp::Or, Some(true), _) | (BinOp::Or, _, Some(true))
                                    if truthiness =>
                                {
                                    Some(true)
                                }
                                (BinOp::And, Some(a), Some(b)) => Some(a && b),
                                (BinOp::Or, Some(a), Some(b)) => Some(a || b),
                                (BinOp::EqEq | BinOp::EqEqEq, Some(a), Some(b)) => Some(a == b),
                                (BinOp::Neq | BinOp::NeqEq, Some(a), Some(b)) => Some(a != b),
                                _ => None,
                            }
                        }
                        _ => None,
                    },
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn argument(&self, env: &Environment, operand: &Operand) -> Argument {
        if let Some(value) = self.boolean(operand, 0, false) {
            return Argument::Bool(value);
        }
        // Literal Undef also represents unsupported expressions in legacy IR;
        // only a proven undeclared `undefined` binding qualifies as an actual.
        if matches!(operand, Operand::Var(var) if var.projections.is_empty()
                && matches!(var.base, Base::Var(id) if matches!(self.body.vars.get(id),
                    Some(VarKind::GlobalRef(def)) if env.is_undeclared_global(*def) && env.def_name(*def) == "undefined")))
        {
            Argument::Undefined
        } else {
            Argument::Unknown
        }
    }
}

pub(super) fn analyze(env: &Environment, root: DefId) -> Option<Reachability> {
    let written: BTreeSet<_> = env
        .bodies()
        .flat_map(|body| body.authz_written_bindings.iter().copied())
        .collect();
    let mut result = Reachability::default();
    let mut pending = VecDeque::from([(root, None)]);
    let mut contexts = BTreeSet::new();
    let mut steps = 0usize;
    while let Some((def, args)) = pending.pop_front() {
        if !contexts.insert((def, args.clone())) {
            continue;
        }
        if contexts.len() > 512 {
            return None;
        }
        let body = env.def_ref(def).as_body().copied()?;
        if body.authz_principal_opaque {
            return None;
        }
        let mut facts = Facts {
            body,
            params: BTreeMap::new(),
            temps: BTreeMap::new(),
        };
        if let Some(args) = args {
            let args: Vec<Argument> = args;
            for (index, parameter) in body.authz_bool_parameters.iter().enumerate() {
                let Some((binding, default)) = parameter else {
                    continue;
                };
                if written.contains(binding) {
                    continue;
                }
                let value = match args.get(index).copied().unwrap_or(Argument::Undefined) {
                    Argument::Bool(value) => Some(value),
                    Argument::Undefined => *default,
                    Argument::Unknown => None,
                };
                if let Some(value) = value {
                    facts.params.insert(*binding, value);
                }
            }
        }
        // Only temporary expressions with a single definition may be evaluated.
        let mut assigned = BTreeSet::new();
        for block in &body.blocks {
            for inst in &block.insts {
                steps += 1;
                if steps > 100_000 {
                    return None;
                }
                if let Inst::Assign(var, value) = inst
                    && let Base::Var(id) = var.base
                    && matches!(body.vars.get(id), Some(VarKind::Temp { .. }))
                {
                    if var.projections.is_empty() && assigned.insert(id) {
                        facts.temps.insert(id, value);
                    } else {
                        assigned.insert(id);
                        facts.temps.remove(&id);
                    }
                }
            }
        }
        result.functions.insert(def);
        let mut blocks = vec![STARTING_BLOCK];
        let mut visited = BTreeSet::new();
        while let Some(id) = blocks.pop() {
            if !visited.insert(id) {
                continue;
            }
            result.blocks.insert((def, id));
            let block = body.blocks.get(id)?;
            for (index, inst) in block.insts.iter().enumerate() {
                if let Rvalue::Call(callee_operand, args) = inst.rvalue()
                    && let Some((callee, callee_body)) = body.resolve_call(env, callee_operand)
                {
                    let binding_written = matches!(callee_operand, Operand::Var(var)
                        if matches!(var.base, Base::Var(id) if matches!(body.vars.get(id),
                            Some(VarKind::LocalDef(binding) | VarKind::GlobalRef(binding))
                                if written.contains(binding))));
                    if written.contains(&callee) || binding_written {
                        return None;
                    }
                    let actuals = if body
                        .authz_spread_calls
                        .contains(&Location::new(id, index as u32))
                        // The legacy resolver can resolve fn.call/apply/bind as
                        // fn itself. Do not assume direct-call argument positions
                        // for member calls, even when a target body is resolved.
                        || matches!(callee_operand, Operand::Var(var) if !var.projections.is_empty())
                    {
                        vec![
                            Argument::Unknown;
                            args.len().max(callee_body.authz_bool_parameters.len())
                        ]
                    } else {
                        args.iter().map(|arg| facts.argument(env, arg)).collect()
                    };
                    pending.push_back((callee, Some(actuals)));
                }
            }
            if let Terminator::If { cond, cons, alt } = &block.term
                && let Some(value) = facts.boolean(cond, 0, true)
            {
                blocks.push(if value { *cons } else { *alt });
            } else {
                match block.successors() {
                    Successors::Return => {}
                    Successors::One(next) => blocks.push(next),
                    Successors::Two(a, b) => {
                        blocks.push(a);
                        blocks.push(b);
                    }
                }
            }
        }
    }
    Some(result)
}
