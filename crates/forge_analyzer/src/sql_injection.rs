use crate::{
    definitions::{Const, DefId, DefKind, Environment, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, Runner,
        WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, Inst, Intrinsic, Location, Operand, Projection, Rvalue,
        STARTING_BLOCK, SqlSink, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    worklist::WorkList,
};
use smallvec::SmallVec;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    ops::ControlFlow,
    path::PathBuf,
    sync::Arc,
};
use swc_core::common::SourceMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SqlTaint {
    #[default]
    Trusted,
    Unknown,
    Untrusted,
}

impl JoinSemiLattice for SqlTaint {
    const BOTTOM: Self = Self::Trusted;

    fn join_changed(&mut self, other: &Self) -> bool {
        let old = *self;
        *self = max(*self, *other);
        old != *self
    }

    fn join(&self, other: &Self) -> Self {
        max(*self, *other)
    }
}

type SqlVarKey = (DefId, VarId, Vec<Projection>);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct SqlState {
    values: BTreeMap<SqlVarKey, SqlTaint>,
}

impl JoinSemiLattice for SqlState {
    const BOTTOM: Self = Self {
        values: BTreeMap::new(),
    };

    fn join_changed(&mut self, other: &Self) -> bool {
        let old = self.clone();
        for (key, value) in &other.values {
            self.values
                .entry(key.clone())
                .and_modify(|current| {
                    *current = current.join(value);
                })
                .or_insert(*value);
        }
        old != *self
    }

    fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        joined.join_changed(other);
        joined
    }
}

impl SqlState {
    fn key(def: DefId, variable: &Variable) -> Option<SqlVarKey> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        Some((def, var, variable.projections.iter().cloned().collect()))
    }

    fn insert_variable(&mut self, def: DefId, variable: &Variable, value: SqlTaint) {
        let Some(key) = Self::key(def, variable) else {
            return;
        };
        // Assignments are strong updates. Control-flow alternatives are merged by
        // SqlState::join at CFG edges, not by retaining a variable's old value.
        self.values.insert(key, value);
    }

    fn insert_var(&mut self, def: DefId, var: VarId, value: SqlTaint) {
        self.insert_variable(def, &Variable::new(var), value);
    }

    fn logical_name<'a>(
        env: &'a Environment,
        body: &crate::ir::Body,
        variable: &Variable,
    ) -> Option<&'a str> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        let binding = match body.vars.get(var)? {
            VarKind::Arg(binding) | VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) => {
                *binding
            }
            _ => return None,
        };
        let name = env.def_name(binding);
        (!name.starts_with("__")).then_some(name)
    }

    fn insert_assignment(
        &mut self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
        value: SqlTaint,
    ) {
        if variable.projections.is_empty() {
            if let Some(name) = Self::logical_name(env, body, variable) {
                let aliases = body
                    .vars
                    .iter_enumerated()
                    .filter_map(|(var, _)| {
                        let candidate = Variable::new(var);
                        (Self::logical_name(env, body, &candidate) == Some(name)).then_some(var)
                    })
                    .collect::<HashSet<_>>();
                self.values
                    .retain(|(owner, var, _), _| *owner != def || !aliases.contains(var));
            }
            self.insert_variable(def, variable, value);
            return;
        }

        self.insert_variable(def, variable, value);
        if let Base::Var(var) = variable.base {
            let root = (def, var, vec![]);
            self.values
                .entry(root)
                .and_modify(|aggregate| *aggregate = aggregate.join(&value))
                .or_insert(value);
        }
    }

    fn variable(&self, def: DefId, variable: &Variable) -> Option<SqlTaint> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        let projections: Vec<_> = variable.projections.iter().cloned().collect();
        self.values
            .get(&(def, var, projections))
            .copied()
            .or_else(|| self.values.get(&(def, var, vec![])).copied())
    }

    fn variable_with_aliases(
        &self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> Option<SqlTaint> {
        let Some(name) = Self::logical_name(env, body, variable) else {
            return self.variable(def, variable);
        };
        body.vars
            .iter_enumerated()
            .filter_map(|(var, _)| {
                let mut candidate = Variable::new(var);
                candidate.projections = variable.projections.clone();
                (Self::logical_name(env, body, &candidate) == Some(name))
                    .then(|| self.variable(def, &candidate))
                    .flatten()
            })
            .reduce(|left, right| left.join(&right))
    }
}

fn trusted_context_property(variable: &Variable, arg_name: &str) -> Option<SqlTaint> {
    let names: Vec<&str> = variable
        .projections
        .iter()
        .filter_map(|projection| match projection {
            Projection::Known(name) => Some(name.as_ref()),
            Projection::Computed(_) => None,
        })
        .collect();

    let (root, property) = if arg_name == "context" {
        (Some("context"), names.first().copied())
    } else {
        (names.first().copied(), names.get(1).copied())
    };

    if root != Some("context") {
        return None;
    }

    match property {
        Some("installContext" | "accountId" | "license" | "jobId" | "installation") => {
            Some(SqlTaint::Trusted)
        }
        _ => Some(SqlTaint::Unknown),
    }
}

fn resolver_argument_taint<'cx, C: Runner<'cx, State = SqlState>>(
    _interp: &Interp<'cx, C>,
    variable: &Variable,
    arg_name: &str,
) -> SqlTaint {
    if let Some(context) = trusted_context_property(variable, arg_name) {
        return context;
    }

    let has_payload_projection = variable
        .projections
        .iter()
        .any(|projection| matches!(projection, Projection::Known(name) if name == "payload"));
    if arg_name == "payload" || has_payload_projection || matches!(arg_name, "req" | "request") {
        SqlTaint::Untrusted
    } else {
        SqlTaint::Unknown
    }
}

fn classify_variable<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    state: &SqlState,
) -> SqlTaint {
    classify_variable_inner(interp, def, variable, state, &mut HashSet::new())
}

fn classify_variable_inner<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    variable: &Variable,
    state: &SqlState,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> SqlTaint {
    let state_taint = state.variable_with_aliases(interp.env(), interp.body(), def, variable);
    if let Some(state_taint @ (SqlTaint::Trusted | SqlTaint::Untrusted)) = state_taint {
        return state_taint;
    }

    let Base::Var(var) = variable.base else {
        return SqlTaint::Unknown;
    };

    let key = (def, var, variable.projections.iter().cloned().collect());
    if !visiting.insert(key.clone()) {
        return state_taint.unwrap_or(SqlTaint::Unknown);
    }

    // The block worklist can encounter a phi before its predecessor blocks. Use
    // the SSA definitions as a second source of truth so a value is not frozen
    // as Unknown merely because of traversal order.
    let definitions = interp
        .body()
        .iter_blocks_enumerated()
        .flat_map(|(_, block)| block.iter())
        .filter_map(|inst| match inst {
            Inst::Assign(target, rvalue)
                if target.base == variable.base && target.projections == variable.projections =>
            {
                Some(rvalue)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !definitions.is_empty() {
        let result = definitions
            .into_iter()
            .fold(SqlTaint::Trusted, |result, rvalue| {
                result.join(&classify_rvalue_inner(interp, def, rvalue, state, visiting))
            });
        visiting.remove(&key);
        return result;
    }

    if let Some(kind) = interp.body().vars.get(var) {
        match kind {
            VarKind::Arg(arg_def) => {
                let result =
                    resolver_argument_taint(interp, variable, interp.env().def_name(*arg_def));
                visiting.remove(&key);
                return result;
            }
            VarKind::GlobalRef(global_def) => {
                let name = interp.env().def_name(*global_def);
                if matches!(interp.env().def_ref(*global_def), DefKind::Arg) {
                    let result = resolver_argument_taint(interp, variable, name);
                    visiting.remove(&key);
                    return result;
                }
                let resolved_global = interp.env().resolve_alias(*global_def);
                if global_is_proven_constant(interp.env(), resolved_global)
                    || matches!(
                        interp
                            .value_manager
                            .defid_to_value
                            .get(global_def)
                            .or_else(|| {
                                interp.value_manager.defid_to_value.get(&resolved_global)
                            }),
                        Some(Value::Const(_) | Value::Phi(_))
                    )
                {
                    visiting.remove(&key);
                    return SqlTaint::Trusted;
                }
            }
            _ => {}
        }
    }

    let result = match interp.get_value(def, var, Some(variable.projections.clone())) {
        Some(Value::Const(Const::Literal(_))) | Some(Value::Phi(_)) => SqlTaint::Trusted,
        Some(Value::Object(object)) => state
            .variable(def, &Variable::new(*object))
            .unwrap_or(SqlTaint::Trusted),
        Some(Value::Unknown | Value::Uninit) | None => state_taint.unwrap_or(SqlTaint::Unknown),
    };
    visiting.remove(&key);
    result
}

/// Local-module imports may deliberately retain an `Undefined` definition kind
/// while referring to a variable in that module's global body. Prove those
/// bindings constant from the IR itself instead of treating their shape or name
/// as trusted. Every assignment encountered for the binding must be constant.
fn global_is_proven_constant(env: &Environment, def: DefId) -> bool {
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
                let definitions = variable_definitions(body, variable);
                let result = if definitions.is_empty() {
                    match body.vars.get(var) {
                        Some(VarKind::GlobalRef(global) | VarKind::LocalDef(global)) => {
                            definition_is_constant(env, env.resolve_alias(*global), visiting_defs)
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
            Rvalue::Aggregate(elements) => elements.iter().all(|operand| {
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
        let result = env.bodies().all(|body| {
            body.iter_blocks_enumerated()
                .flat_map(|(_, block)| block.iter())
                .filter_map(|inst| match inst {
                    Inst::Assign(target, rvalue) => {
                        let Base::Var(var) = target.base else {
                            return None;
                        };
                        let binding = match body.vars.get(var) {
                            Some(VarKind::GlobalRef(binding) | VarKind::LocalDef(binding)) => {
                                env.resolve_alias(*binding)
                            }
                            _ => return None,
                        };
                        (binding == def).then_some(rvalue)
                    }
                    _ => None,
                })
                .all(|rvalue| {
                    found = true;
                    rvalue_is_constant(env, body, rvalue, &mut HashSet::new(), visiting_defs)
                })
        });
        visiting_defs.remove(&def);
        found && result
    }

    definition_is_constant(env, def, &mut HashSet::new())
}

fn classify_operand<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operand: &Operand,
    state: &SqlState,
) -> SqlTaint {
    match operand {
        Operand::Lit(_) => SqlTaint::Trusted,
        Operand::Var(variable) => classify_variable(interp, def, variable, state),
    }
}

fn classify_operand_inner<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operand: &Operand,
    state: &SqlState,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> SqlTaint {
    match operand {
        Operand::Lit(_) => SqlTaint::Trusted,
        Operand::Var(variable) => classify_variable_inner(interp, def, variable, state, visiting),
    }
}

fn join_operands<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operands: impl IntoIterator<Item = Operand>,
    state: &SqlState,
) -> SqlTaint {
    operands
        .into_iter()
        .fold(SqlTaint::Trusted, |result, operand| {
            result.join(&classify_operand(interp, def, &operand, state))
        })
}

fn classify_rvalue_inner<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    rvalue: &Rvalue,
    state: &SqlState,
    visiting: &mut HashSet<(DefId, VarId, Vec<Projection>)>,
) -> SqlTaint {
    let classify = |operand: &Operand, visiting: &mut HashSet<_>| {
        classify_operand_inner(interp, def, operand, state, visiting)
    };
    match rvalue {
        Rvalue::Read(operand) | Rvalue::Unary(_, operand) => classify(operand, visiting),
        Rvalue::Aggregate(elements) => elements.iter().fold(SqlTaint::Trusted, |value, operand| {
            value.join(&classify(operand, visiting))
        }),
        Rvalue::Bin(_, left, right) => classify(left, visiting).join(&classify(right, visiting)),
        Rvalue::Template(template) => template.exprs.iter().fold(SqlTaint::Trusted, |value, op| {
            value.join(&classify(op, visiting))
        }),
        Rvalue::Phi(values) => values.iter().fold(SqlTaint::Trusted, |value, (var, _)| {
            value.join(&classify_variable_inner(
                interp,
                def,
                &Variable::new(*var),
                state,
                visiting,
            ))
        }),
        Rvalue::Intrinsic(intrinsic, _) => match intrinsic {
            Intrinsic::Fetch
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::StorageRead => SqlTaint::Untrusted,
            // prepare creates a statement. Its execute() result is handled by
            // ordinary receiver propagation; executeRaw returns query data.
            Intrinsic::SqlQuery(SqlSink::ExecuteRaw) => SqlTaint::Untrusted,
            Intrinsic::SqlQuery(SqlSink::Prepare | SqlSink::MigrationEnqueue)
            | Intrinsic::Authorize(_)
            | Intrinsic::SecretFunction(_)
            | Intrinsic::EnvRead => SqlTaint::Trusted,
        },
        Rvalue::Call(callee, operands) => {
            if let Some((callee_def, callee_body)) =
                interp.body().resolve_call(interp.env(), callee)
            {
                if let Some(final_state) = interp.func_state(callee_def)
                    && let Some((return_var, _)) = callee_body
                        .vars
                        .iter_enumerated()
                        .find(|(_, kind)| matches!(kind, VarKind::Ret))
                {
                    return final_state
                        .variable(callee_def, &Variable::new(return_var))
                        .unwrap_or(SqlTaint::Unknown);
                }
                return SqlTaint::Unknown;
            }

            let operand_taint = operands.iter().fold(SqlTaint::Trusted, |value, operand| {
                value.join(&classify(operand, visiting))
            });
            if let Some((receiver, method)) = method_receiver(callee) {
                if method == "execute"
                    && originates_from_prepare(interp, &receiver, &mut HashSet::new())
                {
                    return SqlTaint::Untrusted;
                }
                return classify_variable_inner(interp, def, &receiver, state, visiting)
                    .join(&operand_taint);
            }
            SqlTaint::Unknown.join(&operand_taint)
        }
    }
}

fn method_receiver(callee: &Operand) -> Option<(Variable, &str)> {
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

fn variable_definitions<'a>(
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    let exact: Vec<_> = body
        .iter_blocks_enumerated()
        .flat_map(|(block_id, block)| {
            block
                .iter()
                .enumerate()
                .filter_map(move |(stmt, inst)| match inst {
                    Inst::Assign(target, rvalue)
                        if target.base == variable.base
                            && target.projections == variable.projections =>
                    {
                        Some((Location::new(block_id, stmt as u32), rvalue))
                    }
                    _ => None,
                })
        })
        .collect();
    if !exact.is_empty() || variable.projections.is_empty() {
        return exact;
    }
    let mut root = variable.clone();
    root.projections.clear();
    variable_definitions(body, &root)
}

fn projected_variable_definitions<'a>(
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

fn variable_definitions_with_aliases<'a>(
    env: &Environment,
    body: &'a crate::ir::Body,
    variable: &Variable,
) -> Vec<(Location, &'a Rvalue)> {
    let Some(name) = SqlState::logical_name(env, body, variable) else {
        let definitions = variable_definitions(body, variable);
        if definitions.is_empty() && variable.projections.is_empty() {
            return projected_variable_definitions(body, variable);
        }
        return definitions;
    };
    let mut definitions = BTreeMap::new();
    for (var, _) in body.vars.iter_enumerated() {
        let mut candidate = Variable::new(var);
        candidate.projections = variable.projections.clone();
        if SqlState::logical_name(env, body, &candidate) == Some(name) {
            let mut candidate_definitions = variable_definitions(body, &candidate);
            if candidate_definitions.is_empty() && candidate.projections.is_empty() {
                candidate_definitions = projected_variable_definitions(body, &candidate);
            }
            for (location, rvalue) in candidate_definitions {
                definitions.entry(location).or_insert(rvalue);
            }
        }
    }
    definitions.into_iter().collect()
}

fn originates_from_prepare<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    variable: &Variable,
    visiting: &mut HashSet<Variable>,
) -> bool {
    if !visiting.insert(variable.clone()) {
        return false;
    }
    variable_definitions(interp.body(), variable)
        .into_iter()
        .any(|(_, rvalue)| match rvalue {
            Rvalue::Intrinsic(Intrinsic::SqlQuery(SqlSink::Prepare), _) => true,
            Rvalue::Read(Operand::Var(source)) => originates_from_prepare(interp, source, visiting),
            Rvalue::Call(callee, _) => method_receiver(callee)
                .is_some_and(|(receiver, _)| originates_from_prepare(interp, &receiver, visiting)),
            _ => false,
        })
}

fn variable_name(env: &Environment, body: &crate::ir::Body, variable: &Variable) -> String {
    let Base::Var(var) = variable.base else {
        return format!("{variable:?}");
    };
    let root = match body.vars.get(var) {
        Some(VarKind::Arg(def) | VarKind::LocalDef(def) | VarKind::GlobalRef(def)) => {
            env.def_name(*def).to_owned()
        }
        Some(VarKind::Ret) => "return value".to_owned(),
        _ => format!("temporary#{}", var.0),
    };
    variable
        .projections
        .iter()
        .fold(root, |mut value, projection| {
            match projection {
                Projection::Known(name) => {
                    value.push('.');
                    value.push_str(name);
                }
                Projection::Computed(_) => value.push_str("[computed]"),
            }
            value
        })
}

fn render_query_operand(env: &Environment, def: DefId, operand: &Operand) -> String {
    fn render(
        env: &Environment,
        def: DefId,
        operand: &Operand,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> String {
        match operand {
            Operand::Lit(literal) => literal.to_string(),
            Operand::Var(variable) => {
                let Base::Var(var) = variable.base else {
                    return format!("{operand:?}");
                };
                let body = env.def_ref(def).expect_body();
                if !variable.projections.is_empty() || !visiting.insert((def, var)) {
                    return variable_name(env, body, variable);
                }
                let mut alternatives = variable_definitions_with_aliases(env, body, variable)
                    .into_iter()
                    .map(|(_, rvalue)| match rvalue {
                        Rvalue::Read(source) => render(env, def, source, visiting),
                        Rvalue::Aggregate(elements) => format!(
                            "[{}]",
                            elements
                                .iter()
                                .map(|element| render(env, def, element, visiting))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        Rvalue::Bin(crate::ir::BinOp::Add, left, right) => format!(
                            "{} + {}",
                            render(env, def, left, visiting),
                            render(env, def, right, visiting)
                        ),
                        Rvalue::Template(template) => {
                            let mut output = String::new();
                            for (index, quasi) in template.quasis.iter().enumerate() {
                                output.push_str(quasi);
                                if let Some(expr) = template.exprs.get(index) {
                                    output.push_str("${");
                                    output.push_str(&render(env, def, expr, visiting));
                                    output.push('}');
                                }
                            }
                            output
                        }
                        Rvalue::Call(callee, _) => format!("dynamic result of {callee:?}"),
                        _ => format!("{rvalue:?}"),
                    })
                    .collect::<Vec<_>>();
                alternatives.sort();
                alternatives.dedup();
                let rendered = match alternatives.as_slice() {
                    [] => variable_name(env, body, variable),
                    [only] => only.clone(),
                    _ => format!("one of ({})", alternatives.join(" | ")),
                };
                visiting.remove(&(def, var));
                rendered
            }
        }
    }

    render(env, def, operand, &mut HashSet::new())
}

fn collect_sources<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    operand: &Operand,
    source_map: &SourceMap,
) -> Vec<String> {
    fn collect<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        body: &crate::ir::Body,
        active_callers: &HashMap<DefId, (DefId, Location)>,
        operand: &Operand,
        visiting: &mut HashSet<(DefId, VarId)>,
        sources: &mut BTreeMap<String, ()>,
        source_map: &SourceMap,
    ) {
        let Operand::Var(variable) = operand else {
            return;
        };
        let Base::Var(var) = variable.base else {
            return;
        };
        if !visiting.insert((def, var)) {
            return;
        }
        if let Some(kind) = body.vars.get(var) {
            match kind {
                VarKind::Arg(arg) | VarKind::GlobalRef(arg)
                    if matches!(interp.env().def_ref(*arg), DefKind::Arg) =>
                {
                    let name = interp.env().def_name(*arg);
                    let argument_index = body
                        .argument_defs
                        .iter()
                        .position(|argument| {
                            argument == arg || interp.env().def_name(*argument) == name
                        })
                        .or_else(|| {
                            body.vars
                                .iter_enumerated()
                                .filter_map(|(candidate, kind)| {
                                    matches!(kind, VarKind::Arg(_)).then_some(candidate)
                                })
                                .position(|candidate| candidate == var)
                        });
                    let mut followed_caller = false;
                    if let Some(&(caller_def, call_location)) = active_callers.get(&def) {
                        let caller_body = interp.env().def_ref(caller_def).expect_body();
                        if let Some(arguments) = caller_body
                            .block(call_location.block)
                            .insts
                            .get(call_location.stmt as usize)
                            .and_then(|inst| inst.rvalue().as_call())
                            .map(|(_, arguments)| arguments)
                        {
                            let argument = if arguments.len() == 1 && argument_index.is_none() {
                                let mut projected = arguments[0].clone();
                                if let Operand::Var(variable) = &mut projected {
                                    variable
                                        .projections
                                        .push(Projection::Known(name.to_owned().into()));
                                }
                                Some(projected)
                            } else {
                                argument_index
                                    .and_then(|index| arguments.get(index))
                                    .cloned()
                            };
                            if let Some(argument) = argument {
                                followed_caller = true;
                                collect(
                                    interp,
                                    caller_def,
                                    caller_body,
                                    active_callers,
                                    &argument,
                                    visiting,
                                    sources,
                                    source_map,
                                );
                            }
                        }
                    }
                    if !followed_caller {
                        let category = if matches!(interp.entry().kind, EntryKind::Resolver(..))
                            && (name == "payload"
                                || variable.projections.iter().any(
                                    |projection| matches!(projection, Projection::Known(name) if name == "payload"),
                                ))
                        {
                            "resolver payload"
                        } else if matches!(name, "req" | "request") {
                            "HTTP request data"
                        } else {
                            "entrypoint or propagated input"
                        };
                        sources.insert(
                            format!(
                                "{category} `{name}` at {}",
                                argument_source_location(
                                    source_map,
                                    body,
                                    *arg,
                                    &interp.entry().file,
                                )
                            ),
                            (),
                        );
                    }
                }
                _ => {}
            }
        }
        for (location, rvalue) in variable_definitions_with_aliases(interp.env(), body, variable) {
            let at = source_location(source_map, body, location, &interp.entry().file);
            match rvalue {
                Rvalue::Read(source) | Rvalue::Unary(_, source) => collect(
                    interp,
                    def,
                    body,
                    active_callers,
                    source,
                    visiting,
                    sources,
                    source_map,
                ),
                Rvalue::Aggregate(elements) => {
                    for source in elements {
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            source,
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                }
                Rvalue::Bin(_, left, right) => {
                    collect(
                        interp,
                        def,
                        body,
                        active_callers,
                        left,
                        visiting,
                        sources,
                        source_map,
                    );
                    collect(
                        interp,
                        def,
                        body,
                        active_callers,
                        right,
                        visiting,
                        sources,
                        source_map,
                    );
                }
                Rvalue::Template(template) => {
                    for source in &template.exprs {
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            source,
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                }
                Rvalue::Phi(values) => {
                    for (source, _) in values {
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            &Operand::with_var(*source),
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                }
                Rvalue::Intrinsic(intrinsic, args) => {
                    let category = match intrinsic {
                        Intrinsic::Fetch => Some("external network response"),
                        Intrinsic::ApiCall(_)
                        | Intrinsic::SafeCall(_)
                        | Intrinsic::ApiCustomField
                        | Intrinsic::UserFieldAccess => Some("Atlassian API response"),
                        Intrinsic::StorageRead => Some("Forge storage read"),
                        Intrinsic::SqlQuery(SqlSink::ExecuteRaw) => Some("Forge SQL result"),
                        _ => None,
                    };
                    if let Some(category) = category {
                        sources.insert(format!("{category} at {at}"), ());
                    }
                    for source in args {
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            source,
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                }
                Rvalue::Call(callee, args) => {
                    if let Some((receiver, method)) = method_receiver(callee) {
                        if method == "execute"
                            && originates_from_prepare(interp, &receiver, &mut HashSet::new())
                        {
                            sources.insert(format!("Forge SQL result at {at}"), ());
                        }
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            &Operand::Var(receiver),
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                    for source in args {
                        collect(
                            interp,
                            def,
                            body,
                            active_callers,
                            source,
                            visiting,
                            sources,
                            source_map,
                        );
                    }
                }
            }
        }
        visiting.remove(&(def, var));
    }

    let callstack = interp.callstack();
    let mut active_callers = HashMap::new();
    for (index, frame) in callstack.iter().enumerate() {
        let callee = callstack
            .get(index + 1)
            .map_or(def, |next| next.calling_function);
        active_callers.insert(
            callee,
            (
                frame.calling_function,
                Location::new(frame.block, frame.inst_idx as u32),
            ),
        );
    }
    let mut sources = BTreeMap::new();
    collect(
        interp,
        def,
        interp.body(),
        &active_callers,
        operand,
        &mut HashSet::new(),
        &mut sources,
        source_map,
    );
    sources.into_keys().take(8).collect()
}

fn collect_entry_argument_sources<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    source_map: &SourceMap,
) -> Vec<String> {
    let root_def = interp
        .callstack()
        .first()
        .map_or(def, |frame| frame.calling_function);
    let root_body = interp.env().def_ref(root_def).expect_body();
    let mut sources = BTreeMap::new();
    for (_, kind) in root_body.vars.iter_enumerated() {
        let argument = match kind {
            VarKind::Arg(argument) | VarKind::GlobalRef(argument)
                if matches!(interp.env().def_ref(*argument), DefKind::Arg) =>
            {
                *argument
            }
            _ => continue,
        };
        let name = interp.env().def_name(argument);
        let category =
            if matches!(interp.entry().kind, EntryKind::Resolver(..)) && name == "payload" {
                "resolver payload"
            } else if matches!(name, "req" | "request") {
                "HTTP request data"
            } else if name == "payload" {
                "entrypoint input"
            } else {
                continue;
            };
        sources.insert(
            format!(
                "{category} `{name}` at {}",
                argument_source_location(source_map, root_body, argument, &interp.entry().file)
            ),
            (),
        );
    }
    sources.into_keys().take(8).collect()
}

fn argument_source_location(
    source_map: &SourceMap,
    body: &crate::ir::Body,
    def: DefId,
    fallback_file: &PathBuf,
) -> String {
    let Some(span) = body.argument_span(def) else {
        return format!("{fallback_file:?}");
    };
    let Ok(position) = source_map.try_lookup_char_pos(span.lo) else {
        return format!("{fallback_file:?}");
    };
    format!(
        "{}:{}:{}",
        position.file.name,
        position.line,
        position.col_display + 1
    )
}

fn source_location(
    source_map: &SourceMap,
    body: &crate::ir::Body,
    location: Location,
    fallback_file: &PathBuf,
) -> String {
    let Some(span) = body.instruction_span(location) else {
        return format!(
            "{:?} (IR block {}, instruction {})",
            fallback_file, location.block.0, location.stmt
        );
    };
    let Ok(position) = source_map.try_lookup_char_pos(span.lo) else {
        return format!(
            "{:?} (IR block {}, instruction {})",
            fallback_file, location.block.0, location.stmt
        );
    };
    format!(
        "{}:{}:{}",
        position.file.name,
        position.line,
        position.col_display + 1
    )
}

pub struct SqlDataflow {
    needs_call: Vec<(DefId, bool)>,
}

impl SqlDataflow {
    fn classify_rvalue<'cx, C: Runner<'cx, State = SqlState>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        rvalue: &Rvalue,
        state: &SqlState,
    ) -> SqlTaint {
        classify_rvalue_inner(interp, def, rvalue, state, &mut HashSet::new())
    }

    fn propagate_call_arguments<'cx, C: Runner<'cx, State = SqlState>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        callee: &Operand,
        operands: &[Operand],
        state: &mut SqlState,
    ) {
        let Some((callee_def, callee_body)) = interp.body().resolve_call(interp.env(), callee)
        else {
            return;
        };
        for (argument_def, operand) in callee_body.argument_defs.iter().zip(operands) {
            let taint = classify_operand(interp, def, operand, state);
            for (arg, kind) in callee_body.vars.iter_enumerated() {
                let binding = match kind {
                    VarKind::Arg(binding)
                    | VarKind::GlobalRef(binding)
                    | VarKind::LocalDef(binding) => Some(binding),
                    _ => None,
                };
                if binding == Some(argument_def) {
                    state.insert_var(callee_def, arg, taint);
                }
            }
        }
        let changed = interp.join_block_state(callee_def, STARTING_BLOCK, state);
        self.needs_call.push((callee_def, changed));
    }
}

impl<'cx> Dataflow<'cx> for SqlDataflow {
    type State = SqlState;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        inst: &'cx Inst,
        mut state: Self::State,
    ) -> Self::State {
        if let Inst::Assign(target, rvalue) = inst {
            if let Rvalue::Call(callee, operands) = rvalue {
                self.propagate_call_arguments(interp, def, callee, operands, &mut state);
            }
            // SqlState owns SQL classification, argument propagation, and return
            // propagation. Populating the shared ValueManager as well duplicates
            // that work and makes projected object assignments dominate runtime
            // on large entrypoint graphs.
            let taint = self.classify_rvalue(interp, def, rvalue, &state);
            state.insert_assignment(interp.env(), interp.body(), def, target, taint);
        } else if let Inst::Expr(Rvalue::Call(callee, operands)) = inst {
            self.propagate_call_arguments(interp, def, callee, operands, &mut state);
            if let Some((receiver, method)) = method_receiver(callee)
                && method == "push"
            {
                let taint = classify_variable(interp, def, &receiver, &state).join(&join_operands(
                    interp,
                    def,
                    operands.iter().cloned(),
                    &state,
                ));
                state.insert_assignment(interp.env(), interp.body(), def, &receiver, taint);
            }
        }
        state
    }

    fn join_term<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for (callee, changed) in self.needs_call.drain(..) {
            if !worklist.push_front_blocks(interp.env(), callee, interp.call_all) && changed {
                let blocks = interp
                    .env()
                    .def_ref(callee)
                    .expect_body()
                    .iter_block_keys()
                    .map(|block| (callee, block));
                worklist.extend(blocks);
            }
        }
    }
}

#[derive(Debug)]
pub struct SqlInjectionVuln {
    sink: SqlSink,
    taint: SqlTaint,
    paths: Vec<String>,
    sink_location: String,
    sink_function: String,
    query: String,
    sources: Vec<String>,
}

impl SqlInjectionVuln {
    fn new(
        sink: SqlSink,
        taint: SqlTaint,
        callstack: Vec<Frame>,
        env: &Environment,
        entry: &EntryPoint,
        def: DefId,
        sink_location: String,
        query: &Operand,
        sources: Vec<String>,
        source_map: &SourceMap,
    ) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(function) => function.clone(),
            EntryKind::Resolver(resolver, property) => format!("{resolver}.{property}"),
            EntryKind::Empty => String::new(),
        };
        let mut propagation = vec![entry_func.clone()];
        for (index, frame) in callstack.iter().enumerate() {
            let caller = if index == 0 {
                entry_func.as_str()
            } else {
                env.def_name(frame.calling_function)
            };
            let body = env.def_ref(frame.calling_function).expect_body();
            let location = source_location(
                source_map,
                body,
                Location::new(frame.block, frame.inst_idx as u32),
                &entry.file,
            );
            propagation.push(format!("call from {caller} at {location}"));
        }
        if !callstack.is_empty() {
            propagation.push(env.def_name(def).to_owned());
        }
        let path = propagation.join(" -> ");
        Self {
            sink,
            taint,
            paths: vec![path],
            sink_location,
            sink_function: env.def_name(def).to_owned(),
            query: render_query_operand(env, def, query),
            sources,
        }
    }

    fn merge(&mut self, mut other: Self) {
        self.taint = self.taint.join(&other.taint);
        for source in other.sources.drain(..) {
            if self.sources.len() == 8 {
                break;
            }
            if !self.sources.contains(&source) {
                self.sources.push(source);
            }
        }
        for path in other.paths.drain(..) {
            if self.paths.len() == 8 {
                break;
            }
            if !self.paths.contains(&path) {
                self.paths.push(path);
            }
        }
        self.sources.sort();
    }
}

impl fmt::Display for SqlInjectionVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Forge SQL injection vulnerability")
    }
}

impl WithCallStack for SqlInjectionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl IntoVuln for SqlInjectionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        let sink_name = self.sink.api_name();
        let location = format!("{} in {}", self.sink_location, self.sink_function);
        let source_text = if self.sources.is_empty() {
            "unresolved dynamic origin".to_owned()
        } else {
            self.sources.join(", ")
        };
        let (severity, description, proof) = match self.taint {
            SqlTaint::Untrusted => (
                Severity::High,
                format!(
                    "Confirmed untrusted data is incorporated into SQL query text passed to {sink_name} at {location}."
                ),
                format!(
                    "Source: {source_text}. Propagation path: {}. Query argument at {location}: `{}`. Binding: the value is part of SQL text, so bindParams does not repair interpolation already present in the query. Limitation: FSRT models locally resolvable calls and supported IR operations; review the reported source and path in application context.",
                    self.paths.join("; "),
                    self.query
                ),
            ),
            SqlTaint::Unknown => (
                Severity::Low,
                format!(
                    "Dynamic SQL query text passed to {sink_name} at {location} has an unresolved origin."
                ),
                format!(
                    "Unresolved dynamic origin reaches {sink_name}. Propagation path: {}. Query argument at {location}: `{}`. Binding: placeholders with bindParams protect values, but interpolated SQL structure does not. Limitation: FSRT could not prove the dynamic component trusted or attacker-controlled within locally resolvable calls and supported IR operations.",
                    self.paths.join("; "),
                    self.query
                ),
            ),
            SqlTaint::Trusted => unreachable!("trusted SQL does not produce a finding"),
        };

        Vulnerability {
            check_name: "forge-sql-injection".to_string(),
            description,
            recommendation: "Use placeholders and bindParams for values. For identifiers or SQL structure that cannot be bound, select only from IR-provable trusted constant alternatives.",
            proof,
            severity,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: "CWE-89",
            date: reporter.current_date(),
        }
    }
}

pub struct SqlInjectionChecker {
    vulns: Vec<SqlInjectionVuln>,
    seen: HashMap<(DefId, Location, SqlSink), usize>,
    source_map: Arc<SourceMap>,
}

impl SqlInjectionChecker {
    pub fn new(source_map: Arc<SourceMap>) -> Self {
        Self {
            vulns: vec![],
            seen: HashMap::new(),
            source_map,
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = SqlInjectionVuln> {
        self.vulns
    }
}

impl<'cx> Runner<'cx> for SqlInjectionChecker {
    type State = SqlState;
    type Dataflow = SqlDataflow;

    const NAME: &'static str = "SQLInjection";
    const REQUIRE_CALLEE_STATE_COVERS_CALLER: bool = false;
    const JOIN_FUNCTION_RETURN_STATES: bool = true;

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        loc: Location,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        let Intrinsic::SqlQuery(sink) = intrinsic else {
            return ControlFlow::Continue(state.clone());
        };
        let operands = operands.unwrap_or_default();
        let query_index = match sink {
            SqlSink::Prepare | SqlSink::ExecuteRaw => 0,
            SqlSink::MigrationEnqueue => 1,
        };
        let final_state = interp
            .func_state(def)
            .map_or_else(|| state.clone(), |analysis| analysis.join(state));
        let query_taint = operands
            .get(query_index)
            .map(|operand| classify_operand(interp, def, operand, &final_state))
            .unwrap_or(SqlTaint::Unknown);
        if query_taint != SqlTaint::Trusted {
            let query = operands.get(query_index).cloned().unwrap_or(Operand::UNDEF);
            let mut sources = collect_sources(interp, def, &query, &self.source_map);
            if query_taint == SqlTaint::Untrusted {
                for source in collect_entry_argument_sources(interp, def, &self.source_map) {
                    if sources.len() == 8 {
                        break;
                    }
                    if !sources.contains(&source) {
                        sources.push(source);
                    }
                }
                sources.sort();
            }
            let vuln = SqlInjectionVuln::new(
                *sink,
                query_taint,
                interp.callstack(),
                interp.env(),
                interp.entry(),
                def,
                source_location(&self.source_map, interp.body(), loc, &interp.entry().file),
                &query,
                sources,
                &self.source_map,
            );
            let key = (def, loc, *sink);
            if let Some(index) = self.seen.get(&key).copied() {
                self.vulns[index].merge(vuln);
            } else {
                self.seen.insert(key, self.vulns.len());
                self.vulns.push(vuln);
            }
        }
        ControlFlow::Continue(state.clone())
    }
}

impl Checker<'_> for SqlInjectionChecker {
    type Vuln = SqlInjectionVuln;
}
