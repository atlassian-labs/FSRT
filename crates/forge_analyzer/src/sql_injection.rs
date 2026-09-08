use crate::{
    definitions::{Const, DefId, DefKind, Environment, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, Runner,
        WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Inst, Intrinsic, Literal, Location, Operand,
        Projection, Rvalue, STARTING_BLOCK, SqlSink, Terminator, UnOp, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    worklist::WorkList,
};
use smallvec::SmallVec;
use std::{
    cmp::max,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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
    /// The value may still be attacker-controlled, but JavaScript semantics
    /// guarantee that its string representation cannot contain SQL syntax.
    Numeric,
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
    allowlisted: BTreeSet<SqlVarKey>,
    reachable: bool,
}

impl JoinSemiLattice for SqlState {
    const BOTTOM: Self = Self {
        values: BTreeMap::new(),
        allowlisted: BTreeSet::new(),
        reachable: false,
    };

    fn join_changed(&mut self, other: &Self) -> bool {
        if !other.reachable {
            return false;
        }
        if !self.reachable {
            *self = other.clone();
            return true;
        }
        let old = self.clone();
        for (key, value) in &other.values {
            self.values
                .entry(key.clone())
                .and_modify(|current| {
                    *current = current.join(value);
                })
                .or_insert(*value);
        }
        self.allowlisted
            .retain(|key| other.allowlisted.contains(key));
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
        self.reachable = true;
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
                self.allowlisted
                    .retain(|(owner, var, _)| *owner != def || !aliases.contains(var));
            }
            self.insert_variable(def, variable, value);
            return;
        }

        if let Some(name) = Self::logical_name(env, body, variable) {
            let projections = &variable.projections;
            let aliases = body
                .vars
                .iter_enumerated()
                .filter_map(|(var, _)| {
                    let mut candidate = Variable::new(var);
                    candidate.projections = projections.clone();
                    (Self::logical_name(env, body, &candidate) == Some(name)).then_some(var)
                })
                .collect::<HashSet<_>>();
            self.allowlisted
                .retain(|(owner, var, candidate_projections)| {
                    *owner != def
                        || !aliases.contains(var)
                        || candidate_projections.as_slice() != projections.as_slice()
                });
        } else if let Some(key) = Self::key(def, variable) {
            self.allowlisted.remove(&key);
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

    fn exact_variable(&self, def: DefId, variable: &Variable) -> Option<SqlTaint> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        self.values
            .get(&(def, var, variable.projections.iter().cloned().collect()))
            .copied()
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
        let aliases = body
            .vars
            .iter_enumerated()
            .filter_map(|(var, _)| {
                let mut candidate = Variable::new(var);
                candidate.projections = variable.projections.clone();
                (Self::logical_name(env, body, &candidate) == Some(name)).then_some(candidate)
            })
            .collect::<Vec<_>>();

        // A field-specific fact is more precise than the aggregate object fact.
        // Consult roots only when no alias has a fact for this exact projection.
        let exact = aliases
            .iter()
            .filter_map(|candidate| self.exact_variable(def, candidate))
            .reduce(|left, right| left.join(&right));
        exact.or_else(|| {
            aliases
                .iter()
                .filter_map(|candidate| self.variable(def, candidate))
                .reduce(|left, right| left.join(&right))
        })
    }

    fn mark_allowlisted(
        &mut self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) {
        self.reachable = true;
        let Some(name) = Self::logical_name(env, body, variable) else {
            if let Some(key) = Self::key(def, variable) {
                self.allowlisted.insert(key);
            }
            return;
        };
        for (var, _) in body.vars.iter_enumerated() {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            if Self::logical_name(env, body, &candidate) == Some(name)
                && let Some(key) = Self::key(def, &candidate)
            {
                self.allowlisted.insert(key);
            }
        }
    }

    fn is_allowlisted(
        &self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> bool {
        let Some(name) = Self::logical_name(env, body, variable) else {
            return Self::key(def, variable).is_some_and(|key| self.allowlisted.contains(&key));
        };
        body.vars.iter_enumerated().any(|(var, _)| {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            Self::logical_name(env, body, &candidate) == Some(name)
                && Self::key(def, &candidate).is_some_and(|key| self.allowlisted.contains(&key))
        })
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
    if state.is_allowlisted(interp.env(), interp.body(), def, variable) {
        return SqlTaint::Trusted;
    }
    let state_taint = state.variable_with_aliases(interp.env(), interp.body(), def, variable);
    if let Some(state_taint @ (SqlTaint::Trusted | SqlTaint::Numeric | SqlTaint::Untrusted)) =
        state_taint
    {
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

fn literal_string(operand: &Operand) -> Option<&str> {
    match operand {
        Operand::Lit(Literal::Str(value) | Literal::JSXText(value)) => Some(value.as_ref()),
        _ => None,
    }
}

fn is_placeholder_fragment(operand: &Operand) -> bool {
    literal_string(operand).is_some_and(|value| value.contains('?'))
}

fn is_placeholder_separator(operand: &Operand) -> bool {
    literal_string(operand).is_some()
}

fn is_fresh_array_variable<'cx, C: Runner<'cx, State = SqlState>>(
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
    if placeholder_collection_is_modified_or_escapes(interp.env(), interp.body(), variable, "fill")
    {
        visiting.remove(&(def, var));
        return false;
    }
    let definitions = variable_definitions_with_aliases(interp.env(), interp.body(), variable);
    let result = !definitions.is_empty()
        && definitions.into_iter().all(|(_, rvalue)| match rvalue {
            Rvalue::Aggregate(_) => true,
            Rvalue::Read(Operand::Var(source)) => {
                is_fresh_array_variable(interp, def, source, visiting)
            }
            Rvalue::Phi(values) => values.iter().all(|(source, _)| {
                is_fresh_array_variable(interp, def, &Variable::new(*source), visiting)
            }),
            Rvalue::Call(callee, _) => {
                unresolved_global_named(interp.env(), interp.body(), callee, "Array")
            }
            _ => false,
        });
    visiting.remove(&(def, var));
    result
}

fn placeholder_collection_is_modified_or_escapes(
    env: &Environment,
    body: &crate::ir::Body,
    variable: &Variable,
    allowed_method: &str,
) -> bool {
    let Base::Var(root) = variable.base else {
        return true;
    };
    let aliases = SqlState::logical_name(env, body, variable).map_or_else(
        || HashSet::from([root]),
        |name| {
            body.vars
                .iter_enumerated()
                .filter_map(|(var, _)| {
                    let candidate = Variable::new(var);
                    (SqlState::logical_name(env, body, &candidate) == Some(name)).then_some(var)
                })
                .collect()
        },
    );
    let is_alias =
        |candidate: &Variable| matches!(candidate.base, Base::Var(var) if aliases.contains(&var));

    body.iter_blocks_enumerated()
        .flat_map(|(_, block)| block.iter())
        .any(|inst| {
            if let Inst::Assign(target, _) = inst
                && !target.projections.is_empty()
                && is_alias(target)
            {
                return true;
            }
            let Some((callee, operands)) = inst.rvalue().as_call() else {
                return false;
            };
            if operands
                .iter()
                .any(|operand| matches!(operand, Operand::Var(value) if is_alias(value)))
            {
                return true;
            }
            method_receiver(callee).is_some_and(|(receiver, method)| {
                if !is_alias(&receiver) {
                    return false;
                }
                method != allowed_method
                    || (allowed_method == "fill"
                        && (operands.len() != 1 || !is_placeholder_fragment(&operands[0])))
            })
        })
}

fn is_placeholder_sequence_variable<'cx, C: Runner<'cx, State = SqlState>>(
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
    if placeholder_collection_is_modified_or_escapes(interp.env(), interp.body(), variable, "join")
    {
        visiting.remove(&(def, var));
        return false;
    }
    let definitions = variable_definitions_with_aliases(interp.env(), interp.body(), variable);
    let result = !definitions.is_empty()
        && definitions.into_iter().all(|(_, rvalue)| match rvalue {
            Rvalue::Aggregate(elements) => {
                !elements.is_empty() && elements.iter().all(is_placeholder_fragment)
            }
            Rvalue::Read(Operand::Var(source)) => {
                is_placeholder_sequence_variable(interp, def, source, visiting)
            }
            Rvalue::Phi(values) => values.iter().all(|(source, _)| {
                is_placeholder_sequence_variable(interp, def, &Variable::new(*source), visiting)
            }),
            Rvalue::Call(callee, operands) => {
                let Some((receiver, "fill")) = method_receiver(callee) else {
                    return false;
                };
                operands.len() == 1
                    && is_placeholder_fragment(&operands[0])
                    && is_fresh_array_variable(interp, def, &receiver, &mut HashSet::new())
            }
            _ => false,
        });
    visiting.remove(&(def, var));
    result
}

fn is_placeholder_list_call<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    callee: &Operand,
    operands: &[Operand],
) -> bool {
    let Some((receiver, "join")) = method_receiver(callee) else {
        return false;
    };
    operands.len() <= 1
        && operands.first().is_none_or(is_placeholder_separator)
        && is_placeholder_sequence_variable(interp, def, &receiver, &mut HashSet::new())
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
        Rvalue::Read(operand) => classify(operand, visiting),
        Rvalue::Unary(op, operand) => match op {
            UnOp::Neg | UnOp::Plus | UnOp::BitNot => SqlTaint::Numeric,
            _ => classify(operand, visiting),
        },
        Rvalue::Aggregate(elements) => elements.iter().fold(SqlTaint::Trusted, |value, operand| {
            value.join(&classify(operand, visiting))
        }),
        Rvalue::Bin(op, left, right) => match op {
            BinOp::Sub
            | BinOp::Mul
            | BinOp::Div
            | BinOp::Exp
            | BinOp::Mod
            | BinOp::BitOr
            | BinOp::BitAnd
            | BinOp::BitXor
            | BinOp::Lshift
            | BinOp::Rshift
            | BinOp::RshiftLogical => SqlTaint::Numeric,
            _ => classify(left, visiting).join(&classify(right, visiting)),
        },
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
            if is_placeholder_list_call(interp, def, callee, operands) {
                return SqlTaint::Trusted;
            }
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

            if is_numeric_builtin_call(interp, callee) {
                return SqlTaint::Numeric;
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

fn is_numeric_builtin_call<'cx, C: Runner<'cx, State = SqlState>>(
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

fn unresolved_global_named(
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

fn constant_string_collection(
    env: &Environment,
    def: DefId,
    body: &crate::ir::Body,
    variable: &Variable,
) -> Option<HashSet<String>> {
    fn variable_binding(env: &Environment, body: &crate::ir::Body, var: VarId) -> Option<DefId> {
        match body.vars.get(var)? {
            VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) => {
                Some(env.resolve_alias(*binding))
            }
            _ => None,
        }
    }

    fn collection_is_mutated(env: &Environment, body: &crate::ir::Body, binding: DefId) -> bool {
        body.iter_blocks_enumerated()
            .flat_map(|(_, block)| block.iter())
            .any(|inst| {
                if let Inst::Assign(target, _) = inst
                    && !target.projections.is_empty()
                    && let Base::Var(var) = target.base
                    && variable_binding(env, body, var) == Some(binding)
                {
                    return true;
                }
                let Some((callee, _)) = inst.rvalue().as_call() else {
                    return false;
                };
                let Some((receiver, method)) = method_receiver(callee) else {
                    return false;
                };
                let Base::Var(var) = receiver.base else {
                    return false;
                };
                variable_binding(env, body, var) == Some(binding)
                    && matches!(method, "add" | "push" | "splice" | "unshift")
            })
    }

    fn from_operand(
        env: &Environment,
        def: DefId,
        body: &crate::ir::Body,
        operand: &Operand,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> Option<HashSet<String>> {
        let Operand::Var(variable) = operand else {
            return None;
        };
        from_variable(env, def, body, variable, visiting)
    }

    fn from_rvalue(
        env: &Environment,
        def: DefId,
        body: &crate::ir::Body,
        rvalue: &Rvalue,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> Option<HashSet<String>> {
        match rvalue {
            Rvalue::Aggregate(elements) => elements
                .iter()
                .map(|element| match element {
                    Operand::Lit(Literal::Str(value) | Literal::JSXText(value)) => {
                        Some(value.to_string())
                    }
                    _ => None,
                })
                .collect(),
            Rvalue::Read(operand) => from_operand(env, def, body, operand, visiting),
            Rvalue::Phi(values) => {
                let mut constants = HashSet::new();
                for (var, _) in values {
                    constants.extend(from_variable(
                        env,
                        def,
                        body,
                        &Variable::new(*var),
                        visiting,
                    )?);
                }
                Some(constants)
            }
            Rvalue::Call(callee, operands)
                if unresolved_global_named(env, body, callee, "Set") && operands.len() == 1 =>
            {
                from_operand(env, def, body, &operands[0], visiting)
            }
            _ => None,
        }
    }

    fn from_variable(
        env: &Environment,
        def: DefId,
        body: &crate::ir::Body,
        variable: &Variable,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> Option<HashSet<String>> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        if !visiting.insert((def, var)) {
            return None;
        }

        let definitions = variable_definitions_with_aliases(env, body, variable);
        let result = if definitions.is_empty() {
            let binding = variable_binding(env, body, var)?;
            let mut found = false;
            let mut constants = HashSet::new();
            for candidate_body in env.bodies() {
                let Some(candidate_def) = candidate_body.owner() else {
                    continue;
                };
                if collection_is_mutated(env, candidate_body, binding) {
                    return None;
                }
                for inst in candidate_body
                    .iter_blocks_enumerated()
                    .flat_map(|(_, block)| block.iter())
                {
                    let Inst::Assign(target, rvalue) = inst else {
                        continue;
                    };
                    let Base::Var(target_var) = target.base else {
                        continue;
                    };
                    if !target.projections.is_empty()
                        || variable_binding(env, candidate_body, target_var) != Some(binding)
                    {
                        continue;
                    }
                    found = true;
                    constants.extend(from_rvalue(
                        env,
                        candidate_def,
                        candidate_body,
                        rvalue,
                        visiting,
                    )?);
                }
            }
            found.then_some(constants)
        } else {
            if variable_binding(env, body, var)
                .is_some_and(|binding| collection_is_mutated(env, body, binding))
            {
                visiting.remove(&(def, var));
                return None;
            }
            let mut constants = HashSet::new();
            for (_, rvalue) in definitions {
                constants.extend(from_rvalue(env, def, body, rvalue, visiting)?);
            }
            Some(constants)
        };
        visiting.remove(&(def, var));
        result.filter(|constants| !constants.is_empty())
    }

    from_variable(env, def, body, variable, &mut HashSet::new())
}

fn exact_allowlist_guard<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    def: DefId,
    condition: &Operand,
) -> Option<(Variable, bool)> {
    fn inspect<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        operand: &Operand,
        allowed_when_true: bool,
        visiting: &mut HashSet<VarId>,
    ) -> Option<(Variable, bool)> {
        let Operand::Var(variable) = operand else {
            return None;
        };
        let Base::Var(var) = variable.base else {
            return None;
        };
        if !visiting.insert(var) {
            return None;
        }
        let definitions = variable_definitions_with_aliases(interp.env(), interp.body(), variable);
        for (_, rvalue) in definitions {
            match rvalue {
                Rvalue::Unary(UnOp::Not, inner) => {
                    if let Some(result) = inspect(interp, def, inner, !allowed_when_true, visiting)
                    {
                        visiting.remove(&var);
                        return Some(result);
                    }
                }
                Rvalue::Call(callee, operands) if operands.len() == 1 => {
                    let Some((receiver, "has" | "includes")) = method_receiver(callee) else {
                        continue;
                    };
                    let constants =
                        constant_string_collection(interp.env(), def, interp.body(), &receiver);
                    if constants.is_none() {
                        continue;
                    }
                    let Operand::Var(candidate) = &operands[0] else {
                        continue;
                    };
                    visiting.remove(&var);
                    return Some((candidate.clone(), allowed_when_true));
                }
                Rvalue::Read(inner) => {
                    if let Some(result) = inspect(interp, def, inner, allowed_when_true, visiting) {
                        visiting.remove(&var);
                        return Some(result);
                    }
                }
                _ => {}
            }
        }
        visiting.remove(&var);
        None
    }

    inspect(interp, def, condition, true, &mut HashSet::new())
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

fn returned_object_variables(body: &crate::ir::Body) -> Vec<Variable> {
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
    allowlist_refinements: HashMap<(DefId, BasicBlockId), Vec<Variable>>,
}

impl SqlDataflow {
    fn target_aliases<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        target: &Variable,
    ) -> Vec<Variable> {
        SqlState::logical_name(interp.env(), interp.body(), target).map_or_else(
            || vec![target.clone()],
            |name| {
                interp
                    .body()
                    .vars
                    .iter_enumerated()
                    .filter_map(|(var, _)| {
                        let candidate = Variable::new(var);
                        (SqlState::logical_name(interp.env(), interp.body(), &candidate)
                            == Some(name))
                        .then_some(candidate)
                    })
                    .collect()
            },
        )
    }

    fn insert_projections<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        target: &Variable,
        projections: BTreeMap<Vec<Projection>, SqlTaint>,
        state: &mut SqlState,
    ) {
        for (suffix, value) in projections {
            for alias in Self::target_aliases(interp, target) {
                let mut projected_target = alias;
                projected_target.projections.extend(suffix.iter().cloned());
                state.insert_variable(def, &projected_target, value);
            }
        }
    }

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

    fn propagate_call_return_projections<'cx, C: Runner<'cx, State = SqlState>>(
        &self,
        interp: &Interp<'cx, C>,
        caller_def: DefId,
        callee: &Operand,
        target: &Variable,
        state: &mut SqlState,
    ) {
        let Some((callee_def, callee_body)) = interp.body().resolve_call(interp.env(), callee)
        else {
            return;
        };
        let Some(final_state) = interp.func_state(callee_def) else {
            return;
        };

        let mut projections = BTreeMap::<Vec<Projection>, SqlTaint>::new();
        for returned in returned_object_variables(callee_body) {
            let Base::Var(returned_var) = returned.base else {
                continue;
            };
            for ((owner, var, path), value) in &final_state.values {
                if *owner != callee_def
                    || *var != returned_var
                    || path.len() <= returned.projections.len()
                    || !path.starts_with(&returned.projections)
                {
                    continue;
                }
                let suffix = path[returned.projections.len()..].to_vec();
                projections
                    .entry(suffix)
                    .and_modify(|current| *current = current.join(value))
                    .or_insert(*value);
            }
        }

        Self::insert_projections(interp, caller_def, target, projections, state);
    }

    fn propagate_assignment_projections<'cx, C: Runner<'cx, State = SqlState>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        source: &Variable,
        target: &Variable,
        state: &mut SqlState,
    ) {
        let Base::Var(source_var) = source.base else {
            return;
        };
        let mut projections = BTreeMap::<Vec<Projection>, SqlTaint>::new();
        for ((owner, var, path), value) in &state.values {
            if *owner != def
                || *var != source_var
                || path.len() <= source.projections.len()
                || !path.starts_with(&source.projections)
            {
                continue;
            }
            let suffix = path[source.projections.len()..].to_vec();
            projections
                .entry(suffix)
                .and_modify(|current| *current = current.join(value))
                .or_insert(*value);
        }
        Self::insert_projections(interp, def, target, projections, state);
    }

    fn propagate_container_mutation<'cx, C: Runner<'cx, State = SqlState>>(
        &self,
        interp: &Interp<'cx, C>,
        def: DefId,
        callee: &Operand,
        operands: &[Operand],
        state: &mut SqlState,
    ) {
        let Some((receiver, "push")) = method_receiver(callee) else {
            return;
        };
        let taint = classify_variable(interp, def, &receiver, state).join(&join_operands(
            interp,
            def,
            operands.iter().cloned(),
            state,
        ));
        state.insert_assignment(interp.env(), interp.body(), def, &receiver, taint);
    }
}

impl<'cx> Dataflow<'cx> for SqlDataflow {
    type State = SqlState;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self {
            needs_call: vec![],
            allowlist_refinements: HashMap::new(),
        }
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
        state.reachable = true;
        if let Inst::Assign(target, rvalue) = inst {
            if let Rvalue::Call(callee, operands) = rvalue {
                self.propagate_call_arguments(interp, def, callee, operands, &mut state);
                self.propagate_container_mutation(interp, def, callee, operands, &mut state);
            }
            // SqlState owns SQL classification, argument propagation, and return
            // propagation. Populating the shared ValueManager as well duplicates
            // that work and makes projected object assignments dominate runtime
            // on large entrypoint graphs.
            let taint = self.classify_rvalue(interp, def, rvalue, &state);
            state.insert_assignment(interp.env(), interp.body(), def, target, taint);
            match rvalue {
                Rvalue::Call(callee, _) => {
                    self.propagate_call_return_projections(interp, def, callee, target, &mut state);
                }
                Rvalue::Read(Operand::Var(source)) => {
                    self.propagate_assignment_projections(interp, def, source, target, &mut state);
                }
                _ => {}
            }
        } else if let Inst::Expr(Rvalue::Call(callee, operands)) = inst {
            self.propagate_call_arguments(interp, def, callee, operands, &mut state);
            self.propagate_container_mutation(interp, def, callee, operands, &mut state);
        }
        state
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
    ) -> Self::State {
        let mut state = initial_state;
        if let Some(candidates) = self.allowlist_refinements.get(&(def, bb)).cloned() {
            for candidate in candidates {
                state.mark_allowlisted(interp.env(), interp.body(), def, &candidate);
            }
        }
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
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
        if let Terminator::If { cond, cons, alt } = &block.term
            && let Some((candidate, allowed_when_true)) = exact_allowlist_guard(interp, def, cond)
        {
            let allowed_successor = if allowed_when_true { *cons } else { *alt };
            let rejected_successor = if allowed_when_true { *alt } else { *cons };
            if allowed_successor != rejected_successor
                && interp.body().predecessors(allowed_successor).len() == 1
            {
                let candidates = self
                    .allowlist_refinements
                    .entry((def, allowed_successor))
                    .or_default();
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                    // SWC numbers a conditional expression's join block before
                    // its alternatives. Analyze both alternatives first so a
                    // sink in the join block does not observe a partial phi.
                    worklist
                        .worklist
                        .retain(|work| *work != (def, *cons) && *work != (def, *alt));
                    worklist.worklist.push_front((def, *alt));
                    worklist.worklist.push_front((def, *cons));
                }
            }
        }
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
            SqlTaint::Trusted | SqlTaint::Numeric => {
                unreachable!("SQL-safe values do not produce a finding")
            }
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
        if !matches!(query_taint, SqlTaint::Trusted | SqlTaint::Numeric) {
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
