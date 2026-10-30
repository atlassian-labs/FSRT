//! SQL injection, as a policy on the shared taint tracker in `crate::taint`.
//!
//! A value is either attacker controlled (`Taint::Yes`) or not. Sources are the
//! module payload and request envelope of a Forge invocation, storage and API
//! reads, network responses, and the rows `@forge/sql` returns; a sink is the
//! query text of `sql.prepare`, `sql.executeRaw` or `migrationRunner.enqueue`.
//! Numeric conversion, a placeholder list and an exact allowlist check keep a
//! value's provenance but make its text safe.
//!
//! A value the analysis cannot classify is `UNKNOWN`, which is trusted for now:
//! it never produces a finding. `UNKNOWN_IS_UNTRUSTED` is the one switch to
//! change that. Findings no longer say which source reached the query.
//!
//! The tracker copies values rather than sharing them, so a write through an
//! alias of an object does not reach the object it aliases.

use crate::{
    definitions::{DefId, Environment, ImportKind},
    interp::{
        Checker, EntryKind, EntryPoint, Frame, Interp, InvocationContract, JoinSemiLattice, Runner,
        WithCallStack,
    },
    ir::{
        Base, BasicBlockId, BinOp, Body, CallPathPart, Inst, Intrinsic, Literal, Location, Operand,
        Projection, Rvalue, Terminator, UnOp, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{
        BlockSite, EntryInput, FlowValue, InstSite, Taint, TaintDataflow, TaintPolicy, TaintReader,
        TrackedValue, UnresolvedCall, visit_taint_call,
    },
};
use smallvec::SmallVec;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,
    ops::ControlFlow,
    path::PathBuf,
    sync::Arc,
};
use swc_core::common::SourceMap;

mod semantics;
use semantics::*;

/// Whether a value that is neither shown trusted nor known to be attacker
/// controlled counts as attacker controlled. Off, such a value never produces a
/// finding; on, it is reported as if it were untrusted. This is the only place
/// the choice is made: every source of an unknown value goes through `UNKNOWN`.
pub const UNKNOWN_IS_UNTRUSTED: bool = false;

/// The facts of a value the analysis cannot classify.
const UNKNOWN: Taint = if UNKNOWN_IS_UNTRUSTED {
    Taint::Yes
} else {
    Taint::No
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SqlSink {
    Prepare,
    ExecuteRaw,
    MigrationEnqueue,
}

impl SqlSink {
    pub fn api_name(self) -> &'static str {
        match self {
            Self::Prepare => "sql.prepare",
            Self::ExecuteRaw => "sql.executeRaw",
            Self::MigrationEnqueue => "migrationRunner.enqueue",
        }
    }

    /// The position of the query text among the sink's arguments.
    fn query_index(self) -> usize {
        match self {
            Self::Prepare | Self::ExecuteRaw => 0,
            Self::MigrationEnqueue => 1,
        }
    }
}

fn sql_sink(env: &Environment, body: &Body, location: Location) -> Option<SqlSink> {
    let facts = body.call_facts(location)?;
    // Match the actual terminal method, never an earlier known path component.
    let CallPathPart::Property(method) = facts.path.last()? else {
        return None;
    };
    if !matches!(method.as_ref(), "prepare" | "executeRaw" | "enqueue") {
        return None;
    }
    let (module, kind) = env.call_import(body, location)?;
    if module != "@forge/sql" {
        return None;
    }
    match method.as_ref() {
        "prepare" => Some(SqlSink::Prepare),
        "executeRaw" => Some(SqlSink::ExecuteRaw),
        "enqueue" if matches!(kind, ImportKind::Named(name) if name == "migrationRunner") => {
            Some(SqlSink::MigrationEnqueue)
        }
        _ => None,
    }
}

/// Taint on main's tracker, with a value's facts meaning "may put SQL syntax of
/// an attacker's choosing into query text". Provenance records only that a value
/// derives from a source: numeric conversion, a placeholder list and an
/// allowlist check clear the facts and keep the provenance.
#[derive(Default)]
pub struct SqlPolicy {
    /// The allowlisted variables each block is entered with, by body and block.
    guards: RefCell<HashMap<(DefId, BasicBlockId), Vec<Variable>>>,
    /// Whether a `join` call builds a list of `?` placeholders, by call site.
    placeholder_lists: RefCell<HashMap<(DefId, Location), bool>>,
}

impl SqlPolicy {
    fn is_placeholder_list(&self, call: &UnresolvedCall<'_, Taint>) -> bool {
        let site = call.site();
        *self
            .placeholder_lists
            .borrow_mut()
            .entry(site)
            .or_insert_with(|| {
                is_placeholder_list_call(
                    call.env(),
                    call.body(),
                    site.0,
                    call.callee(),
                    call.operands(),
                )
            })
    }
}

/// The root of a Forge `context` object. Only these paths are known trusted;
/// everything else in it is unclassified.
fn approved_context_paths(ordinary: bool) -> Vec<Vec<&'static str>> {
    let mut paths = vec![
        vec!["installContext"],
        vec!["installation", "ari", "installationId"],
    ];
    for name in [
        "active",
        "billingPeriod",
        "ccpEntitlementId",
        "ccpEntitlementSlug",
        "isEvaluation",
        "subscriptionEndDate",
        "supportEntitlementNumber",
        "trialEndDate",
        "type",
    ] {
        paths.push(vec!["license", name]);
    }
    if ordinary {
        paths.extend([
            vec!["principal", "accountId"],
            vec!["license", "isActive"],
            vec!["license", "capabilitySet"],
        ]);
    } else {
        paths.push(vec!["accountId"]);
    }
    paths
}

/// A context object, or the same object at `prefix` of a larger one.
fn context_value(
    mut value: TrackedValue<Taint>,
    prefix: &[&str],
    ordinary: bool,
) -> TrackedValue<Taint> {
    let unknown = || FlowValue::from_taint(UNKNOWN);
    if !prefix.is_empty() {
        value = value.with_field(prefix, unknown());
    }
    for path in approved_context_paths(ordinary) {
        let path: Vec<&str> = prefix.iter().copied().chain(path).collect();
        value = value.with_field(&path, FlowValue::default());
    }
    value
}

impl TaintPolicy for SqlPolicy {
    type Facts = Taint;

    fn intrinsic_value(&self, intrinsic: &Intrinsic) -> FlowValue<Taint> {
        FlowValue::from_taint(match intrinsic {
            Intrinsic::Authorize(_) | Intrinsic::SecretFunction(_) | Intrinsic::EnvRead => {
                Taint::No
            }
            Intrinsic::Fetch
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::StorageRead
            | Intrinsic::SecretRead => Taint::Yes,
            _ => UNKNOWN,
        })
    }

    fn is_violation(&self, _inst: &Inst, _values: &TaintReader<'_, Self>) -> bool {
        false
    }

    fn is_violation_at(
        &self,
        site: &InstSite<'_>,
        inst: &Inst,
        values: &TaintReader<'_, Self>,
    ) -> bool {
        let Rvalue::Call(_, operands) = inst.rvalue() else {
            return false;
        };
        let Some(sink) = sql_sink(site.env, site.body, site.location) else {
            return false;
        };
        // A sink without its query argument has a query nothing is known of.
        operands
            .get(sink.query_index())
            .map_or(UNKNOWN == Taint::Yes, |query| {
                values.operand(query).facts == Taint::Yes
            })
    }

    fn tracks_fields(&self) -> bool {
        true
    }

    fn binary_value(
        &self,
        op: BinOp,
        left: FlowValue<Taint>,
        right: FlowValue<Taint>,
    ) -> FlowValue<Taint> {
        match op {
            BinOp::Or | BinOp::And | BinOp::NullishCoalesce => left.join(&right),
            // Arithmetic yields a number, whose text cannot contain SQL syntax.
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
            | BinOp::RshiftLogical => left.combine(&right).with_facts(Taint::No),
            _ if crate::taint::binary_taint(op, Taint::Yes, Taint::Yes) == Taint::No => {
                left.combine(&right).with_facts(Taint::No)
            }
            _ => left.combine(&right),
        }
    }

    fn unary_value(&self, _op: UnOp, value: FlowValue<Taint>) -> FlowValue<Taint> {
        // `!x` is a boolean and `-x`, `+x` and `~x` are numbers.
        value.with_facts(Taint::No)
    }

    fn global_call_value(&self, name: &str, path: &[Projection]) -> Option<FlowValue<Taint>> {
        let numeric = match path {
            // `Array(n)` is an array of empty slots, not text.
            [] => matches!(name, "Number" | "parseInt" | "parseFloat" | "Array"),
            [Projection::Known(method)] if name == "Math" => matches!(
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
        };
        numeric.then(FlowValue::default)
    }

    fn method_value(&self, call: &UnresolvedCall<'_, Taint>) -> Option<FlowValue<Taint>> {
        let (env, body) = (call.env(), call.body());
        match sql_sink(env, body, call.site().1) {
            // A statement is built and not yet run, so its text is checked
            // where it is prepared; a migration's text where it is enqueued.
            Some(SqlSink::Prepare | SqlSink::MigrationEnqueue) => {
                return Some(FlowValue::default());
            }
            Some(SqlSink::ExecuteRaw) => return Some(FlowValue::from_taint(Taint::Yes)),
            None => {}
        }
        // The rows of a prepared statement come from the database.
        if call.method == "execute"
            && method_receiver(call.callee()).is_some_and(|(receiver, _)| {
                originates_from_prepare(env, body, &receiver, &mut HashSet::new())
            })
        {
            return Some(FlowValue::from_taint(Taint::Yes));
        }
        if call.method == "join" && self.is_placeholder_list(call) {
            return Some(FlowValue::default());
        }
        if UNKNOWN_IS_UNTRUSTED && is_unmodelled_call(env, body, call.callee()) {
            let inputs = call
                .args
                .iter()
                .fold(call.receiver.clone(), |value, arg| value.combine(arg));
            return Some(inputs.with_facts(Taint::Yes));
        }
        None
    }

    fn adds_arguments_to_receiver(&self, method: &str) -> bool {
        method == "push"
    }

    fn entry_argument(&self, input: &EntryInput<'_>) -> Option<TrackedValue<Taint>> {
        let unknown = || TrackedValue::from(FlowValue::from_taint(UNKNOWN));
        let value = match (input.contract, input.position) {
            // The module's payload is attacker data in full.
            (InvocationContract::ForgeFunction, 0) => {
                TrackedValue::from(FlowValue::from_taint(Taint::Yes))
            }
            (InvocationContract::ForgeFunction, 1) => context_value(unknown(), &[], true),
            // An envelope: its payload is attacker data, its context is the
            // platform's, and anything else on it is unclassified.
            (InvocationContract::ResolverCallback, 0) => context_value(
                unknown().with_field(&["payload"], FlowValue::from_taint(Taint::Yes)),
                &["context"],
                false,
            ),
            _ => unknown(),
        };
        Some(if input.supported {
            value
        } else if value.aggregate().facts == Taint::Yes {
            // A pattern or default the IR does not model may bind anything.
            TrackedValue::from(FlowValue::from_taint(Taint::Yes))
        } else {
            unknown()
        })
    }

    fn safe_on_entry(&self, site: &BlockSite<'_>, block: BasicBlockId) -> Vec<Variable> {
        let key = (site.def, block);
        if let Some(found) = self.guards.borrow().get(&key) {
            return found.clone();
        }
        let found = allowlisted_on_entry(site.env, site.body, site.def, block);
        self.guards.borrow_mut().insert(key, found.clone());
        found
    }
}

/// The variable a block is entered with only after an exact allowlist check.
fn allowlisted_on_entry(
    env: &Environment,
    body: &Body,
    def: DefId,
    block: BasicBlockId,
) -> Vec<Variable> {
    let &[predecessor] = body.predecessors(block) else {
        return Vec::new();
    };
    let Terminator::If { cond, cons, alt } = &body.block(predecessor).term else {
        return Vec::new();
    };
    if cons == alt {
        return Vec::new();
    }
    match exact_allowlist_guard(env, body, def, cond) {
        Some((candidate, allowed_when_true))
            if block == if allowed_when_true { *cons } else { *alt } =>
        {
            vec![candidate]
        }
        _ => Vec::new(),
    }
}

/// Whether the call's result has no model: a bare call, or a method of an
/// undeclared global such as `JSON`.
fn is_unmodelled_call(env: &Environment, body: &Body, callee: &Operand) -> bool {
    let Operand::Var(variable) = callee else {
        return true;
    };
    variable.projections.is_empty()
        || matches!(variable.base, Base::Var(var)
            if matches!(body.vars.get(var), Some(VarKind::GlobalRef(binding))
                if env.is_undeclared_global(*binding)))
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

fn is_fresh_array_variable(
    env: &Environment,
    body: &Body,
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
    if placeholder_collection_is_modified_or_escapes(body, variable, "fill") {
        visiting.remove(&(def, var));
        return false;
    }
    let definitions = variable_definitions_with_aliases(body, variable);
    let result = !definitions.is_empty()
        && definitions.into_iter().all(|(_, rvalue)| match rvalue {
            Rvalue::Array(_) => true,
            Rvalue::Read(Operand::Var(source)) => {
                is_fresh_array_variable(env, body, def, source, visiting)
            }
            Rvalue::Phi(values) => values.iter().all(|(source, _)| {
                is_fresh_array_variable(env, body, def, &Variable::new(*source), visiting)
            }),
            Rvalue::Call(callee, _) => unresolved_global_named(env, body, callee, "Array"),
            _ => false,
        });
    visiting.remove(&(def, var));
    result
}

fn placeholder_collection_is_modified_or_escapes(
    body: &Body,
    variable: &Variable,
    allowed_method: &str,
) -> bool {
    let Base::Var(root) = variable.base else {
        return true;
    };
    let aliases = body.binding_variables(variable).map_or_else(
        || HashSet::from([root]),
        |aliases| aliases.iter().copied().collect(),
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

fn is_placeholder_sequence_variable(
    env: &Environment,
    body: &Body,
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
    if placeholder_collection_is_modified_or_escapes(body, variable, "join") {
        visiting.remove(&(def, var));
        return false;
    }
    let definitions = variable_definitions_with_aliases(body, variable);
    let result = !definitions.is_empty()
        && definitions.into_iter().all(|(_, rvalue)| match rvalue {
            Rvalue::Array(elements) => {
                !elements.is_empty() && elements.iter().all(is_placeholder_fragment)
            }
            Rvalue::Read(Operand::Var(source)) => {
                is_placeholder_sequence_variable(env, body, def, source, visiting)
            }
            Rvalue::Phi(values) => values.iter().all(|(source, _)| {
                is_placeholder_sequence_variable(env, body, def, &Variable::new(*source), visiting)
            }),
            Rvalue::Call(callee, operands) => {
                let Some((receiver, "fill")) = method_receiver(callee) else {
                    return false;
                };
                operands.len() == 1
                    && is_placeholder_fragment(&operands[0])
                    && is_fresh_array_variable(env, body, def, &receiver, &mut HashSet::new())
            }
            _ => false,
        });
    visiting.remove(&(def, var));
    result
}

fn is_placeholder_list_call(
    env: &Environment,
    body: &Body,
    def: DefId,
    callee: &Operand,
    operands: &[Operand],
) -> bool {
    let Some((receiver, "join")) = method_receiver(callee) else {
        return false;
    };
    operands.len() <= 1
        && operands.first().is_none_or(is_placeholder_separator)
        && is_placeholder_sequence_variable(env, body, def, &receiver, &mut HashSet::new())
}

fn constant_string_collection(
    env: &Environment,
    def: DefId,
    body: &Body,
    variable: &Variable,
) -> Option<HashSet<String>> {
    fn variable_binding(env: &Environment, body: &Body, var: VarId) -> Option<DefId> {
        match body.vars.get(var)? {
            VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) => {
                Some(env.resolve_alias(*binding))
            }
            _ => None,
        }
    }

    fn collection_is_mutated(env: &Environment, body: &Body, binding: DefId) -> bool {
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
        body: &Body,
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
        body: &Body,
        rvalue: &Rvalue,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> Option<HashSet<String>> {
        match rvalue {
            Rvalue::Array(elements) => elements
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
        body: &Body,
        variable: &Variable,
        visiting: &mut HashSet<(DefId, VarId)>,
    ) -> Option<HashSet<String>> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        if !visiting.insert((def, var)) {
            return None;
        }

        let definitions = variable_definitions_with_aliases(body, variable);
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

fn exact_allowlist_guard(
    env: &Environment,
    body: &Body,
    def: DefId,
    condition: &Operand,
) -> Option<(Variable, bool)> {
    fn inspect(
        env: &Environment,
        body: &Body,
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
        let definitions = variable_definitions_with_aliases(body, variable);
        for (_, rvalue) in definitions {
            match rvalue {
                Rvalue::Unary(UnOp::Not, inner) => {
                    if let Some(result) =
                        inspect(env, body, def, inner, !allowed_when_true, visiting)
                    {
                        visiting.remove(&var);
                        return Some(result);
                    }
                }
                Rvalue::Call(callee, operands) if operands.len() == 1 => {
                    let Some((receiver, "has" | "includes")) = method_receiver(callee) else {
                        continue;
                    };
                    let constants = constant_string_collection(env, def, body, &receiver);
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
                    if let Some(result) =
                        inspect(env, body, def, inner, allowed_when_true, visiting)
                    {
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

    inspect(env, body, def, condition, true, &mut HashSet::new())
}

fn originates_from_prepare(
    env: &Environment,
    body: &Body,
    variable: &Variable,
    visiting: &mut HashSet<Variable>,
) -> bool {
    if !visiting.insert(variable.clone()) {
        return false;
    }
    variable_definitions(body, variable)
        .into_iter()
        .any(|(location, rvalue)| match rvalue {
            Rvalue::Call(_, _) if sql_sink(env, body, location) == Some(SqlSink::Prepare) => true,
            Rvalue::Read(Operand::Var(source)) => {
                originates_from_prepare(env, body, source, visiting)
            }
            Rvalue::Call(callee, _) => method_receiver(callee).is_some_and(|(receiver, _)| {
                originates_from_prepare(env, body, &receiver, visiting)
            }),
            _ => false,
        })
}

fn variable_name(env: &Environment, body: &Body, variable: &Variable) -> String {
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
                let mut alternatives = variable_definitions_with_aliases(body, variable)
                    .into_iter()
                    .map(|(_, rvalue)| match rvalue {
                        Rvalue::Read(source) => render(env, def, source, visiting),
                        Rvalue::Array(elements) => format!(
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

fn source_location(
    source_map: &SourceMap,
    body: &Body,
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

#[derive(Debug)]
pub struct SqlInjectionVuln {
    sink: SqlSink,
    paths: Vec<String>,
    sink_location: String,
    sink_function: String,
    query: String,
}

impl SqlInjectionVuln {
    fn new(
        sink: SqlSink,
        callstack: Vec<Frame>,
        env: &Environment,
        entry: &EntryPoint,
        def: DefId,
        sink_location: String,
        query: &Operand,
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
            paths: vec![path],
            sink_location,
            sink_function: env.def_name(def).to_owned(),
            query: render_query_operand(env, def, query),
        }
    }

    fn merge(&mut self, mut other: Self) {
        for path in other.paths.drain(..) {
            if self.paths.len() == 8 {
                break;
            }
            if !self.paths.contains(&path) {
                self.paths.push(path);
            }
        }
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
        Vulnerability {
            check_name: "forge-sql-injection".to_string(),
            description: format!(
                "Confirmed untrusted data is incorporated into SQL query text passed to {sink_name} at {location}."
            ),
            recommendation: "Use placeholders and bindParams for values. For identifiers or SQL structure that cannot be bound, select only from IR-provable trusted constant alternatives.",
            proof: format!(
                "Propagation path: {}. Query argument at {location}: `{}`. Binding: the value is part of SQL text, so bindParams does not repair interpolation already present in the query. Limitation: FSRT models locally resolvable calls and supported IR operations; review the reported source and path in application context.",
                self.paths.join("; "),
                self.query
            ),
            severity: Severity::High,
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
    /// Whether any lowered call can be a SQL sink under the reporting rules.
    ///
    /// Check every body, including helpers and closures: a sink need not occur
    /// directly in an entrypoint. This uses the same import-provenance requirements
    /// as reporting and performs no taint analysis.
    pub fn has_candidate_sinks(env: &Environment) -> bool {
        env.bodies().any(|body| {
            body.iter_blocks_enumerated().any(|(block, data)| {
                data.insts.iter().enumerate().any(|(index, _)| {
                    sql_sink(env, body, Location::new(block, index as u32)).is_some()
                })
            })
        })
    }

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
    type State = Vec<Taint>;
    type Dataflow = TaintDataflow<SqlPolicy>;

    const NAME: &'static str = "SQLInjection";

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        _loc: Location,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }

    fn visit_call(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        callee: &'cx Operand,
        arguments: &'cx [Operand],
        loc: Location,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        let Some(sink) = sql_sink(interp.env(), interp.body(), loc) else {
            return visit_taint_call(self, interp, def, callee, loc, state);
        };
        if interp.instruction_has_finding(def, loc) {
            let query = arguments
                .get(sink.query_index())
                .cloned()
                .unwrap_or(Operand::UNDEF);
            let vuln = SqlInjectionVuln::new(
                sink,
                interp.callstack(),
                interp.env(),
                interp.entry(),
                def,
                source_location(&self.source_map, interp.body(), loc, &interp.entry().file),
                &query,
                &self.source_map,
            );
            let key = (def, loc, sink);
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
