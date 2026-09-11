use crate::{
    definitions::{DefId, Environment},
    interp::{
        Checker, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, Runner, WithCallStack,
    },
    ir::{
        Base, BinOp, CallPathPart, Inst, Intrinsic, Literal, Location, Operand, Projection, Rvalue,
        UnOp, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
};
use smallvec::SmallVec;
use std::{
    cmp::max,
    collections::{HashMap, HashSet},
    fmt,
    ops::ControlFlow,
    path::PathBuf,
    sync::Arc,
};
use swc_core::common::SourceMap;

use crate::definitions::ImportKind;
use crate::taint::{
    self, Classification, FlowPolicy, FlowState, OriginSite, PolicyFacts, TaintDataflow,
    semantics::*,
    sources::{FORGE_SOURCES, SourceContext, SourceDefinition},
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SqlTextSafety {
    #[default]
    Trusted,
    /// The value may still be attacker-controlled, but JavaScript semantics
    /// guarantee that its string representation cannot contain SQL syntax.
    Numeric,
    Unknown,
    Untrusted,
}

impl JoinSemiLattice for SqlTextSafety {
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

pub type SqlState = FlowState<SqlTextSafety>;
pub type SqlDataflow = TaintDataflow<SqlPolicy>;
pub struct SqlPolicy;

impl PolicyFacts for SqlTextSafety {
    fn from_classification(classification: Classification) -> Self {
        match classification {
            Classification::Trusted => Self::Trusted,
            Classification::Unknown => Self::Unknown,
            Classification::Untrusted => Self::Untrusted,
        }
    }
    fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}

fn sql_sink(env: &Environment, body: &crate::ir::Body, location: Location) -> Option<SqlSink> {
    let facts = body.call_facts(location)?;
    let method = facts.path.iter().rev().find_map(|part| match part {
        CallPathPart::Property(name) => Some(name.as_ref()),
        _ => None,
    })?;
    let sink = match method {
        "prepare" => SqlSink::Prepare,
        "executeRaw" => SqlSink::ExecuteRaw,
        "enqueue" => {
            let imported_runner = matches!(&facts.import, Some((module, ImportKind::Named(name))) if module == "@forge/sql" && name == "migrationRunner");
            let named_runner = facts.path.iter().any(
                |part| matches!(part, CallPathPart::Property(name) if name == "migrationRunner"),
            ) || facts
                .root
                .is_some_and(|root| env.def_name(root).contains("migrationRunner"));
            if !imported_runner && !named_runner {
                return None;
            }
            SqlSink::MigrationEnqueue
        }
        _ => return None,
    };
    // Only candidate methods pay for the bounded provenance walk.
    if facts
        .import
        .as_ref()
        .is_some_and(|(module, _)| module != "@forge/sql")
    {
        return None;
    }
    (!call_has_local_receiver(env, facts)).then_some(sink)
}

static SQL_SOURCES: &[SourceDefinition] = &[SourceDefinition {
    id: "forge.sql.result",
    label: "Forge SQL result",
    classification: Classification::Untrusted,
    matches: |ctx: &SourceContext<'_>| {
        if ctx.call.is_none() {
            return false;
        }
        if sql_sink(ctx.env, ctx.body, ctx.location) == Some(SqlSink::ExecuteRaw) {
            return true;
        }
        ctx.call
            .and_then(|(callee, _)| method_receiver(callee))
            .is_some_and(|(receiver, method)| {
                method == "execute"
                    && originates_from_prepare(ctx.env, ctx.body, &receiver, &mut HashSet::new())
            })
    },
}];

impl FlowPolicy for SqlPolicy {
    type Facts = SqlTextSafety;
    fn sources() -> &'static [SourceDefinition] {
        SQL_SOURCES
    }
    fn variable_facts<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        variable: &Variable,
        state: &SqlState,
    ) -> Option<SqlTextSafety> {
        if state.is_refined(interp.env(), interp.body(), def, variable) {
            Some(SqlTextSafety::Trusted)
        } else if is_proven_local_array_length(interp, def, variable) {
            Some(SqlTextSafety::Numeric)
        } else {
            None
        }
    }
    fn rvalue_facts<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        location: Location,
        rvalue: &Rvalue,
    ) -> Option<SqlTextSafety> {
        match rvalue {
            Rvalue::Unary(UnOp::Neg | UnOp::Plus | UnOp::BitNot, _)
            | Rvalue::Bin(
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
                | BinOp::RshiftLogical,
                _,
                _,
            ) => Some(SqlTextSafety::Numeric),
            Rvalue::Intrinsic(
                Intrinsic::Authorize(_) | Intrinsic::SecretFunction(_) | Intrinsic::EnvRead,
                _,
            ) => Some(SqlTextSafety::Trusted),
            Rvalue::Call(callee, operands) => {
                if matches!(
                    sql_sink(interp.env(), interp.body(), location),
                    Some(SqlSink::Prepare | SqlSink::MigrationEnqueue)
                ) || is_placeholder_list_call(interp, def, callee, operands)
                {
                    Some(SqlTextSafety::Trusted)
                } else if interp.body().resolve_call(interp.env(), callee).is_none()
                    && is_numeric_builtin_call(interp, callee)
                {
                    Some(SqlTextSafety::Numeric)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    fn branch_refinement<'cx, C: Runner<'cx, State = SqlState>>(
        interp: &Interp<'cx, C>,
        def: DefId,
        condition: &Operand,
    ) -> Option<(Variable, bool)> {
        exact_allowlist_guard(interp, def, condition)
    }
}

fn source_labels<'cx, C: Runner<'cx, State = SqlState>>(
    interp: &Interp<'cx, C>,
    value: &taint::TaintValue,
    source_map: &SourceMap,
) -> Vec<String> {
    let mut labels = value
        .origins
        .iter()
        .filter_map(|origin| {
            let rule = SQL_SOURCES
                .iter()
                .chain(FORGE_SOURCES)
                .find(|rule| rule.id == origin.source)?;
            let body = interp.env().def_ref(origin.function).expect_body();
            Some(match origin.site {
                OriginSite::Argument(arg) => format!(
                    "{} `{}` at {}",
                    rule.label,
                    interp.env().def_name(arg),
                    argument_source_location(source_map, body, arg, &interp.entry().file)
                ),
                OriginSite::Instruction(location) => format!(
                    "{} at {}",
                    rule.label,
                    source_location(source_map, body, location, &interp.entry().file)
                ),
            })
        })
        .collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    labels
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
            Rvalue::Array(_) => true,
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
    let aliases = body.logical_aliases(env, variable).map_or_else(
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
            Rvalue::Array(elements) => {
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

fn originates_from_prepare(
    env: &Environment,
    body: &crate::ir::Body,
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

#[derive(Debug)]
pub struct SqlInjectionVuln {
    sink: SqlSink,
    taint: SqlTextSafety,
    paths: Vec<String>,
    sink_location: String,
    sink_function: String,
    query: String,
    sources: Vec<String>,
}

impl SqlInjectionVuln {
    fn new(
        sink: SqlSink,
        taint: SqlTextSafety,
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
            SqlTextSafety::Untrusted => (
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
            SqlTextSafety::Unknown => (
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
            SqlTextSafety::Trusted | SqlTextSafety::Numeric => {
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
    /// Whether any lowered call can be a SQL sink under the reporting rules.
    ///
    /// Check every body, including helpers and closures: a sink need not occur
    /// directly in an entrypoint. This does not require resolved import provenance
    /// and performs no taint analysis.
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
    type State = SqlState;
    type Dataflow = SqlDataflow;

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
            return self.super_visit_call(interp, def, callee, arguments, loc, state);
        };
        let operands = arguments;
        let query_index = match sink {
            SqlSink::Prepare | SqlSink::ExecuteRaw => 0,
            SqlSink::MigrationEnqueue => 1,
        };
        let final_state = interp
            .func_state(def)
            .map_or_else(|| state.clone(), |analysis| analysis.join(state));
        let query_taint = operands
            .get(query_index)
            .map(|operand| {
                taint::classify_operand::<SqlPolicy, Self>(interp, def, operand, &final_state)
            })
            .unwrap_or_else(taint::FlowValue::unknown);
        let query_value = query_taint;
        let query_taint = query_value.facts;
        if !matches!(query_taint, SqlTextSafety::Trusted | SqlTextSafety::Numeric) {
            let query = operands.get(query_index).cloned().unwrap_or(Operand::UNDEF);
            let sources = source_labels(interp, &query_value.taint, &self.source_map);
            let vuln = SqlInjectionVuln::new(
                sink,
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
