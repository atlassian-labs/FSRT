//! SQL injection, as a policy on the shared taint tracker in `crate::taint`.
//!
//! A value is either attacker controlled (`Taint::Yes`) or not. Sources are the
//! module payload and request envelope of a Forge invocation, storage and API
//! reads, network responses, and the rows `@forge/sql` returns; a sink is the
//! query text of `sql.prepare`, `sql.executeRaw` or `migrationRunner.enqueue`.
//! Numeric conversion keeps a value's provenance but makes its text safe.
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
        Base, BinOp, Body, CallPathPart, Inst, Intrinsic, Location, Operand, Projection, Rvalue,
        UnOp, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{
        EntryInput, FlowValue, InstSite, Taint, TaintDataflow, TaintPolicy, TaintReader,
        TrackedValue, UnresolvedCall, visit_taint_call,
    },
};
use smallvec::SmallVec;
use std::{
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
/// derives from a source: numeric conversion clears the facts and keep the
/// provenance.
#[derive(Default)]
pub struct SqlPolicy {}

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
        if UNKNOWN_IS_UNTRUSTED && is_unmodelled_call(env, body, call.callee()) {
            let inputs = call
                .args
                .iter()
                .fold(call.receiver.clone(), |value, arg| value.combine(arg));
            return Some(inputs.with_facts(Taint::Yes));
        }
        None
    }

    fn entry_argument(&self, input: &EntryInput<'_>) -> Option<TrackedValue<Taint>> {
        // What the platform passes first, a function's payload or a resolver's
        // request, is attacker data. Nothing else about the invocation is classified.
        let value = match (input.contract, input.position) {
            (InvocationContract::ForgeFunction | InvocationContract::ResolverCallback, 0) => {
                FlowValue::from_taint(Taint::Yes)
            }
            _ => FlowValue::from_taint(UNKNOWN),
        };
        Some(TrackedValue::from(value))
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
                if let Some(elements) = array_literal_elements(env, body, variable) {
                    let rendered = format!(
                        "[{}]",
                        elements
                            .iter()
                            .map(|element| render(env, def, element, visiting))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    visiting.remove(&(def, var));
                    return rendered;
                }
                let mut alternatives = variable_definitions_with_aliases(body, variable)
                    .into_iter()
                    .map(|(_, rvalue)| match rvalue {
                        Rvalue::Read(source) => render(env, def, source, visiting),
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
                env.def_name(frame.caller)
            };
            let body = env.def_ref(frame.caller).expect_body();
            let location = source_location(source_map, body, frame.call_site, &entry.file);
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
