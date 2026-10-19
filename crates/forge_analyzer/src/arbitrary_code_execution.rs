//! IR-based execution checks. `sink` recognizes execution targets from IR
//! bindings, so a call and a `new` expression are classified the same way.
//! `ExecutionTaint` supplies sources and the reporting predicate to the shared
//! fixed-point engine: Forge entrypoint arguments and IO results are sources,
//! and text assembled only from constants is not.

use std::{
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    ops::ControlFlow,
    path::PathBuf,
};

use smallvec::SmallVec;

use crate::{
    definitions::{DefId, Environment, ImportKind},
    interp::{Checker, Interp, Runner, WithCallStack},
    ir::{
        BasicBlockId, Body, Inst, Intrinsic, Literal, Location, Operand, Projection, Rvalue, VarId,
        VarKind,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{FlowValue, Taint, TaintDataflow, TaintPolicy, TaintReader, visit_taint_call},
};

fn child_process_api(name: &str) -> Option<&'static str> {
    [
        "exec",
        "execFile",
        "execSync",
        "execFileSync",
        "fork",
        "spawn",
        "spawnSync",
    ]
    .into_iter()
    .find(|api| *api == name)
}

/// `node:vm` entry points that compile their first argument.
fn vm_api(name: &str) -> Option<&'static str> {
    [
        "compileFunction",
        "runInContext",
        "runInNewContext",
        "runInThisContext",
        "Script",
        "SourceTextModule",
    ]
    .into_iter()
    .find(|api| *api == name)
}

/// The `Function` family, whose every argument is compiled.
fn function_constructor(name: &str) -> Option<&'static str> {
    [
        "Function",
        "AsyncFunction",
        "GeneratorFunction",
        "AsyncGeneratorFunction",
    ]
    .into_iter()
    .find(|api| *api == name)
}

/// Global bindings that compile their arguments, whether called or constructed.
fn code_constructor(name: &str) -> Option<&'static str> {
    match name {
        "eval" => Some("eval"),
        _ => function_constructor(name),
    }
}

/// The module namespace bound by `require(module)`.
fn required_module(module: &str) -> Option<Binding> {
    match module {
        "child_process" | "node:child_process" => Some(Binding::ChildProcess),
        "vm" | "node:vm" => Some(Binding::Vm),
        _ => None,
    }
}

/// How many leading arguments of `name` are executed as code or as a command.
fn executable_arguments(name: &str) -> usize {
    // Every parameter name is compiled alongside the body.
    if function_constructor(name).is_some() {
        return usize::MAX;
    }
    match name {
        // The command or the source text; options and callbacks follow it.
        "eval" | "exec" | "execSync" | "compileFunction" | "runInContext" | "runInNewContext"
        | "runInThisContext" | "Script" | "SourceTextModule" => 1,
        // The command and its argument vector.
        _ => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Binding {
    Global(String),
    ChildProcess,
    Vm,
    /// `Object.getPrototypeOf` or `Reflect.getPrototypeOf`.
    GetPrototypeOf,
    /// A prototype object returned by `getPrototypeOf`, whose `constructor`
    /// property is the `Function` variant that built the inspected function.
    Prototype,
    Sink(&'static str),
}

/// Follow IR reads, including module captures and CommonJS destructuring. Only
/// single-assignment aliases are accepted; a reassigned binding is ambiguous.
fn binding(
    env: &Environment,
    body: &Body,
    op: &Operand,
    seen: &mut HashSet<(DefId, VarId)>,
) -> Option<Binding> {
    let Operand::Var(var) = op else { return None };
    let id = var.as_var_id()?;
    let key = (body.owner()?, id);
    if !seen.insert(key) {
        return None;
    }
    let def = match body.vars[id] {
        VarKind::GlobalRef(def) | VarKind::LocalDef(def) | VarKind::Arg(def) => Some(def),
        _ => None,
    };
    let mut result = def.and_then(|def| {
        if env.is_undeclared_global(def) {
            return Some(Binding::Global(env.def_name(def).to_owned()));
        }
        for (modules, namespace, api) in [
            (
                ["child_process", "node:child_process"],
                Binding::ChildProcess,
                child_process_api as fn(&str) -> Option<&'static str>,
            ),
            (["vm", "node:vm"], Binding::Vm, vm_api),
        ] {
            for module in modules {
                if let Some(import) = env.is_imported_from(def, module) {
                    return match import {
                        ImportKind::Star | ImportKind::Default => Some(namespace),
                        ImportKind::Named(name) => api(name).map(Binding::Sink),
                    };
                }
            }
        }
        None
    });
    if result.is_none() {
        let mut writes = body
            .blocks
            .iter()
            .flat_map(|block| block.iter())
            .filter_map(|inst| match inst {
                Inst::Assign(target, value)
                    if target.as_var_id() == Some(id) && target.projections.is_empty() =>
                {
                    Some(value)
                }
                _ => None,
            });
        if let Some(value) = writes.next() {
            if writes.next().is_none() {
                result = match value {
                    Rvalue::Read(value) => binding(env, body, value, seen),
                    Rvalue::Call(callee, args) => match binding(env, body, callee, seen) {
                        Some(Binding::Global(name)) if name == "require" => match args.as_slice() {
                            [Operand::Lit(Literal::Str(module))] => required_module(module),
                            _ => None,
                        },
                        Some(Binding::GetPrototypeOf) => Some(Binding::Prototype),
                        _ => None,
                    },
                    _ => None,
                };
            }
        } else if let Some(def) = def
            && let Some(owner) = env.binding_owner(def)
            && Some(owner) != body.owner()
        {
            let owner_body = env.def_ref(owner).expect_body();
            if let Some(&owner_var) = owner_body.def_id_to_vars.get(&def) {
                result = binding(env, owner_body, &Operand::with_var(owner_var), seen);
            }
        }
    }
    seen.remove(&key);
    for projection in &var.projections {
        let Projection::Known(name) = projection else {
            return None;
        };
        result = match result? {
            Binding::Global(global) if global == "global" || global == "globalThis" => {
                code_constructor(name).map(Binding::Sink)
            }
            Binding::Global(global) if global == "Object" || global == "Reflect" => {
                (name == "getPrototypeOf").then_some(Binding::GetPrototypeOf)
            }
            Binding::ChildProcess => child_process_api(name).map(Binding::Sink),
            Binding::Vm => vm_api(name).map(Binding::Sink),
            // `Object.getPrototypeOf(function () {}).constructor` reaches the
            // `Function` variant for a generator or an async function.
            Binding::Prototype if name == "constructor" => Some(Binding::Sink("Function")),
            _ => None,
        };
    }
    result
}

fn sink<'a>(
    env: &Environment,
    body: &Body,
    inst: &'a Inst,
) -> Option<(&'static str, &'a [Operand])> {
    let Rvalue::Call(callee, args) = inst.rvalue() else {
        return None;
    };
    let name = match binding(env, body, callee, &mut HashSet::new())? {
        Binding::Global(name) => code_constructor(&name)?,
        Binding::Sink(name) => name,
        _ => return None,
    };
    Some((name, &args[..args.len().min(executable_arguments(name))]))
}

#[derive(Default)]
pub struct ExecutionTaint;

impl TaintPolicy for ExecutionTaint {
    type Facts = Taint;
    const TAINT_ENTRYPOINT_INPUTS: bool = true;

    fn intrinsic_value(&self, intrinsic: &Intrinsic) -> FlowValue<Taint> {
        FlowValue::from_taint(match intrinsic {
            Intrinsic::Fetch
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::StorageRead
            | Intrinsic::SecretRead
            | Intrinsic::EnvRead => Taint::Yes,
            _ => Taint::Unknown,
        })
    }

    // Each written property keeps its own taint, so reading one field of an
    // object excludes the taint of its siblings.
    fn tracks_fields(&self) -> bool {
        true
    }

    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool {
        sink(values.env, values.body, inst).is_some_and(|(_, args)| {
            args.iter()
                .any(|arg| values.operand(arg).facts != Taint::No)
        })
    }

    fn global_call_value(&self, name: &str, path: &[Projection]) -> Option<FlowValue<Taint>> {
        match (name, path) {
            // A bare `fetch` call nested in another call reaches the policy as
            // a global rather than as `Intrinsic::Fetch`.
            ("fetch" | "forgeFetch", []) => Some(FlowValue::from_taint(Taint::Yes)),
            // A coerced boolean carries a decision, not the text behind it.
            ("Boolean", []) => Some(FlowValue::default()),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct ArbitraryCodeExecutionChecker {
    vulns: Vec<ArbitraryCodeExecutionVuln>,
    reported: HashSet<(DefId, Location)>,
}

impl ArbitraryCodeExecutionChecker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn into_vulns(self) -> impl Iterator<Item = ArbitraryCodeExecutionVuln> {
        self.vulns.into_iter()
    }
}

pub struct ArbitraryCodeExecutionVuln {
    sink: &'static str,
    file: PathBuf,
    function: String,
    body: DefId,
    location: Location,
}

impl fmt::Display for ArbitraryCodeExecutionVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Potential arbitrary code execution through {}",
            self.sink
        )
    }
}

impl WithCallStack for ArbitraryCodeExecutionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl IntoVuln for ArbitraryCodeExecutionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.file.hash(&mut hasher);
        self.body.hash(&mut hasher);
        self.location.hash(&mut hasher);
        self.sink.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Arbitrary-Code-Execution-{}", hasher.finish()),
            description: format!(
                "Non-constant input is passed to {} in {} (entry file {:?}), which may allow arbitrary code execution.",
                self.sink, self.function, self.file
            ),
            recommendation: "Do not execute dynamically constructed code, commands, or arguments. Remove child-process execution where possible; otherwise use a strict allowlist and an isolated sandbox.",
            proof: format!(
                "Potential execution input reaches {}; IR body: {:?} ({}); IR location: {:?}.",
                self.sink, self.body, self.function, self.location
            ),
            severity: Severity::Critical,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: "Requirement 10.2",
            date: reporter.current_date(),
        }
    }
}

impl<'cx> Runner<'cx> for ArbitraryCodeExecutionChecker {
    type State = Vec<Taint>;
    type Dataflow = TaintDataflow<ExecutionTaint>;
    const NAME: &'static str = "ArbitraryCodeExecution";
    const VISIT_GLOBALS: bool = true;

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }

    fn visit_call(
        &mut self,
        interp: &Interp<'cx, Self>,
        callee: &'cx Operand,
        _args: &'cx [Operand],
        block: BasicBlockId,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        visit_taint_call(self, interp, callee, block, state)
    }

    fn visit_inst(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        loc: Location,
        inst: &'cx Inst,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        if interp.instruction_has_finding(def, loc)
            && let Some((sink, _)) =
                sink(interp.env(), interp.env().def_ref(def).expect_body(), inst)
            && self.reported.insert((def, loc))
        {
            self.vulns.push(ArbitraryCodeExecutionVuln {
                sink,
                file: interp.entry().file.clone(),
                function: interp.env().def_name(def).to_owned(),
                body: def,
                location: loc,
            });
        }
        self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state)
    }
}

impl Checker<'_> for ArbitraryCodeExecutionChecker {
    type Vuln = ArbitraryCodeExecutionVuln;
}
