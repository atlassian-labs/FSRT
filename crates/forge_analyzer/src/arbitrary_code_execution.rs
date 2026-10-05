//! IR-based execution checks. The conservative policy is intentionally a starting
//! point: unmodelled calls remain unknown until their source semantics are modelled.
//! `sink` recognizes execution targets from IR bindings; `ExecutionTaint` supplies
//! sources and the reporting predicate to the shared fixed-point engine. New
//! constructor syntax is marked by the lowerer in `definitions.rs`.
//! See fsrt/src/test/arbitrary_code_execution.rs for the enabled, intentionally
//! failing acceptance cases. Pure string transformations are the remaining work.
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
    interp::{Checker, Interp, JoinSemiLattice, Runner, WithCallStack},
    ir::{
        BasicBlockId, Body, Inst, Intrinsic, Literal, Location, Operand, Projection, Rvalue, VarId,
        VarKind,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{Taint, TaintDataflow, TaintPolicy, TaintReader, visit_taint_call},
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum Binding {
    Global(String),
    ChildProcess,
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
        for module in ["child_process", "node:child_process"] {
            if let Some(import) = env.is_imported_from(def, module) {
                return match import {
                    ImportKind::Star | ImportKind::Default => Some(Binding::ChildProcess),
                    ImportKind::Named(name) => child_process_api(name).map(Binding::Sink),
                };
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
                    Rvalue::Call(callee, args) if matches!(binding(env, body, callee, seen), Some(Binding::Global(name)) if name == "require") => {
                        match args.as_slice() {
                            [Operand::Lit(Literal::Str(module))]
                                if module == "child_process" || module == "node:child_process" =>
                            {
                                Some(Binding::ChildProcess)
                            }
                            _ => None,
                        }
                    }
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
            Binding::Global(global)
                if (global == "global" || global == "globalThis") && name == "eval" =>
            {
                Some(Binding::Sink("eval"))
            }
            Binding::ChildProcess => child_process_api(name).map(Binding::Sink),
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
    let (name, args) = match inst.rvalue() {
        Rvalue::Intrinsic(Intrinsic::CodeConstructor(name), args) => {
            return Some((name, args));
        }
        Rvalue::Call(callee, args) => {
            let name = match binding(env, body, callee, &mut HashSet::new())? {
                Binding::Global(name) if name == "eval" => "eval",
                Binding::Sink(name) => name,
                _ => return None,
            };
            (name, args)
        }
        _ => return None,
    };
    let count = if matches!(name, "eval" | "exec" | "execSync") {
        1
    } else {
        2
    };
    Some((name, &args[..args.len().min(count)]))
}

#[derive(Default)]
pub struct ExecutionTaint;

impl TaintPolicy for ExecutionTaint {
    const TAINT_ENTRYPOINT_INPUTS: bool = true;

    fn intrinsic_taint(&self, intrinsic: &Intrinsic) -> Taint {
        match intrinsic {
            Intrinsic::Fetch
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::StorageRead
            | Intrinsic::SecretRead
            | Intrinsic::EnvRead => Taint::Yes,
            _ => Taint::Unknown,
        }
    }

    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool {
        sink(values.env, values.body, inst)
            .is_some_and(|(_, args)| args.iter().any(|arg| values.operand(arg) != Taint::No))
    }

    fn method_taint(&self, _method: &str, receiver: Taint, args: &[Taint]) -> Option<Taint> {
        // TODO: Distinguish pure construction from IO. Keep unknown call results
        // reportable until the handoff's static-construction tests are implemented.
        Some(
            args.iter()
                .fold(Taint::Unknown.join(&receiver), |taint, arg| taint.join(arg)),
        )
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
