use std::{
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    ops::ControlFlow,
    path::PathBuf,
};

use smallvec::SmallVec;

use crate::{
    definitions::DefId,
    interp::{Checker, Interp, Runner, WithCallStack},
    ir::{BasicBlockId, ConsoleMethod, Inst, Intrinsic, Location, Operand, Rvalue},
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{SecretTaint, Taint, TaintDataflow, read_taint, visit_taint_call},
};

const SOURCES: &str = "@forge/kvs kvs.getSecret or @forge/api storage.getSecret";

#[derive(Default)]
pub struct SecretLoggingChecker {
    vulns: Vec<SecretLoggingVuln>,
    reported: HashSet<(DefId, Location)>,
}

impl SecretLoggingChecker {
    pub fn into_vulns(self) -> impl IntoIterator<Item = SecretLoggingVuln> {
        self.vulns
    }
}

pub struct SecretLoggingVuln {
    file: PathBuf,
    function: String,
    body: DefId,
    stack: String,
    location: Location,
    sink: ConsoleMethod,
}

impl fmt::Display for SecretLoggingVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret logged to {}", self.sink)
    }
}

impl WithCallStack for SecretLoggingVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl IntoVuln for SecretLoggingVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.file.hash(&mut hasher);
        self.function.hash(&mut hasher);
        self.body.hash(&mut hasher);
        self.location.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Secret-Logging-{}", hasher.finish()),
            description: format!(
                "A value returned by a Forge secret storage read is logged to {} in {} (entry file {:?}).",
                self.sink, self.function, self.file
            ),
            recommendation: "Remove secrets from console arguments. Log only non-sensitive metadata or an explicitly redacted value.",
            proof: format!(
                "Secret source: {SOURCES}; sink: {}; call path: {}; IR body: {:?} ({}); IR location: {:?}.",
                self.sink, self.stack, self.body, self.function, self.location
            ),
            severity: Severity::High,
            marketplace_security_requirement: "Requirement 5",
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl<'cx> Runner<'cx> for SecretLoggingChecker {
    type State = Vec<Taint>;
    type Dataflow = TaintDataflow<SecretTaint>;
    const NAME: &'static str = "SecretLogging";
    const VISIT_GLOBALS: bool = true;

    fn instruction_has_violation(inst: &Inst, state: &Self::State) -> bool {
        matches!(inst.rvalue(), Rvalue::Intrinsic(Intrinsic::ConsoleLog(_), args)
            if args.iter().any(|arg| read_taint::<SecretTaint>(state, arg) == Taint::Yes))
    }

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
        if let Rvalue::Intrinsic(Intrinsic::ConsoleLog(sink), _) = inst.rvalue()
            && interp.instruction_has_finding(def, loc)
            && self.reported.insert((def, loc))
        {
            let entry = &interp.entry().kind;
            let mut path = vec![match entry {
                crate::interp::EntryKind::Function(name) => name.clone(),
                crate::interp::EntryKind::Resolver(name, method) => format!("{name}.{method}"),
                crate::interp::EntryKind::Empty => String::new(),
            }];
            path.extend(
                interp
                    .callstack()
                    .iter()
                    .map(|frame| interp.env().def_name(frame.calling_function).to_owned()),
            );
            self.vulns.push(SecretLoggingVuln {
                file: interp.entry().file.clone(),
                function: interp.env().def_name(def).to_owned(),
                body: def,
                stack: path.join(" -> "),
                location: loc,
                sink: *sink,
            });
        }
        self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state)
    }
}

impl Checker<'_> for SecretLoggingChecker {
    type Vuln = SecretLoggingVuln;
}
