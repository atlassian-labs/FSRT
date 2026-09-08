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
    ir::{BasicBlockId, Inst, Intrinsic, Location, Operand, Rvalue},
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{SecretTaint, Taint, TaintDataflow, operand_taint, visit_taint_call},
};

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
}

impl fmt::Display for SecretLoggingVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret logged to console.log")
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
                "A value returned by kvs.getSecret is logged to console.log in {} (entry file {:?}).",
                self.function, self.file
            ),
            recommendation: "Remove secrets from console.log arguments. Log only non-sensitive metadata or an explicitly redacted value.",
            proof: format!(
                "Secret source: @forge/kvs kvs.getSecret; sink: console.log; call path: {}; IR body: {:?} ({}); IR location: {:?}.",
                self.stack, self.body, self.function, self.location
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
        matches!(inst.rvalue(), Rvalue::Intrinsic(Intrinsic::ConsoleLog, args)
            if args.iter().any(|arg| operand_taint(state, arg) == Taint::Yes))
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
        if interp.instruction_has_finding(def, loc) && self.reported.insert((def, loc)) {
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
            });
        }
        self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state)
    }
}

impl Checker<'_> for SecretLoggingChecker {
    type Vuln = SecretLoggingVuln;
}
