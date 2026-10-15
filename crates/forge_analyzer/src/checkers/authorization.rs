//! Authorization eligibility uses the legacy checker. Only proven REST GETs
//! receive an independent, source-specific response-to-root-return analysis.
use super::*;
use crate::{
    ir::{Body, STARTING_BLOCK, UnOp},
    taint::{TaintPolicy, TaintReader},
};
use std::{cell::Cell, rc::Rc};

#[derive(Default)]
struct ResponsePolicy {
    source: Option<(DefId, Location)>,
    observed: Rc<Cell<bool>>,
}

impl TaintPolicy for ResponsePolicy {
    const CHECK_COMPLETENESS: bool = true;

    fn intrinsic_taint(&self, _: &Intrinsic) -> Taint {
        Taint::No
    }

    fn intrinsic_taint_at(&self, def: DefId, loc: Location, _: &Intrinsic) -> Taint {
        if self.source == Some((def, loc)) {
            self.observed.set(true);
            Taint::Yes
        } else {
            Taint::No
        }
    }

    fn call_taint_at(&self, body: &Body, loc: Location) -> Option<Taint> {
        body.storage_calls.contains(&loc).then_some(Taint::No)
    }

    fn call_is_pure(&self, body: &Body, loc: Location) -> bool {
        body.pure_calls.contains(&loc)
    }

    fn is_violation(&self, _: &Inst, _: &TaintReader<'_, Self>) -> bool {
        false
    }
    fn tracks_fields(&self) -> bool {
        true
    }
    fn unary_taint(&self, op: UnOp, value: Taint) -> Taint {
        match op {
            UnOp::Void => Taint::No,
            _ => value,
        }
    }
    fn binary_taint(&self, _: BinOp, left: Taint, right: Taint) -> Taint {
        left.join(&right)
    }
}

struct ResponseRunner;
impl<'cx> Runner<'cx> for ResponseRunner {
    type State = Vec<Taint>;
    type Dataflow = TaintDataflow<ResponsePolicy>;
    const NAME: &'static str = "AuthorizationResponse";
    fn visit_intrinsic(
        &mut self,
        _: &Interp<'cx, Self>,
        _: &'cx Intrinsic,
        _: DefId,
        state: &Self::State,
        _: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }
}

pub struct AuthZChecker {
    vulns: Vec<AuthZVuln>,
    seen: HashSet<(String, DefId, Location)>,
    root: Option<DefId>,
    check_remotes: bool,
}

impl AuthZChecker {
    pub fn new(check_remotes: bool) -> Self {
        Self {
            vulns: vec![],
            seen: HashSet::new(),
            root: None,
            check_remotes,
        }
    }
    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthZVuln> {
        self.vulns.into_iter()
    }

    fn record<'cx>(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        loc: Location,
        kind: AuthZVulnKind,
    ) {
        let vuln = AuthZVuln::new(
            interp.callstack(),
            interp.env(),
            interp.entry(),
            kind,
            def,
            loc,
        );
        if !self.seen.insert((vuln.entry_func.clone(), def, loc)) {
            return;
        }
        if interp.body().rest_gets.contains(&loc)
            && let Some(root) = self.root
        {
            let mut isolated = interp.fresh::<ResponseRunner>();
            isolated.set_body(interp.env().def_ref(root).expect_body());
            let observed = Rc::new(Cell::new(false));
            let mut flow = TaintDataflow::new(ResponsePolicy {
                source: Some((def, loc)),
                observed: observed.clone(),
            });
            flow.analyze(&mut isolated, root);
            debug!(entrypoint = %vuln.entry_func, ?def, ?loc, observed = observed.get(), returned = ?flow.analyzed_return(), "authorization-get-analysis");
            if observed.get() && flow.analyzed_return() == Some(Taint::No) {
                debug!(entrypoint = %vuln.entry_func, ?def, ?loc, "internal-get");
                return;
            }
        }
        self.vulns.push(vuln);
    }
}
impl Default for AuthZChecker {
    fn default() -> Self {
        Self::new(false)
    }
}

#[derive(Debug)]
pub enum AuthZVulnKind {
    ApiCall,
    RemoteCall(String),
}

#[derive(Debug)]
pub struct AuthZVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
    kind: AuthZVulnKind,
    body: DefId,
    location: Location,
    sink_function: String,
}

impl AuthZVuln {
    fn new(
        callstack: Vec<Frame>,
        env: &Environment,
        entry: &EntryPoint,
        kind: AuthZVulnKind,
        body: DefId,
        location: Location,
    ) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => String::new(),
        };
        let stack = Itertools::intersperse(
            iter::once(&*entry_func).chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            ),
            " -> ",
        )
        .collect();
        Self {
            stack,
            entry_func,
            file: entry.file.clone(),
            kind,
            body,
            location,
            sink_function: env.def_name(body).to_owned(),
        }
    }
}
impl fmt::Display for AuthZVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authorization vulnerability")
    }
}
impl IntoVuln for AuthZVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        self.body.hash(&mut hasher);
        self.location.hash(&mut hasher);
        let (proof, req_id) = match self.kind {
            ApiCall => (
                format!("Unauthorized API call via asApp() found via {}", self.stack),
                "Requirement 1.2",
            ),
            RemoteCall(remote) => (
                format!(
                    "Unauthorized call to forge remote `{remote}` with app system token found via {}",
                    self.stack
                ),
                "AEC Requirement 1.14",
            ),
        };
        Vulnerability {
            check_name: format!("Custom-Check-Authorization-{}", hasher.finish()),
            description: format!(
                "Authorization bypass detected through {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation: "Use the authorize API _https://developer.atlassian.com/platform/forge/runtime-reference/authorize-api/_ or manually authorize the user via the product REST APIs.",
            proof: format!(
                "{proof}; operation in {} ({:?}) at {:?}",
                self.sink_function, self.body, self.location
            ),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: req_id,
            date: reporter.current_date(),
        }
    }
}
impl WithCallStack for AuthZVuln {
    fn add_call_stack(&mut self, _: Vec<DefId>) {}
}

impl<'cx> Runner<'cx> for AuthZChecker {
    type State = AuthorizeState;
    type Dataflow = AuthorizeDataflow;
    const NAME: &'static str = "Authorization";
    // Keep candidate discovery compatible with baseline shared-helper visitation.
    // Each GET exposure analysis still uses its own fresh interpreter.

    fn visit_body(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        body: &'cx Body,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        if interp.callstack().is_empty() {
            self.root = Some(def);
        }
        let old_body = interp.body();
        interp.set_body(body);
        let result = self.visit_block(
            interp,
            def,
            STARTING_BLOCK,
            body.block(STARTING_BLOCK),
            state,
        );
        interp.set_body(old_body);
        result
    }

    // Intrinsics are handled by visit_inst, which supplies their exact location.
    fn visit_intrinsic(
        &mut self,
        _: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        _: DefId,
        state: &Self::State,
        _: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(if matches!(intrinsic, Intrinsic::Authorize(_)) {
            AuthorizeState::Yes
        } else {
            *state
        })
    }

    fn visit_inst(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        loc: Location,
        inst: &'cx Inst,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        let Rvalue::Intrinsic(intrinsic, _) = inst.rvalue() else {
            return self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state);
        };
        let findings_before = self.vulns.len();
        match intrinsic {
            Intrinsic::Authorize(_) => return ControlFlow::Continue(AuthorizeState::Yes),
            Intrinsic::ApiCall(IntrinsicName::InvokeRemote(remote))
                if *state != AuthorizeState::Yes && self.check_remotes =>
            {
                if let Some(name) = remote {
                    self.record(interp, def, loc, RemoteCall(name.clone()));
                } else {
                    warn!("Privileged remote missing ID");
                }
            }
            Intrinsic::ApiCall(IntrinsicName::InvokeRemote(_)) => {}
            Intrinsic::ApiCall(_) if *state != AuthorizeState::Yes => {
                self.record(interp, def, loc, ApiCall)
            }
            Intrinsic::ApiCustomField if *state < AuthorizeState::CustomFieldOnly => {
                self.record(interp, def, loc, ApiCall)
            }
            _ => {}
        }
        // Temporary baseline comparison: stop at the first *reported* operation
        // in this handler. An exempt internal GET must not hide a later finding.
        if self.vulns.len() > findings_before {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(*state)
        }
    }
}
impl Checker<'_> for AuthZChecker {
    type Vuln = AuthZVuln;
}
