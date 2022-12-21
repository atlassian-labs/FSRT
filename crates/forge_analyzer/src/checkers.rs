use core::fmt;
use itertools::Itertools;
use std::{cmp::max, iter, mem, ops::ControlFlow, path::PathBuf};

use tracing::{debug, info, warn};

use crate::{
    definitions::{DefId, Environment},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, WithCallStack,
    },
    ir::{BasicBlock, BasicBlockId, Intrinsic, Location},
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    worklist::WorkList,
};

pub struct AuthorizeDataflow {
    needs_call: Vec<DefId>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum AuthorizeState {
    No,
    Yes,
}

impl JoinSemiLattice for AuthorizeState {
    const BOTTOM: Self = Self::No;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

impl<'cx> Dataflow<'cx> for AuthorizeDataflow {
    type State = AuthorizeState;

    fn with_interp<C: crate::interp::Checker<'cx, State = Self::State>>(
        interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize => {
                debug!("authorize intrinsic found");
                AuthorizeState::Yes
            }
            Intrinsic::Fetch => initial_state,
            Intrinsic::ApiCall => initial_state,
            Intrinsic::SafeCall => initial_state,
            Intrinsic::EnvRead => initial_state,
            Intrinsic::StorageRead => initial_state,
        }
    }

    fn transfer_call<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
    ) -> Self::State {
        let Some((callee_def, body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };
        match interp.func_state(callee_def) {
            Some(state) => {
                if state == AuthorizeState::Yes {
                    debug!("Found call to authorize at {def:?} {loc:?}");
                }
                initial_state.join(&state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                initial_state
            }
        }
    }

    fn join_term<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def);
        }
    }
}

pub struct AuthZChecker {
    vulns: Vec<AuthZVuln>,
}

impl AuthZChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthZVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
    }
}

impl Default for AuthZChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AuthZVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthZVuln {
    fn new(mut callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
        let stack = iter::once(&*entry_func)
            .chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            )
            .intersperse(" -> ")
            .collect();
        Self {
            stack,
            entry_func,
            file,
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
        self.file.hash(&mut hasher);
        self.entry_func.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authorization-{}", hasher.finish()),
            description: format!("Authorization bypass detected through {} in {:?}.", self.entry_func, self.file),
            recommendation: "Use the authorize API _https://developer.atlassian.com/platform/forge/runtime-reference/authorize-api/_ or manually authorize the user via the product REST APIs.",
            proof: format!("Unauthorized API call via asApp() found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthZVuln {
    fn add_call_stack(&mut self, stack: Vec<DefId>) {}
}

impl<'cx> Checker<'cx> for AuthZChecker {
    type State = AuthorizeState;
    type Dataflow = AuthorizeDataflow;
    type Vuln = AuthZVuln;

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall if *state == AuthorizeState::No => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCall => ControlFlow::Continue(*state),
            Intrinsic::SafeCall => ControlFlow::Continue(*state),
            Intrinsic::EnvRead => ControlFlow::Continue(*state),
            Intrinsic::StorageRead => ControlFlow::Continue(*state),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum Authenticated {
    No,
    Yes,
}

impl JoinSemiLattice for Authenticated {
    const BOTTOM: Self = Self::No;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, max(*other, *self));
        old == *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

pub struct AuthenticateDataflow {
    needs_call: Vec<DefId>,
}

impl<'cx> Dataflow<'cx> for AuthenticateDataflow {
    type State = Authenticated;

    fn with_interp<C: crate::interp::Checker<'cx, State = Self::State>>(
        interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize => initial_state,
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                Authenticated::Yes
            }
            Intrinsic::ApiCall => initial_state,
            Intrinsic::SafeCall => initial_state,
        }
    }

    fn transfer_call<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
    ) -> Self::State {
        let Some((callee_def, body)) = self.resolve_call(interp, callee) else {
                                                return initial_state;
                                                        };
        match interp.func_state(callee_def) {
            Some(state) => {
                if state == Authenticated::Yes {
                    debug!("Found call to authenticate at {def:?} {loc:?}");
                }
                initial_state.join(&state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                initial_state
            }
        }
    }

    fn join_term<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def);
        }
    }
}

pub struct AuthenticateChecker {
    vulns: Vec<AuthNVuln>,
}

impl AuthenticateChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthNVuln> {
        self.vulns.into_iter()
    }
}

impl Default for AuthenticateChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl<'cx> Checker<'cx> for AuthenticateChecker {
    type State = Authenticated;
    type Dataflow = AuthenticateDataflow;
    type Vuln = AuthNVuln;

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize => ControlFlow::Continue(*state),
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                ControlFlow::Continue(Authenticated::Yes)
            }
            Intrinsic::ApiCall if *state == Authenticated::No => {
                let vuln = AuthNVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCall => ControlFlow::Continue(*state),
            Intrinsic::SafeCall => ControlFlow::Continue(*state),
        }
    }
}

#[derive(Debug)]
pub struct AuthNVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthNVuln {
    fn new(mut callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
        let stack = iter::once(&*entry_func)
            .chain(
                callstack
                    .into_iter()
                    .rev()
                    .map(|frame| env.def_name(frame.calling_function)),
            )
            .intersperse(" -> ")
            .collect();
        Self {
            stack,
            entry_func,
            file,
        }
    }
}

impl fmt::Display for AuthNVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authentication vulnerability")
    }
}

impl IntoVuln for AuthNVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.file.hash(&mut hasher);
        self.entry_func.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authentication-{}", hasher.finish()),
            description: format!("Insufficient Authentication through webhook {} in {:?}.", self.entry_func, self.file),
            recommendation: "Properly authenticate incoming webhooks and ensure that any shared secrets are stored in Forge Secure Storage.",
            proof: format!("Unauthenticated API call via asApp() found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthNVuln {
    fn add_call_stack(&mut self, stack: Vec<DefId>) {}
}
