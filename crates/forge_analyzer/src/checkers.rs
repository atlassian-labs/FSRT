use crate::interp::ProjectionVec;
use crate::utils::projvec_from_str;
use crate::{
    definitions::{Const, DefId, Environment, IntrinsicName, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, Runner,
        WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Inst, Intrinsic, Literal, Location, Operand,
        Projection, Rvalue, VarId, VarKind, Variable,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    utils::{add_elements_to_intrinsic_struct, convert_lit_to_raw, translate_request_type},
    worklist::WorkList,
};
use core::fmt;
use forge_permission_resolver::permissions_resolver::{
    PermissionHashMap, RequestType, check_url_for_permissions,
};
use forge_utils::FxHashMap;
use itertools::Itertools;
use regex::{Regex, RegexSet};
use smallvec::SmallVec;
use std::{
    cmp::max,
    collections::HashMap,
    collections::HashSet,
    iter::{self, zip},
    mem,
    ops::ControlFlow,
    path::PathBuf,
};
use tracing::{debug, info, warn};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub enum Taint {
    No,
    Yes,
    #[default]
    Unknown,
}

impl JoinSemiLattice for Taint {
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

impl<D: JoinSemiLattice> JoinSemiLattice for Vec<D> {
    const BOTTOM: Self = vec![];
    fn join_changed(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (l, r) in zip(self, other) {
            changed |= l.join_changed(r);
        }
        changed
    }
    fn join(&self, other: &Self) -> Self {
        self.iter()
            .zip(other.iter())
            .map(|(a, b)| a.join(b))
            .collect()
    }
}

pub struct TaintDataflow {
    started: bool,
}

impl<'cx> Dataflow<'cx> for TaintDataflow {
    type State = Vec<Taint>;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self { started: false }
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        callee: &'cx Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        self.super_transfer_call(
            interp,
            def,
            loc,
            block,
            callee,
            initial_state,
            oprands.clone(),
        )
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        inst: &'cx Inst,
        mut initial_state: Self::State,
    ) -> Self::State {
        match inst {
            Inst::Assign(l, v) => {
                interp.add_value_to_definition(def, l.clone(), v.clone());
                let Some(var) = l.as_var_id() else {
                    return initial_state;
                };

                if let Some(var) = v.as_var() {
                    let Some(var_id) = var.as_var_id() else {
                        return initial_state;
                    };
                    let taint = initial_state[var_id.0 as usize];
                    if !self.started && taint == Taint::Yes {
                        let Some(Projection::Known(s)) = var.projections.first() else {
                            return initial_state;
                        };
                        if *s == "payload" {
                            initial_state[var_id.0 as usize] = Taint::Yes;
                            self.started = true;
                        }
                        return initial_state;
                    } else {
                        let new_state = initial_state[var_id.0 as usize].join(&taint);
                        initial_state[var_id.0 as usize] = new_state;
                        return initial_state;
                    }
                } else if initial_state[var.0 as usize] == Taint::Yes {
                    initial_state[var.0 as usize] = Taint::Unknown;
                }
                initial_state
            }
            Inst::Expr(rvalue) => {
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
        }
    }

    fn transfer_block<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        mut initial_state: Self::State,
    ) -> Self::State {
        if initial_state.len() < interp.body().vars.len() {
            initial_state.resize(interp.body().vars.len(), Taint::Unknown);
        }
        if matches!(interp.entry.kind, EntryKind::Resolver(..)) {
            debug!("analyzing resolver");
            let kind = interp.body().vars.get(VarId::from(1));
            if matches!(kind, Some(VarKind::Arg(_))) {
                debug!("found taint start");
                initial_state[1] = Taint::Yes;
            } else {
                debug!(first_var = ?kind, "no arguments read");
            }
        }
        for (idx, inst) in block.iter().enumerate() {
            initial_state = self.transfer_inst(
                interp,
                def,
                Location::new(bb, idx as u32),
                block,
                inst,
                initial_state,
            );
        }
        initial_state
    }
}

pub struct AuthorizeDataflow {
    needs_call: Vec<DefId>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum AuthorizeState {
    No,
    CustomFieldOnly,
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

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                AuthorizeState::Yes
            }
            Intrinsic::UserFieldAccess => {
                debug!("user field access found");
                std::cmp::max(AuthorizeState::CustomFieldOnly, initial_state)
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::Fetch
            | Intrinsic::ApiCustomField
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::EnvRead
            | Intrinsic::StorageRead => initial_state,
        }
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let state =
            self.super_transfer_call(interp, def, loc, _block, callee, initial_state, oprands);
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return state;
        };
        match interp.func_state(callee_def) {
            Some(func_state) => {
                if func_state == AuthorizeState::Yes {
                    debug!("Found call to authorize at {def:?} {loc:?}");
                }
                state.join(&func_state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                state
            }
        }
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct PrototypePollutionChecker;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Default)]
enum PrototypePollutionState {
    Yes,
    #[default]
    No,
}

impl JoinSemiLattice for PrototypePollutionState {
    const BOTTOM: Self = Self::No;
    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            _ => Self::No,
        }
    }

    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, self.join(other));
        old != *self
    }
}

impl<'cx> Runner<'cx> for PrototypePollutionChecker {
    type State = Vec<Taint>;

    type Dataflow = TaintDataflow;

    const NAME: &'static str = "PrototypePollution";

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
    fn visit_block(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _def: DefId,
        _id: BasicBlockId,
        block: &'cx BasicBlock,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        for inst in &block.insts {
            if let Inst::Assign(l, _r) = inst
                && let [
                    Projection::Computed(Base::Var(fst)),
                    Projection::Computed(Base::Var(snd)),
                    ..,
                ] = *l.projections
                && curr_state.get(fst.0 as usize).copied() == Some(Taint::Yes)
                && curr_state.get(snd.0 as usize).copied() == Some(Taint::Yes)
            {
                info!("Prototype pollution vuln detected");
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(curr_state.clone())
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
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
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
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authorization-{}", hasher.finish()),
            description: format!(
                "Authorization bypass detected through {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation: "Use the authorize API _https://developer.atlassian.com/platform/forge/runtime-reference/authorize-api/_ or manually authorize the user via the product REST APIs.",
            proof: format!("Unauthorized API call via asApp() found via {}", self.stack),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: "Requirement 1.2",
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthZVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl<'cx> Runner<'cx> for AuthZChecker {
    type State = AuthorizeState;
    type Dataflow = AuthorizeDataflow;

    const NAME: &'static str = "Authorization";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) if *state != AuthorizeState::Yes => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCustomField if *state < AuthorizeState::CustomFieldOnly => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::ApiCall(_)
            | Intrinsic::SafeCall(_)
            | Intrinsic::EnvRead
            | Intrinsic::UserFieldAccess
            | Intrinsic::ApiCustomField
            | Intrinsic::StorageRead => ControlFlow::Continue(*state),
        }
    }
}

impl Checker<'_> for AuthZChecker {
    type Vuln = AuthZVuln;
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

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize(_) => initial_state,
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                Authenticated::Yes
            }
            Intrinsic::SecretFunction(_)
            | Intrinsic::ApiCall(_)
            | Intrinsic::ApiCustomField
            | Intrinsic::UserFieldAccess
            | Intrinsic::SafeCall(_) => initial_state,
        }
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let state = self.super_transfer_call(
            interp,
            def,
            loc,
            _block,
            callee,
            initial_state,
            oprands.clone(),
        );
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return state;
        };
        match interp.func_state(callee_def) {
            Some(func_state) => {
                if func_state == Authenticated::Yes {
                    debug!("Found call to authenticate at {def:?} {loc:?}");
                }
                state.join(&func_state)
            }
            None => {
                let callee_name = interp.env().def_name(callee_def);
                let caller_name = interp.env().def_name(def);
                debug!("Found call to {callee_name} at {def:?} {caller_name}");
                self.needs_call.push(callee_def);
                state
            }
        }
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
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

impl<'cx> Runner<'cx> for AuthenticateChecker {
    type State = Authenticated;
    type Dataflow = AuthenticateDataflow;

    const NAME: &'static str = "Authentication";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => ControlFlow::Continue(*state),
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                ControlFlow::Continue(Authenticated::Yes)
            }
            Intrinsic::ApiCall(_) | Intrinsic::ApiCustomField if *state == Authenticated::No => {
                let vuln = AuthNVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::SecretFunction(_) => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) | Intrinsic::UserFieldAccess | Intrinsic::ApiCustomField => {
                ControlFlow::Continue(*state)
            }
            Intrinsic::SafeCall(_) => ControlFlow::Continue(*state),
        }
    }
}

impl Checker<'_> for AuthenticateChecker {
    type Vuln = AuthNVuln;
}

#[derive(Debug)]
pub struct AuthNVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthNVuln {
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
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
        self.file
            .iter()
            .skip_while(|comp| *comp != "src")
            .for_each(|comp| comp.hash(&mut hasher));
        self.entry_func.hash(&mut hasher);
        self.stack.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Authentication-{}", hasher.finish()),
            description: format!(
                "Insufficient Authentication through webhook {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation: "Properly authenticate incoming webhooks and ensure that any shared secrets are stored in Forge Secure Storage.",
            proof: format!(
                "Unauthenticated API call via asApp() found via {}",
                self.stack
            ),
            severity: Severity::High,
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            marketplace_security_requirement: "Requirement 1.1",
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for AuthNVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

pub struct SecretDataflow {
    needs_call: Vec<DefId>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum SecretState {
    ALL,
}

impl JoinSemiLattice for SecretState {
    const BOTTOM: Self = Self::ALL;

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

impl<'cx> Dataflow<'cx> for SecretDataflow {
    type State = SecretState;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let state =
            self.super_transfer_call(interp, def, loc, _block, callee, initial_state, oprands);
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return state;
        };
        self.needs_call.push(callee_def);
        SecretState::ALL
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct SecretChecker {
    vulns: Vec<SecretVuln>,
}

impl SecretChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = SecretVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
    }

    pub fn add_manifest_secret(
        &mut self,
        location: String,
        field_name: String,
        secret_type: SecretType,
    ) {
        let vuln = SecretVuln::from_manifest(location, field_name, secret_type);
        self.vulns.push(vuln);
    }
}

impl Default for SecretChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretType {
    OAuthProvider,
    Regular,
}

#[derive(Debug)]
pub struct SecretVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
    secret_type: SecretType,
}

impl SecretVuln {
    fn new(callstack: Vec<Frame>, env: &Environment, entry: &EntryPoint) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
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
            file,
            secret_type: SecretType::Regular,
        }
    }

    fn from_manifest(location: String, field_name: String, secret_type: SecretType) -> Self {
        Self {
            stack: format!("manifest.yml: {}", field_name),
            entry_func: location,
            file: PathBuf::from("manifest.yml"),
            secret_type,
        }
    }
}

impl fmt::Display for SecretVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hardcoded secret vulnerability")
    }
}

impl IntoVuln for SecretVuln {
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

        let recommendation = match self.secret_type {
            SecretType::OAuthProvider => {
                "Configure the OAuth Provider secrets in your OAuth Provider settings and use runtime templates (e.g. {{client_secret}} to reference secrets securely as opposed to hardcoding them directly in the codebase. See https://developer.atlassian.com/platform/forge/runtime-reference/storage-api-secret/ for more details.)"
            }
            SecretType::Regular => {
                "Use secrets as enviornment variables instead of hardcoding them."
            }
        };

        let check_name = match self.secret_type {
            SecretType::OAuthProvider => {
                format!(
                    "Custom-Check-Hardcoded-Secret-OAuth-Provider-{}",
                    hasher.finish()
                )
            }
            SecretType::Regular => format!("Custom-Check-Hardcoded-Secret-{}", hasher.finish()),
        };

        Vulnerability {
            check_name,
            description: format!(
                "Hardcoded secret found within codebase {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation,
            proof: format!("Hardcoded secret found in found via {}", self.stack),
            severity: Severity::High,
            marketplace_security_requirement: "Requirement 5",
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl WithCallStack for SecretVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl<'cx> Runner<'cx> for SecretChecker {
    type State = SecretState;
    type Dataflow = SecretDataflow;

    const NAME: &'static str = "Secret";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match intrinsic {
            Intrinsic::SecretFunction(package_data) => {
                if let Some(operand) = operands
                    .unwrap_or_default()
                    .get((package_data.secret_position - 1) as usize)
                {
                    {
                        if interp.check_for_const(operand, def) {
                            let vuln =
                                SecretVuln::new(interp.callstack(), interp.env(), interp.entry());
                            info!("Found a vuln!");
                            self.vulns.push(vuln);
                        }
                    }
                }
            }
            Intrinsic::Fetch => {
                if let Some(Operand::Var(Variable {
                    base: Base::Var(varid),
                    ..
                })) = operands.unwrap_or_default().get(1)
                {
                    let varid_argument =
                        if let Some(Value::Object(varid)) = interp.get_value(def, *varid, None) {
                            varid
                        } else {
                            varid
                        };
                    let headers_proj = projvec_from_str("headers");
                    if let Some(Value::Object(varid)) =
                        interp.get_value(def, *varid_argument, Some(headers_proj))
                    {
                        let auth_proj = projvec_from_str("Authorization");
                        let aut_proj_lower = projvec_from_str("authorization");
                        if let Some(Value::Const(_) | Value::Phi(_)) = interp
                            .get_value(def, *varid, Some(auth_proj.clone()))
                            .or_else(|| interp.get_value(def, *varid, Some(aut_proj_lower.clone())))
                        {
                            let vuln =
                                SecretVuln::new(interp.callstack(), interp.env(), interp.entry());
                            info!("Found a vuln!");
                            self.vulns.push(vuln);
                        } else if let Some(Value::Const(_) | Value::Phi(_)) = interp.get_value(
                            def,
                            *varid,
                            projvec_from_str("X-Automation-Webhook-Token").into(),
                        ) && interp
                            .get_value(def, *varid_argument, Some(projvec_from_str("method")))
                            .is_some_and(|x| *x == *"POST")
                        {
                            let vuln =
                                SecretVuln::new(interp.callstack(), interp.env(), interp.entry());
                            info!("Webhook token found!");
                            self.vulns.push(vuln);
                        }
                    }
                }
            }

            _ => {}
        }

        ControlFlow::Continue(*state)
    }
}

impl Checker<'_> for SecretChecker {
    type Vuln = SecretVuln;
}

#[derive(Debug, Clone)]
pub enum AuthHeaderVulnKind {
    BasicAuth,
    BearerAdmin,
}

#[derive(Debug)]
pub struct AuthHeaderVuln {
    kind: AuthHeaderVulnKind,
    stack: String,
    entry_func: String,
    file: PathBuf,
}

impl AuthHeaderVuln {
    fn new(
        kind: AuthHeaderVulnKind,
        callstack: Vec<Frame>,
        env: &Environment,
        entry: &EntryPoint,
    ) -> Self {
        let entry_func = match &entry.kind {
            EntryKind::Function(func) => func.clone(),
            EntryKind::Resolver(res, prop) => format!("{res}.{prop}"),
            EntryKind::Empty => {
                warn!("empty function");
                String::new()
            }
        };
        let file = entry.file.clone();
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
            kind,
            stack,
            entry_func,
            file,
        }
    }
}

impl fmt::Display for AuthHeaderVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            AuthHeaderVulnKind::BasicAuth => {
                write!(f, "HTTP Basic Authorization header on fetch")
            }
            AuthHeaderVulnKind::BearerAdmin => {
                write!(
                    f,
                    "Bearer token used with Atlassian admin API endpoint on fetch"
                )
            }
        }
    }
}

impl IntoVuln for AuthHeaderVuln {
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

        match self.kind {
            AuthHeaderVulnKind::BasicAuth => Vulnerability {
                check_name: format!("Custom-Check-Basic-Authorization-{}", hasher.finish()),
                description: format!(
                    "HTTP Basic authentication used in fetch request from {} in {:?}.",
                    self.entry_func, self.file
                ),
                recommendation: "Prefer OAuth or API tokens scoped to least privilege. If Basic auth is required, load credentials from Forge secrets or environment variables and avoid logging or exposing the Authorization header.",
                proof: format!(
                    "Basic Authorization header on fetch found via {}",
                    self.stack
                ),
                severity: Severity::Critical,
                app_key: reporter.app_key().to_owned(),
                app_name: reporter.app_name().to_owned(),
                marketplace_security_requirement: "Requirement 10",
                date: reporter.current_date(),
            },
            AuthHeaderVulnKind::BearerAdmin => Vulnerability {
                check_name: format!("Custom-Check-Bearer-Admin-{}", hasher.finish()),
                description: format!(
                    "Bearer token used with Atlassian admin API endpoint in fetch from {} in {:?}.",
                    self.entry_func, self.file
                ),
                recommendation: "Avoid using admin API tokens in Forge apps. Prefer scoped OAuth tokens or Forge-native APIs.",
                proof: format!("Bearer token on admin API fetch found via {}", self.stack),
                severity: Severity::Medium,
                app_key: reporter.app_key().to_owned(),
                app_name: reporter.app_name().to_owned(),
                marketplace_security_requirement: "Requirement 10",
                date: reporter.current_date(),
            },
        }
    }
}

impl WithCallStack for AuthHeaderVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

pub struct AuthHeaderDataflow {
    needs_call: Vec<DefId>,
}

impl<'cx> Dataflow<'cx> for AuthHeaderDataflow {
    type State = SecretState;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        _intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };
        self.needs_call.push(callee_def);
        SecretState::ALL
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct AuthHeaderChecker {
    vulns: Vec<AuthHeaderVuln>,
}

impl Default for AuthHeaderChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthHeaderChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthHeaderVuln> {
        self.vulns.into_iter()
    }

    /// Merges vulnerabilities from another checker (typically the full-scan pass)
    /// into this checker, avoiding duplicates.
    pub fn extend_vulns(&mut self, other: AuthHeaderChecker) {
        self.vulns.extend(other.vulns);
    }
}

const ATLASSIAN_HOST_SUFFIXES: &[&str] = &[
    "atlassian.net",
    "atlassian.com",
    "jira-dev.com",
    "atl-paas.net",
    "bitbucket.org",
    "trello.com",
    "statuspage.io",
    "opsgenie.com",
    "loom.com",
    "halp.com",
    "mindville.com",
];

fn host_is_atlassian(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    ATLASSIAN_HOST_SUFFIXES.iter().any(|&suffix| {
        host == suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Cached regex for extracting the host from an `http(s)://` URL.
fn url_host_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^\s*https?://([^/\s?#:]*)").unwrap())
}

/// Cached `RegexSet` built from the comprehensive Atlassian endpoint list
/// (`atlassian_rest_endpoints.txt`). Each line in the file is a regex pattern
/// matching a known Atlassian REST API path. The set is compiled once into a
/// single DFA for O(n) matching regardless of pattern count.
fn atlassian_path_set() -> &'static RegexSet {
    static SET: std::sync::OnceLock<RegexSet> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        let raw = include_str!("../../../atlassian_rest_api_endpoints.txt");
        // Replace [^/]+ with [^/]* so that dynamic path segments match
        // empty strings — which arise when template quasis are joined without
        // their substitution values (e.g. `${orgId}` collapses to "").
        let patterns: Vec<String> = raw
            .lines()
            .map(|l: &str| l.trim())
            .filter(|l: &&str| !l.is_empty() && !l.starts_with('#'))
            .map(|l: &str| l.trim_end_matches('$').replace("[^/]+", "[^/]*"))
            .collect();
        RegexSet::new(&patterns).expect("failed to compile atlassian endpoint RegexSet")
    })
}

/// Extracts the path portion from a URL string for endpoint matching.
/// - Full URL `https://host/path...` → `/path...`
/// - Relative path `/rest/api/3/...` → `/rest/api/3/...`
/// - Query strings are stripped: `/rest/api/3/issue?foo=bar` → `/rest/api/3/issue`
fn extract_path_for_matching(url: &str) -> &str {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let path = match after_scheme {
        Some(rest) => {
            // Full URL — strip host portion
            rest.find('/').map(|i| &rest[i..]).unwrap_or(rest)
        }
        None => {
            // No scheme. If the first segment contains a dot it's likely a
            // bare host (e.g. `api.atlassian.com/rest/...` from test fixtures
            // that can't use `//`). Extract the path from the first `/`.
            if let Some(slash) = url.find('/') {
                let maybe_host = &url[..slash];
                if maybe_host.contains('.') {
                    &url[slash..]
                } else {
                    url
                }
            } else {
                url
            }
        }
    };
    // Normalize leading double-slash from template substitution
    // (e.g. `${baseUrl}/rest/...` where baseUrl is empty → `//rest/...`)
    let path = path.strip_prefix('/').unwrap_or(path);
    // Strip query string and fragment
    let path = path.split_once('?').map_or(path, |(p, _)| p);
    path.split_once('#').map_or(path, |(p, _)| p)
}

/// Cached regex matching Atlassian admin-scoped REST API path patterns.
fn admin_path_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?ix)
              ( ^ | [^A-Za-z0-9_] )
              /?
              (
                  admin/v[12]/orgs                               (?: [^A-Za-z0-9_-] | $ )
                | admin/control/v[12]/orgs                       (?: [^A-Za-z0-9_-] | $ )
                | admin/user-provisioning/v1/org                 (?: [^A-Za-z0-9_-] | $ )
                | scim/directory/[^/]+/(ResourceTypes|Schemas|ServiceProviderConfig|Groups|Users)
                                                                  (?: [^A-Za-z0-9_-] | $ )
                | users/[^/]+/manage                              (?: [^A-Za-z0-9_-] | $ )
                | orgs/[^/]+/(classification-levels|api-tokens|service-accounts|api-keys)
                                                                  (?: [^A-Za-z0-9_-] | $ )
              )",
        )
        .unwrap()
    })
}

pub fn is_admin_path(url: &str) -> bool {
    admin_path_re().is_match(url)
}

/// Returns `true` if `url` (full URL or relative path) targets an Atlassian
/// product endpoint.
///
/// 1. **Full http(s) URL**: extracts the host and suffix-matches against
///    [`ATLASSIAN_HOST_SUFFIXES`]. An empty host (e.g. `https:///rest/...`)
///    falls through to the path check. A non-empty non-Atlassian host returns
///    `false` immediately.
/// 2. **Relative path / empty host**: matched against known Atlassian product
///    REST API path patterns via [`atlassian_path_re`].
pub fn is_atlassian_url(url: &str) -> bool {
    if url.is_empty() {
        return false;
    }

    if let Some(caps) = url_host_re().captures(url) {
        let host = caps.get(1).map_or("", |m| m.as_str());
        if !host.is_empty() {
            return host_is_atlassian(host);
        }
        // Empty host (e.g. `https:///rest/...`) — fall through to path check.
    }

    atlassian_path_set().is_match(extract_path_for_matching(url))
}

/// Detected authorization scheme from IR-level inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthScheme {
    Basic,
    Bearer,
}

/// Inspects a literal string to determine if it starts with an auth scheme prefix.
fn classify_auth_literal(s: &str) -> Option<AuthScheme> {
    if s.len() >= 6 && s[..6].eq_ignore_ascii_case("basic ") {
        Some(AuthScheme::Basic)
    } else if s.len() >= 7 && s[..7].eq_ignore_ascii_case("bearer ") {
        Some(AuthScheme::Bearer)
    } else {
        None
    }
}

/// Extracts an auth scheme prefix from the IR instructions that define the
/// Authorization header value. This handles cases where the value resolves to
/// `Unknown` because it was built via concatenation (e.g. `"Basic " + token`)
/// or a template literal (e.g. `` `Basic ${token}` ``).
///
/// The function searches two patterns:
/// 1. Direct assignment to `target_varid` with no projection (the value was
///    assigned to a temp var that the value manager later resolved).
/// 2. Assignment with a projection ending in `Authorization`/`authorization`
///    on the headers object VarId (inline object literal case).
///
/// For each match, it inspects the rvalue for `BinOp(Add, ...)` or `Template`
/// with a recognizable auth scheme literal prefix.
///
/// Returns `Some(AuthScheme)` if a recognizable prefix is found, `None` otherwise.
fn extract_auth_scheme_from_body(body: &crate::ir::Body, target: VarId) -> Option<AuthScheme> {
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in &block.insts {
            let (assigned_var, rvalue) = match inst {
                Inst::Assign(var, rval) => (var, rval),
                Inst::Expr(_) => continue,
            };

            let is_direct_target =
                assigned_var.base == Base::Var(target) && assigned_var.projections.is_empty();

            // Only match Authorization projections on the specific headers
            // VarId we're inspecting — not on any VarId in the body — to
            // avoid cross-contaminating auth headers from different call sites
            // within the same function body.
            let is_auth_projection = assigned_var.base == Base::Var(target)
                && assigned_var.projections.iter().any(|p| {
                    matches!(p, Projection::Known(name) if name.eq_ignore_ascii_case("authorization"))
                });

            if !is_direct_target && !is_auth_projection {
                continue;
            }

            if let Some(scheme) = classify_rvalue_auth_scheme(rvalue, body) {
                return Some(scheme);
            }
        }
    }
    None
}

/// Inspects an Rvalue for auth scheme prefixes in concatenations and templates.
/// Also follows `Rvalue::Read(Var(v))` chains (up to a bounded depth) to handle
/// cases where the Authorization property reads from a separate variable that
/// holds the concat result, possibly through intermediate copies.
fn classify_rvalue_auth_scheme(rvalue: &Rvalue, body: &crate::ir::Body) -> Option<AuthScheme> {
    match rvalue {
        // "Basic " + token  or  token + "Basic ..."
        Rvalue::Bin(BinOp::Add, op1, op2) => {
            operand_auth_scheme(op1).or_else(|| operand_auth_scheme(op2))
        }
        // `Basic ${token}` — check the first quasi
        Rvalue::Template(template) => template
            .quasis
            .first()
            .and_then(|q| classify_auth_literal(q)),
        // Authorization: basicAuthHeader — follow read chain to find the defining instruction
        Rvalue::Read(Operand::Var(Variable {
            base: Base::Var(source_var),
            projections,
        })) if projections.is_empty() => follow_var_to_auth_scheme(body, *source_var, 4),
        _ => None,
    }
}

/// Follows a VarId through `Read(Var)` assignments up to `depth` levels to find
/// a `BinOp(Add, ...)` or `Template(...)` that reveals the auth scheme prefix.
fn follow_var_to_auth_scheme(
    body: &crate::ir::Body,
    target: VarId,
    depth: u8,
) -> Option<AuthScheme> {
    if depth == 0 {
        return None;
    }
    for (_, blk) in body.iter_blocks_enumerated() {
        for inst in &blk.insts {
            if let Inst::Assign(var, rval) = inst
                && var.base == Base::Var(target)
                && var.projections.is_empty()
            {
                match rval {
                    Rvalue::Bin(BinOp::Add, op1, op2) => {
                        return operand_auth_scheme(op1).or_else(|| operand_auth_scheme(op2));
                    }
                    Rvalue::Template(template) => {
                        return template
                            .quasis
                            .first()
                            .and_then(|q| classify_auth_literal(q));
                    }
                    Rvalue::Read(Operand::Var(Variable {
                        base: Base::Var(next_var),
                        projections,
                    })) if projections.is_empty() => {
                        return follow_var_to_auth_scheme(body, *next_var, depth - 1);
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

/// Checks whether an operand is a literal string with an auth scheme prefix.
fn operand_auth_scheme(op: &Operand) -> Option<AuthScheme> {
    match op {
        Operand::Lit(Literal::Str(s)) => classify_auth_literal(s),
        _ => None,
    }
}

/// Tries to extract the URL string from a VarId by walking the IR when the
/// value lattice resolves to `Unknown` (e.g. template literals with unknown
/// substitutions where the static quasis still contain the host). Follows
/// `Read(Var)` chains up to a bounded depth to handle intermediate copies.
fn extract_url_prefix_from_body(body: &crate::ir::Body, target: VarId) -> Option<String> {
    extract_url_prefix_from_var(body, target, 4)
}

fn extract_url_prefix_from_var(body: &crate::ir::Body, target: VarId, depth: u8) -> Option<String> {
    if depth == 0 {
        return None;
    }
    for (_, block) in body.iter_blocks_enumerated() {
        for inst in &block.insts {
            let (assigned_var, rvalue) = match inst {
                Inst::Assign(var, rval) => (var, rval),
                Inst::Expr(_) => continue,
            };
            if assigned_var.base != Base::Var(target) || !assigned_var.projections.is_empty() {
                continue;
            }
            match rvalue {
                Rvalue::Bin(BinOp::Add, Operand::Lit(Literal::Str(s)), _) => {
                    return Some(s.to_string());
                }
                Rvalue::Template(template) => {
                    let joined: String = template.quasis.iter().map(|q| q.as_ref()).collect();
                    if !joined.is_empty() {
                        return Some(joined);
                    }
                }
                Rvalue::Read(Operand::Var(Variable {
                    base: Base::Var(source_var),
                    projections,
                })) if projections.is_empty() => {
                    return extract_url_prefix_from_var(body, *source_var, depth - 1);
                }
                _ => {}
            }
        }
    }
    None
}

impl<'cx> Runner<'cx> for AuthHeaderChecker {
    type State = SecretState;
    type Dataflow = AuthHeaderDataflow;

    const NAME: &'static str = "AuthHeader";

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        // Determine if this is a fetch-like or platform API intrinsic.
        // Platform API shims (requestJira, requestConfluence, etc.) are always
        // Atlassian calls, so the api.atlassian.com URL check is skipped.
        let is_platform_api = matches!(intrinsic, Intrinsic::ApiCall(_) | Intrinsic::SafeCall(_));
        let is_fetch = matches!(intrinsic, Intrinsic::Fetch);
        // requestGraph(query, variables, options) — options at index 2
        let is_request_graph = matches!(
            intrinsic,
            Intrinsic::ApiCall(IntrinsicName::RequestGraph)
                | Intrinsic::SafeCall(IntrinsicName::RequestGraph)
        );

        if is_fetch || is_platform_api {
            let ops = operands.unwrap_or_default();

            // requestGraph takes (query, variables, options) so options is at index 2.
            // For fetch and all other request* shims, options is at index 1.
            let opts_index = if is_request_graph { 2 } else { 1 };

            // Resolve URL from operand 0.
            // Try the value lattice first; fall back to IR inspection for
            // template literals / concatenations with unknown parts.
            let url_str: Option<String> = match ops.first() {
                Some(Operand::Var(Variable {
                    base: Base::Var(varid),
                    ..
                })) => match interp.get_value(def, *varid, None) {
                    Some(Value::Const(Const::Literal(s))) => Some(s.clone()),
                    Some(Value::Phi(phi)) => phi.iter().map(|Const::Literal(s)| s.clone()).next(),
                    _ => extract_url_prefix_from_body(interp.body(), *varid),
                },
                Some(Operand::Lit(lit)) => convert_lit_to_raw(lit),
                _ => None,
            };

            if let Some(Operand::Var(Variable {
                base: Base::Var(varid),
                ..
            })) = ops.get(opts_index)
            {
                let varid_argument =
                    if let Some(Value::Object(varid)) = interp.get_value(def, *varid, None) {
                        varid
                    } else {
                        varid
                    };
                let headers_proj = projvec_from_str("headers");
                if let Some(Value::Object(varid)) =
                    interp.get_value(def, *varid_argument, Some(headers_proj))
                {
                    let auth_proj = projvec_from_str("Authorization");
                    let aut_proj_lower = projvec_from_str("authorization");
                    let auth_val = interp
                        .get_value(def, *varid, Some(auth_proj.clone()))
                        .or_else(|| interp.get_value(def, *varid, Some(aut_proj_lower.clone())));

                    // Try to determine the auth scheme from the resolved value.
                    // If the value is fully known, classify directly. If unknown
                    // (e.g. "Basic " + variable), walk the IR to inspect the
                    // operands of the concatenation/template that produced it.
                    let auth_scheme: Option<AuthScheme> = match auth_val {
                        Some(Value::Const(Const::Literal(s))) => classify_auth_literal(s),
                        Some(Value::Phi(phi)) => phi
                            .iter()
                            .find_map(|Const::Literal(s)| classify_auth_literal(s)),
                        Some(Value::Unknown) | None => {
                            // Value collapsed to Unknown — inspect the IR directly.
                            // The auth header VarId is `*varid` from the headers object.
                            extract_auth_scheme_from_body(interp.body(), *varid)
                        }
                        _ => None,
                    };

                    if let Some(scheme) = auth_scheme {
                        match scheme {
                            AuthScheme::Basic => {
                                // Platform API shims (requestJira, requestConfluence,
                                // requestBitbucket, requestGraph) always target
                                // Atlassian APIs — their route operand is opaque
                                // (tagged template) so URL resolution won't help.
                                // For fetch / api.fetch / node-fetch the full URL
                                // must target an Atlassian endpoint.
                                let should_flag = is_platform_api
                                    || url_str.as_deref().is_some_and(is_atlassian_url);
                                if should_flag {
                                    self.vulns.push(AuthHeaderVuln::new(
                                        AuthHeaderVulnKind::BasicAuth,
                                        interp.callstack(),
                                        interp.env(),
                                        interp.entry(),
                                    ));
                                }
                            }
                            AuthScheme::Bearer if is_fetch => {
                                // BearerAdmin is only checked for fetch, not
                                // platform API shims.
                                let should_flag = url_str.as_deref().is_some_and(|s| {
                                    (s.contains("api.atlassian.com") && s.contains("admin"))
                                        || is_admin_path(s)
                                });
                                if should_flag {
                                    self.vulns.push(AuthHeaderVuln::new(
                                        AuthHeaderVulnKind::BearerAdmin,
                                        interp.callstack(),
                                        interp.env(),
                                        interp.entry(),
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        ControlFlow::Continue(*state)
    }
}

impl Checker<'_> for AuthHeaderChecker {
    type Vuln = AuthHeaderVuln;
}

pub struct PermissionDataflow {
    needs_call: Vec<(DefId, Vec<Operand>)>,
    pub varid_to_value: FxHashMap<(DefId, VarId, Option<Projection>), Value>,
    pub defid_to_value: FxHashMap<DefId, Value>,
}

impl PermissionDataflow {
    fn handle_second_arg(&self, value: &Value, intrinsic_argument: &mut IntrinsicArguments) {
        match value {
            Value::Const(Const::Literal(lit)) => {
                intrinsic_argument.second_arg = Some(vec![lit.clone()]);
            }
            Value::Phi(phi_val) => {
                intrinsic_argument.second_arg = Some(
                    phi_val
                        .iter()
                        .map(|Const::Literal(lit)| lit.clone())
                        .collect_vec(),
                )
            }
            _ => {}
        }
    }
}

impl WithCallStack for PermissionVuln<'_> {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

#[derive(Debug, Default, Clone)]
pub struct IntrinsicArguments {
    name: Option<IntrinsicName>,
    first_arg: Option<Vec<String>>,
    second_arg: Option<Vec<String>>,
}

impl<'cx> Dataflow<'cx> for PermissionDataflow {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Runner<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self {
            needs_call: vec![],
            varid_to_value: FxHashMap::default(),
            defid_to_value: FxHashMap::default(),
        }
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[Operand; 4]>,
    ) -> Self::State {
        let mut intrinsic_argument = IntrinsicArguments::default();
        if let Intrinsic::ApiCall(name) | Intrinsic::SafeCall(name) | Intrinsic::Authorize(name) =
            intrinsic
        {
            intrinsic_argument.name = Some(name.clone());
            let (first, second) = (operands.first(), operands.get(1));
            if let Some(operand) = first {
                match operand {
                    Operand::Lit(lit) => {
                        if &Literal::Undef != lit {
                            intrinsic_argument.first_arg = Some(vec![lit.to_string()]);
                        }
                    }
                    Operand::Var(var) => {
                        if let Base::Var(varid) = var.base {
                            if let Some(value) = interp.get_value(_def, varid, None) {
                                add_elements_to_intrinsic_struct(
                                    value,
                                    intrinsic_argument.first_arg.insert(vec![]),
                                );
                            } else if let Some(VarKind::GlobalRef(def)) =
                                interp.body().vars.get(varid)
                                && let Some(value @ Value::Const(_)) =
                                    interp.value_manager.defid_to_value.get(def)
                            {
                                add_elements_to_intrinsic_struct(
                                    value,
                                    intrinsic_argument.first_arg.insert(vec![]),
                                );
                            }
                        }
                    }
                }
            }
            if let Some(Operand::Var(variable)) = second
                && let Base::Var(varid) = variable.base
            {
                let mut method_vec = ProjectionVec::new();
                method_vec.push(Projection::Known("method".into()));
                if let Some(value) = interp.get_value(_def, varid, Some(method_vec)) {
                    self.handle_second_arg(value, &mut intrinsic_argument);
                }
            }

            let intrinsic_func_type = intrinsic_argument.name.unwrap();

            // Handle RequestCompass case first
            if let IntrinsicName::RequestCompass(api_name) = intrinsic_func_type {
                if let Some(oauth_scopes) = interp.compass_permission_resolver.get(&api_name) {
                    interp
                        .permissions
                        .retain(|p| !oauth_scopes.contains(&p.as_str()));
                }
                return initial_state;
            }

            let mut permissions_within_call: Vec<String> = vec![];
            let (resolver, regex_map) = match intrinsic_func_type {
                IntrinsicName::RequestJiraAny => (
                    interp.jira_any_permission_resolver,
                    interp.jira_any_regex_map,
                ),
                IntrinsicName::RequestJiraSoftware => (
                    interp.jira_software_permission_resolver,
                    interp.jira_software_regex_map,
                ),
                IntrinsicName::RequestJiraServiceManagement => (
                    interp.jira_service_management_permission_resolver,
                    interp.jira_service_management_regex_map,
                ),
                IntrinsicName::RequestConfluence => (
                    interp.confluence_permission_resolver,
                    interp.confluence_regex_map,
                ),
                IntrinsicName::RequestJira => {
                    (interp.jira_permission_resolver, interp.jira_regex_map)
                }
                IntrinsicName::RequestBitbucket => (
                    interp.bitbucket_permission_resolver,
                    interp.bitbucket_regex_map,
                ),
                IntrinsicName::RequestCompass(_)
                | IntrinsicName::RequestGraph
                | IntrinsicName::Other => {
                    (&PermissionHashMap::new(), &HashMap::<String, Regex>::new())
                }
            };

            if intrinsic_argument.first_arg.is_none() {
                interp.permissions.drain(..);
            } else {
                intrinsic_argument
                    .first_arg
                    .iter()
                    .for_each(|first_arg_vec| {
                        first_arg_vec.iter().for_each(|first_arg| {
                            let first_arg = first_arg.replace(&['\"'][..], "");
                            let request_types = intrinsic_argument
                                .second_arg
                                .as_ref()
                                .map(|args| {
                                    args.iter()
                                        .map(|arg| translate_request_type(Some(arg)))
                                        .collect::<Vec<_>>()
                                        .into_iter()
                                })
                                .unwrap_or_else(|| vec![RequestType::Get].into_iter());

                            for req_type in request_types {
                                let permissions = check_url_for_permissions(
                                    resolver, regex_map, req_type, &first_arg,
                                );
                                permissions_within_call.extend_from_slice(&permissions);
                            }
                        });
                    });
                interp
                    .permissions
                    .retain(|permissions| !permissions_within_call.contains(permissions));
            }
            // remove all permissions that it finds
        }
        initial_state
    }

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let state = self.super_transfer_call(
            interp,
            def,
            loc,
            _block,
            callee,
            initial_state,
            oprands.clone(),
        );
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return state;
        };

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");
        self.needs_call.push((callee_def, oprands.into_vec()));
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

        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }
        state
    }

    fn join_term<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for (def, _arguments) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}

pub struct PermissionChecker<'a> {
    pub visit: bool,
    pub vulns: Vec<PermissionVuln<'a>>,
}

impl<'a> PermissionChecker<'a> {
    pub fn new() -> Self {
        Self {
            visit: false,
            vulns: vec![],
        }
    }

    pub fn into_vulns(
        mut self,
        permissions: HashSet<&'a str>,
    ) -> impl IntoIterator<Item = PermissionVuln<'a>> {
        if !permissions.is_empty() {
            self.vulns.resize(1, PermissionVuln::new(permissions));
        }
        self.vulns
    }
}

impl Default for PermissionChecker<'_> {
    fn default() -> Self {
        PermissionChecker::new()
    }
}

impl fmt::Display for PermissionVuln<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permission vulnerability")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub enum PermissionTest {
    #[default]
    Yes,
    No,
}

impl JoinSemiLattice for PermissionTest {
    const BOTTOM: Self = Self::Yes;

    #[inline]
    fn join_changed(&mut self, other: &Self) -> bool {
        let old = mem::replace(self, self.join(other));
        old != *self
    }

    #[inline]
    fn join(&self, other: &Self) -> Self {
        max(*other, *self)
    }
}

#[derive(Debug, Clone)]
pub struct PermissionVuln<'a> {
    unused_permissions: Vec<&'a str>,
}

impl<'a> PermissionVuln<'a> {
    pub fn new(unused_permissions: impl IntoIterator<Item = &'a str> + 'a) -> Self {
        PermissionVuln {
            unused_permissions: unused_permissions.into_iter().collect(),
        }
    }
}

pub struct DefinitionAnalysisRunner {
    pub needs_call: Vec<DefId>,
}

impl<'cx> Runner<'cx> for PermissionChecker<'_> {
    type State = PermissionTest;
    type Dataflow = PermissionDataflow;

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(*state)
    }
}

impl<'a> Checker<'_> for PermissionChecker<'a> {
    type Vuln = PermissionVuln<'a>;
}

impl IntoVuln for PermissionVuln<'_> {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        Vulnerability {
            check_name: "Least-Privilege".to_owned(),
            description: "Unused permissions listed in manifest file. Please remove the unused permissions or provide a justification for the unused permissions.".to_string(),
            recommendation: "Remove the unused permissions in manifest file or add a comment explaining why the permissions are needed.",
            proof: format!(
                "Unused permissions found in manifest.yml: {:?}",
                self.unused_permissions
            ),
            severity: Severity::Low,
            app_key: reporter.app_key().to_string(),
            app_name: reporter.app_name().to_string(),
            marketplace_security_requirement: "Requirement 4.0",
            date: reporter.current_date(),
        }
    }
}

impl<'cx> Runner<'cx> for DefinitionAnalysisRunner {
    type State = PermissionTest;
    type Dataflow = DefinitionAnalysisRunner;
    const NAME: &'static str = "DefinitionAnalysis";

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        _state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Break(())
    }
}

impl DefinitionAnalysisRunner {
    pub fn new() -> Self {
        Self {
            needs_call: Vec::default(),
        }
    }
}

impl Default for DefinitionAnalysisRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl<'cx> Dataflow<'cx> for DefinitionAnalysisRunner {
    type State = PermissionTest;

    fn with_interp<C: Runner<'cx, State = Self::State>>(_interp: &Interp<'cx, C>) -> Self {
        Self { needs_call: vec![] }
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

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        callee: &'cx Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let state =
            self.super_transfer_call(interp, def, loc, block, callee, initial_state, oprands);
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return state;
        };

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");

        self.needs_call.push(callee_def);
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
        self.super_join_term(interp, def, block, state, worklist);
        for def in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, interp.call_all);
        }
    }
}
