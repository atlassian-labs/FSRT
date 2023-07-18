use core::fmt;
use std::{cmp::max, mem, ops::ControlFlow};

use tracing::{debug, info, warn};

use crate::{
    definitions::{Class, Const, DefId, DefKind, Environment, IntrinsicName, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, BinOp, Inst, Intrinsic, Literal, Location, Operand, Rvalue,
        Successors, VarId, VarKind,
    },
    permissionclassifier::check_permission_used,
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    worklist::WorkList,
};

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
    needs_call: Vec<DefId>,
    started: bool,
}

impl<'cx> Dataflow<'cx> for TaintDataflow {
    type State = Vec<Taint>;

    fn with_interp<C: Runner<'cx, State = Self::State>>(interp: &Interp<'cx, C>) -> Self {
        Self {
            needs_call: vec![],
            started: false,
        }
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
        initial_state
    }

    fn transfer_intrinsic<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
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
                let Some(var) = l.as_var_id() else {
                    return initial_state;
                };

                if let Some(var) = v.as_var() {
                    let Some(var_id) = var.as_var_id() else {
                        return initial_state;
                    };
                    let taint = initial_state[var_id.0 as usize];
                    if !self.started && taint == Taint::Yes {
                        let Some(Projection::Known(s)) = var.projections.get(0) else {
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
        arguments: Option<Vec<Value>>,
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

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        _operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
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
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }
    fn visit_block(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        id: BasicBlockId,
        block: &'cx BasicBlock,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        for inst in &block.insts {
            if let Inst::Assign(l, r) = inst {
                if let [Projection::Computed(Base::Var(fst)), Projection::Computed(Base::Var(snd)), ..] =
                    *l.projections
                {
                    if curr_state.get(fst.0 as usize).copied() == Some(Taint::Yes)
                        && curr_state.get(snd.0 as usize).copied() == Some(Taint::Yes)
                    {
                        info!("Prototype pollution vuln detected");
                        return ControlFlow::Break(());
                    }
                }
            }
        }
        ControlFlow::Continue(curr_state.clone())
    }
}

pub struct AuthZChecker {
    visit: bool,
    vulns: Vec<AuthZVuln>,
}

impl AuthZChecker {
    pub fn new() -> Self {
        Self {
            visit: true,
            vulns: vec![],
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthZVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
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
    stackframe: Vec<Frame>,
}

impl fmt::Display for AuthZVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authorization vulnerability")
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
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall if *state == AuthorizeState::No => {
                let vuln = AuthZVuln {
                    stackframe: interp.callstack(),
                };
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

impl<'cx> Checker<'cx> for AuthenticateChecker {
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
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        initial_state
    }

    fn transfer_call<C: crate::interp::Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
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

pub struct SecretChecker {
    visit: bool,
    vulns: Vec<SecretVuln>,
}

impl SecretChecker {
    pub fn new() -> Self {
        Self {
            visit: true,
            vulns: vec![],
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = SecretVuln> {
        // TODO: make this an associated function on the Checker trait.
        self.vulns.into_iter()
    }
}

impl Default for SecretChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SecretVuln {
    stack: String,
    entry_func: String,
    file: PathBuf,
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
        Vulnerability {
            check_name: format!("Hardcoded-Secret-{}", hasher.finish()),
            description: format!(
                "Hardcoded secret found within codebase {} in {:?}.",
                self.entry_func, self.file
            ),
            recommendation: "Use secrets as enviornment variables instead of hardcoding them.",
            proof: format!("Hardcoded secret found in found via {}", self.stack),
            severity: Severity::High,
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
        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) if *state == AuthorizeState::No => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCall(_) => ControlFlow::Continue(*state),
            Intrinsic::SafeCall(_) => ControlFlow::Continue(*state),
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
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self { needs_call: vec![] }
    }

    fn transfer_intrinsic<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::Authorize(_) => initial_state,
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                Authenticated::Yes
            }
            Intrinsic::ApiCall(_) => initial_state,
            Intrinsic::SafeCall(_) => initial_state,
        }
    }

    fn transfer_call<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
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
        interp: &mut Interp<'cx, C>,
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
    visit: bool,
    vulns: Vec<AuthNVuln>,
}

impl AuthenticateChecker {
    pub fn new() -> Self {
        Self {
            visit: false,
            vulns: vec![],
        }
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
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        match *intrinsic {
            Intrinsic::Authorize(_) => ControlFlow::Continue(*state),
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                ControlFlow::Continue(Authenticated::Yes)
            }
            Intrinsic::ApiCall(_) if *state == Authenticated::No => {
                let vuln = AuthNVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Break(())
            }
            Intrinsic::ApiCall(_) => ControlFlow::Continue(*state),
            Intrinsic::SafeCall(_) => ControlFlow::Continue(*state),
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
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

pub struct PermisisionDataflow {
    needs_call: Vec<DefId>,
    variables: FxHashMap<VarId, Value>,
}

impl WithCallStack for PermissionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

#[derive(Debug, Default, Clone)]
pub struct IntrinsicArguments {
    name: Option<IntrinsicName>,
    first_arg: Option<Vec<String>>,
    second_arg: Option<Vec<String>>,
}

impl PermissionDataflow {
    fn handle_first_arg(
        &self,
        operand: &Operand,
        _def: DefId,
        intrinsic_argument: &mut IntrinsicArguments,
    ) {
        match operand {
            Operand::Lit(lit) => {
                intrinsic_argument.first_arg = Some(vec![lit.to_string()]);
            }
            Operand::Var(var) => {
                if let Base::Var(varid) = var.base {
                    if let Some(value) = self.get_value(_def, varid) {
                        intrinsic_argument.first_arg = Some(vec![]);
                        add_elements_to_intrinsic_struct(value, &mut intrinsic_argument.first_arg);
                    }
                }
            }
        }
    }

    fn add_value(&mut self, defid_block: DefId, varid: VarId, value: Value) {
        self.varid_to_value.insert(varid, value);
    }

    fn get_value(&self, defid_block: DefId, varid: VarId) -> Option<&Value> {
        self.varid_to_value.get(&varid)
    }

    fn get_str_from_expr(&self, expr: &Operand, def: DefId) -> Vec<Option<String>> {
        if let Some(str) = get_str_from_operand(expr) {
            return vec![Some(str)];
        } else if let Operand::Var(var) = expr {
            if let Base::Var(varid) = var.base {
                let value = self.get_value(def, varid);
                if let Some(value) = value {
                    match value {
                        Value::Const(const_val) => {
                            if let Const::Literal(str) = const_val {
                                return vec![Some(str.clone())];
                            }
                        }
                        Value::Phi(phi_val) => {
                            return phi_val
                                .iter()
                                .map(|const_val| {
                                    if let Const::Literal(str) = const_val {
                                        Some(str.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect_vec();
                        }
                        _ => {}
                    }
                }
            }
        }
        vec![None]
    }
}

impl<'cx> Dataflow<'cx> for PermissionDataflow {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Checker<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self {
            needs_call: vec![],
            varid_to_value: FxHashMap::default(),
        }
    }

    fn try_insert<C: crate::interp::Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        const_var: Const,
        intrinsic_argument: &mut IntrinsicArguments,
    ) {
        if let Some(val) = self.try_read_mem_from_object(_interp, _def.clone(), const_var.clone()) {
            intrinsic_argument.second_arg = Some(vec![]);
            add_elements_to_intrinsic_struct(val, &mut intrinsic_argument.second_arg);
        }
    }

    fn handle_second_arg<C: crate::interp::Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        operand: &Operand,
        _def: DefId,
        intrinsic_argument: &mut IntrinsicArguments,
    ) {
        if let Some((defid, varid)) = self.get_defid_from_operand(_interp, operand) {
            // getting number 29 here

            println!("defid -varid {defid:?}. {varid:?}");

            println!("varid ~~~ values {:?}", _interp.body().vars.get(varid));

            if let Some(val) = self.get_value(_def, varid) {
                println!("this is the value {val:?}");

                match val {
                    Value::Const(const_var) => {
                        self.try_insert(_interp, _def, const_var.clone(), &mut *intrinsic_argument);
                    }
                    Value::Phi(phi_var) => {
                        phi_var.iter().for_each(|const_val| {
                            self.try_insert(
                                _interp,
                                _def,
                                const_val.clone(),
                                &mut *intrinsic_argument,
                            );
                        });
                    }
                    _ => {}
                }
            } else if let Some(val) = self.def_to_class_property(_interp, _def, defid) {
                /* looks like a misclassification here */
                println!("within class to property {val:?} ");

                println!("this is the value {val:?}");
                intrinsic_argument.second_arg = Some(vec![]);
                add_elements_to_intrinsic_struct(val, &mut intrinsic_argument.second_arg);
                println!("{:?} intrinsic arg second", intrinsic_argument.second_arg);
            }
        } else {
            // println!("found other arg {var:?}")
        }
    }

    fn transfer_intrinsic<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let mut intrinsic_argument = IntrinsicArguments::default();
        if let Intrinsic::ApiCall(name) | Intrinsic::SafeCall(name) | Intrinsic::Authorize(name) =
            intrinsic
        {
            intrinsic_argument.name = Some(name.clone());
            let (first, second) = (operands.get(0), operands.get(1));
            if let Some(operand) = first {
                self.handle_first_arg(operand, _def, &mut intrinsic_argument);
            }
            if let Some(operand) = second {
                self.handle_second_arg(_interp, operand, _def, &mut intrinsic_argument);
            }
            let mut permissions_within_call: Vec<ForgePermissions> = vec![];
            let intrinsic_func_type = intrinsic_argument.name.unwrap();
            intrinsic_argument
                .first_arg
                .iter()
                .for_each(|first_arg_vec| {
                    if let Some(second_arg_vec) = intrinsic_argument.second_arg.clone() {
                        first_arg_vec.iter().for_each(|first_arg| {
                            second_arg_vec.iter().for_each(|second_arg| {
                                let permissions = check_permission_used(
                                    intrinsic_func_type,
                                    first_arg,
                                    Some(second_arg),
                                );
                                permissions_within_call.extend_from_slice(&permissions);
                            })
                        })
                    } else {
                        first_arg_vec.iter().for_each(|first_arg| {
                            let permissions =
                                check_permission_used(intrinsic_func_type, first_arg, None);
                            permissions_within_call.extend_from_slice(&permissions);
                        })
                    }
                });

            println!("intrinsic args {:?}", intrinsic_argument);
            _interp
                .permissions
                .extend_from_slice(&permissions_within_call);
        }
        println!("all permissions: {:?}", _interp.permissions);
        initial_state
    }

    fn read_class_from_object<C: Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        defid: DefId,
    ) -> Option<Class> {
        let def_kind = _interp.env().defs.defs.get(defid);
        if let Some(id) = def_kind {
            if let DefKind::GlobalObj(obj_id) = id {
                let class = _interp.env().defs.classes.get(obj_id.clone());
                if let Some(class) = class {
                    return Some(class.clone());
                }
            }
        }
        None
    }

    fn try_read_mem_from_object<C: Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        const_var: Const,
    ) -> Option<&Value> {
        if let Const::Object(obj) = const_var {
            return self.read_mem_from_object(_interp, _def, obj);
        }
        None
    }

    fn read_mem_from_object<C: Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        obj: Class,
    ) -> Option<&Value> {
        let defid_method = obj
            .pub_members
            .iter()
            .filter(|(mem, _)| mem == "method")
            .map(|(_, defid)| defid)
            .collect_vec();
        if let Some(_alt_defid) = defid_method.get(0) {
            for (varid_new, varkind) in _interp.body().vars.clone().into_iter_enumerated() {
                if let Some(defid) = get_varid_from_defid(&varkind) {
                    if &&defid == _alt_defid {
                        return self.varid_to_value.get(&(_def, varid_new));
                    }
                }
            }
        }
        None
    }

    fn try_read_mem_from_object<C: Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        const_var: Const,
    ) -> Option<&Value> {
        if let Const::Object(obj) = const_var {
            return self.read_mem_from_object(_interp, _def, obj);
        }
        None
    }

    fn read_mem_from_object<C: Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        obj: Class,
    ) -> Option<&Value> {
        let defid_method = obj
            .pub_members
            .iter()
            .filter(|(mem, _)| mem == "method")
            .map(|(_, defid)| defid)
            .collect_vec();
        if let Some(_alt_defid) = defid_method.get(0) {
            for (varid_new, varkind) in _interp.body().vars.clone().into_iter_enumerated() {
                if let Some(defid) = get_defid_from_varkind(&varkind) {
                    if &&defid == _alt_defid {
                        println!(
                            "incorrect value - misinterpreting here {_alt_defid:?} {defid:?} {:?}",
                            self.get_value(_def, varid_new)
                        );
                        return self.get_value(_def, varid_new);
                    }
                }
            }
        }
        None
    }

    fn def_to_class_property<C: Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        defid: DefId,
    ) -> Option<&Value> {
        if let Some(DefKind::GlobalObj(objid)) = _interp.env().defs.defs.get(defid) {
            if let Some(class) = _interp.env().defs.classes.get(objid.clone()) {
                println!("class~~ {class:?}");

                return self.read_mem_from_object(_interp, _def, class.clone());
            }
        }
        None
    }

    fn get_values_from_operand<C: Checker<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        operand: &Operand,
    ) -> Option<&Value> {
        if let Some((_, varid)) = self.get_defid_from_operand(_interp, operand) {
            return self.get_value(_def, varid);
        }
        None
    }

    fn transfer_call<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
    ) -> Self::State {
        for inst in &_block.insts {
            match inst {
                Inst::Assign(variable, rvalue) => match variable.base {
                    Base::Var(varid) => {
                        match rvalue {
                            /* this puts any return value back in the thing */
                            Rvalue::Call(operand, _) => {
                                println!("Expecting return from call {varid:?}"); /* Issue here where the variable is not beign assigned correctly to the proper variable */
                                if let Some((defid, varid)) =
                                    self.get_defid_from_operand(interp, operand)
                                {
                                    interp.expecting_value.push_back((defid, (varid, defid)));
                                }
                                // if let Some((value, defid)) = interp.return_value.clone() {

                                //     //println!("expecitng val {:?}", interp.expecting_value);

                                //     if defid != def {
                                //         //println!("return value being returned {def:?}, {varid:?}, {value:?}");
                                //         //self.add_value(def, varid, value);
                                //     }
                                // }
                                if let Some((defid, _)) =
                                    self.get_defid_from_operand(interp, operand)
                                {
                                    if let Some(return_value) = interp.return_value_alt.get(&defid)
                                    {
                                        println!("kiwi return value {return_value:?} {varid:?}");
                                        self.add_value(def, varid, return_value.clone());
                                    }
                                }
                            }
                            Rvalue::Read(_) => {
                                self.add_variable(interp, &varid, def, rvalue);
                            }
                            Rvalue::Template(_) => {
                                self.add_variable(interp, &varid, def, rvalue);
                            }
                            _ => {}
                        }

                        //self.add_variable(interp, &varid, def, rvalue);
                    }
                    _ => {}
                },
            }
        }

        for (varid, varkind) in interp.body().vars.iter_enumerated() {
            match varkind {
                VarKind::Ret => {
                    for (defid, (varid_value, defid_value)) in &interp.expecting_value {
                        if def == defid.clone() {
                            if let Some(value) = self.get_value(def, varid) {
                                self.add_value(def, varid, value.clone());
                            }
                        }
                    }
                    if let Some(value) = self.get_value(def, varid) {
                        interp.return_value = Some((value.clone(), def));
                        interp.return_value_alt.insert(def, value.clone());
                    }
                }
                _ => {}
            }
        }

        state
    }

    fn add_variable<C: Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        varid: &VarId,
        def: DefId,
        rvalue: &Rvalue,
    ) {
        match rvalue {
            Rvalue::Read(operand) => {
                if let Some(value) = get_prev_value(self.get_value(def, *varid)) {
                    self.insert_value2(operand, varid, def, interp, Some(value));
                } else {
                    self.insert_value2(operand, varid, def, interp, None);
                }
            }
            Rvalue::Template(template) => {
                let quasis_joined = template.quasis.join("");
                let mut all_potential_values = vec![quasis_joined];
                for expr in &template.exprs {
                    if let Some(value) = self.get_value(def, *varid) {
                        match value {
                            // TODO: get values from all of the operands and add them if they do have a value
                            Value::Const(const_value) => {
                                let mut new_all_values = vec![];
                                if let Const::Literal(literal_string) = const_value {
                                    for values in &all_potential_values {
                                        new_all_values.push(values.clone() + literal_string);
                                    }
                                }
                                all_potential_values = new_all_values;
                            }
                            Value::Phi(phi_value) => {
                                let mut new_all_values = vec![];
                                for constant in phi_value {
                                    if let Const::Literal(literal_string) = constant {
                                        for values in &all_potential_values {
                                            new_all_values.push(values.clone() + literal_string);
                                        }
                                    }
                                }
                                all_potential_values = new_all_values;
                            }
                            _ => {}
                        }
                    }
                }

                if all_potential_values.len() > 1 {
                    let consts = all_potential_values
                        .into_iter()
                        .map(|value| Const::Literal(value.clone()))
                        .collect::<Vec<_>>();
                    let value = Value::Phi(consts);
                    self.add_value(def, *varid, value.clone());
                } else if all_potential_values.len() == 1 {
                    self.add_value(
                        def,
                        *varid,
                        Value::Const(Const::Literal(all_potential_values.get(0).unwrap().clone())),
                    );
                }
            }
            Rvalue::Bin(binop, op1, op2) => {
                if binop == &BinOp::Add {
                    let val1 = if let Some(val) = get_str_from_operand(op1) {
                        Some(Value::Const(Const::Literal(val)))
                    } else {
                        self.get_values_from_operand(interp, def, op1).cloned()
                    };
                    let val2 = if let Some(val) = get_str_from_operand(op2) {
                        Some(Value::Const(Const::Literal(val)))
                    } else {
                        self.get_values_from_operand(interp, def, op2).cloned()
                    };
                    let mut new_vals = vec![];
                    if let (Some(val1), Some(val2)) = (val1.clone(), val2.clone()) {
                        match val1 {
                            Value::Const(const_val) => {
                                add_const_to_val_vec(&val2, &const_val, &mut new_vals)
                            }
                            Value::Phi(phi_val) => phi_val
                                .iter()
                                .for_each(|val1| add_const_to_val_vec(&val2, &val1, &mut new_vals)),
                            _ => {}
                        }
                        self.varid_to_value
                            .insert(*varid, return_value_from_string(new_vals));
                    } else if let Some(val1) = val1 {
                        self.add_value(def, *varid, val1);
                    } else if let Some(val2) = val2 {
                        self.add_value(def, *varid, val2);
                    }
                }
            }
            _ => {}
        }
    }

    fn insert_value2<C: Checker<'cx, State = Self::State>>(
        &mut self,
        operand: &Operand,
        varid: &VarId,
        def: DefId,
        interp: &Interp<'cx, C>,
        prev_values: Option<Vec<Const>>,
    ) {
        match operand {
            Operand::Lit(_lit) => {
                if let Some(prev_values) = prev_values {
                    if let Some(lit_value) = convert_operand_to_raw(operand) {
                        let const_value = Const::Literal(lit_value);
                        let mut all_values = prev_values.clone();
                        all_values.push(const_value);
                        let value = Value::Phi(all_values);
                        self.add_value(def, *varid, value);
                    }
                } else {
                    if let Some(lit_value) = convert_operand_to_raw(operand) {
                        let value = Value::Const(Const::Literal(lit_value));
                        self.add_value(def, *varid, value);
                    }
                }
            }
            Operand::Var(var) => {
                if let Base::Var(prev_varid) = var.base {
                    let potential_varkind = &interp.curr_body.get().unwrap().vars.get(prev_varid);
                    if let Some(VarKind::LocalDef(local_defid)) = potential_varkind {
                        if let Some(class) =
                            self.read_class_from_object(interp, local_defid.clone())
                        {
                            if let Some(prev_values) = prev_values {
                                let const_value = Const::Object(class.clone());
                                let mut all_values = prev_values.clone();
                                all_values.push(const_value);
                                let value = Value::Phi(all_values);
                                self.add_value(def, *varid, value);
                            } else {
                                let value = Value::Const(Const::Object(class));
                                self.add_value(def, *varid, value);
                            }
                        }
                    } else {
                        if let Some(potential_value) = self.get_value(def, prev_varid) {
                            self.varid_to_value.insert(*varid, potential_value.clone());
                        }
                    }
                }
            }
        }
    }

    fn join_term<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        self.super_join_term(interp, def, block, state, worklist);
        for (def, arguments, values) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def);
            interp.callstack_arguments.push(values.clone());
        }
    }
}

pub(crate) fn resolve_var_from_operand(operand: &Operand) -> Option<VarId> {
    if let Operand::Var(var) = operand {
        if let Base::Var(varid) = var.base {
            return Some(varid);
        }
    }
    None
}

fn resolve_literal_from_operand(operand: &Operand) -> Option<Literal> {
    if let Operand::Lit(lit) = operand {
        return Some(lit.clone());
    }
    None
}

fn add_const_to_val_vec(val: &Value, const_val: &Const, vals: &mut Vec<String>) {
    match val {
        Value::Const(Const::Literal(lit)) => {
            if let Const::Literal(lit2) = const_val {
                vals.push(lit.to_owned() + &lit2);
            }
        }
        Value::Phi(phi_val2) => phi_val2.iter().for_each(|val2| {
            if let (Const::Literal(lit1), Const::Literal(lit2)) = (&const_val, val2) {
                vals.push(lit1.to_owned() + lit2);
            }
        }),
        _ => {}
    }
}

pub(crate) fn get_defid_from_varkind(varkind: &VarKind) -> Option<DefId> {
    match varkind {
        VarKind::GlobalRef(defid) => Some(defid.clone()),
        VarKind::LocalDef(defid) => Some(defid.clone()),
        VarKind::Arg(defid) => Some(defid.clone()),
        VarKind::AnonClosure(defid) => Some(defid.clone()),
        VarKind::Temp { parent } => parent.clone(),
        _ => None,
    }
}

fn convert_operand_to_raw(operand: &Operand) -> Option<String> {
    if let Operand::Lit(lit) = operand {
        convert_lit_to_raw(lit)
    } else {
        None
    }
}

fn convert_lit_to_raw(lit: &Literal) -> Option<String> {
    match lit {
        Literal::BigInt(bigint) => Some(bigint.to_string()),
        Literal::Number(num) => Some(num.to_string()),
        Literal::Str(str) => Some(str.to_string()),
        _ => None,
    }
}

fn get_str_from_operand(operand: &Operand) -> Option<String> {
    if let Operand::Lit(lit) = operand {
        if let Literal::Str(str) = lit {
            return Some(str.to_string());
        }
    }
    None
}

fn add_elements_to_intrinsic_struct(value: &Value, args: &mut Option<Vec<String>>) {
    match value {
        Value::Const(const_value) => {
            if let Const::Literal(literal) = const_value {
                args.as_mut().unwrap().push(literal.clone());
            }
        }
        Value::Phi(phi_value) => {
            for value in phi_value {
                if let Const::Literal(literal) = value {
                    args.as_mut().unwrap().push(literal.clone());
                }
            }
        }
        _ => {}
    }
}

fn get_prev_value(value: Option<&Value>) -> Option<Vec<Const>> {
    if let Some(value) = value {
        return match value {
            Value::Const(const_value) => Some(vec![const_value.clone()]),
            Value::Phi(phi_value) => Some(phi_value.clone()),
            _ => None,
        };
    }
    None
}

fn return_value_from_string(values: Vec<String>) -> Value {
    // assert!(values.len() > 0);
    if values.len() == 1 {
        return Value::Const(Const::Literal(values.get(0).unwrap().clone()));
    } else {
        return Value::Phi(
            values
                .iter()
                .map(|val_string| Const::Literal(val_string.clone()))
                .collect_vec(),
        );
    }
}

pub struct PermissionChecker {
    pub visit: bool,
    pub vulns: Vec<PermissionVuln>,
    pub declared_permissions: HashSet<ForgePermissions>,
    pub used_permissions: HashSet<ForgePermissions>,
}

impl PermissionChecker {
    pub fn new(declared_permissions: HashSet<ForgePermissions>) -> Self {
        Self {
            visit: false,
            vulns: vec![],
            declared_permissions,
            used_permissions: HashSet::default(),
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = PermissionVuln> {
        if self.declared_permissions.len() > 0 {
            println!("here in wrong case");
            return Vec::from([PermissionVuln {
                unused_permissions: self.declared_permissions.clone(),
            }])
            .into_iter();
        }
        self.vulns.into_iter()
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new(HashSet::new())
    }
}

impl fmt::Display for PermissionVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Authentication vulnerability")
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum PermissionTest {
    Yes,
}

impl JoinSemiLattice for PermissionTest {
    const BOTTOM: Self = Self::Yes;

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

impl<'cx> Checker<'cx> for PermissionChecker {
    type State = PermissionTest;
    type Dataflow = PermissionDataflow;
    type Vuln = PermissionVuln;

    fn visit(&mut self) -> bool {
        self.visit
    }

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        for permission in &interp.permissions {
            self.declared_permissions.remove(permission);
            self.used_permissions.insert(permission.clone());
        }
        ControlFlow::Continue(*state)
    }
}

#[derive(Debug)]
pub struct PermissionVuln {
    unused_permissions: HashSet<ForgePermissions>,
}

impl PermissionVuln {
    pub fn new(unused_permissions: HashSet<ForgePermissions>) -> PermissionVuln {
        PermissionVuln { unused_permissions }
    }
}

impl IntoVuln for PermissionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        Vulnerability {
            check_name: format!("Least-Privilege"),
            description: format!(
                "Unused permissions listed in manifest file: {:?}",
                self.unused_permissions
            ),
            recommendation: "Remove permissions in manifest file that are not needed.",
            proof: format!(
                "Unused permissions found in manifest.yml: {:?}",
                self.unused_permissions
            ),
            severity: Severity::Low,
            app_key: reporter.app_key().to_string(),
            app_name: reporter.app_name().to_string(),
            date: reporter.current_date(),
        }
    }
}
