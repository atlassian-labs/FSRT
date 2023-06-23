use core::fmt;
use forge_utils::FxHashMap;
use itertools::Itertools;
use smallvec::SmallVec;
use std::{cmp::max, iter, mem, ops::ControlFlow, path::PathBuf};

use tracing::{debug, info, warn};

use crate::{
    definitions::{Const, DefId, DefKind, Environment, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, Inst, Intrinsic, Location, Operand, Rvalue, VarId, VarKind,
    },
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
        _interp: &Interp<'cx, C>,
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
        operands: SmallVec<[crate::ir::Operand; 4]>,
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
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
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
            worklist.push_front_blocks(interp.env(), def, vec![]);
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
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
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
        operands: Option<SmallVec<[Operand; 4]>>,
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
                ControlFlow::Continue(*state)
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
        _interp: &Interp<'cx, C>,
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
        operands: SmallVec<[crate::ir::Operand; 4]>,
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
        _block: &'cx BasicBlock,
        callee: &'cx crate::ir::Operand,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
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
            worklist.push_front_blocks(interp.env(), def, vec![]);
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
        operands: Option<SmallVec<[Operand; 4]>>,
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
                ControlFlow::Continue(*state)
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
    needs_call: Vec<(DefId, Vec<DefId>)>,
    variables: FxHashMap<DefId, Value>,
    variables_from_defid: FxHashMap<DefId, Value>,
}

impl WithCallStack for PermissionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl PermisisionDataflow {
    fn add_variables(&mut self, rvalue: &Rvalue, defid: &DefId) {
        match rvalue {
            Rvalue::Read(operand) => {
                if self.variables_from_defid.contains_key(&defid)
                    && self.variables_from_defid.get(&defid).unwrap()
                        != &Value::Const(Const::Literal(operand.clone()))
                {
                    // currently assuming prev value is not phi
                    let prev_vars = &self.variables_from_defid[&defid];
                    match prev_vars {
                        Value::Const(prev_var_const) => {
                            match operand {
                                Operand::Lit(_) => {}
                                Operand::Var(var) => match var.base {
                                    Base::Var(var_id) => {}
                                    _ => {}
                                },
                            }
                            let var_vec =
                                vec![prev_var_const.clone(), Const::Literal(operand.clone())];

                            self.variables_from_defid
                                .insert(*defid, Value::Phi(Vec::from(var_vec)));
                        }
                        _ => {}
                    }
                } else {
                    let value = Value::Const(Const::Literal(operand.clone()));
                    self.variables_from_defid.insert(*defid, value.clone());
                }
            }
            Rvalue::Template(template) => {}
            _ => {}
        }
    }

    fn add_something() {}
}

impl<'cx> Dataflow<'cx> for PermisisionDataflow {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Checker<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self {
            needs_call: vec![],
            variables: FxHashMap::default(),
            variables_from_defid: FxHashMap::default(),
        }
    }

    fn transfer_intrinsic<C: crate::interp::Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        match *intrinsic {
            Intrinsic::ApiCall | Intrinsic::SafeCall | Intrinsic::Authorize => {
                let second = operands.get(1);
                if let Some(operand) = second {
                    match operand {
                        Operand::Lit(lit) => {
                            println!("lit {:?}", lit);
                        }
                        Operand::Var(var) => {
                            if let Base::Var(varid) = var.base {
                                match _interp.curr_body.get().unwrap().vars[varid].clone() {
                                    VarKind::GlobalRef(_def_id) => {
                                        self.read_variable_from_variable(_interp, _def_id);
                                    }
                                    VarKind::LocalDef(_def_id) => {
                                        self.read_variable_from_variable(_interp, _def_id);
                                        println!("parent3 {:?}", _def_id);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        match *intrinsic {
            Intrinsic::Authorize => initial_state,
            Intrinsic::Fetch => initial_state,
            Intrinsic::ApiCall => initial_state,
            Intrinsic::SafeCall => initial_state,
            Intrinsic::EnvRead => initial_state,
            Intrinsic::StorageRead => initial_state,
        }
    }

    fn read_variable_from_variable<C: Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        defid: DefId,
    ) {
        if let Some(value) = self.variables_from_defid.get(&defid) {
            if let Value::Const(const_var) = value {
                match const_var {
                    Const::Literal(_lit) => match _lit {
                        Operand::Var(var) => {
                            if let Base::Var(var_id__) = var.base {
                                let varkind =
                                    _interp.curr_body.get().unwrap().vars[var_id__].clone();
                                match varkind {
                                    VarKind::LocalDef(def__) => {
                                        self.read_variable_from_class(_interp, def__);
                                    }
                                    VarKind::GlobalRef(def__) => {
                                        self.read_variable_from_class(_interp, def__);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    fn read_variable_from_class<C: Checker<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        defid: DefId,
    ) {
        let def_kind = _interp.env().defs.defs.get(defid);
        if let Some(id) = def_kind {
            if let DefKind::GlobalObj(obj_id) = id {
                let class = _interp.env().defs.classes.get(obj_id.clone());
            }
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
        let Some((callee_def, _body)) = self.resolve_call(interp, callee) else {
            return initial_state;
        };

        let mut def_ids_operands = vec![];

        for operand in operands {
            match operand {
                Operand::Var(variable) => match variable.base {
                    Base::Var(varid) => {
                        let varkind = &interp.curr_body.get().unwrap().vars[varid];

                        match varkind {
                            VarKind::LocalDef(defid) => {
                                def_ids_operands.push(defid.clone());
                            }
                            VarKind::GlobalRef(defid) => {
                                if self.variables_from_defid.contains_key(defid) {
                                    def_ids_operands.push(defid.clone());
                                } else {
                                }
                            }
                            VarKind::Arg(defid) => {
                                def_ids_operands.push(defid.clone());
                            }
                            VarKind::Temp { parent } => {
                                if let Some(defid) = parent {
                                    def_ids_operands.push(defid.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                },
                Operand::Lit(lit) => {}
            }
        }

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");
        self.needs_call.push((callee_def, def_ids_operands.clone()));
        initial_state
    }

    fn transfer_block<C: Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
        arguments: Option<Vec<DefId>>,
    ) -> Self::State {
        let mut state: PermissionTest = initial_state;

        if let Some(args) = arguments {
            let mut args = args.clone();
            for var in &interp.curr_body.get().unwrap().vars {
                match var {
                    VarKind::Arg(defid_new) => {
                        let defid_old = args.pop();
                        if let Some(def_id_old_unwrapped) = defid_old {
                            self.variables_from_defid.insert(
                                defid_new.clone(),
                                self.variables_from_defid[&def_id_old_unwrapped.clone()].clone(),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        /* collecting the variables that were used :) */
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);

            match inst {
                Inst::Assign(variable, rvalue) => match variable.base {
                    Base::Var(varid) => {
                        let var_kind = &interp.curr_body.get().unwrap().vars[varid];
                        match var_kind {
                            VarKind::LocalDef(defid) => {
                                match rvalue {
                                    Rvalue::Read(operand) => {
                                        if self.variables_from_defid.contains_key(&defid)
                                            && self.variables_from_defid.get(&defid).unwrap()
                                                != &Value::Const(Const::Literal(operand.clone()))
                                        {
                                            // currently assuming prev value is not phi
                                            let prev_vars = &self.variables_from_defid[&defid];
                                            match prev_vars {
                                                Value::Const(prev_var_const) => {
                                                    let var_vec = vec![
                                                        prev_var_const.clone(),
                                                        Const::Literal(operand.clone()),
                                                    ];

                                                    self.variables_from_defid.insert(
                                                        *defid,
                                                        Value::Phi(Vec::from(var_vec)),
                                                    );
                                                }
                                                _ => {}
                                            }
                                        } else {
                                            match operand {
                                                Operand::Lit(lit) => {
                                                    // let value = Value::Const(Const::Literal(operand.clone()));
                                                    // self.variables_from_defid.insert(*defid, value.clone());
                                                }
                                                Operand::Var(var) => match var.base {
                                                    Base::Var(var_id) => {
                                                        let something =
                                                            &interp.curr_body.get().unwrap().vars
                                                                [var_id];
                                                    }
                                                    _ => {}
                                                },
                                            }
                                            let value =
                                                Value::Const(Const::Literal(operand.clone()));
                                            self.variables_from_defid.insert(*defid, value.clone());
                                        }
                                    }
                                    Rvalue::Template(template) => {}
                                    _ => {}
                                }
                            }
                            VarKind::GlobalRef(defid) => {
                                match rvalue {
                                    Rvalue::Read(operand) => {
                                        if self.variables_from_defid.contains_key(&defid)
                                            && self.variables_from_defid.get(&defid).unwrap()
                                                != &Value::Const(Const::Literal(operand.clone()))
                                        {
                                            // currently assuming prev value is not phi
                                            let prev_vars = &self.variables_from_defid[&defid];
                                            match prev_vars {
                                                Value::Const(prev_var_const) => {
                                                    let var_vec = vec![
                                                        prev_var_const.clone(),
                                                        Const::Literal(operand.clone()),
                                                    ];

                                                    self.variables_from_defid.insert(
                                                        *defid,
                                                        Value::Phi(Vec::from(var_vec)),
                                                    );
                                                }
                                                _ => {}
                                            }
                                        } else {
                                            match operand {
                                                Operand::Lit(lit) => {}
                                                Operand::Var(var) => match var.base {
                                                    Base::Var(var_id) => {
                                                        let something =
                                                            &interp.curr_body.get().unwrap().vars
                                                                [var_id];
                                                    }
                                                    _ => {}
                                                },
                                            }
                                            let value =
                                                Value::Const(Const::Literal(operand.clone()));
                                            self.variables_from_defid.insert(*defid, value.clone());
                                        }
                                    }
                                    Rvalue::Template(template) => {}
                                    _ => {}
                                }
                            }
                            VarKind::Arg(defid) => {
                                match rvalue {
                                    Rvalue::Read(operand) => {
                                        if self.variables_from_defid.contains_key(&defid)
                                            && self.variables_from_defid.get(&defid).unwrap()
                                                != &Value::Const(Const::Literal(operand.clone()))
                                        {
                                            // currently assuming prev value is not phi
                                            let prev_vars = &self.variables_from_defid[&defid];
                                            match prev_vars {
                                                Value::Const(prev_var_const) => {
                                                    let var_vec = vec![
                                                        prev_var_const.clone(),
                                                        Const::Literal(operand.clone()),
                                                    ];

                                                    self.variables_from_defid.insert(
                                                        *defid,
                                                        Value::Phi(Vec::from(var_vec)),
                                                    );
                                                }
                                                _ => {}
                                            }
                                        } else {
                                            match operand {
                                                Operand::Lit(lit) => {}
                                                Operand::Var(var) => match var.base {
                                                    Base::Var(var_id) => {
                                                        let something =
                                                            &interp.curr_body.get().unwrap().vars
                                                                [var_id];
                                                    }
                                                    _ => {}
                                                },
                                            }
                                            let value =
                                                Value::Const(Const::Literal(operand.clone()));
                                            self.variables_from_defid.insert(*defid, value.clone());
                                        }
                                    }
                                    Rvalue::Template(template) => {}
                                    _ => {}
                                }
                            }
                            VarKind::Temp { parent } => {
                                match rvalue {
                                    Rvalue::Template(template) => {}
                                    _ => {}
                                }
                                if let Some(defid) = parent {
                                    self.add_variables(rvalue, defid)
                                }
                            }
                            _ => {}
                        }
                    }

                    _ => {}
                },
                _ => {}
            }
        }
        state
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
        for (def, arguments) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, arguments);
        }
    }
}

pub struct PermissionChecker {
    vulns: Vec<AuthNVuln>,
}

impl PermissionChecker {
    pub fn new() -> Self {
        Self { vulns: vec![] }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = AuthNVuln> {
        self.vulns.into_iter()
    }
}

impl Default for PermissionChecker {
    fn default() -> Self {
        Self::new()
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
    type Dataflow = PermisisionDataflow;
    type Vuln = PermissionVuln;

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(*state)
    }
}

#[derive(Debug)]
pub struct PermissionVuln {
    // unused_permissions: HashSet<ForgePermissions>,
}

impl PermissionVuln {
    pub fn new(/*unused_permissions: HashSet<ForgePermissions> */) -> PermissionVuln {
        PermissionVuln { /*unused_permissions*/ }
    }
}

impl IntoVuln for PermissionVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        Vulnerability {
            check_name: format!("Least-Privilege"),
            description: format!(
                "Unused permissions listed in manifest file:.",
                // self.unused_permissions.into_iter().join(", ")
            ),
            // unused_permissions: Some(self.unused_permissions),
            recommendation: "Remove permissions in manifest file that are not needed.",
            proof: format!("Unused permissions found in manifest.yml"),
            severity: Severity::Low,
            app_key: reporter.app_key().to_string(),
            app_name: reporter.app_name().to_string(),
            date: reporter.current_date(),
        }
    }
}
