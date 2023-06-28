use core::fmt;
use forge_loader::forgepermissions::ForgePermissions;
use forge_utils::FxHashMap;
use itertools::Itertools;
use smallvec::SmallVec;
use std::{cmp::max, collections::HashSet, iter, mem, ops::ControlFlow, path::PathBuf};

use tracing::{debug, info, warn};

use crate::{
    definitions::{Class, Const, DefId, DefKind, Environment, Value},
    interp::{
        Checker, Dataflow, EntryKind, EntryPoint, Frame, Interp, JoinSemiLattice, WithCallStack,
    },
    ir::{
        Base, BasicBlock, BasicBlockId, Inst, Intrinsic, Literal, Location, Operand, Rvalue,
        Successors, VarId, VarKind,
    },
    permissionclassifier::{check_intrinsic_permission, check_permission_used},
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
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        intrinsic: &'cx Intrinsic,
        initial_state: Self::State,
        operands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        if let Some(intrinsic_state) = _interp.pop_intrinsic_state(_loc) {
            if let Some(first_args) = intrinsic_state.first_arg {
                if check_intrinsic_permission(first_args.clone()) {
                    println!("here {first_args:?}");
                    return AuthorizeState::Yes;
                }
            }
        }
        return AuthorizeState::Yes;

        match *intrinsic {
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                AuthorizeState::Yes
            }
            Intrinsic::Fetch => initial_state,
            Intrinsic::ApiCall(_) => initial_state,
            Intrinsic::SafeCall(_) => initial_state,
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
        return AuthorizeState::Yes;
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
        interp: &mut Interp<'cx, C>,
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
            Intrinsic::Authorize(_) => {
                debug!("authorize intrinsic found");
                ControlFlow::Continue(AuthorizeState::Yes)
            }
            Intrinsic::Fetch => ControlFlow::Continue(*state),
            Intrinsic::ApiCall(_) if *state == AuthorizeState::No => {
                let vuln = AuthZVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Continue(*state)
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
        interp: &mut Interp<'cx, C>,
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
            Intrinsic::Authorize(_) => ControlFlow::Continue(*state),
            Intrinsic::Fetch | Intrinsic::EnvRead | Intrinsic::StorageRead => {
                debug!("authenticated");
                ControlFlow::Continue(Authenticated::Yes)
            }
            Intrinsic::ApiCall(_) if *state == Authenticated::No => {
                let vuln = AuthNVuln::new(interp.callstack(), interp.env(), interp.entry());
                info!("Found a vuln!");
                self.vulns.push(vuln);
                ControlFlow::Continue(*state)
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

pub struct PermissionDataflow {
    needs_call: Vec<(DefId, Vec<Operand>)>,
    variables_from_defid: FxHashMap<DefId, Value>,
}

impl WithCallStack for PermissionVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

#[derive(Debug, Default, Clone)]
pub struct IntrinsicArguments {
    name: Option<String>,
    first_arg: Option<Vec<String>>,
    second_arg: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
pub enum IntrinsicName {
    RequestConfluence,
    RequestJira,
}

impl<'cx> Dataflow<'cx> for PermissionDataflow {
    type State = PermissionTest;

    fn with_interp<C: crate::interp::Checker<'cx, State = Self::State>>(
        _interp: &Interp<'cx, C>,
    ) -> Self {
        Self {
            needs_call: vec![],
            variables_from_defid: FxHashMap::default(),
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

        match &*intrinsic {
            Intrinsic::ApiCall(value)
            | Intrinsic::SafeCall(value)
            | Intrinsic::Authorize(value) => {
                intrinsic_argument.name = Some(value.clone());
                let (first, second) = (operands.get(0), operands.get(1));
                if let Some(operand) = first {
                    match operand {
                        Operand::Lit(lit) => {
                            intrinsic_argument.first_arg = Some(vec![lit.to_string()]);
                        }
                        Operand::Var(var) => match var.base {
                            Base::Var(varid) => {
                                let varkind = &_interp.curr_body.get().unwrap().vars[varid];
                                let defid = get_varid_from_defid(&varkind);
                                if let Some(defid) = defid {
                                    if let Some(value) = self.variables_from_defid.get(&defid) {
                                        intrinsic_argument.first_arg = Some(vec![]);
                                        add_elements_to_intrinsic_struct(
                                            value,
                                            &mut intrinsic_argument.first_arg,
                                        );
                                    }
                                }
                            }
                            _ => {}
                        },
                    }
                }
                if let Some(operand) = second {
                    match operand {
                        Operand::Lit(_) => {}
                        Operand::Var(var) => {
                            if let Base::Var(varid) = var.base {
                                match _interp.curr_body.get().unwrap().vars[varid].clone() {
                                    VarKind::GlobalRef(_def_id) => {
                                        /* case where it is passed in as a variable */
                                        match &self.variables_from_defid.get(&_def_id).unwrap() {
                                            Value::Const(const_var) => {
                                                if let Const::Object(obj) = const_var {
                                                    let defid = find_member_of_obj("method", obj);
                                                    if let Some(defid) = defid {
                                                        if let Some(value) =
                                                            self.variables_from_defid.get(&defid)
                                                        {
                                                            intrinsic_argument.second_arg =
                                                                Some(vec![]);
                                                            add_elements_to_intrinsic_struct(
                                                                value,
                                                                &mut intrinsic_argument.second_arg,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Value::Phi(phi_var) => {}
                                            _ => {}
                                        }
                                    }
                                    VarKind::LocalDef(_def_id) => {
                                        let class = self.read_class_from_object(_interp, _def_id);
                                        if let Some(obj) = class {
                                            let defid = find_member_of_obj("method", &obj);
                                            if let Some(defid) = defid {
                                                if let Some(value) =
                                                    self.variables_from_defid.get(&defid)
                                                {
                                                    intrinsic_argument.second_arg = Some(vec![]);
                                                    add_elements_to_intrinsic_struct(
                                                        value,
                                                        &mut intrinsic_argument.second_arg,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                let mut permissions_within_call: Vec<ForgePermissions> = vec![];
                let function_name =
                    if intrinsic_argument.clone().name.unwrap() == String::from("requestJira") {
                        IntrinsicName::RequestJira
                    } else {
                        IntrinsicName::RequestConfluence
                    };

                intrinsic_argument
                    .clone()
                    .first_arg
                    .iter()
                    .for_each(|first_arg_vec| {
                        intrinsic_argument
                            .second_arg
                            .iter()
                            .for_each(|second_arg_vec| {
                                first_arg_vec.iter().for_each(|first_arg| {
                                    second_arg_vec.iter().for_each(|second_arg| {
                                        let permissions = check_permission_used(
                                            function_name,
                                            first_arg,
                                            Some(second_arg),
                                        );
                                        permissions_within_call.extend_from_slice(&permissions);
                                    })
                                })
                            })
                    });

                _interp
                    .permissions
                    .extend_from_slice(&permissions_within_call);
            }
            _ => {}
        }
        _interp.push_intrinsic_state(_loc, &intrinsic_argument);
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

        let callee_name = interp.env().def_name(callee_def);
        let caller_name = interp.env().def_name(def);
        debug!("Found call to {callee_name} at {def:?} {caller_name}");
        self.needs_call.push((callee_def, operands.into_vec()));
        initial_state
    }

    fn transfer_block<C: Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: Self::State,
        arguments: Option<Vec<Operand>>,
    ) -> Self::State {
        let mut state = initial_state;

        let mut function_var = interp.curr_body.get().unwrap().vars.clone();
        function_var.pop();

        if let Some(args) = arguments {
            let mut args = args.clone();
            args.reverse();
            for var in function_var {
                if let VarKind::Arg(defid_new) = var {
                    if let Some(operand) = args.pop() {
                        self.insert_value(&operand, &defid_new, interp, None);
                    }
                }
            }
        }

        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
            match inst {
                Inst::Assign(variable, rvalue) => match variable.base {
                    Base::Var(varid) => {
                        let varkind = &interp.curr_body.get().unwrap().vars[varid];
                        if let Some(defid) = get_varid_from_defid(varkind) {
                            self.add_variable(interp, &defid, rvalue);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        state
    }

    fn add_variable<C: Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        defid: &DefId,
        rvalue: &Rvalue,
    ) {
        match rvalue {
            Rvalue::Read(operand) => {
                if let Some(values) = self.variables_from_defid.get(&defid) {
                    match values {
                        Value::Const(const_value) => {
                            let prev_value = vec![const_value.clone()];
                            self.insert_value(operand, defid, interp, Some(prev_value.clone()));
                        }
                        Value::Phi(phi_value) => {
                            self.insert_value(operand, defid, interp, Some(phi_value.clone()));
                        }
                        _ => {}
                    }
                } else {
                    self.insert_value(operand, defid, interp, None)
                }
            }
            Rvalue::Template(template) => {
                // self.insert_value(operand, defid, interp, None);

                let quasis_joined = template.quasis.join("");
                let mut all_potential_values = vec![quasis_joined];
                for expr in &template.exprs {
                    if let Some(varid) = resolve_var_from_operand(&expr) {
                        if let Some(varkind) = interp.curr_body.get().unwrap().vars.get(varid) {
                            let defid = get_varid_from_defid(&varkind);
                            if let Some(defid) = defid {
                                if let Some(value) = self.variables_from_defid.get(&defid) {
                                    match value {
                                        Value::Const(const_value) => {
                                            let mut new_all_values = vec![];
                                            if let Const::Literal(literal_string) = const_value {
                                                for values in &all_potential_values {
                                                    new_all_values
                                                        .push(values.clone() + literal_string);
                                                }
                                            }
                                            all_potential_values = new_all_values;
                                        }
                                        Value::Phi(phi_value) => {
                                            let mut new_all_values = vec![];
                                            for constant in phi_value {
                                                if let Const::Literal(literal_string) = constant {
                                                    for values in &all_potential_values {
                                                        new_all_values
                                                            .push(values.clone() + literal_string);
                                                    }
                                                }
                                            }
                                            all_potential_values = new_all_values;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    } else if let Some(literal) = resolve_literal_from_operand(&expr) {
                        /* add literal functionality */
                    }
                }

                if all_potential_values.len() > 1 {
                    let consts = all_potential_values
                        .into_iter()
                        .map(|value| Const::Literal(value.clone()))
                        .collect::<Vec<_>>();
                    let value = Value::Phi(consts);
                    self.variables_from_defid.insert(*defid, value.clone());
                } else if all_potential_values.len() == 1 {
                    self.variables_from_defid.insert(
                        *defid,
                        Value::Const(Const::Literal(all_potential_values.get(0).unwrap().clone())),
                    );
                }
            }
            Rvalue::Bin(binop, op1, op2) => { /* add bin op functionality */ }
            _ => {}
        }
    }

    fn insert_value<C: Checker<'cx, State = Self::State>>(
        &mut self,
        operand: &Operand,
        defid: &DefId,
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
                        self.variables_from_defid.insert(*defid, value.clone());
                    }
                } else {
                    if let Some(lit_value) = convert_operand_to_raw(operand) {
                        let value = Value::Const(Const::Literal(lit_value));
                        self.variables_from_defid.insert(*defid, value.clone());
                    }
                }
            }
            Operand::Var(var) => match var.base {
                Base::Var(var_id) => {
                    let varkind = &interp.curr_body.get().unwrap().vars[var_id];
                    if let VarKind::LocalDef(local_defid) = varkind {
                        if let Some(class) =
                            self.read_class_from_object(interp, local_defid.clone())
                        {
                            if let Some(prev_values) = prev_values {
                                let const_value = Const::Object(class.clone());
                                let mut all_values = prev_values.clone();
                                all_values.push(const_value);
                                let value = Value::Phi(all_values);
                                self.variables_from_defid.insert(*defid, value.clone());
                            } else {
                                let value = Value::Const(Const::Object(class.clone()));
                                self.variables_from_defid.insert(*defid, value.clone());
                            }
                        } else if let Some(value) = self.variables_from_defid.get(defid) {
                            /* add value from defid */
                        }
                    }
                }
                _ => {}
            },
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
        for (def, arguments) in self.needs_call.drain(..) {
            worklist.push_front_blocks(interp.env(), def, arguments.clone());
            interp.callstack_arguments.push(arguments.clone());
        }
    }
}

fn resolve_var_from_operand(operand: &Operand) -> Option<VarId> {
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

fn get_varid_from_defid(varkind: &VarKind) -> Option<DefId> {
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

fn find_member_of_obj(member: &str, obj: &Class) -> Option<DefId> {
    for (mem, memdefid) in &obj.pub_members {
        if mem == member {
            return Some(memdefid.clone());
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

pub struct PermissionChecker {
    pub vulns: Vec<PermissionVuln>,
    pub declared_permissions: HashSet<ForgePermissions>,
    pub used_permissions: HashSet<ForgePermissions>,
}

impl PermissionChecker {
    pub fn new(declared_permissions: HashSet<ForgePermissions>) -> Self {
        Self {
            vulns: vec![],
            declared_permissions,
            used_permissions: HashSet::default(),
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = PermissionVuln> {
        if self.declared_permissions.len() > 0 {
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
