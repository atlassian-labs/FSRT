use std::{
    borrow::BorrowMut,
    cell::{Cell, RefCell, RefMut},
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::{self, Display},
    hash::Hash,
    iter,
    marker::PhantomData,
    ops::ControlFlow,
    path::PathBuf,
};

use forge_permission_resolver::permissions_resolver::PermissionHashMap;
use forge_permission_resolver::permissions_resolver_compass::CompassPermissionResolver;
use forge_utils::{FxHashMap, FxHashSet};
use itertools::Itertools;
use regex::Regex;
use smallvec::SmallVec;
use swc_core::ecma::atoms::Atom;
use tracing::{debug, instrument, trace, warn};

use crate::definitions::DefKind;
use crate::ir::{BinOp, Literal, VarKind};
use crate::utils::{
    convert_lit_to_raw, get_defid_from_varkind, projvec_from_projvec, return_combinations_phi,
};
use crate::{
    checkers::IntrinsicArguments,
    definitions::{Const, DefId, Environment, Value},
    ir::{
        Base, BasicBlock, BasicBlockId, Body, Inst, Intrinsic, Location, Operand, Projection,
        Rvalue, STARTING_BLOCK, Successors, VarId, Variable,
    },
    worklist::WorkList,
};

#[cfg(test)]
mod tests;

pub type DefinitionAnalysisMapProjection = BTreeMap<(DefId, VarId, ProjectionVec), Value>;

pub type DefinitionAnalysisMap = FxHashMap<(DefId, VarId), Value>;

pub type ProjectionVec = SmallVec<[Projection; 1]>;

pub trait JoinSemiLattice: Sized + Ord {
    const BOTTOM: Self;

    fn join_changed(&mut self, other: &Self) -> bool;
    fn join(&self, other: &Self) -> Self;
}

pub enum Transition {
    Call,
    Break,
    StepOver,
}

pub trait WithCallStack {
    fn add_call_stack(&mut self, stack: Vec<DefId>);
}

pub trait Dataflow<'cx>: Sized {
    type State: JoinSemiLattice + Clone;

    fn with_interp<C: Runner<'cx, State = Self::State>>(interp: &Interp<'cx, C>) -> Self;

    /// Override the legacy effect analysis for value-sensitive analyses. Return
    /// true after computing block inputs, function summaries and instruction findings.
    fn analyze<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &mut Interp<'cx, C>,
        _entry: DefId,
    ) -> bool {
        false
    }

    #[inline]
    fn resolve_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        callee: &Operand,
    ) -> Option<(DefId, &'cx Body)> {
        interp.body().resolve_call(interp.env(), callee)
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
    ) -> Self::State;

    fn transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        self.super_transfer_call(interp, def, _loc, _block, callee, initial_state, oprands)
    }

    fn super_transfer_call<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        def: DefId,
        _loc: Location,
        _block: &'cx BasicBlock,
        callee: &'cx Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State {
        let all_values_to_be_pushed = oprands
            .into_iter()
            .map(|operand| interp.value_from_operand(def, operand))
            .collect();
        if let Some((callee_def, _body)) = interp.body().resolve_call(interp.env(), callee) {
            interp
                .value_manager
                .expecting_value
                .borrow_mut()
                .insert(callee_def, (def, all_values_to_be_pushed));
        }
        initial_state
    }

    fn transfer_rvalue<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        rvalue: &'cx Rvalue,
        initial_state: Self::State,
    ) -> Self::State {
        match rvalue {
            Rvalue::Intrinsic(intrinsic, args) => self.transfer_intrinsic(
                interp,
                def,
                loc,
                block,
                intrinsic,
                initial_state,
                args.clone(),
            ),
            Rvalue::Call(callee, operands) => self.transfer_call(
                interp,
                def,
                loc,
                block,
                callee,
                initial_state,
                operands.clone(),
            ),
            Rvalue::Unary(_, _) => initial_state,
            Rvalue::Bin(_, _, _) => initial_state,
            Rvalue::Read(_) => initial_state,
            Rvalue::Phi(_) => initial_state,
            Rvalue::Template(_) => initial_state,
        }
    }

    fn transfer_inst<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        inst: &'cx Inst,
        initial_state: Self::State,
    ) -> Self::State {
        if let Rvalue::Call(callee, _) = inst.rvalue()
            && let Some((callee, _)) = interp.body().resolve_call(interp.env(), callee)
        {
            interp.value_manager.expecting_captures.insert(callee, def);
        }
        match inst {
            Inst::Expr(rvalue) => {
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
            Inst::Assign(var, rvalue) => {
                interp.add_value_to_definition(def, var.clone(), rvalue.clone());
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
        initial_state: Self::State,
    ) -> Self::State {
        let mut state = initial_state;
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            trace!(?def, ?loc, ?inst, "transferring instruction");
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }
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
        self.super_join_term(interp.borrow_mut(), def, block, state, worklist);
    }

    fn super_join_term<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        block: &'cx BasicBlock,
        state: Self::State,
        worklist: &mut WorkList<DefId, BasicBlockId>,
    ) {
        match block.successors() {
            Successors::Return => {
                if interp
                    .func_state(def)
                    .is_none_or(|old_state| old_state < state)
                {
                    interp.set_func_state(def, state);
                    let calls = interp.called_from(def);
                    let name = interp.env().def_name(def);
                    debug!("{name} {def:?} is called from {calls:?}");
                    for &(caller_def, loc) in calls {
                        if worklist.visited(&caller_def) {
                            worklist.push_back_force(caller_def, loc.block);
                        }
                    }
                }
            }
            Successors::One(succ) => {
                interp.block_state_mut(def, succ).join_changed(&state);
            }
            Successors::Two(succ1, succ2) => {
                interp.block_state_mut(def, succ1).join_changed(&state);
                interp.block_state_mut(def, succ2).join_changed(&state);
            }
        }
    }

    fn try_insert<C: crate::interp::Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        _const_var: Const,
        _intrinsic_argument: &mut IntrinsicArguments,
    ) {
    }
}

pub trait Runner<'cx>: Sized {
    type State: JoinSemiLattice + Clone + fmt::Debug;
    type Dataflow: Dataflow<'cx, State = Self::State>;

    const VISIT_ALL: bool = true;

    const VISIT_GLOBALS: bool = false;

    const NAME: &'static str = "Runner";

    /// Evaluate a value-sensitive sink against the state before its instruction.
    /// Dataflow retains only matching locations for the later diagnostic walk;
    /// unrelated instructions never retain copies of the full variable state.
    fn instruction_has_violation(_inst: &Inst, _state: &Self::State) -> bool {
        false
    }

    fn visit_intrinsic(
        &mut self,
        interp: &Interp<'cx, Self>,
        intrinsic: &'cx Intrinsic,
        def: DefId,
        state: &Self::State,
        operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State>;

    fn visit_call(
        &mut self,
        interp: &Interp<'cx, Self>,
        callee: &'cx Operand,
        _args: &'cx [Operand],
        block: BasicBlockId,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        let Some((callee, body)) = interp.body().resolve_call(interp.env(), callee) else {
            return ControlFlow::Continue(curr_state.clone());
        };

        let func_state = interp.func_state(callee).unwrap_or(Self::State::BOTTOM);
        if func_state < *curr_state || !interp.checker_visit(callee) {
            return ControlFlow::Continue(curr_state.clone());
        }
        interp.push_frame(callee, block);
        let res = self.visit_body(interp, callee, body, curr_state);
        interp.pop_frame();
        // FIXME: Should probably join instead of relying on the caller to propogate state
        res
    }

    fn visit_body(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        body: &'cx Body,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        let name = interp.env.def_name(def);
        debug!("visiting body of {name}");
        let old_body = interp.body();
        interp.set_body(body);
        let block = body.block(STARTING_BLOCK);
        let res = self.visit_block(interp, def, STARTING_BLOCK, block, curr_state);
        interp.set_body(old_body);
        res
    }

    fn visit_rvalue(
        &mut self,
        interp: &Interp<'cx, Self>,
        rvalue: &'cx Rvalue,
        def: DefId,
        id: BasicBlockId,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        trace!("visiting rvalue {rvalue:?} with {curr_state:?}");
        match rvalue {
            Rvalue::Intrinsic(intrinsic, operands) => {
                self.visit_intrinsic(interp, intrinsic, def, curr_state, Some(operands.clone()))
            }
            Rvalue::Call(callee, args) => self.visit_call(interp, callee, args, id, curr_state),
            Rvalue::Unary(_, _)
            | Rvalue::Bin(_, _, _)
            | Rvalue::Read(_)
            | Rvalue::Phi(_)
            | Rvalue::Template(_) => ControlFlow::Continue(curr_state.clone()),
        }
    }

    fn visit_block(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        id: BasicBlockId,
        block: &'cx BasicBlock,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        interp.runner_visited.borrow_mut().insert((def, id));
        let mut curr_state = interp.block_state(def, id).join(curr_state);
        for (idx, stmt) in block.iter().enumerate() {
            let loc = Location::new(id, idx as u32);
            curr_state = self.visit_inst(interp, def, loc, stmt, &curr_state)?;
        }
        match block.successors() {
            Successors::Return => ControlFlow::Continue(curr_state),
            Successors::One(succ) => {
                if !interp.runner_visited.borrow().contains(&(def, succ)) {
                    let bb = interp.body().block(succ);
                    self.visit_block(interp, def, succ, bb, &curr_state)
                } else {
                    ControlFlow::Continue(curr_state)
                }
            }
            Successors::Two(succ1, succ2) => {
                let bb = interp.body().block(succ1);
                if !interp.runner_visited.borrow().contains(&(def, succ1)) {
                    self.visit_block(interp, def, succ1, bb, &curr_state)?;
                }
                let bb = interp.body().block(succ2);
                if !interp.runner_visited.borrow().contains(&(def, succ2)) {
                    self.visit_block(interp, def, succ2, bb, &curr_state)
                } else {
                    ControlFlow::Continue(curr_state)
                }
            }
        }
    }

    fn visit_inst(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        loc: Location,
        inst: &'cx Inst,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state)
    }
}

pub trait Checker<'cx>: Sized + Runner<'cx> {
    type Vuln: Display + WithCallStack;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Frame {
    pub(crate) calling_function: DefId,
    pub(crate) block: BasicBlockId,
    pub(crate) inst_idx: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) enum EntryKind {
    Function(String),
    Resolver(String, Atom),
    #[default]
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct EntryPoint {
    pub(crate) file: PathBuf,
    pub(crate) kind: EntryKind,
}

#[derive(Debug)]
pub struct Interp<'cx, C: Runner<'cx>> {
    pub env: &'cx Environment,
    // We can probably get rid of these RefCells by refactoring the Interp and Checker into
    // two fields in another struct.
    pub call_all: bool,
    pub call_uncalled: bool,
    call_graph: CallGraph,
    pub return_value: Option<(Value, DefId)>,
    pub return_value_alt: HashMap<DefId, Value>,
    pub(crate) entry: EntryPoint,
    func_state: RefCell<FxHashMap<DefId, C::State>>,
    pub curr_body: Cell<Option<&'cx Body>>,
    states: RefCell<BTreeMap<(DefId, BasicBlockId), C::State>>,
    pub(crate) instruction_findings: BTreeSet<(DefId, Location)>,
    dataflow_visited: FxHashSet<DefId>,
    checker_visited: RefCell<FxHashSet<DefId>>,
    callstack: RefCell<Vec<Frame>>,
    pub(crate) runner_visited: RefCell<FxHashSet<(DefId, BasicBlockId)>>,
    pub value_manager: ValueManager,
    pub permissions: Vec<String>,
    pub jira_any_permission_resolver: &'cx PermissionHashMap,
    pub jira_software_permission_resolver: &'cx PermissionHashMap,
    pub jira_service_management_permission_resolver: &'cx PermissionHashMap,
    pub jira_permission_resolver: &'cx PermissionHashMap,
    pub confluence_permission_resolver: &'cx PermissionHashMap,
    pub bitbucket_permission_resolver: &'cx PermissionHashMap,
    pub compass_permission_resolver: &'cx CompassPermissionResolver,
    pub jira_any_regex_map: &'cx HashMap<String, Regex>,
    pub jira_software_regex_map: &'cx HashMap<String, Regex>,
    pub jira_service_management_regex_map: &'cx HashMap<String, Regex>,
    pub jira_regex_map: &'cx HashMap<String, Regex>,
    pub confluence_regex_map: &'cx HashMap<String, Regex>,
    pub bitbucket_regex_map: &'cx HashMap<String, Regex>,
    _checker: PhantomData<C>,
}

#[derive(Debug)]
pub struct ValueManager {
    pub varid_to_value_with_proj: DefinitionAnalysisMapProjection,
    pub varid_to_value: DefinitionAnalysisMap,
    pub defid_to_value: FxHashMap<DefId, Value>,
    pub expecting_value: RefCell<FxHashMap<DefId, (DefId, Vec<Value>)>>,
    pub expected_return_values: HashMap<DefId, (DefId, VarId)>,
    expecting_captures: FxHashMap<DefId, DefId>,
    // Imported objects occupy value-manager-only slots after a body's IR variables.
    // Keep the originating body/slot for analyses that inspect unresolved values' IR.
    imported_vars: FxHashMap<(DefId, DefId, VarId), VarId>,
    value_origins: FxHashMap<(DefId, VarId), (DefId, VarId)>,
    next_imported_var: FxHashMap<DefId, u32>,
    changed: bool,
}

impl ValueManager {
    pub fn reset_changed(&mut self) {
        self.changed = false;
    }

    pub fn has_changed(&self) -> bool {
        self.changed
    }

    pub fn insert_var(&mut self, def_id_func: DefId, var_id: VarId, value: Value) {
        let key = (def_id_func, var_id);
        if self.varid_to_value.get(&key) != Some(&value) {
            self.changed = true;
        }
        self.varid_to_value.insert(key, value);
    }

    pub fn insert_var_with_projection(
        &mut self,
        def_id_func: DefId,
        var_id: VarId,
        projection_vec: ProjectionVec,
        value: Value,
    ) {
        if projection_vec.is_empty() {
            self.insert_var(def_id_func, var_id, value);
        } else {
            let key = (def_id_func, var_id, projection_vec);
            if self.varid_to_value_with_proj.get(&key) != Some(&value) {
                self.changed = true;
            }
            self.varid_to_value_with_proj.insert(key, value);
        }
    }

    pub fn insert_defid_value(&mut self, def_id: DefId, value: Value) {
        if self.defid_to_value.get(&def_id) != Some(&value) {
            self.changed = true;
        }
        self.defid_to_value.insert(def_id, value);
    }

    pub fn get_var_with_projection(
        &self,
        def_id_func: DefId,
        var_id: VarId,
        projection_vec: ProjectionVec,
    ) -> Option<&Value> {
        self.get_var_with_projection_internal(
            def_id_func,
            var_id,
            projection_vec,
            &mut FxHashSet::default(),
        )
    }

    fn get_var_with_projection_internal(
        &self,
        def_id_func: DefId,
        var_id: VarId,
        projection_vec: ProjectionVec,
        visited: &mut FxHashSet<VarId>,
    ) -> Option<&Value> {
        if !visited.insert(var_id) {
            return None;
        }
        if let Some(value) =
            self.varid_to_value_with_proj
                .get(&(def_id_func, var_id, projection_vec.clone()))
        {
            Some(value)
        } else if let Some(Value::Object(next_var_id)) =
            self.varid_to_value.get(&(def_id_func, var_id))
        {
            self.get_var_with_projection_internal(
                def_id_func,
                *next_var_id,
                projection_vec,
                visited,
            )
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct CallGraph {
    called_from: FxHashMap<DefId, Vec<(DefId, Location)>>,
    // (Caller, Callee) -> Location
    callgraph: BTreeMap<(DefId, DefId), Location>,
}

impl CallGraph {
    fn new(env: &Environment) -> Self {
        let mut called_from: FxHashMap<_, Vec<(_, Location)>> = FxHashMap::default();
        let callgraph = env
            .bodies()
            .filter_map(|body| body.owner().zip(Some(body)))
            .flat_map(|(def, body)| {
                iter::repeat((def, body)).zip(
                    body.iter_blocks_enumerated()
                        .flat_map(|(bb, block)| iter::repeat(bb).zip(block.iter().enumerate())),
                )
            })
            .filter_map(|((def, body), (bb, (inst_idx, inst)))| {
                let (callee, _) = inst.rvalue().as_call()?;
                let (callee_def, _) = body.resolve_call(env, callee)?;
                trace!(
                    "found call from {def:?} {} to {callee_def:?} {}",
                    env.def_name(def),
                    env.def_name(callee_def)
                );
                let loc = Location::new(bb, inst_idx as u32);
                called_from.entry(callee_def).or_default().push((def, loc));
                Some(((def, callee_def), loc))
            })
            .collect();
        Self {
            called_from,
            callgraph,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotAFunction(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAFunction(name) => write!(f, "Not a function: {name}"),
        }
    }
}

impl std::error::Error for Error {}

impl<'cx, C: Runner<'cx>> Interp<'cx, C> {
    pub fn new(
        env: &'cx Environment,
        call_all: bool,
        call_uncalled: bool,
        permissions: Vec<String>,
        jira_any_permission_resolver: &'cx PermissionHashMap,
        jira_any_regex_map: &'cx HashMap<String, Regex>,
        jira_software_permission_resolver: &'cx PermissionHashMap,
        jira_software_regex_map: &'cx HashMap<String, Regex>,
        jira_service_management_permission_resolver: &'cx PermissionHashMap,
        jira_service_management_regex_map: &'cx HashMap<String, Regex>,
        jira_permission_resolver: &'cx PermissionHashMap,
        jira_regex_map: &'cx HashMap<String, Regex>,
        confluence_permission_resolver: &'cx PermissionHashMap,
        confluence_regex_map: &'cx HashMap<String, Regex>,
        bitbucket_permission_resolver: &'cx PermissionHashMap,
        bitbucket_regex_map: &'cx HashMap<String, Regex>,
        compass_permission_resolver: &'cx CompassPermissionResolver,
    ) -> Self {
        let call_graph = CallGraph::new(env);

        Self {
            env,
            call_graph,
            call_all,
            call_uncalled,
            entry: Default::default(),
            return_value: None,
            return_value_alt: HashMap::default(),
            func_state: RefCell::new(FxHashMap::default()),
            curr_body: Cell::new(None),
            states: RefCell::new(BTreeMap::new()),
            instruction_findings: BTreeSet::new(),
            dataflow_visited: FxHashSet::default(),
            checker_visited: RefCell::new(FxHashSet::default()),
            callstack: RefCell::new(Vec::new()),
            value_manager: ValueManager {
                varid_to_value: DefinitionAnalysisMap::default(),
                varid_to_value_with_proj: DefinitionAnalysisMapProjection::default(),
                defid_to_value: FxHashMap::default(),
                expected_return_values: HashMap::default(),
                expecting_captures: FxHashMap::default(),
                imported_vars: FxHashMap::default(),
                value_origins: FxHashMap::default(),
                next_imported_var: FxHashMap::default(),
                expecting_value: RefCell::new(FxHashMap::default()),
                changed: false,
            },
            permissions,
            jira_any_permission_resolver,
            jira_software_permission_resolver,
            jira_service_management_permission_resolver,
            jira_permission_resolver,
            confluence_permission_resolver,
            bitbucket_permission_resolver,
            compass_permission_resolver,
            jira_any_regex_map,
            jira_software_regex_map,
            jira_service_management_regex_map,
            jira_regex_map,
            confluence_regex_map,
            bitbucket_regex_map,
            _checker: PhantomData,
            runner_visited: RefCell::new(FxHashSet::default()),
        }
    }

    #[inline]
    pub fn get_defs(&self) -> DefinitionAnalysisMap {
        self.value_manager.varid_to_value.clone()
    }

    #[inline]
    pub(crate) fn is_obj(&self, varid: VarId) -> bool {
        if let Some(defid) = self.body().get_defid_from_var(varid) {
            return matches!(
                self.env.defs.defs[defid],
                DefKind::GlobalObj(_) | DefKind::Class(_)
            );
        }
        false
    }

    #[inline]
    pub(crate) fn env(&self) -> &'cx Environment {
        self.env
    }

    #[inline]
    pub fn body(&self) -> &'cx Body {
        self.curr_body.get().unwrap()
    }

    #[inline]
    pub fn set_body(&self, body: &'cx Body) {
        self.curr_body.set(Some(body));
    }

    #[inline]
    pub(crate) fn callstack(&self) -> Vec<Frame> {
        (*self.callstack.borrow()).clone()
    }

    #[inline]
    pub(crate) fn checker_visit(&self, def: DefId) -> bool {
        self.checker_visited.borrow_mut().insert(def)
    }

    #[inline]
    pub(crate) fn add_value(&mut self, defid_block: DefId, varid: VarId, value: Value) {
        self.value_manager.insert_var(defid_block, varid, value);
    }

    #[inline]
    pub(crate) fn add_value_with_projection(
        &mut self,
        defid_block: DefId,
        varid: VarId,
        value: Value,
        projections: ProjectionVec,
    ) {
        let Some((varid, projections)) = self.get_farthest_obj(defid_block, varid, projections)
        else {
            return;
        };
        self.value_manager
            .insert_var_with_projection(defid_block, varid, projections, value);
    }

    // This function takes in an operand, checks for existing values, and returns a value optional.
    // There are 4 cases for the existing values.
    #[inline]
    pub fn add_value_to_definition(&mut self, defid_block: DefId, lval: Variable, rvalue: Rvalue) {
        if let Variable {
            base: Base::Var(varid),
            projections,
        } = lval
        {
            // this piece is definition analysis largely for global variables since they are not assigned a VarId, so we use the DefId
            match &rvalue {
                Rvalue::Call(Operand::Var(variable), _) => {
                    if let Base::Var(callee_varid) = variable.base
                        && let Some(VarKind::GlobalRef(defid)) = self.body().vars.get(callee_varid)
                    {
                        self.value_manager
                            .expected_return_values
                            .insert(*defid, (defid_block, varid));
                    }
                }
                Rvalue::Read(Operand::Lit(Literal::Str(str))) => {
                    let val = Value::Const(Const::Literal(str.to_string()));
                    if let Some(VarKind::GlobalRef(def)) = self.body().vars.get(varid) {
                        self.value_manager.insert_defid_value(*def, val);
                    } else if let Some(VarKind::LocalDef(def)) = self.body().vars.get(varid) {
                        self.value_manager.insert_defid_value(*def, val);
                    }
                }
                _ => {}
            }
            let assigned_var = varid;
            let Some((varid, projections)) = self.get_farthest_obj(defid_block, varid, projections)
            else {
                return;
            };
            let rval_value = self.value_from_rval(defid_block, rvalue);
            if projections.is_empty()
                && self
                    .value_manager
                    .value_origins
                    .contains_key(&(defid_block, varid))
            {
                // A captured object may be rebound in this body. Its imported
                // storage is reused by the legacy value lattice, but fallback
                // IR inspection must follow the new value rather than the capture.
                let origin = match &rval_value {
                    Value::Object(source) => self.value_origin(defid_block, *source),
                    _ => (defid_block, assigned_var),
                };
                self.value_manager
                    .value_origins
                    .insert((defid_block, varid), origin);
            }
            if let Some(existing_lval) = self
                .get_value(defid_block, varid, Some(projections.clone()))
                .cloned()
            {
                // if there is an existing value...
                match (existing_lval, rval_value) {
                    (Value::Unknown, _)
                    | (_, Value::Unknown)
                    | (Value::Const(_), Value::Object(_))
                    | (Value::Phi(_), Value::Object(_))
                    | (Value::Object(_), Value::Phi(_))
                    | (Value::Object(_), Value::Const(_)) => self.add_value_with_projection(
                        defid_block,
                        varid,
                        Value::Unknown,
                        projections,
                    ),
                    // push other const onto phi vec if either are const and phi
                    (Value::Const(const_value), Value::Phi(phi_value))
                    | (Value::Phi(phi_value), Value::Const(const_value)) => {
                        let mut new_phi = phi_value;
                        new_phi.push(const_value);
                        self.add_value_with_projection(
                            defid_block,
                            varid,
                            Value::Phi(new_phi),
                            projections,
                        )
                    }
                    // push consts into vec if both are consts
                    (Value::Const(const_value1), Value::Const(const_value2)) => self
                        .add_value_with_projection(
                            defid_block,
                            varid,
                            Value::Phi(vec![const_value1, const_value2]),
                            projections,
                        ),
                    (Value::Object(exist_var), Value::Object(new_var)) => {
                        // store projection values that are transferred
                        let mut projections_transferred = vec![];
                        // transfer all projection values from the new_var into the existing var
                        let start_new = (defid_block, new_var, ProjectionVec::new());
                        let query_new = match new_var.0.checked_add(1) {
                            Some(end) => self
                                .value_manager
                                .varid_to_value_with_proj
                                .range(start_new..(defid_block, VarId(end), ProjectionVec::new())),
                            None => self
                                .value_manager
                                .varid_to_value_with_proj
                                .range(start_new..),
                        };

                        let vals = query_new
                            .map(|((_, _, projections), value)| {
                                (projections.clone(), value.clone())
                            })
                            .collect_vec();
                        for (projections, value) in vals {
                            projections_transferred.push(projections.clone());
                            self.add_value_with_projection(
                                defid_block,
                                exist_var,
                                value,
                                projections,
                            )
                        }

                        // clear remaining vars
                        let start_exists = (defid_block, exist_var, ProjectionVec::new());
                        let query_exists = match exist_var.0.checked_add(1) {
                            Some(end) => self.value_manager.varid_to_value_with_proj.range_mut(
                                start_exists..(defid_block, VarId(end), ProjectionVec::new()),
                            ),
                            None => self
                                .value_manager
                                .varid_to_value_with_proj
                                .range_mut(start_exists..),
                        };

                        let mut any_changed = false;
                        for (_, value) in query_exists.filter(|((_, _, projections), _)| {
                            !projections_transferred.contains(projections)
                        }) {
                            if *value != Value::Unknown {
                                any_changed = true;
                            }
                            *value = Value::Unknown
                        }
                        if any_changed {
                            self.value_manager.changed = true;
                        }
                    }
                    _ => {}
                }
            } else {
                // push the rval if no existing value
                self.add_value_with_projection(defid_block, varid, rval_value, projections)
            }
        }
    }

    // this function takes in any operands and returns a value optional
    #[inline]
    fn value_from_rval(&self, defid_block: DefId, rvalue: Rvalue) -> Value {
        match rvalue {
            Rvalue::Read(operand) => self.value_from_operand(defid_block, operand),
            Rvalue::Template(template) => {
                let all_values = template
                    .exprs
                    .iter()
                    .map(|expr| self.value_from_operand(defid_block, expr.clone()))
                    .collect_vec();

                if all_values.contains(&Value::Unknown) {
                    return Value::Unknown;
                }

                let quasis_as_values: Vec<Value> = template
                    .quasis
                    .iter()
                    .map(|quasis| Value::Const(Const::Literal(quasis.to_string())))
                    .collect_vec();

                let values_joined = quasis_as_values
                    .iter()
                    .zip(all_values.iter())
                    .flat_map(|(a, b)| vec![a.clone(), b.clone()])
                    .chain(quasis_as_values.iter().skip(all_values.len()).cloned())
                    .chain(all_values.iter().skip(quasis_as_values.len()).cloned())
                    .collect_vec();

                return_combinations_phi(values_joined)
            }
            Rvalue::Bin(BinOp::Add, op1, op2) => {
                let value_op1 = self.value_from_operand(defid_block, op1);
                let value_op2 = self.value_from_operand(defid_block, op2);
                if value_op1 == Value::Unknown || value_op2 == Value::Unknown {
                    return Value::Unknown;
                }
                return_combinations_phi(vec![value_op1, value_op2])
            }
            _ => Value::Unknown,
        }
    }

    #[inline]
    fn value_from_operand(&self, defid_block: DefId, operand: Operand) -> Value {
        match operand {
            Operand::Var(Variable {
                base: Base::Var(varid),
                projections,
            }) => {
                let Some((varid, projections)) =
                    self.get_farthest_obj(defid_block, varid, projections)
                else {
                    return Value::Unknown;
                };
                match self.get_value(defid_block, varid, Some(projections)) {
                    Some(value) => value.clone(),
                    None => {
                        if self.is_obj(varid) {
                            Value::Object(varid)
                        } else if let Some(defid) = self.body().get_defid_from_var(varid)
                            && let Some(val) = self.value_manager.defid_to_value.get(&defid)
                        {
                            val.clone()
                        } else {
                            Value::Unknown
                        }
                    }
                }
            }
            Operand::Lit(str) => {
                if let Some(value) = convert_lit_to_raw(&str) {
                    Value::Const(Const::Literal(value))
                } else {
                    Value::Unknown
                }
            }
            _ => Value::Unknown,
        }
    }

    #[inline]
    fn get_farthest_obj(
        &self,
        defid_block: DefId,
        varid: VarId,
        mut projections: ProjectionVec,
    ) -> Option<(VarId, ProjectionVec)> {
        let mut current_var_id = varid;
        for i in 0..projections.len() {
            if let Some(Value::Object(varid)) = self.get_value(
                defid_block,
                current_var_id,
                Some(projvec_from_projvec(&projections[..i])),
            ) {
                current_var_id = *varid;
                projections = projvec_from_projvec(&projections[i..]);
            }
        }

        let mut visited = FxHashSet::default();
        while let Some(Value::Object(varid)) =
            self.get_value(defid_block, current_var_id, Some(ProjectionVec::new()))
        {
            if current_var_id == *varid {
                break;
            }
            // A self-reference represents an object root, but a longer cycle has
            // no root. Do not choose an arbitrary alias as a read or write target.
            if !visited.insert(current_var_id) {
                debug!(
                    function = self.env.def_name(defid_block),
                    ?defid_block,
                    ?current_var_id,
                    "cyclic object aliases; value cannot be resolved"
                );
                return None;
            }
            current_var_id = *varid;
        }
        Some((current_var_id, projections))
    }

    #[inline]
    pub(crate) fn get_value(
        &self,
        defid_block: DefId,
        varid: VarId,
        projection: Option<ProjectionVec>,
    ) -> Option<&Value> {
        match projection {
            Some(projection) if !projection.is_empty() => self
                .value_manager
                .get_var_with_projection(defid_block, varid, projection),
            _ => self.value_manager.varid_to_value.get(&(defid_block, varid)),
        }
    }

    #[inline]
    fn called_from(&self, def: DefId) -> &[(DefId, Location)] {
        self.call_graph.called_from.get(&def).map_or(&[], |v| v)
    }

    #[inline]
    pub fn block_state(&self, def: DefId, block: BasicBlockId) -> C::State {
        self.states
            .borrow()
            .get(&(def, block))
            .cloned()
            .unwrap_or(C::State::BOTTOM)
    }

    pub(crate) fn instruction_has_finding(&self, def: DefId, loc: Location) -> bool {
        self.instruction_findings.contains(&(def, loc))
    }

    pub(crate) fn set_block_states(&self, states: BTreeMap<(DefId, BasicBlockId), C::State>) {
        *self.states.borrow_mut() = states;
    }

    pub(crate) fn replace_func_states(&self, states: impl IntoIterator<Item = (DefId, C::State)>) {
        let mut summaries = self.func_state.borrow_mut();
        summaries.clear();
        summaries.extend(states);
    }

    #[inline]
    fn block_state_mut(&self, def: DefId, block: BasicBlockId) -> RefMut<'_, C::State> {
        let states = self.states.borrow_mut();
        RefMut::map(states, |states| {
            states.entry((def, block)).or_insert(C::State::BOTTOM)
        })
    }

    #[inline]
    pub(crate) fn func_state(&self, def: DefId) -> Option<C::State> {
        self.func_state.borrow().get(&def).cloned()
    }

    #[inline]
    fn set_func_state(&self, def: DefId, state: C::State) -> Option<C::State> {
        self.func_state.borrow_mut().insert(def, state)
    }

    #[inline]
    pub(crate) fn push_frame(&self, def: DefId, block: BasicBlockId) {
        self.callstack.borrow_mut().push(Frame {
            calling_function: def,
            block,
            inst_idx: 0,
        });
    }

    #[inline]
    pub fn check_for_const(&self, operand: &Operand, def: DefId) -> bool {
        match operand {
            Operand::Lit(Literal::Str(_)) => true,
            Operand::Var(var) => {
                if let Base::Var(varid) = var.base {
                    if let Some(value) = self.get_value(def, varid, Some(var.projections.clone())) {
                        return matches!(value, Value::Const(_) | Value::Phi(_));
                    } else if let Some(VarKind::GlobalRef(def)) = self.body().vars.get(varid)
                        && let Some(value) = self.value_manager.defid_to_value.get(def)
                    {
                        return matches!(value, Value::Const(_) | Value::Phi(_));
                    }
                }
                false
            }
            _ => false,
        }
    }

    #[inline]
    pub(crate) fn pop_frame(&self) -> Option<Frame> {
        self.callstack.borrow_mut().pop()
    }

    #[inline]
    pub(crate) fn entry(&self) -> &EntryPoint {
        &self.entry
    }

    #[inline]
    pub fn callees(
        &self,
        caller: DefId,
    ) -> impl DoubleEndedIterator<Item = (DefId, Location)> + use<'_, C> {
        self.call_graph
            .callgraph
            .range((caller, DefId::new(0))..(caller, DefId::new(u32::MAX)))
            .map(move |(&(_, callee), &loc)| (callee, loc))
    }

    fn bind_arguments(&mut self, def: DefId, body: &Body) {
        if let Some(caller) = self.value_manager.expecting_captures.remove(&def) {
            self.propagate_captured_values(caller, def, body);
        }
        let Some((caller, args)) = self.value_manager.expecting_value.borrow_mut().remove(&def)
        else {
            return;
        };
        // GlobalRef slots alias formals; their IR assignments read the Arg slots.
        // Only the latter consume actual arguments, including destructured formals.
        let formals = body
            .vars
            .iter_enumerated()
            .filter_map(|(var, kind)| matches!(kind, VarKind::Arg(_)).then_some(var));
        for (var, value) in formals.zip(args) {
            let value = self.import_value(caller, def, value, &mut FxHashSet::default());
            self.add_value(def, var, value);
        }
    }

    fn propagate_captured_values(&mut self, caller: DefId, callee: DefId, body: &Body) {
        if caller == callee {
            return;
        }
        let caller_body = self.env.def_ref(caller).expect_body();
        let mut visited = FxHashSet::default();
        for (target, kind) in body.vars.iter_enumerated() {
            let Some(binding) = get_defid_from_varkind(kind) else {
                continue;
            };
            if self.env.binding_owner(binding) == Some(callee) {
                continue;
            }
            let source = caller_body
                .def_id_to_vars
                .get(&binding)
                .map(|&var| (caller, var))
                .or_else(|| {
                    let owner = self.env.binding_owner(binding)?;
                    let body = self.env.def_ref(owner).as_body().copied()?;
                    body.def_id_to_vars.get(&binding).map(|&var| (owner, var))
                });
            let Some((source_def, source_var)) = source else {
                continue;
            };
            let imported = self.import_variable(source_def, source_var, callee, &mut visited);
            let value = self
                .get_value(callee, imported, None)
                .cloned()
                .unwrap_or(Value::Unknown);
            self.add_value(callee, target, value);
            let origin = self.value_origin(source_def, source_var);
            self.value_manager
                .value_origins
                .insert((callee, target), origin);
        }
    }

    fn import_value(
        &mut self,
        source: DefId,
        target: DefId,
        value: Value,
        visited: &mut FxHashSet<(DefId, VarId)>,
    ) -> Value {
        match value {
            Value::Object(var) if source != target => {
                Value::Object(self.import_variable(source, var, target, visited))
            }
            value => value,
        }
    }

    fn import_variable(
        &mut self,
        source: DefId,
        source_var: VarId,
        target: DefId,
        visited: &mut FxHashSet<(DefId, VarId)>,
    ) -> VarId {
        let body_len = self.env.def_ref(target).expect_body().vars.len() as u32;
        let next_var = self
            .value_manager
            .next_imported_var
            .entry(target)
            .or_insert(body_len);
        let target_var = *self
            .value_manager
            .imported_vars
            .entry((target, source, source_var))
            .or_insert_with(|| {
                let var = VarId(*next_var);
                *next_var += 1;
                var
            });
        if !visited.insert((source, source_var)) {
            return target_var;
        }
        let origin = self.value_origin(source, source_var);
        self.value_manager
            .value_origins
            .insert((target, target_var), origin);
        let properties = self
            .value_manager
            .varid_to_value_with_proj
            .range((source, source_var, ProjectionVec::new())..)
            .take_while(|((def, var, _), _)| *def == source && *var == source_var)
            .map(|((_, _, projections), value)| (projections.clone(), value.clone()))
            .collect::<Vec<_>>();
        let value = self
            .get_value(source, source_var, None)
            .cloned()
            .unwrap_or({
                if properties.is_empty() {
                    Value::Unknown
                } else {
                    Value::Object(source_var)
                }
            });
        let value = self.import_value(source, target, value, visited);
        self.add_value(target, target_var, value);
        // Reusing the same imported slots must not retain properties from an older call.
        let old_properties = self
            .value_manager
            .varid_to_value_with_proj
            .range((target, target_var, ProjectionVec::new())..)
            .take_while(|((def, var, _), _)| *def == target && *var == target_var)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in old_properties {
            self.value_manager.varid_to_value_with_proj.remove(&key);
        }
        for (projection, value) in properties {
            let value = self.import_value(source, target, value, visited);
            self.value_manager
                .insert_var_with_projection(target, target_var, projection, value);
        }
        target_var
    }

    pub(crate) fn value_origin(&self, def: DefId, var: VarId) -> (DefId, VarId) {
        self.value_manager
            .value_origins
            .get(&(def, var))
            .copied()
            .unwrap_or((def, var))
    }

    fn run(&mut self, func_def: DefId) {
        let mut dataflow = C::Dataflow::with_interp(self);
        if dataflow.analyze(self, func_def) {
            return;
        }
        if self.dataflow_visited.contains(&func_def) {
            return;
        }
        self.dataflow_visited.insert(func_def);
        let mut worklist: WorkList<DefId, BasicBlockId> = WorkList::new();

        // globals first (in module order so dependencies are resolved before dependents),
        // then the entry function
        for global_def in self.env().global.iter() {
            worklist.push_back_blocks(self.env, *global_def, self.call_all);
        }
        worklist.push_back_blocks(self.env, func_def, self.call_all);
        let old_body = self.curr_body.get();
        while let Some((def, block_id)) = worklist.pop_front() {
            let name = self.env.def_name(def);
            debug!(
                ?def,
                checker = C::NAME,
                pending = worklist.len(),
                "Dataflow: {name} - {block_id}"
            );
            self.dataflow_visited.insert(def);
            let func = self.env().def_ref(def).expect_body();
            self.curr_body.set(Some(func));
            self.value_manager.reset_changed();

            if block_id == STARTING_BLOCK {
                self.bind_arguments(def, func);
            }

            let mut before_state = self.block_state(def, block_id);
            let block = func.block(block_id);
            for &pred in func.predecessors(block_id) {
                before_state = before_state.join(&self.block_state(def, pred));
            }
            let state = dataflow.transfer_block(self, def, block_id, block, before_state);

            if matches!(block.successors(), Successors::Return) {
                for (varid, varkind) in func.vars.iter_enumerated() {
                    if &VarKind::Ret == varkind
                        && let Some((defid_calling_func, varid_calling_func)) =
                            self.value_manager.expected_return_values.get(&def)
                        && let Some(value) = self.get_value(def, varid, None)
                    {
                        self.add_value(*defid_calling_func, *varid_calling_func, value.clone());
                    }
                }
            }
            dataflow.join_term(self, def, block, state, &mut worklist);
        }

        if self.call_uncalled {
            let all_functions = self.env.get_all_functions();
            let all_functions_set = FxHashSet::from_iter(all_functions.iter());

            for def in all_functions_set {
                if !worklist.visited(def) {
                    let body = self.env.def_ref(*def).expect_body();
                    let blocks = body.iter_block_keys().map(|bb| (*def, bb)).rev();
                    worklist.reserve(blocks.len());
                    for work in blocks {
                        debug!(?work, "push_front_blocks");
                        worklist.push_back_force(work.0, work.1);
                    }
                }
            }

            while let Some((def, block_id)) = worklist.pop_front() {
                let name = self.env.def_name(def);
                debug!(
                    ?def,
                    checker = C::NAME,
                    pending = worklist.len(),
                    "Dataflow: {name} - {block_id}"
                );
                self.dataflow_visited.insert(def);
                let func = self.env().def_ref(def).expect_body();
                self.curr_body.set(Some(func));
                self.value_manager.reset_changed();

                if block_id == STARTING_BLOCK {
                    self.bind_arguments(def, func);
                }

                let mut before_state = self.block_state(def, block_id);
                let block = func.block(block_id);
                for &pred in func.predecessors(block_id) {
                    before_state = before_state.join(&self.block_state(def, pred));
                }
                let state = dataflow.transfer_block(self, def, block_id, block, before_state);

                if matches!(block.successors(), Successors::Return) {
                    for (varid, varkind) in func.vars.iter_enumerated() {
                        if &VarKind::Ret == varkind
                            && let Some((defid_calling_func, varid_calling_func)) =
                                self.value_manager.expected_return_values.get(&def)
                            && let Some(value) = self.get_value(def, varid, None)
                        {
                            self.add_value(*defid_calling_func, *varid_calling_func, value.clone());
                        }
                    }
                }
                dataflow.join_term(self, def, block, state, &mut worklist);
            }
        }

        self.curr_body.set(old_body);
    }

    /// Removes a DefId from the dataflow visited set so it can be re-analyzed.
    pub fn reset_dataflow_visited(&mut self, def: DefId) {
        self.dataflow_visited.remove(&def);
    }

    pub fn try_check_function(&mut self, def: DefId, checker: &mut C) -> Result<(), Error> {
        let resolved_def = self.env.resolve_alias(def);
        let name = self.env.def_name(resolved_def);
        debug!(%name, "found definition");
        let body = *self.env.def_ref(resolved_def).as_body().ok_or_else(|| {
            debug!(%name, "unknown function");
            Error::NotAFunction(name.to_owned())
        })?;
        self.set_body(body);
        self.run(resolved_def);
        if C::VISIT_GLOBALS {
            for &global in &self.env.global {
                let global_body = self.env.def_ref(global).expect_body();
                _ = checker.visit_body(self, global, global_body, &C::State::BOTTOM);
            }
        }
        _ = checker.visit_body(self, resolved_def, body, &C::State::BOTTOM);
        self.runner_visited.borrow_mut().clear();
        Ok(())
    }

    /// Sets the current entry point for tracing/reporting purposes.
    pub fn set_entry(&mut self, file: PathBuf, function: String) {
        self.entry = EntryPoint {
            file,
            kind: EntryKind::Function(function),
        };
    }

    /// Checks a single function body without resolver-callback discovery.
    /// Use this for full-function scans where entry points are iterated directly.
    pub fn check_function(
        &mut self,
        def: DefId,
        checker: &mut C,
        file: PathBuf,
        function: String,
    ) -> Result<(), Error> {
        self.set_entry(file, function);
        self.try_check_function(def, checker)
    }

    #[instrument(level = "info", skip(self, checker, entry_file), fields(checker = %C::NAME, file = %entry_file.display()))]
    pub fn run_checker(
        &mut self,
        def: DefId,
        checker: &mut C,
        entry_file: PathBuf,
        function: String,
    ) -> Result<(), Error> {
        self.entry = EntryPoint {
            file: entry_file,
            kind: EntryKind::Function(function),
        };
        let Err(error) = self.try_check_function(def, checker) else {
            return Ok(());
        };
        debug!("failed to check function, trying resolver");
        let resolver = self.env.resolver_defs(def);
        if resolver.is_empty() {
            warn!("no resolver found");
            return Err(error);
        }
        debug!("found potential resolver");
        for (name, prop) in resolver {
            debug!("checking resolver prop: {name}");
            self.entry.kind = match std::mem::take(&mut self.entry.kind) {
                EntryKind::Function(fname) => EntryKind::Resolver(fname, name.clone()),
                EntryKind::Resolver(res, _) => EntryKind::Resolver(res, name.clone()),
                EntryKind::Empty => unreachable!(),
            };
            if let Err(error) = self.try_check_function(prop, checker) {
                warn!("Resolver prop {name} failed: {error}");
            }
        }
        Ok(())
    }
}
