use std::{
    borrow::BorrowMut,
    cell::{Cell, RefCell, RefMut},
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::{self, Display},
    hash::Hash,
    iter,
    marker::PhantomData,
    ops::ControlFlow,
    path::PathBuf,
};

use forge_permission_resolver::permissions_resolver::PermissionHashMap;
use forge_utils::{FxHashMap, FxHashSet};
use itertools::Itertools;
use regex::Regex;
use smallvec::SmallVec;
use swc_core::ecma::atoms::JsWord;
use tracing::{debug, instrument, warn};

use crate::definitions::DefKind;
use crate::ir::{BinOp, Literal, VarKind};
use crate::utils::{convert_lit_to_raw, projvec_from_projvec, return_combinations_phi};
use crate::{
    checkers::IntrinsicArguments,
    definitions::{Const, DefId, Environment, Value},
    ir::{
        Base, BasicBlock, BasicBlockId, Body, Inst, Intrinsic, Location, Operand, Projection,
        Rvalue, Successors, VarId, Variable, STARTING_BLOCK,
    },
    worklist::WorkList,
};

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
        loc: Location,
        block: &'cx BasicBlock,
        callee: &'cx Operand,
        initial_state: Self::State,
        oprands: SmallVec<[crate::ir::Operand; 4]>,
    ) -> Self::State;

    fn transfer_rvalue<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        def: DefId,
        loc: Location,
        block: &'cx BasicBlock,
        rvalue: &'cx Rvalue,
        initial_state: Self::State,
    ) -> Self::State {
        // println!("hi");
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
        match inst {
            Inst::Expr(rvalue) => {
                self.transfer_rvalue(interp, def, loc, block, rvalue, initial_state)
            }
            Inst::Assign(_, rvalue) => {
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
        _arguments: Option<Vec<Value>>,
    ) -> Self::State {
        let mut state = initial_state;
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
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
                    .map_or(true, |old_state| old_state < state)
                {
                    interp.set_func_state(def, state);
                    let calls = interp.called_from(def);
                    let name = interp.env().def_name(def);
                    debug!("{name} {def:?} is called from {calls:?}");
                    for &(def, loc) in calls {
                        if worklist.visited(&def) {
                            worklist.push_back_force(def, loc.block);
                        }
                    }
                }
            }
            Successors::One(succ) => {
                let mut succ_state = interp.block_state_mut(def, succ);
                if succ_state.join_changed(&state) {
                    worklist.push_back(def, succ);
                }
            }
            Successors::Two(succ1, succ2) => {
                if interp.block_state_mut(def, succ1).join_changed(&state) {
                    worklist.push_back(def, succ1);
                }
                if interp.block_state_mut(def, succ2).join_changed(&state) {
                    worklist.push_back(def, succ2);
                }
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

    const NAME: &'static str = "Runner";

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
        debug!("visiting rvalue {rvalue:?} with {curr_state:?}");
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
        for stmt in block {
            match stmt {
                Inst::Expr(r) => curr_state = self.visit_rvalue(interp, r, def, id, &curr_state)?,
                Inst::Assign(_, r) => {
                    curr_state = self.visit_rvalue(interp, r, def, id, &curr_state)?
                }
            }
        }
        match block.successors() {
            Successors::Return => ControlFlow::Continue(curr_state),
            Successors::One(succ) => {
                let bb = interp.body().block(id);
                self.visit_block(interp, def, succ, bb, &curr_state)
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
    Resolver(String, JsWord),
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
    dataflow_visited: FxHashSet<DefId>,
    checker_visited: RefCell<FxHashSet<DefId>>,
    callstack: RefCell<Vec<Frame>>,
    pub(crate) runner_visited: RefCell<FxHashSet<(DefId, BasicBlockId)>>,
    pub callstack_arguments: Vec<Vec<Value>>,
    pub value_manager: ValueManager,
    pub permissions: Vec<String>,
    pub jira_permission_resolver: &'cx PermissionHashMap,
    pub confluence_permission_resolver: &'cx PermissionHashMap,
    pub jira_regex_map: &'cx HashMap<String, Regex>,
    pub confluence_regex_map: &'cx HashMap<String, Regex>,
    _checker: PhantomData<C>,
}

#[derive(Debug)]
pub struct ValueManager {
    pub varid_to_value_with_proj: DefinitionAnalysisMapProjection,
    pub varid_to_value: DefinitionAnalysisMap,
    pub defid_to_value: FxHashMap<DefId, Value>,
    pub expecting_value: VecDeque<(DefId, (VarId, DefId))>,
    pub expected_return_values: HashMap<DefId, (DefId, VarId)>,
}

impl ValueManager {
    pub fn insert_var(&mut self, def_id_func: DefId, var_id: VarId, value: Value) {
        self.varid_to_value.insert((def_id_func, var_id), value);
    }

    pub fn insert_var_with_projection(
        &mut self,
        def_id_func: DefId,
        var_id: VarId,
        projection_vec: ProjectionVec,
        value: Value,
    ) {
        // println!("Attempting to insert: defid - {:?} varid - {:?} proj vec - {:?} val - {:?}", def_id_func, var_id, projection_vec[0], value);
        // println!("Current var mapping with projects: {:?}", self.varid_to_value_with_proj);
        // println!("Current var mapping with values: {:?}", self.varid_to_value);
        if projection_vec.is_empty() {
            // println!("EMPTY!");
            self.varid_to_value.insert((def_id_func, var_id), value);
        } else {
            // println!("NOT EMPTY");
            // DOES NOT FIX:
            self.varid_to_value_with_proj
                .insert((def_id_func, var_id, projection_vec), value);
        }
    }

    pub fn get_var_with_projection(
        &self,
        def_id_func: DefId,
        var_id: VarId,
        projection_vec: ProjectionVec,
    ) -> Option<&Value> {
        if let Some(value) =
            self.varid_to_value_with_proj
                .get(&(def_id_func, var_id, projection_vec.clone()))
        {
            Some(value)
        } else if let Some(Value::Object(var_id)) = self.varid_to_value.get(&(def_id_func, var_id))
        {
            self.get_var_with_projection(def_id_func, *var_id, projection_vec)
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
                debug!(
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
        jira_permission_resolver: &'cx PermissionHashMap,
        jira_regex_map: &'cx HashMap<String, Regex>,
        confluence_permission_resolver: &'cx PermissionHashMap,
        confluence_regex_map: &'cx HashMap<String, Regex>,
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
            dataflow_visited: FxHashSet::default(),
            checker_visited: RefCell::new(FxHashSet::default()),
            callstack_arguments: Vec::new(),
            callstack: RefCell::new(Vec::new()),
            value_manager: ValueManager {
                varid_to_value: DefinitionAnalysisMap::default(),
                varid_to_value_with_proj: DefinitionAnalysisMapProjection::default(),
                defid_to_value: FxHashMap::default(),
                expected_return_values: HashMap::default(),
                expecting_value: VecDeque::default(),
            },
            permissions,
            jira_permission_resolver,
            confluence_permission_resolver,
            jira_regex_map,
            confluence_regex_map,
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
        // println!("In add val with proj: Adding new value defid - {:?} varid - {:?} proj vec - {:?} val - {:?}", defid_block, varid, projections, value);
        println!("Add val with projection: {:?}", value);
        let (varid, projections) = self.get_farthest_obj(defid_block, varid, projections);
        self.value_manager
            .insert_var_with_projection(defid_block, varid, projections, value);
    }

    // this function takes in an operand checks for previous values and returns a value optional
    //
    // SW: This function adds a value to a definition,
    //      with the input of a DefId, the locator value (points to memory location), and the read value (value to be read).
    // There are 4 cases - if the existing value
    #[inline]
    pub fn add_value_to_definition(&mut self, defid_block: DefId, lval: Variable, rvalue: Rvalue) {
        // println!("Entered add val to def function with defid - {:?}, lval - {:?}, rval - {:?}", defid_block, lval, rvalue);
        println!("Add val to def: {:?}", rvalue);
        if let Variable {
            base: Base::Var(varid),
            projections,
        } = lval
        {
            let (varid, projections) = self.get_farthest_obj(defid_block, varid, projections);
            let rval_value = self.value_from_rval(defid_block, rvalue);
            if let Some(existing_lval) = self
                .get_value(defid_block, varid, Some(projections.clone()))
                .cloned()
            {
                println!("The existing value: {:?}", existing_lval);
                // println!("The (current) real value: {:?}", rval_value);
                // if there is an existing value...
                match (existing_lval, rval_value) {
                    // return unknown if either values are unknown
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
                    // SW: NEED TO MODIFY THIS CASE TO HANDLE REASSIGNMENTS. Hits if we do a reassignment after already having done one.
                    (Value::Const(const_value), Value::Phi(phi_value))
                    | (Value::Phi(phi_value), Value::Const(const_value)) => {
                        println!("Entered constant and phi vec match case");
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
                    // SW: NEED TO MODIFY THIS CASE TO HANDLE REASSIGNMENTS. Hits if we do a single reassignment.
                    (Value::Const(const_value1), Value::Const(const_value2)) => {
                        self.add_value_with_projection(
                            defid_block,
                            varid,
                            Value::Phi(vec![const_value1, const_value2]),
                            projections,
                        );
                        println!("Entered double constant match case");
                    }
                    (Value::Object(exist_var), Value::Object(new_var)) => {
                        // store projection values that are transferred
                        let mut projections_transferred = vec![];
                        // println!("In add val to def - projections transferred are: {:?}", projections_transferred);
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

                        for (_, value) in query_exists.filter(|((_, _, projections), _)| {
                            !projections_transferred.contains(projections)
                        }) {
                            *value = Value::Unknown
                        }
                    }
                    _ => {}
                }
            } else {
                // push the rval if no existing value
                println!("No existing value");
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
                let (varid, projections) = self.get_farthest_obj(defid_block, varid, projections);
                match self.get_value(defid_block, varid, Some(projections)) {
                    Some(value) => value.clone(),
                    None => {
                        if self.is_obj(varid) {
                            Value::Object(varid)
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
    ) -> (VarId, ProjectionVec) {
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

        while let Some(Value::Object(varid)) =
            self.get_value(defid_block, current_var_id, Some(ProjectionVec::new()))
        {
            if current_var_id == *varid {
                break;
            }
            current_var_id = *varid;
        }
        (current_var_id, projections)
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
    fn push_frame(&self, def: DefId, block: BasicBlockId) {
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
                    } else if let Some(VarKind::GlobalRef(def)) = self.body().vars.get(varid) {
                        if let Some(value) = self.value_manager.defid_to_value.get(def) {
                            return matches!(value, Value::Const(_) | Value::Phi(_));
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    #[inline]
    fn pop_frame(&self) -> Option<Frame> {
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
    ) -> impl DoubleEndedIterator<Item = (DefId, Location)> + '_ {
        self.call_graph
            .callgraph
            .range((caller, DefId::new(0))..(caller, DefId::new(u32::MAX)))
            .map(|(&(_, callee), &loc)| (callee, loc))
    }

    fn run(&mut self, func_def: DefId) {
        if self.dataflow_visited.contains(&func_def) {
            return;
        }
        self.dataflow_visited.insert(func_def);
        let mut dataflow = C::Dataflow::with_interp(self);
        let mut worklist = WorkList::new();

        for global_def in &self.env().global {
            worklist.push_front_blocks(self.env, *global_def, self.call_all);
        }

        worklist.push_front_blocks(self.env, func_def, self.call_all);
        let old_body = self.curr_body.get();
        while let Some((def, block_id)) = worklist.pop_front() {
            let arguments = self.callstack_arguments.pop();
            let name = self.env.def_name(def);
            debug!("Dataflow: {name} - {block_id}");
            self.dataflow_visited.insert(def);
            let func = self.env().def_ref(def).expect_body();
            self.curr_body.set(Some(func));
            let mut before_state = self.block_state(def, block_id);
            let block = func.block(block_id);
            for &pred in func.predecessors(block_id) {
                before_state = before_state.join(&self.block_state(def, pred));
            }
            let state =
                dataflow.transfer_block(self, def, block_id, block, before_state, arguments);
            dataflow.join_term(self, def, block, state, &mut worklist);
        }

        if self.call_uncalled {
            let all_functions = self.env.get_all_functions();
            let all_functions_set = FxHashSet::from_iter(all_functions.iter());

            for def in all_functions_set {
                if !worklist.visited(def) {
                    let body = self.env.def_ref(*def).expect_body();
                    let blocks = body.iter_block_keys().map(|bb| (def, bb)).rev();
                    worklist.reserve(blocks.len());
                    for work in blocks {
                        debug!(?work, "push_front_blocks");
                        worklist.push_back_force(*work.0, work.1);
                    }
                }
            }

            while let Some((def, block_id)) = worklist.pop_front() {
                let arguments = self.callstack_arguments.pop();
                let name = self.env.def_name(def);
                debug!("Dataflow: {name} - {block_id}");
                self.dataflow_visited.insert(def);
                let func = self.env().def_ref(def).expect_body();
                self.curr_body.set(Some(func));
                let mut before_state = self.block_state(def, block_id);
                let block = func.block(block_id);
                for &pred in func.predecessors(block_id) {
                    before_state = before_state.join(&self.block_state(def, pred));
                }
                let state =
                    dataflow.transfer_block(self, def, block_id, block, before_state, arguments);
                dataflow.join_term(self, def, block, state, &mut worklist);
            }
        }

        self.curr_body.set(old_body);
    }

    fn try_check_function(&mut self, def: DefId, checker: &mut C) -> Result<(), Error> {
        let resolved_def = self.env.resolve_alias(def);
        let name = self.env.def_name(resolved_def);
        debug!(%name, "found definition");
        let body = *self.env.def_ref(resolved_def).as_body().ok_or_else(|| {
            debug!(%name, "unknown function");
            Error::NotAFunction(name.to_owned())
        })?;
        self.set_body(body);
        self.run(resolved_def);
        checker.visit_body(self, resolved_def, body, &C::State::BOTTOM);
        self.runner_visited.borrow_mut().clear();
        Ok(())
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
