use std::{
    borrow::BorrowMut,
    cell::{Cell, RefCell, RefMut},
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::{self, Display},
    hash::Hash,
    io::{self, Write},
    iter,
    marker::PhantomData,
    ops::ControlFlow,
    path::PathBuf,
};

use forge_loader::forgepermissions::ForgePermissions;
use forge_permission_resolver::permissions_resolver::{
    check_url_for_permissions, get_permission_resolver_confluence, get_permission_resolver_jira,
    PermissionHashMap,
};
use forge_utils::{FxHashMap, FxHashSet};
use itertools::Itertools;
use regex::Regex;
use smallvec::SmallVec;
use swc_core::ecma::atoms::JsWord;
use tracing::{debug, info, instrument, warn};

use crate::{
    checkers::IntrinsicArguments,
    definitions::{Class, Const, DefId, Environment, Value},
    ir::{
        Base, BasicBlock, BasicBlockId, Body, Inst, Intrinsic, Location, Operand, Projection,
        Rvalue, Successors, VarId, Variable, STARTING_BLOCK,
    },
    utils::{get_defid_from_varkind, get_str_from_operand, resolve_var_from_operand},
    worklist::WorkList,
};

pub type DefinitionAnalysisMap = FxHashMap<(DefId, VarId, Option<Projection>), Value>;

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
        // operands: &SmallVec<[Operand; 4]>,
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
        arguments: Option<Vec<Value>>,
    ) -> Self::State {
        let mut state = initial_state;
        for (stmt, inst) in block.iter().enumerate() {
            let loc = Location::new(bb, stmt as u32);
            state = self.transfer_inst(interp, def, loc, block, inst, state);
        }
        state
    }

    fn add_variable<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        lval: &Variable,
        varid: &VarId,
        def: DefId,
        rvalue: &Rvalue,
    ) {
    }

    fn insert_value<C: Runner<'cx, State = Self::State>>(
        &mut self,
        interp: &mut Interp<'cx, C>,
        operand: &Operand,
        lval: &Variable,
        varid: &VarId,
        def: DefId,
        prev_values: Option<Vec<Const>>,
    ) {
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

    fn read_class_from_variable<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        defid: DefId,
    ) -> Option<Class> {
        None
    }

    fn read_class_from_object<C: Runner<'cx, State = Self::State>>(
        &mut self,
        _interp: &Interp<'cx, C>,
        defid: DefId,
    ) -> Option<Class> {
        None
    }

    fn try_read_mem_from_object<C: Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        const_var: Const,
    ) -> Option<&Value> {
        None
    }

    fn insert_with_existing_value<C: Runner<'cx, State = Self::State>>(
        &mut self,
        operand: &Operand,
        value: &Value,
        varid: &VarId,
        def: DefId,
        interp: &Interp<'cx, C>,
    ) {
    }

    fn read_mem_from_object<C: Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        obj: Class,
    ) -> Option<&Value> {
        None
    }

    fn get_str_from_expr<C: Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        expr: &Operand,
        def: DefId,
    ) -> Vec<Option<String>> {
        if let Some(str) = get_str_from_operand(expr) {
            return vec![Some(str)];
        } else if let Operand::Var(var) = expr {
            if let Base::Var(varid) = var.base {
                let value = _interp.get_value(def, varid, None);
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

    fn def_to_class_property<C: Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        defid: DefId,
    ) -> Option<&Value> {
        None
    }

    #[inline]
    fn get_values_from_operand<C: Runner<'cx, State = Self::State>>(
        &self,
        _interp: &mut Interp<'cx, C>,
        _def: DefId,
        operand: &Operand,
    ) -> Option<Value> {
        if let Some((var, varid)) = resolve_var_from_operand(operand) {
            return _interp
                .get_value(_def, varid, var.projections.get(0).cloned())
                .cloned();
        }
        None
    }

    fn try_insert<C: crate::interp::Runner<'cx, State = Self::State>>(
        &self,
        _interp: &Interp<'cx, C>,
        _def: DefId,
        const_var: Const,
        intrinsic_argument: &mut IntrinsicArguments,
    ) {
    }
}

pub trait Runner<'cx>: Sized {
    type State: JoinSemiLattice + Clone + fmt::Debug;
    type Dataflow: Dataflow<'cx, State = Self::State>;

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

    #[instrument(skip(self, interp, block))]
    fn visit_block(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        id: BasicBlockId,
        block: &'cx BasicBlock,
        curr_state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
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
                self.visit_block(interp, def, succ1, bb, &curr_state)?;
                let bb = interp.body().block(succ2);
                self.visit_block(interp, def, succ2, bb, &curr_state)
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
    call_graph: CallGraph,
    pub return_value: Option<(Value, DefId)>,
    pub return_value_alt: HashMap<DefId, Value>,
    entry: EntryPoint,
    func_state: RefCell<FxHashMap<DefId, C::State>>,
    pub curr_body: Cell<Option<&'cx Body>>,
    states: RefCell<BTreeMap<(DefId, BasicBlockId), C::State>>,
    dataflow_visited: FxHashSet<DefId>,
    checker_visited: RefCell<FxHashSet<DefId>>,
    callstack: RefCell<Vec<Frame>>,
    pub callstack_arguments: Vec<Vec<Value>>,
    // vulns: RefCell<Vec<C::Vuln>>,
    pub expected_return_values: HashMap<DefId, (DefId, VarId)>,
    pub permissions: Vec<String>,
    pub expecting_value: VecDeque<(DefId, (VarId, DefId))>,
    pub jira_permission_resolver: PermissionHashMap,
    pub confluence_permission_resolver: PermissionHashMap,
    pub jira_regex_map: HashMap<String, Regex>,
    pub confluence_regex_map: HashMap<String, Regex>,
    pub varid_to_value: FxHashMap<(DefId, VarId, Option<Projection>), Value>,
    _checker: PhantomData<C>,
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
    pub fn new(env: &'cx Environment) -> Self {
        let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira();
        let (confluence_permission_resolver, confluence_regex_map) =
            get_permission_resolver_confluence();

        let call_graph = CallGraph::new(env);
        Self {
            env,
            call_graph,
            entry: Default::default(),
            return_value: None,
            return_value_alt: HashMap::default(),
            func_state: RefCell::new(FxHashMap::default()),
            curr_body: Cell::new(None),
            states: RefCell::new(BTreeMap::new()),
            dataflow_visited: FxHashSet::default(),
            checker_visited: RefCell::new(FxHashSet::default()),
            callstack_arguments: Vec::new(),
            expecting_value: VecDeque::default(),
            callstack: RefCell::new(Vec::new()),
            // vulns: RefCell::new(Vec::new()),
            expected_return_values: HashMap::default(),
            permissions: Vec::new(),
            varid_to_value: DefinitionAnalysisMap::default(),
            jira_permission_resolver,
            confluence_permission_resolver,
            jira_regex_map,
            confluence_regex_map,
            _checker: PhantomData,
        }
    }

    #[inline]
    pub fn get_defs(&self) -> DefinitionAnalysisMap {
        self.varid_to_value.clone()
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
    pub(crate) fn add_value(
        &mut self,
        defid_block: DefId,
        varid: VarId,
        value: Value,
        projection: Option<Projection>,
    ) {
        self.varid_to_value
            .insert((defid_block, varid, projection), value);
    }

    #[inline]
    pub(crate) fn get_value(
        &self,
        defid_block: DefId,
        varid: VarId,
        projection: Option<Projection>,
    ) -> Option<&Value> {
        self.varid_to_value.get(&(defid_block, varid, projection))
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
        worklist.push_front_blocks(self.env, func_def);
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
        self.curr_body.set(old_body);
    }

    fn try_check_function(&mut self, def: DefId, checker: &mut C) -> Result<(), Error> {
        let resolved_def = self.env.resolve_alias(def);
        let name = self.env.def_name(resolved_def);
        info!("Checking function: {name}");
        let body = *self
            .env
            .def_ref(resolved_def)
            .as_body()
            .ok_or_else(|| Error::NotAFunction(name.to_owned()))?;
        self.set_body(body);
        self.run(resolved_def);
        checker.visit_body(self, resolved_def, body, &C::State::BOTTOM);
        Ok(())
    }

    #[instrument(skip(self, checker))]
    pub fn run_checker(
        &mut self,
        def: DefId,
        checker: &mut C,
        entry_file: PathBuf,
        fname: String,
    ) -> Result<(), Error> {
        self.entry = EntryPoint {
            file: entry_file,
            kind: EntryKind::Function(fname),
        };
        let Err(error) = self.try_check_function(def, checker) else {
            return Ok(());
        };
        let resolver = self.env.resolver_defs(def);
        if resolver.is_empty() {
            return Err(error);
        }
        info!("Found potential resolver");
        for (name, prop) in resolver {
            debug!("Checking resolver prop: {name}");
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

    // pub fn dump_results(&self, out: &mut dyn Write) -> io::Result<()> {
    //     let vulns = &**self.vulns.borrow();
    //     if vulns.is_empty() {
    //         writeln!(out, "No vulnerabilities found")
    //     } else {
    //         writeln!(out, "Found {} vulnerabilities", vulns.len())?;
    //         for vuln in vulns {
    //             writeln!(out, "{vuln}")?;
    //         }
    //         Ok(())
    //     }
    // }
}
