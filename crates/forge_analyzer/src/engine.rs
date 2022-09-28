use std::collections::VecDeque;

use rustc_hash::FxHashSet;
use swc_core::ecma::ast::Id;
use tracing::{debug, info, instrument};

use crate::{
    analyzer::AuthZVal,
    ctx::{AppCtx, BasicBlockId, ModId, StmtId, ENTRY_STMT, STARTING_BLOCK},
};

type Instruction = (BasicBlockId, StmtId);
const PRELUDE: Instruction = (STARTING_BLOCK, ENTRY_STMT);

#[derive(Debug)]
enum Inst {
    Call {
        func: Id,
        module: ModId,
        ret: Instruction,
    },
    Step(BasicBlockId, StmtId),
}

#[derive(Debug)]
struct Frame {
    ret: Instruction,
    calling_function: Id,
}

pub struct Machine<'ctx> {
    callstack: Vec<Frame>,
    curr_function: Id,
    mod_id: ModId,
    eip: Instruction,
    app: &'ctx mut AppCtx,
    worklist: VecDeque<Inst>,
    visited: FxHashSet<(ModId, Id)>,
    result: Option<AuthZVal>,
}

impl<'ctx> Machine<'ctx> {
    #[inline]
    pub fn new(modid: ModId, func: Id, app: &'ctx mut AppCtx) -> Self {
        Self {
            callstack: vec![],
            curr_function: func,
            mod_id: modid,
            eip: PRELUDE,
            app,
            worklist: VecDeque::new(),
            visited: FxHashSet::default(),
            result: None,
        }
    }

    fn add_call(&mut self, module: ModId, func: Id) -> bool {
        debug!(?module, ?func, "checking call");
        let ret = self.eip;
        if self.visited.insert((module, func.clone())) {
            debug!(?module, ?func, "adding call to worklist");
            self.worklist.push_back(Inst::Call { func, module, ret });
            return true;
        }
        false
    }

    fn transfer(&mut self) -> Option<AuthZVal> {
        let result = self.result.take();
        let (call, changed) = self
            .app
            .meet(self.mod_id, &self.curr_function, self.eip.0, result);
        debug!(?call, ?changed, "transfer function");
        if let Some((modid, func)) = call {
            if self.add_call(modid, func) {
                return None;
            }
        }
        if changed {
            if let Some(succ) = self.app.succ(self.mod_id, &self.curr_function, self.eip.0) {
                self.worklist
                    .extend(succ.map(|next_block| Inst::Step(next_block, ENTRY_STMT)));
            }
            Some(self.app.func_res(self.mod_id, &self.curr_function))
        } else {
            None
        }
    }

    fn invoke(&mut self, mod_id: ModId, calling_function: Id, ret: Instruction) {
        debug!(?mod_id, ?calling_function, "invoking");
        self.callstack.push(Frame {
            ret,
            calling_function: self.curr_function.clone(),
        });
        self.curr_function = calling_function;
        self.mod_id = mod_id;
        self.eip = PRELUDE;
        self.worklist.push_back(Inst::Step(PRELUDE.0, PRELUDE.1));
    }

    #[instrument(level = "debug", skip(self), fields(module = ?self.mod_id, invoked = ?self.curr_function))]
    pub fn run(&mut self) -> AuthZVal {
        let (orig_mod, orig_func) = (self.mod_id, self.curr_function.clone());
        self.worklist.push_back(Inst::Step(self.eip.0, self.eip.1));
        while let Some(inst) = self.worklist.pop_front() {
            match inst {
                Inst::Call { func, module, ret } => self.invoke(module, func, ret),
                Inst::Step(next_block, next_stmt) => {
                    debug!(?next_block, ?next_stmt, "stepping into");
                    self.eip = (next_block, next_stmt);
                    // we need to return if possible
                    if let Some(val) = self.transfer() {
                        if let Some(ret) = self.callstack.pop() {
                            debug!(?ret, "returning");
                            self.curr_function = ret.calling_function;
                            self.result = Some(val);
                            let (ret_block, ret_stmt) = ret.ret;
                            self.worklist.push_back(Inst::Step(ret_block, ret_stmt));
                        }
                    }
                }
            }
        }
        let result = self.app.func_res(orig_mod, &orig_func);
        info!(?result, "analysis complete");
        result
    }
}
