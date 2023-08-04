use std::collections::VecDeque;

use forge_utils::FxHashSet;
use swc_core::ecma::ast::Id;
use tracing::{debug, info, instrument};

use crate::{
    analyzer::AuthZVal,
    ctx::{AppCtx, BasicBlockId, ModId, ModItem, StmtId, ENTRY_STMT, STARTING_BLOCK},
};

type Instruction = (BasicBlockId, StmtId);
const PRELUDE: Instruction = (STARTING_BLOCK, ENTRY_STMT);
type FuncId = ModItem;

#[derive(Debug)]
enum Inst {
    Call { func: FuncId, ret: Instruction },
    Step(BasicBlockId, StmtId),
}

#[derive(Debug)]
struct Frame {
    ret: Instruction,
    calling_function: FuncId,
}

pub struct Machine<'ctx> {
    callstack: Vec<Frame>,
    curr_function: FuncId,
    eip: Instruction,
    app: &'ctx mut AppCtx,
    worklist: VecDeque<Inst>,
    visited: FxHashSet<FuncId>,
    result: Option<AuthZVal>,
}

impl<'ctx> Machine<'ctx> {
    #[inline]
    pub fn new(mod_id: ModId, func: Id, app: &'ctx mut AppCtx) -> Self {
        Self {
            callstack: vec![],
            curr_function: ModItem {
                mod_id,
                ident: func,
            },
            eip: PRELUDE,
            app,
            worklist: VecDeque::new(),
            visited: FxHashSet::default(),
            result: None,
        }
    }

    fn add_call(&mut self, func: FuncId) -> bool {
        let ret = self.eip;
        if self.visited.insert(func.clone()) {
            debug!("adding {func:?} to worklist");
            self.worklist.push_back(Inst::Call { func, ret });
            return true;
        }
        false
    }

    fn transfer(&mut self) -> Option<AuthZVal> {
        let result = self.result.take();
        let (call, changed) = self.app.meet(&self.curr_function, self.eip.0, result);
        debug!(?call, ?changed, "transfer function");
        if let Some(func) = call {
            if self.add_call(func) {
                return None;
            }
        }

        changed.then(|| {
            if let Some(succ) = self.app.succ(&self.curr_function, self.eip.0) {
                self.worklist
                    .extend(succ.map(|next_block| Inst::Step(next_block, ENTRY_STMT)));
            }
            self.app.func_res(&self.curr_function)
        })
    }

    fn invoke(&mut self, calling_function: FuncId, ret: Instruction) {
        self.callstack.push(Frame {
            ret,
            calling_function: self.curr_function.clone(),
        });
        self.curr_function = calling_function;
        self.eip = PRELUDE;
        // self.worklist.push_back(Inst::Step(PRELUDE.0, PRELUDE.1));
        self.worklist.extend(
            self.app
                .func(&self.curr_function)
                .unwrap()
                .blocks
                .iter_enumerated()
                .map(|(bbid, _)| Inst::Step(bbid, PRELUDE.1)),
        );
    }

    #[instrument(level = "debug", skip(self), fields(invoked = ?self.curr_function))]
    pub fn run(&mut self) -> AuthZVal {
        let orig_func = self.curr_function.clone();
        let fst = self.eip.1;
        self.worklist.extend(
            self.app
                .func(&orig_func)
                .unwrap()
                .blocks
                .iter_enumerated()
                .map(|(bb_id, _)| Inst::Step(bb_id, fst)),
        );
        while let Some(inst) = self.worklist.pop_front() {
            match inst {
                Inst::Call { func, ret } => self.invoke(func, ret),
                Inst::Step(next_block, next_stmt) => {
                    debug!(?next_block, ?next_stmt, "stepping into");
                    self.eip = (next_block, next_stmt);
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
        let result = self.app.func_res(&orig_func);
        info!(?result, "analysis complete");
        let fname: &str = &orig_func.ident.0;
        println!("Result of analyzing {fname}:");
        match result {
            AuthZVal::Unauthorized => {
                println!("FAIL: Unauthorized call detected from handler: {fname}")
            }
            _ => println!("PASS"),
        }
        result
    }
}
