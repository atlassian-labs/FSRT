use std::{
    cell::RefCell,
    fmt::Display,
    io::{self, Write},
};

use forge_utils::{FxHashMap, FxHashSet};

use crate::{
    definitions::{DefId, Environment},
    ir::{BasicBlock, BasicBlockId, Operand, Variable, STARTING_BLOCK},
};

trait JoinSemiLattice: Sized {
    const BOTTOM: Self;

    fn join(&mut self, other: &Self) -> bool;
}

enum Transition {
    Call,
    Break,
    StepOver,
}

trait WithCallStack {
    fn add_call_stack(&mut self, stack: Vec<DefId>);
}

trait Dataflow<'cx>: Sized {
    type State: JoinSemiLattice + Clone;

    fn with_interp<C: Checker<'cx, State = Self::State>>(interp: &Interp<'cx, C>) -> Self;

    fn transfer_block<C: Checker<'cx, State = Self::State>>(
        &mut self,
        interp: &Interp<'cx, C>,
        bb: BasicBlockId,
        block: &'cx BasicBlock,
        initial_state: &Self::State,
    ) -> Self::State;
}

trait Checker<'cx>: Sized {
    type State: JoinSemiLattice + Clone;
    type Vuln: Display + WithCallStack;
    type Dataflow: Dataflow<'cx, State = Self::State>;

    fn visit_call(
        &mut self,
        interp: &Interp<'cx, Self>,
        callee: &'cx Variable,
        args: &'cx [Operand],
        curr_state: &Self::State,
    ) -> (Transition, Self::State);
}

struct Frame {
    calling_function: DefId,
    block: BasicBlockId,
    inst_idx: usize,
}

struct Interp<'cx, C: Checker<'cx>> {
    env: &'cx Environment,
    checker: C,
    func_state: FxHashMap<DefId, C::State>,
    visited: FxHashSet<DefId>,
    callstack: Vec<Frame>,
    func_branches: FxHashMap<DefId, Vec<(BasicBlockId, usize)>>,
    vulns: RefCell<Vec<C::Vuln>>,
}

impl<'cx, C: Checker<'cx>> Interp<'cx, C> {
    #[inline]
    fn env(&self) -> &'cx Environment {
        self.env
    }

    fn note_vuln(&self, mut vuln: C::Vuln) {
        vuln.add_call_stack(
            self.callstack
                .iter()
                .map(|f| f.calling_function)
                .collect::<Vec<_>>(),
        );
        self.vulns.borrow_mut().push(vuln);
    }

    fn run(&mut self, func: DefId) {
        if self.visited.contains(&func) {
            return;
        }
        self.visited.insert(func);
        let func = self.env().def_ref(func).expect_body();
        let mut dataflow = C::Dataflow::with_interp(self);
        let mut block_id = STARTING_BLOCK;
        let block = func.block(block_id);
        let initial_state = C::State::BOTTOM;
        let final_state = dataflow.transfer_block(self, block_id, &block, &initial_state);
    }

    fn dump_results(&self, out: &mut dyn Write) -> io::Result<()> {
        let vulns = &**self.vulns.borrow();
        if vulns.is_empty() {
            writeln!(out, "No vulnerabilities found")
        } else {
            writeln!(out, "Found {} vulnerabilities", vulns.len())?;
            for vuln in vulns {
                writeln!(out, "{vuln}")?;
            }
            Ok(())
        }
    }
}
