use std::io::{self, Write};

use crate::{
    definitions::Environment,
    ir::{BasicBlockId, Body, VarKind},
};

impl Environment {
    pub fn dump_function(&self, output: &mut dyn Write, func_name: &str) {
        let Some(body) = self
            .resolver
            .names
            .iter_enumerated()
            .find_map(|(id, name)| {
                if *func_name == *name {
                    self.def_ref(id).to_body()
                } else {
                    None
                }
            })
        else {
            eprintln!("No function named {func_name}");
            return;
        };
        if let Err(e) = dump_ir(output, self, body) {
            tracing::error!("Error dumping IR: {e}");
        }
    }

    pub fn dump_tree(&self, output: &mut dyn Write, func_name: &str) {
        let Some(body_map) = self
            .resolver
            .names
            .iter_enumerated()
            .find_map(|(id, name)| {
                if *func_name == *name {
                    self.def_ref(id).to_body()
                } else {
                    None
                }
            })
        else {
            eprintln!("No function named {func_name}");
            return;
        };
        if let Err(e) = dump_dom_tree(output, self, body_map) {
            tracing::error!("Error dumping IR: {e}");
        }
    }
}

pub fn dump_ir(output: &mut dyn Write, env: &Environment, body: &Body) -> io::Result<()> {
    let name = body
        .owner()
        .map_or("__ANONYMOUS", |owner| env.def_name(owner));
    writeln!(output, "IR for {name}")?;
    writeln!(output, "Variables:")?;
    for (id, var) in body.iter_vars_enumerated() {
        write!(output, "{id}: ")?;
        match *var {
            VarKind::LocalDef(def) => {
                writeln!(output, "local definition of {}", env.def_name(def))?
            }
            VarKind::GlobalRef(def) => writeln!(output, "global ref to {}", env.def_name(def))?,
            VarKind::Temp { parent: _parent } => writeln!(output, "temporary")?,
            VarKind::AnonClosure(_) => writeln!(output, "closure")?,
            VarKind::Arg(_) => writeln!(output, "arg")?,
            VarKind::Ret => writeln!(output, "return value")?,
        }
    }

    for (id, block) in body.iter_blocks_enumerated() {
        writeln!(output, "{id}:\n{block}")?;
    }

    writeln!(output)?;
    dump_dom_tree(output, env, body)?;

    Ok(())
}

pub fn dump_dom_tree(output: &mut dyn Write, _env: &Environment, body: &Body) -> io::Result<()> {
    writeln!(output, "----------------------------------------------")?;
    writeln!(output, "Checking Control Flow Graph\n")?;

    for (a, b) in body.iter_cfg_enumerated() {
        writeln!(output, "Edge: ({a}, {b})")?;
    }

    writeln!(output, "----------------------------------------------")?;
    let num_blocks = body.blocks.len();
    writeln!(
        output,
        "Dominator Tree idom: {:?}",
        &body.dominator_tree().idom[..num_blocks]
    )?;

    writeln!(output, "Idoms in format of <bb: bb's idom>")?;
    for (block, idom) in body.dominator_tree().idom[..num_blocks].iter().enumerate() {
        writeln!(output, "{}: {:?}", block, idom)?;
    }

    writeln!(output, "----------------------------------------------")?;
    for (block, _) in body.dominator_tree().idom[..num_blocks].iter().enumerate() {
        write!(output, "Blocks that bb{} Dominates: ", block)?;
        for i in 0..num_blocks {
            if body.dominates(BasicBlockId(block as u32), BasicBlockId(i as u32)) {
                write!(output, "{}, ", i)?;
            }
        }
        writeln!(output)?;
    }

    writeln!(output, "----------------------------------------------")?;
    for (block, _) in body.dominator_tree().idom[..num_blocks].iter().enumerate() {
        write!(output, "bb{}'s Dominators: ", block)?;
        for i in 0..num_blocks {
            if body.dominates(BasicBlockId(i as u32), BasicBlockId(block as u32)) {
                write!(output, "{}, ", i)?;
            }
        }
        writeln!(output)?;
    }

    writeln!(output, "----------------------------------------------")?;
    writeln!(output, "Dominance Frontiers:")?;
    for (block, _) in body.iter_blocks_enumerated() {
        write!(output, "bb{}: ", block.0)?;
        let dominance_frontier = body.dominance_frontier(block);

        for frontier_block in dominance_frontier {
            write!(output, "{}, ", frontier_block.0)?;
        }
        writeln!(output)?;
    }

    Ok(())
}
