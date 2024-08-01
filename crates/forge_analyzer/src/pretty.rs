use std::io::{self, Write};

use crate::{
    definitions::Environment,
    ir::{Body, VarKind},
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

    writeln!(output, "Checking Control Flow Graph\n")?;

    for (a, b) in body.iter_cfg_enumerated() {
        write!(output, "Edge: ({a}, {b})\n")?;
    }

    write!(output, "dominator tree idom: {:?}\n", body.dominator_tree().idom)?;

    
    Ok(())
}

pub fn dump_dom_tree(output: &mut dyn Write, env: &Environment, body: &Body) -> io::Result<()> {
    writeln!(output, "Checking Control Flow Graph\n")?;

    for (a, b) in body.iter_cfg_enumerated() {
        write!(output, "Edge: ({a}, {b})\n")?;
    }

    write!(output, "dominator tree idom: {:?}\n", body.dominator_tree().idom)?;
    
    Ok(())
}
