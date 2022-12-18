use std::io::{self, Write};

use crate::{
    definitions::Environment,
    ir::{Body, VarKind},
};

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
    Ok(())
}
