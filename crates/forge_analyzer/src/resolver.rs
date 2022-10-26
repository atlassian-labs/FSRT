use rustc_hash::FxHashSet;

use crate::ctx::{AppCtx, IrStmt, ModItem, UNKNOWN_MODULE};

pub fn resolve_calls(ctx: &mut AppCtx) {
    let mut curr_functions = FxHashSet::default();
    // TODO: don't clone
    let appctx = ctx.clone();
    for (curr_mod, mod_ctx) in ctx.modctx.iter_mut_enumerated() {
        curr_functions.extend(mod_ctx.functions.keys().cloned());
        for func in mod_ctx.functions.values_mut() {
            for stmt in &mut func.iter_stmts_mut() {
                if let IrStmt::Call(ModItem {
                    mod_id: id @ UNKNOWN_MODULE,
                    ident,
                }) = stmt
                {
                    if curr_functions.contains(ident) {
                        *id = curr_mod;
                    } else if let Some((new_mod, new_ident)) =
                        appctx.resolve_export(curr_mod, ident)
                    {
                        *id = new_mod;
                        *ident = new_ident;
                    }
                }
            }
        }
        curr_functions.clear();
    }
}
