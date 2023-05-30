use std::{
    collections::hash_map::Entry::{Occupied, Vacant},
    io::{self, Write},
};

use forge_utils::{FxHashMap, FxHashSet};
use petgraph::{dot::Dot, prelude::DiGraph};
use tracing::debug;

use crate::ctx::{AppCtx, BasicBlock, IrStmt, ModItem, UNKNOWN_MODULE};

pub fn resolve_calls(ctx: &mut AppCtx) {
    let mut curr_functions = FxHashSet::default();
    // TODO: don't clone
    let appctx = ctx.clone();
    for (curr_mod, mod_ctx) in ctx.modctx.iter_mut_enumerated() {
        curr_functions.extend(mod_ctx.functions.keys().cloned());
        for func in mod_ctx.functions.values_mut() {
            for stmt in &mut func.iter_stmts_mut() {
                println!("{}", stmt);
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

pub fn create_cfg(ctx: &AppCtx, func: &ModItem) -> DiGraph<BasicBlock, ()> {
    let mut cfg = DiGraph::new();
    let func_meta = ctx.func(func).unwrap();
    for (_bbid, bb) in func_meta.blocks.iter_enumerated() {
        cfg.add_node(bb.clone());
    }
    for (&bbid, succs) in &func_meta.succ {
        for &succ in succs {
            cfg.add_edge(bbid.into(), succ.into(), ());
        }
    }
    cfg
}

pub fn dump_cfg_dot(ctx: &AppCtx, func: &ModItem, mut out: impl Write) -> io::Result<()> {
    let cfg = create_cfg(ctx, func);
    writeln!(out, "{:?}", Dot::new(&cfg))
}

pub fn dump_callgraph_dot(ctx: &AppCtx, func: &ModItem, mut out: impl Write) -> io::Result<()> {
    let mut cfg = DiGraph::new();
    let mut visited = FxHashSet::default();
    let mut func_to_node = FxHashMap::default();
    let mut stack = vec![func.clone()];
    while let Some(func) = stack.pop() {
        debug!(?func);
        let func_meta = match ctx.func(&func) {
            Some(func_meta) => func_meta,
            _ => continue,
        };
        let nodeidx = *func_to_node
            .entry(func.clone())
            .or_insert_with(|| cfg.add_node(func.clone()));
        for stmt in func_meta.iter_stmts() {
            debug!(?stmt);
            match stmt {
                IrStmt::Call(item) if item.mod_id != UNKNOWN_MODULE => {
                    match func_to_node.entry(item.clone()) {
                        Occupied(node) => {
                            cfg.add_edge(nodeidx, *node.get(), ());
                        }
                        Vacant(node) => {
                            let node = *node.insert(cfg.add_node(item.clone()));
                            cfg.add_edge(nodeidx, node, ());
                            if visited.insert(item.clone()) {
                                stack.push(item.clone());
                            }
                        }
                    };
                }
                _ => {}
            };
        }
    }
    writeln!(out, "{:?}", Dot::new(&cfg))
}
