//! Scanner-neutral import provenance over finalized IR. Unknown alternatives
//! invalidate a proof; absent receivers (undefined/null or a missing object
//! field) cannot supply a different API. No code or module loaders are executed.

use super::{DefId, DefKind, Environment, ImportKind};
use crate::ir::{
    Base, Body, Inst, Literal, Location, Operand, Projection, Rvalue, VarKind, Variable,
};
use std::collections::{HashMap, HashSet};
use swc_core::ecma::atoms::Atom;

type Import = (Atom, ImportKind);
type Proof = Result<Option<Import>, ()>;

impl Environment {
    /// Recover an import for this call's callee through static reads and fields.
    /// Direct ESM and recovered imports use the same callee-based lookup, so
    /// namespace projections and intermediate calls cannot inherit a root-only fact.
    pub(crate) fn call_import(&self, body: &Body, location: Location) -> Option<Import> {
        let facts = body.call_facts(location)?;
        facts
            .recovered_import
            .get_or_init(|| {
                let (callee, _) = body.block(location.block).insts[location.stmt as usize]
                    .rvalue()
                    .as_call()?;
                let Operand::Var(variable) = callee else {
                    return None;
                };
                ImportResolver {
                    env: self,
                    visiting: HashSet::new(),
                    remaining_steps: 1024,
                }
                .variable(body, variable, 32)
                .ok()
                .flatten()
            })
            .clone()
    }
}

// This is an intentionally coarse alias graph, not a points-to heap. A property
// write or an escape into a call invalidates the whole connected alias component.
// Literal initialization writes are handled separately by the provenance walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AliasKey {
    Binding(DefId),
    Temporary(DefId, crate::ir::VarId),
}

fn alias_key(env: &Environment, body: &Body, variable: &Variable) -> Option<AliasKey> {
    let Base::Var(var) = variable.base else {
        return None;
    };
    Some(match body.vars.get(var) {
        Some(VarKind::GlobalRef(def) | VarKind::LocalDef(def) | VarKind::Arg(def)) => {
            AliasKey::Binding(env.resolve_alias(*def))
        }
        _ => AliasKey::Temporary(body.owner()?, var),
    })
}

#[derive(Debug, Clone, Default)]
pub(super) struct ImportMutations(HashSet<AliasKey>);

impl ImportMutations {
    fn collect(env: &Environment) -> Self {
        let mut aliases = HashMap::<AliasKey, Vec<AliasKey>>::new();
        let mut pending = Vec::new();
        for body in env.defs.funcs.iter() {
            for (_, block) in body.iter_blocks_enumerated() {
                for inst in block.iter() {
                    if let Some((_, args)) = inst.rvalue().as_call() {
                        pending.extend(args.iter().filter_map(|arg| match arg {
                            Operand::Var(var) => alias_key(env, body, var),
                            _ => None,
                        }));
                    }
                    let Inst::Assign(target, value) = inst else {
                        continue;
                    };
                    let Some(target_key) = alias_key(env, body, target) else {
                        continue;
                    };
                    let literal = matches!(target_key,
                        AliasKey::Binding(def) if matches!(env.def_ref(def), DefKind::GlobalObj(_))
                    );
                    if !target.projections.is_empty() && !literal {
                        pending.push(target_key);
                    }
                    let sources = match value {
                        Rvalue::Read(Operand::Var(source)) => vec![source.clone()],
                        Rvalue::Phi(values) => {
                            values.iter().map(|(var, _)| Variable::new(*var)).collect()
                        }
                        _ => Vec::new(),
                    };
                    for source in sources {
                        if let Some(source_key) = alias_key(env, body, &source) {
                            aliases.entry(target_key).or_default().push(source_key);
                            aliases.entry(source_key).or_default().push(target_key);
                        }
                    }
                }
            }
        }
        let mut invalid = HashSet::new();
        while let Some(key) = pending.pop() {
            if invalid.insert(key) {
                pending.extend(aliases.get(&key).into_iter().flatten().copied());
            }
        }
        Self(invalid)
    }
}

struct ImportResolver<'a> {
    env: &'a Environment,
    visiting: HashSet<(DefId, Variable)>,
    remaining_steps: usize,
}

fn project_import(mut import: Import, projections: &[Projection]) -> Proof {
    if projections
        .iter()
        .any(|p| matches!(p, Projection::Computed(_)))
    {
        return Err(());
    }
    if matches!(import.1, ImportKind::Star)
        && let Some(Projection::Known(member)) = projections.first()
    {
        import.1 = if member == "default" {
            ImportKind::Default
        } else {
            ImportKind::Named(member.clone())
        };
    }
    Ok(Some(import))
}

fn join_import(left: Option<Import>, right: Option<Import>) -> Proof {
    match (left, right) {
        (Some(left), Some(right)) if left != right => Err(()),
        (Some(import), _) | (_, Some(import)) => Ok(Some(import)),
        (None, None) => Ok(None),
    }
}

impl ImportResolver<'_> {
    fn variable(&mut self, body: &Body, variable: &Variable, depth: usize) -> Proof {
        if depth == 0
            || self.remaining_steps == 0
            || variable
                .projections
                .iter()
                .any(|p| matches!(p, Projection::Computed(_)))
        {
            return Err(());
        }
        self.remaining_steps -= 1;
        let Base::Var(var) = variable.base else {
            return Err(());
        };
        let alias = alias_key(self.env, body, variable).ok_or(())?;
        let mutations = self
            .env
            .immutable_facts
            .import_mutations
            .get_or_init(|| ImportMutations::collect(self.env));
        if mutations.0.contains(&alias)
            || matches!(alias, AliasKey::Binding(def) if self.env.opaque_import_objects.contains(&def))
        {
            return Err(());
        }
        let key = (body.owner().ok_or(())?, variable.clone());
        if !self.visiting.insert(key.clone()) {
            return Err(());
        }
        let result = self.variable_inner(body, variable, var, depth - 1);
        self.visiting.remove(&key);
        result
    }

    fn variable_inner(
        &mut self,
        body: &Body,
        variable: &Variable,
        var: crate::ir::VarId,
        depth: usize,
    ) -> Proof {
        let binding = match body.vars.get(var) {
            Some(VarKind::GlobalRef(def) | VarKind::LocalDef(def) | VarKind::Arg(def)) => {
                Some(self.env.resolve_alias(*def))
            }
            _ => None,
        };
        if let Some(import) = binding.and_then(|def| self.env.as_foreign_import(def)) {
            return project_import(import, &variable.projections);
        }
        let writes = if let Some(binding) = binding {
            self.env.definition_writes(binding).collect::<Vec<_>>()
        } else {
            body.iter_blocks_enumerated()
                .flat_map(|(_, block)| block.iter())
                .filter_map(|inst| match inst {
                    Inst::Assign(target, value) if target.base == variable.base => {
                        Some((body, target, value))
                    }
                    _ => None,
                })
                .collect()
        };
        let mut found = false;
        let mut result = None;
        for (owner, target, value) in writes {
            if target
                .projections
                .iter()
                .any(|p| matches!(p, Projection::Computed(_)))
            {
                return Err(());
            }
            if variable.projections.starts_with(&target.projections) {
                found = true;
                let suffix = &variable.projections[target.projections.len()..];
                result = join_import(result, self.rvalue(owner, value, suffix, depth)?)?;
            }
        }
        if found {
            Ok(result)
        } else if binding.is_some_and(|def| matches!(self.env.def_ref(def), DefKind::GlobalObj(_)))
        {
            // A known object literal with no matching property contributes no API.
            Ok(None)
        } else {
            Err(())
        }
    }

    fn rvalue(
        &mut self,
        body: &Body,
        value: &Rvalue,
        suffix: &[Projection],
        depth: usize,
    ) -> Proof {
        match value {
            Rvalue::Read(Operand::Var(source)) => {
                let mut projected = source.clone();
                projected.projections.extend(suffix.iter().cloned());
                self.variable(body, &projected, depth)
            }
            Rvalue::Read(Operand::Lit(Literal::Undef | Literal::Null)) => Ok(None),
            Rvalue::Phi(alternatives) => {
                let mut result = None;
                for (var, _) in alternatives {
                    let mut variable = Variable::new(*var);
                    variable.projections.extend(suffix.iter().cloned());
                    result = join_import(result, self.variable(body, &variable, depth)?)?;
                }
                Ok(result)
            }
            Rvalue::Call(Operand::Var(callee), args) if callee.projections.is_empty() => {
                let Base::Var(var) = callee.base else {
                    return Err(());
                };
                let Some(VarKind::GlobalRef(def)) = body.vars.get(var) else {
                    return Err(());
                };
                let def = self.env.resolve_alias(*def);
                if !matches!(self.env.def_ref(def), DefKind::Undefined)
                    || self.env.def_name(def) != "require"
                    || self.env.definition_writes(def).next().is_some()
                {
                    return Err(());
                }
                let [Operand::Lit(Literal::Str(module))] = args.as_slice() else {
                    return Err(());
                };
                project_import((module.clone(), ImportKind::Star), suffix)
            }
            _ => Err(()),
        }
    }
}
