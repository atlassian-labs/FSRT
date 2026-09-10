use super::value::{FlowValue, PolicyFacts};
use crate::{
    definitions::{DefId, Environment},
    interp::JoinSemiLattice,
    ir::{Base, Projection, VarId, VarKind, Variable},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

// Compatibility adapter for FSRT's current binding representation. Logical-name
// equivalence is deliberately body-local; it is not a JavaScript heap alias model.
type FlowVarKey = (DefId, VarId, Vec<Projection>);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowState<F> {
    pub(crate) values: BTreeMap<FlowVarKey, FlowValue<F>>,
    refined: BTreeSet<FlowVarKey>,
    pub(crate) reachable: bool,
}

impl<F: PolicyFacts> JoinSemiLattice for FlowState<F> {
    const BOTTOM: Self = Self {
        values: BTreeMap::new(),
        refined: BTreeSet::new(),
        reachable: false,
    };

    fn join_changed(&mut self, other: &Self) -> bool {
        if !other.reachable {
            return false;
        }
        if !self.reachable {
            *self = other.clone();
            return true;
        }
        let mut changed = false;
        for (key, value) in &other.values {
            match self.values.entry(key.clone()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    changed |= entry.get_mut().join_changed(value);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(value.clone());
                    changed = true;
                }
            }
        }
        let refined_len = self.refined.len();
        self.refined.retain(|key| other.refined.contains(key));
        changed || refined_len != self.refined.len()
    }

    fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        joined.join_changed(other);
        joined
    }
}

impl<F: PolicyFacts> FlowState<F> {
    pub(crate) fn key(def: DefId, variable: &Variable) -> Option<FlowVarKey> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        Some((def, var, variable.projections.iter().cloned().collect()))
    }

    pub(crate) fn insert_variable(&mut self, def: DefId, variable: &Variable, value: FlowValue<F>) {
        let Some(key) = Self::key(def, variable) else {
            return;
        };
        // Assignments are strong updates. Control-flow alternatives are merged by
        // FlowState::join at CFG edges, not by retaining a variable's old value.
        self.values.insert(key, value);
    }

    pub(crate) fn insert_var(&mut self, def: DefId, var: VarId, value: FlowValue<F>) {
        self.insert_variable(def, &Variable::new(var), value);
    }

    pub(crate) fn logical_name<'a>(
        env: &'a Environment,
        body: &crate::ir::Body,
        variable: &Variable,
    ) -> Option<&'a str> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        let binding = match body.vars.get(var)? {
            VarKind::Arg(binding) | VarKind::GlobalRef(binding) | VarKind::LocalDef(binding) => {
                *binding
            }
            _ => return None,
        };
        let name = env.def_name(binding);
        (!name.starts_with("__")).then_some(name)
    }

    pub(crate) fn insert_assignment(
        &mut self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
        value: FlowValue<F>,
    ) {
        self.reachable = true;
        if variable.projections.is_empty() {
            if let Some(name) = Self::logical_name(env, body, variable) {
                let aliases = body
                    .vars
                    .iter_enumerated()
                    .filter_map(|(var, _)| {
                        let candidate = Variable::new(var);
                        (Self::logical_name(env, body, &candidate) == Some(name)).then_some(var)
                    })
                    .collect::<HashSet<_>>();
                self.values
                    .retain(|(owner, var, _), _| *owner != def || !aliases.contains(var));
                self.refined
                    .retain(|(owner, var, _)| *owner != def || !aliases.contains(var));
            }
            if let Some((owner, var, _)) = Self::key(def, variable) {
                self.values
                    .retain(|(candidate_owner, candidate_var, _), _| {
                        *candidate_owner != owner || *candidate_var != var
                    });
                self.refined.retain(|(candidate_owner, candidate_var, _)| {
                    *candidate_owner != owner || *candidate_var != var
                });
            }
            self.insert_variable(def, variable, value);
            return;
        }

        if let Some(name) = Self::logical_name(env, body, variable) {
            let projections = &variable.projections;
            let aliases = body
                .vars
                .iter_enumerated()
                .filter_map(|(var, _)| {
                    let mut candidate = Variable::new(var);
                    candidate.projections = projections.clone();
                    (Self::logical_name(env, body, &candidate) == Some(name)).then_some(var)
                })
                .collect::<HashSet<_>>();
            self.refined.retain(|(owner, var, candidate_projections)| {
                *owner != def
                    || !aliases.contains(var)
                    || candidate_projections.as_slice() != projections.as_slice()
            });
        } else if let Some(key) = Self::key(def, variable) {
            self.refined.remove(&key);
        }
        self.insert_variable(def, variable, value.clone());
        if let Base::Var(var) = variable.base {
            let root = (def, var, vec![]);
            self.values
                .entry(root)
                .and_modify(|aggregate| *aggregate = aggregate.join(&value))
                .or_insert(value);
        }
    }

    pub(crate) fn variable(&self, def: DefId, variable: &Variable) -> Option<FlowValue<F>> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        let projections: Vec<_> = variable.projections.iter().cloned().collect();
        self.values
            .get(&(def, var, projections))
            .cloned()
            .or_else(|| self.values.get(&(def, var, vec![])).cloned())
    }

    pub(crate) fn exact_variable(&self, def: DefId, variable: &Variable) -> Option<FlowValue<F>> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        self.values
            .get(&(def, var, variable.projections.iter().cloned().collect()))
            .cloned()
    }

    pub(crate) fn variable_with_aliases(
        &self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> Option<FlowValue<F>> {
        let Some(name) = Self::logical_name(env, body, variable) else {
            return self.variable(def, variable);
        };
        let aliases = body
            .vars
            .iter_enumerated()
            .filter_map(|(var, _)| {
                let mut candidate = Variable::new(var);
                candidate.projections = variable.projections.clone();
                (Self::logical_name(env, body, &candidate) == Some(name)).then_some(candidate)
            })
            .collect::<Vec<_>>();

        // A field-specific fact is more precise than the aggregate object fact.
        // Consult roots only when no alias has a fact for this exact projection.
        let exact = aliases
            .iter()
            .filter_map(|candidate| self.exact_variable(def, candidate))
            .reduce(|left, right| left.join(&right));
        exact.or_else(|| {
            aliases
                .iter()
                .filter_map(|candidate| self.variable(def, candidate))
                .reduce(|left, right| left.join(&right))
        })
    }

    pub(crate) fn projections(
        &self,
        def: DefId,
        variable: &Variable,
    ) -> BTreeMap<Vec<Projection>, FlowValue<F>> {
        let Base::Var(var) = variable.base else {
            return BTreeMap::new();
        };
        self.values
            .iter()
            .filter(|((owner, candidate, path), _)| {
                *owner == def
                    && *candidate == var
                    && path.len() > variable.projections.len()
                    && path.starts_with(&variable.projections)
            })
            .map(|((_, _, path), value)| {
                (path[variable.projections.len()..].to_vec(), value.clone())
            })
            .collect()
    }

    pub(crate) fn mark_refined(
        &mut self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) {
        self.reachable = true;
        let Some(name) = Self::logical_name(env, body, variable) else {
            if let Some(key) = Self::key(def, variable) {
                self.refined.insert(key);
            }
            return;
        };
        for (var, _) in body.vars.iter_enumerated() {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            if Self::logical_name(env, body, &candidate) == Some(name)
                && let Some(key) = Self::key(def, &candidate)
            {
                self.refined.insert(key);
            }
        }
    }

    pub(crate) fn is_refined(
        &self,
        env: &Environment,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> bool {
        let Some(name) = Self::logical_name(env, body, variable) else {
            return Self::key(def, variable).is_some_and(|key| self.refined.contains(&key));
        };
        body.vars.iter_enumerated().any(|(var, _)| {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            Self::logical_name(env, body, &candidate) == Some(name)
                && Self::key(def, &candidate).is_some_and(|key| self.refined.contains(&key))
        })
    }
}
