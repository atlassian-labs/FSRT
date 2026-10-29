use super::value::{FlowValue, PolicyFacts};
use crate::{
    definitions::DefId,
    interp::JoinSemiLattice,
    ir::{Base, Projection, VarId, Variable},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

// Values stay keyed by instruction variable and projection. Binding identity is
// used to reconcile references and assignment versions within the same body.
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
        let original = self.clone();
        for ((owner, var, path), value) in &mut self.values {
            if !path.is_empty()
                && value.shape.is_authoritative()
                && other.values.contains_key(&(*owner, *var, vec![]))
                && !other.values.contains_key(&(*owner, *var, path.clone()))
            {
                let mut variable = Variable::new(*var);
                variable.projections.extend(path.iter().cloned());
                let alternative = other
                    .variable(*owner, &variable)
                    .unwrap_or_else(FlowValue::unknown);
                changed |= value.join_changed(&alternative);
            }
        }
        for (key, value) in &other.values {
            match self.values.entry(key.clone()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    changed |= entry.get_mut().join_changed(value);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let value = if key.2.is_empty()
                        || !value.shape.is_authoritative()
                        || !original.values.contains_key(&(key.0, key.1, vec![]))
                    {
                        value.clone()
                    } else {
                        let mut variable = Variable::new(key.1);
                        variable.projections.extend(key.2.iter().cloned());
                        value.join(
                            &original
                                .variable(key.0, &variable)
                                .unwrap_or_else(FlowValue::unknown),
                        )
                    };
                    entry.insert(value);
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
    pub(crate) fn input_write_targets(
        &self,
        receiver: super::InputShape,
        property: &Projection,
    ) -> Vec<(DefId, Variable)> {
        let super::InputShape::Known {
            root,
            schema,
            node,
            invalid: super::Classification::Trusted,
        } = receiver
        else {
            return vec![];
        };
        if !matches!(property, Projection::Known(_)) || schema.nodes[node].properties.is_empty() {
            return vec![];
        }
        self.values
            .iter()
            .filter_map(|((owner, var, path), value)| {
                if !path.is_empty() {
                    return None;
                }
                let super::InputShape::Known {
                    root: candidate_root,
                    schema: candidate_schema,
                    node: start,
                    invalid: super::Classification::Trusted,
                } = value.shape
                else {
                    return None;
                };
                if root != candidate_root
                    || schema != candidate_schema
                    || schema.nodes[start].properties.is_empty()
                {
                    return None;
                }
                let mut queue = std::collections::VecDeque::from([(start, Vec::new())]);
                let mut seen = BTreeSet::new();
                while let Some((current, prefix)) = queue.pop_front() {
                    if !seen.insert(current) {
                        continue;
                    }
                    if current == node {
                        let mut variable = Variable::new(*var);
                        variable.projections.extend(prefix);
                        variable.projections.push(property.clone());
                        return Some((*owner, variable));
                    }
                    for (name, next) in schema.nodes[current].properties {
                        if schema.nodes[*next].reference {
                            let mut path = prefix.clone();
                            path.push(Projection::Known((*name).into()));
                            queue.push_back((*next, path));
                        }
                    }
                }
                None
            })
            .collect()
    }

    pub(crate) fn invalidate_input(
        &mut self,
        root: super::InputRoot,
        incoming: Option<&FlowValue<F>>,
    ) {
        let objects: BTreeSet<_> = self
            .values
            .iter()
            .filter_map(|((owner, var, path), value)| {
                (path.is_empty() && value.references.contains(&root)).then_some((*owner, *var))
            })
            .collect();
        // Drop cached field overrides on actual aliases. Detached scalar copies
        // (including scalar fields of newly constructed objects) stay snapshots.
        self.values
            .retain(|(owner, var, path), _| path.is_empty() || !objects.contains(&(*owner, *var)));
        for value in self.values.values_mut() {
            if value.references.contains(&root) {
                if let super::InputShape::Known { invalid, .. } = &mut value.shape {
                    *invalid = invalid.join(&super::Classification::Unknown);
                    if let Some(incoming) = incoming {
                        *invalid = invalid.join(&incoming.taint.classification);
                    }
                } else {
                    value.shape = super::InputShape::Unknown;
                }
                value.taint.classification = value
                    .taint
                    .classification
                    .join(&super::Classification::Unknown);
                value.facts = F::from_classification(value.taint.classification);
                if let Some(incoming) = incoming {
                    value.taint = value.taint.join(&incoming.taint);
                    value.facts = value.facts.join(&incoming.facts);
                }
            }
        }
    }

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

    pub(crate) fn insert_assignment(
        &mut self,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
        value: FlowValue<F>,
    ) {
        self.reachable = true;
        if variable.projections.is_empty() {
            if let Some(aliases) = body.binding_variables(variable) {
                let aliases = aliases.iter().copied().collect::<HashSet<_>>();
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

        if let Some(aliases) = body.binding_variables(variable) {
            let projections = &variable.projections;
            let aliases = aliases.iter().copied().collect::<HashSet<_>>();
            self.refined.retain(|(owner, var, candidate_projections)| {
                *owner != def
                    || !aliases.contains(var)
                    || candidate_projections.as_slice() != projections.as_slice()
            });
        } else if let Some(key) = Self::key(def, variable) {
            self.refined.remove(&key);
        }
        let aliases = body
            .binding_variables(variable)
            .map(|items| items.to_vec())
            .unwrap_or_else(|| match variable.base {
                Base::Var(var) => vec![var],
                _ => vec![],
            });
        self.values.retain(|(owner, var, path), _| {
            *owner != def || !aliases.contains(var) || !path.starts_with(&variable.projections)
        });
        self.insert_variable(def, variable, value.clone());
        if let Base::Var(var) = variable.base {
            let root = (def, var, vec![]);
            self.values
                .entry(root)
                .and_modify(|aggregate| {
                    let shape = aggregate.shape;
                    *aggregate = aggregate.join(&value);
                    aggregate.shape = shape;
                })
                .or_insert(value);
        }
    }

    pub(crate) fn variable(&self, def: DefId, variable: &Variable) -> Option<FlowValue<F>> {
        let Base::Var(var) = variable.base else {
            return None;
        };
        let projections: Vec<_> = variable.projections.iter().cloned().collect();
        (0..=projections.len()).rev().find_map(|length| {
            self.values
                .get(&(def, var, projections[..length].to_vec()))
                .map(|value| value.project(&projections[length..]))
        })
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
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> Option<FlowValue<F>> {
        let Some(aliases) = body.binding_variables(variable) else {
            return self.variable(def, variable);
        };
        let candidates = || {
            aliases.iter().map(|&var| {
                let mut candidate = Variable::new(var);
                candidate.projections = variable.projections.clone();
                candidate
            })
        };

        // A field-specific fact is more precise than the aggregate object fact.
        // Consult roots only when no alias has a fact for this exact projection.
        let exact = candidates()
            .filter_map(|candidate| self.exact_variable(def, &candidate))
            .reduce(|left, right| left.join(&right));
        exact.or_else(|| {
            candidates()
                .filter_map(|candidate| self.variable(def, &candidate))
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

    pub(crate) fn mark_refined(&mut self, body: &crate::ir::Body, def: DefId, variable: &Variable) {
        self.reachable = true;
        let Some(aliases) = body.binding_variables(variable) else {
            if let Some(key) = Self::key(def, variable) {
                self.refined.insert(key);
            }
            return;
        };
        for &var in aliases {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            if let Some(key) = Self::key(def, &candidate) {
                self.refined.insert(key);
            }
        }
    }

    pub(crate) fn is_refined(
        &self,
        body: &crate::ir::Body,
        def: DefId,
        variable: &Variable,
    ) -> bool {
        let Some(aliases) = body.binding_variables(variable) else {
            return Self::key(def, variable).is_some_and(|key| self.refined.contains(&key));
        };
        aliases.iter().any(|&var| {
            let mut candidate = Variable::new(var);
            candidate.projections = variable.projections.clone();
            Self::key(def, &candidate).is_some_and(|key| self.refined.contains(&key))
        })
    }
}
