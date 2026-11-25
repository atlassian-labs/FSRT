use std::{collections::BTreeMap, rc::Rc};

use super::{FieldPath, FlowFacts, FlowValue};
use crate::{definitions::DefId, interp::JoinSemiLattice, ir::VarId};

pub(super) type FieldMap<F> = BTreeMap<FieldPath, FlowValue<F>>;
pub(super) type Fields<F> = Rc<FieldMap<F>>;

/// Root describes the value before tracked field writes. Whole-value reads
/// combine the fields; projections use the root as their fallback. Keeping
/// these separate lets field removal preserve unrelated source information.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrackedValue<F> {
    pub root: FlowValue<F>,
    pub(super) fields: Option<Fields<F>>,
}

impl<F: FlowFacts> TrackedValue<F> {
    pub const BOTTOM: Self = Self {
        root: FlowValue::BOTTOM,
        fields: None,
    };

    pub fn aggregate(&self) -> FlowValue<F> {
        self.fields
            .iter()
            .flat_map(|fields| fields.values())
            .fold(self.root.clone(), |value, field| value.combine(field))
    }
}

impl<F: FlowFacts> From<FlowValue<F>> for TrackedValue<F> {
    fn from(root: FlowValue<F>) -> Self {
        Self { root, fields: None }
    }
}

impl<F: FlowFacts> Default for TrackedValue<F> {
    fn default() -> Self {
        FlowValue::default().into()
    }
}

/// Per-function storage. Cloning a block input shares locals until the first
/// write, rather than copying every variable at every instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowState<F> {
    pub(super) vars: Rc<Vec<TrackedValue<F>>>,
    pub(super) captures: BTreeMap<DefId, TrackedValue<F>>,
    pub(super) reachable: bool,
}

impl<F: FlowFacts> Default for FlowState<F> {
    fn default() -> Self {
        Self {
            vars: Rc::default(),
            captures: BTreeMap::new(),
            reachable: false,
        }
    }
}

impl<F: FlowFacts> FlowState<F> {
    pub(super) fn value(&self, id: VarId) -> TrackedValue<F> {
        self.vars
            .get(id.0 as usize)
            .cloned()
            .unwrap_or(TrackedValue::BOTTOM)
    }

    pub(super) fn set(&mut self, id: VarId, value: TrackedValue<F>) {
        Rc::make_mut(&mut self.vars)[id.0 as usize] = value;
    }
}
