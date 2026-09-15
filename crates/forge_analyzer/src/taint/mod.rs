//! Bounded provenance and reusable forward flow. Scanner policies own sink safety.
mod engine;
pub(crate) mod semantics;
pub mod sources;
mod state;
mod value;
pub use engine::{FlowPolicy, TaintDataflow, classify_operand, classify_variable};
pub use state::FlowState;
pub use value::{
    Classification, FlowValue, MAX_ORIGINS, OriginSite, Origins, PolicyFacts, SourceOrigin,
    TaintValue,
};

/// No extra sink-specific facts, useful for consumers interested only in trust.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoFacts;
impl crate::interp::JoinSemiLattice for NoFacts {
    const BOTTOM: Self = Self;
    fn join(&self, _: &Self) -> Self {
        Self
    }
    fn join_changed(&mut self, _: &Self) -> bool {
        false
    }
}
impl PolicyFacts for NoFacts {
    fn from_classification(_: Classification) -> Self {
        Self
    }
    fn is_unknown(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
