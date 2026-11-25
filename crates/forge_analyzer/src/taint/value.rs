//! Values keep source provenance separate from a scanner's safety facts.

use super::Taint;
use crate::interp::JoinSemiLattice;

/// A finite-height domain. `join` merges alternative executions; `combine`
/// constructs a value containing both inputs (for example a template string).
/// Transfers must be monotone. Guarantees must hold on every joined alternative.
pub trait FlowFacts: JoinSemiLattice + Clone + Eq + Ord + std::fmt::Debug {
    fn from_taint(taint: Taint) -> Self;

    fn combine(&self, other: &Self) -> Self {
        self.join(other)
    }
}

impl FlowFacts for Taint {
    fn from_taint(taint: Taint) -> Self {
        taint
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowValue<F> {
    pub provenance: Taint,
    pub facts: F,
    // Bottom is absence of an execution/value, not a public or unknown value.
    pub(crate) reachable: bool,
}

impl<F: FlowFacts> FlowValue<F> {
    pub fn from_taint(taint: Taint) -> Self {
        Self {
            provenance: taint,
            facts: F::from_taint(taint),
            reachable: true,
        }
    }

    pub fn with_facts(&self, facts: F) -> Self {
        Self {
            provenance: self.provenance,
            facts,
            reachable: self.reachable,
        }
    }

    pub fn combine(&self, other: &Self) -> Self {
        if !self.reachable || !other.reachable {
            return Self::BOTTOM;
        }
        Self {
            provenance: self.provenance.join(&other.provenance),
            facts: self.facts.combine(&other.facts),
            reachable: true,
        }
    }
}

impl<F: FlowFacts> Default for FlowValue<F> {
    fn default() -> Self {
        Self::from_taint(Taint::No)
    }
}

impl<F: FlowFacts> JoinSemiLattice for FlowValue<F> {
    const BOTTOM: Self = Self {
        provenance: Taint::No,
        facts: F::BOTTOM,
        reachable: false,
    };

    fn join(&self, other: &Self) -> Self {
        if !self.reachable {
            return other.clone();
        }
        if !other.reachable {
            return self.clone();
        }
        Self {
            provenance: self.provenance.join(&other.provenance),
            facts: self.facts.join(&other.facts),
            reachable: true,
        }
    }

    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.join(other);
        let changed = *self != next;
        *self = next;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_flow_is_distinct_from_a_returned_public_value() {
        let absent = FlowValue::<Taint>::BOTTOM;
        let public = FlowValue::<Taint>::default();
        let source = FlowValue::<Taint>::from_taint(Taint::Yes);
        assert_ne!(absent, public);
        assert_eq!(absent.join(&source), source);
        assert_eq!(source.join(&absent), source);
        assert_eq!(absent.combine(&source), absent);
        assert_eq!(source.combine(&absent), absent);
        assert_eq!(public.combine(&source), source);
    }

    #[test]
    fn sanitization_preserves_provenance_independently_of_safety() {
        let source = FlowValue::<Taint>::from_taint(Taint::Yes);
        let safe = source.with_facts(Taint::No);
        assert_eq!(safe.provenance, Taint::Yes);
        assert_eq!(safe.facts, Taint::No);
        assert_eq!(safe.join(&source), source);
    }
}
