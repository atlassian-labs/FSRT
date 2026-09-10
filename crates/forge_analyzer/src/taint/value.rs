use crate::{definitions::DefId, interp::JoinSemiLattice, ir::Location};
use smallvec::SmallVec;
use std::sync::Arc;

/// Input trust, independent of whether a particular sink can safely consume it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Classification {
    Trusted,
    #[default]
    Unknown,
    Untrusted,
}

impl JoinSemiLattice for Classification {
    const BOTTOM: Self = Self::Trusted;
    fn join(&self, other: &Self) -> Self {
        (*self).max(*other)
    }
    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.join(other);
        let changed = *self != next;
        *self = next;
        changed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OriginSite {
    Argument(DefId),
    Instruction(Location),
}

/// The static source rule ID and IR site remain stable across fixed-point visits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceOrigin {
    pub source: &'static str,
    pub function: DefId,
    pub site: OriginSite,
}

pub const MAX_ORIGINS: usize = 8;

/// Retaining the least eight keys makes bounded union associative, commutative,
/// and idempotent, unlike retaining the first eight encountered by the worklist.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origins(Option<Arc<[SourceOrigin]>>);

impl Origins {
    pub const EMPTY: Self = Self(None);
    fn as_slice(&self) -> &[SourceOrigin] {
        self.0.as_deref().unwrap_or_default()
    }
    pub fn insert(&mut self, origin: SourceOrigin) {
        let current = self.as_slice();
        if let Err(index) = current.binary_search(&origin)
            && index < MAX_ORIGINS
        {
            let mut next = SmallVec::<[SourceOrigin; MAX_ORIGINS]>::from_slice(current);
            if next.len() == MAX_ORIGINS {
                next.pop();
            }
            next.insert(index, origin);
            self.0 = Some(Arc::from(next.as_slice()));
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &SourceOrigin> {
        self.as_slice().iter()
    }
    pub fn union(&self, other: &Self) -> Self {
        if other.0.is_none() || self == other {
            return self.clone();
        }
        if self.0.is_none() {
            return other.clone();
        }
        let mut next = SmallVec::<[SourceOrigin; MAX_ORIGINS]>::from_slice(self.as_slice());
        for origin in other.as_slice() {
            if let Err(index) = next.binary_search(origin)
                && index < MAX_ORIGINS
            {
                if next.len() == MAX_ORIGINS {
                    next.pop();
                }
                next.insert(index, *origin);
            }
        }
        if next.as_slice() == self.as_slice() {
            self.clone()
        } else if next.as_slice() == other.as_slice() {
            other.clone()
        } else {
            Self(Some(Arc::from(next.as_slice())))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaintValue {
    pub classification: Classification,
    pub origins: Origins,
}

impl TaintValue {
    pub const fn new(classification: Classification) -> Self {
        Self {
            classification,
            origins: Origins::EMPTY,
        }
    }
    pub fn source(classification: Classification, origin: SourceOrigin) -> Self {
        let mut value = Self::new(classification);
        value.origins.insert(origin);
        value
    }
}

impl Default for TaintValue {
    fn default() -> Self {
        Self::new(Classification::Unknown)
    }
}

impl JoinSemiLattice for TaintValue {
    const BOTTOM: Self = Self::new(Classification::Trusted);
    fn join(&self, other: &Self) -> Self {
        Self {
            classification: self.classification.join(&other.classification),
            origins: self.origins.union(&other.origins),
        }
    }
    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.join(other);
        let changed = *self != next;
        *self = next;
        changed
    }
}

/// A scanner's sink-safety domain is joined separately from input trust.
pub trait PolicyFacts: JoinSemiLattice + Clone + Default + std::fmt::Debug {
    fn from_classification(classification: Classification) -> Self;
    /// Whether these policy facts still need the existing IR proof fallback.
    /// This is separate from input trust: a numeric-safe value may have unknown
    /// trust but fully resolved safety facts. Strong known values bypass fallback.
    fn is_unknown(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowValue<F> {
    pub taint: TaintValue,
    pub facts: F,
}

impl<F: PolicyFacts> FlowValue<F> {
    pub fn classified(classification: Classification) -> Self {
        Self {
            taint: TaintValue::new(classification),
            facts: F::from_classification(classification),
        }
    }
    pub fn trusted() -> Self {
        Self::classified(Classification::Trusted)
    }
    pub fn unknown() -> Self {
        Self::classified(Classification::Unknown)
    }
    pub fn source(classification: Classification, origin: SourceOrigin) -> Self {
        Self {
            taint: TaintValue::source(classification, origin),
            facts: F::from_classification(classification),
        }
    }
}
impl<F: PolicyFacts> Default for FlowValue<F> {
    fn default() -> Self {
        Self::unknown()
    }
}
impl<F: PolicyFacts> JoinSemiLattice for FlowValue<F> {
    const BOTTOM: Self = Self {
        taint: TaintValue::BOTTOM,
        facts: F::BOTTOM,
    };
    fn join(&self, other: &Self) -> Self {
        Self {
            taint: self.taint.join(&other.taint),
            facts: self.facts.join(&other.facts),
        }
    }
    fn join_changed(&mut self, other: &Self) -> bool {
        let changed_taint = self.taint.join_changed(&other.taint);
        let changed_facts = self.facts.join_changed(&other.facts);
        changed_taint || changed_facts
    }
}
