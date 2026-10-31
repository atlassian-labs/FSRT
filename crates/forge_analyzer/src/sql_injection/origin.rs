//! What made a value attacker controlled, carried in the SQL policy's facts.

use crate::{
    interp::JoinSemiLattice,
    taint::{FlowFacts, Taint},
};

/// The kind of source that put attacker-controlled data into a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The first argument of a Forge function module's handler.
    ModulePayload,
    /// The `payload` of a resolver's request envelope.
    ResolverPayload,
    /// A response to a network `fetch`.
    Fetch,
    /// A response to a call to an Atlassian product API.
    ApiCall,
    /// A read of Forge storage.
    StorageRead,
    /// The rows `@forge/sql` returned.
    SqlResult,
    /// A secret read from Forge storage.
    SecretRead,
    /// A value the analysis could not classify. Only present when
    /// `UNKNOWN_IS_UNTRUSTED` makes such a value attacker controlled.
    Unclassified,
}

impl Origin {
    const ALL: [Self; 8] = [
        Self::ModulePayload,
        Self::ResolverPayload,
        Self::Fetch,
        Self::ApiCall,
        Self::StorageRead,
        Self::SqlResult,
        Self::SecretRead,
        Self::Unclassified,
    ];

    /// How a finding's proof names this origin.
    pub fn label(self) -> &'static str {
        match self {
            Self::ModulePayload => "module payload",
            Self::ResolverPayload => "resolver payload",
            Self::Fetch => "fetch response",
            Self::ApiCall => "API call response",
            Self::StorageRead => "storage read",
            Self::SqlResult => "SQL result",
            Self::SecretRead => "secret read",
            Self::Unclassified => "unclassified value",
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// The origins that make a value attacker controlled, as the SQL policy's
/// facts. No origin is a value whose text cannot carry SQL syntax of an
/// attacker's choosing; any origin is one that may, and says why. A join is a
/// union, so a known origin is never lost to another, and a value stays
/// attacker controlled exactly as long as it has an origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origins(u8);

impl Origins {
    pub const NONE: Self = Self(0);

    pub const fn of(origin: Origin) -> Self {
        Self(origin.bit())
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn contains(self, origin: Origin) -> bool {
        self.0 & origin.bit() != 0
    }

    /// The origins, in a fixed order.
    pub fn iter(self) -> impl Iterator<Item = Origin> {
        Origin::ALL
            .into_iter()
            .filter(move |&origin| self.contains(origin))
    }

    /// The origins' labels, in a fixed order.
    pub fn labels(self) -> Vec<&'static str> {
        self.iter().map(Origin::label).collect()
    }
}

impl JoinSemiLattice for Origins {
    const BOTTOM: Self = Self::NONE;

    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.union(*other);
        let changed = next != *self;
        *self = next;
        changed
    }

    fn join(&self, other: &Self) -> Self {
        self.union(*other)
    }
}

impl FlowFacts for Origins {
    /// A source that names no origin is unclassified. A value that may carry a
    /// source, but is not known to, is not attacker controlled here.
    fn from_taint(taint: Taint) -> Self {
        match taint {
            Taint::Yes => Self::of(Origin::Unclassified),
            Taint::No | Taint::Unknown => Self::NONE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_unions_origins_in_any_order() {
        let payload = Origins::of(Origin::ModulePayload);
        let fetch = Origins::of(Origin::Fetch);
        let both = payload.join(&fetch);
        assert_eq!(both, fetch.join(&payload));
        assert_eq!(both.labels(), ["module payload", "fetch response"]);
        assert_eq!(both.join(&payload), both);
        assert_eq!(both.join(&Origins::NONE), both);
        assert_eq!(Origins::NONE.join(&Origins::NONE), Origins::NONE);
    }

    #[test]
    fn join_changed_reports_only_new_origins() {
        let mut origins = Origins::NONE;
        assert!(!origins.join_changed(&Origins::NONE));
        assert!(origins.join_changed(&Origins::of(Origin::StorageRead)));
        assert!(!origins.join_changed(&Origins::of(Origin::StorageRead)));
        assert!(origins.join_changed(&Origins::of(Origin::SqlResult)));
        assert_eq!(origins.labels(), ["storage read", "SQL result"]);
    }

    #[test]
    fn every_origin_has_a_distinct_bit_and_label() {
        let mut all = Origins::NONE;
        for origin in Origin::ALL {
            let single = Origins::of(origin);
            assert!(!single.is_empty());
            assert_eq!(single.iter().collect::<Vec<_>>(), [origin]);
            assert!(!all.contains(origin), "{origin:?} reuses a bit");
            all = all.union(single);
        }
        let mut labels = all.labels();
        assert_eq!(labels.len(), Origin::ALL.len());
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), Origin::ALL.len());
    }

    #[test]
    fn only_a_yes_source_without_an_origin_is_unclassified() {
        assert_eq!(
            Origins::from_taint(Taint::Yes),
            Origins::of(Origin::Unclassified)
        );
        assert!(Origins::from_taint(Taint::No).is_empty());
        assert!(Origins::from_taint(Taint::Unknown).is_empty());
    }
}
