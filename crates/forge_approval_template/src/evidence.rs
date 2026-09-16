//! Where a pre-filled value came from, and how much to trust it.

use serde::Serialize;

use crate::facts::Located;

/// A citation supporting a pre-filled value.
///
/// Every derived answer carries its evidence. This is the mechanism that makes
/// the output reviewable rather than merely convenient: a partner attesting to a
/// pre-filled answer, or a reviewer auditing one, can follow [`Self::pointer`]
/// straight to the line of the manifest it was read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// Dotted path into the manifest, e.g. `permissions.external.fetch.client[0]`.
    pub pointer: String,
    /// The value found there.
    pub value: String,
}

impl Evidence {
    pub fn new(pointer: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            value: value.into(),
        }
    }
}

impl<T: std::fmt::Display> From<&Located<T>> for Evidence {
    fn from(located: &Located<T>) -> Self {
        Self::new(located.pointer.clone(), located.value.to_string())
    }
}

/// How a value was arrived at.
///
/// This is the governance backbone of the tool. Auto-answering a security
/// questionnaire that a partner then attests to is only safe if the partner can
/// see which answers were *read* and which were *guessed*, so the basis travels
/// with every answer and drives
/// [`Self::requires_confirmation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Read directly out of the manifest. No inference.
    Deterministic,
    /// Inferred from manifest signals. Correct in the common case, but the
    /// manifest does not state it outright.
    Heuristic,
    /// Not answerable from the manifest; needs static analysis of the app's
    /// source. Candidates for a later phase built on FSRT's existing scanners.
    RequiresCodeReview,
    /// Not answerable from any app artefact. Depends on the partner's
    /// organisation, infrastructure or intent.
    RequiresPartnerInput,
}

impl Basis {
    /// Whether the partner must confirm the value before submitting.
    ///
    /// Only [`Self::Deterministic`] values are safe to submit unreviewed, and
    /// even those are the partner's responsibility.
    pub fn requires_confirmation(self) -> bool {
        self != Self::Deterministic
    }

    /// Whether this basis produced an actual value, as opposed to deferring.
    pub fn is_derived(self) -> bool {
        matches!(self, Self::Deterministic | Self::Heuristic)
    }

    /// The less certain of two bases.
    ///
    /// Used when a conclusion inherits the uncertainty of what it was built on,
    /// e.g. marking a sub-question "not applicable" is only as sound as the
    /// parent answer that made it so.
    pub fn weaker_of(self, other: Self) -> Self {
        self.max(other)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Deterministic => "read from manifest",
            Self::Heuristic => "inferred from manifest",
            Self::RequiresCodeReview => "needs code review",
            Self::RequiresPartnerInput => "needs partner input",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_deterministic_values_skip_confirmation() {
        assert!(!Basis::Deterministic.requires_confirmation());
        assert!(Basis::Heuristic.requires_confirmation());
        assert!(Basis::RequiresCodeReview.requires_confirmation());
        assert!(Basis::RequiresPartnerInput.requires_confirmation());
    }

    #[test]
    fn weaker_of_prefers_the_less_certain_basis() {
        assert_eq!(
            Basis::Deterministic.weaker_of(Basis::Heuristic),
            Basis::Heuristic
        );
        assert_eq!(
            Basis::Heuristic.weaker_of(Basis::Deterministic),
            Basis::Heuristic
        );
        assert_eq!(
            Basis::Deterministic.weaker_of(Basis::Deterministic),
            Basis::Deterministic
        );
        assert_eq!(
            Basis::Heuristic.weaker_of(Basis::RequiresPartnerInput),
            Basis::RequiresPartnerInput
        );
    }

    #[test]
    fn deferred_bases_are_not_derived() {
        assert!(Basis::Deterministic.is_derived());
        assert!(Basis::Heuristic.is_derived());
        assert!(!Basis::RequiresCodeReview.is_derived());
        assert!(!Basis::RequiresPartnerInput.is_derived());
    }
}
