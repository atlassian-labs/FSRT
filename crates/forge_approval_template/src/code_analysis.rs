//! Static analysis results, as far as the approval submission cares about them.
//!
//! # Why this crate does not run the analysis itself
//!
//! `crates/fsrt` is a binary-only crate: it has no `[lib]` target, so its
//! `scan_directory` cannot be called from here. The dependency edge only runs the
//! other way.
//!
//! So this module defines the *input* shape and the rules for reading it, and the
//! `fsrt` binary converts its own `Report` into it. That split is worth keeping
//! even if `fsrt` grew a library target: the mapping rules below are the part with
//! judgement in them and they stay unit-testable without running an analysis.
//!
//! # What a clean scan does and does not prove
//!
//! FSRT's analysis is neither sound nor complete, so:
//!
//! - A **finding** is good evidence that the app has the problem. It is used to
//!   answer the corresponding question the unfavourable way.
//! - A **clean run** is weak evidence of absence. It is still used to pre-fill the
//!   favourable answer, because a scanner having looked is materially better than
//!   a blank field — but never as [`Basis::Deterministic`], always flagged for
//!   confirmation, and the rationale always says a scanner found nothing rather
//!   than that nothing is there.
//! - A **checker that did not run** yields nothing at all.
//!
//! Getting this distinction wrong is how a tool launders its own uncertainty into
//! a partner's signature.
//!
//! [`Basis::Deterministic`]: crate::evidence::Basis::Deterministic

use std::collections::BTreeSet;

use serde::Serialize;

/// An FSRT checker, identified from the `check_name` of its findings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Checker {
    /// `AuthZChecker` — an authorisation bypass reaching a privileged call.
    Authorization,
    /// `AuthenticateChecker` — a web trigger or webhook without authentication.
    Authentication,
    /// `SecretChecker` — a secret hardcoded in the app's source or manifest.
    HardcodedSecret,
    /// `AuthHeaderChecker` — an Atlassian API or container token used directly.
    AtlassianCredential,
    /// `PermissionChecker` — scopes declared in the manifest but never used.
    LeastPrivilege,
    /// `ForgeRuntimeVersionPolicyChecker` — an end-of-life Node.js runtime.
    RuntimeVersion,
    /// A checker this mapping does not recognise.
    Other(String),
}

impl Checker {
    /// Classify a finding from FSRT's `Vulnerability::check_name()`.
    ///
    /// Most check names carry a hash of the finding's location, so matching is by
    /// prefix. The names are defined in `forge_analyzer::checkers`.
    pub fn from_check_name(check_name: &str) -> Self {
        // Names ending in a location hash are matched by prefix. Note that the
        // OAuth provider secret name extends the plain secret prefix, so both
        // land on `HardcodedSecret`.
        if check_name.starts_with("Custom-Check-Authorization-") {
            return Self::Authorization;
        }
        if check_name.starts_with("Custom-Check-Authentication-") {
            return Self::Authentication;
        }
        if check_name.starts_with("Custom-Check-Hardcoded-Secret-") {
            return Self::HardcodedSecret;
        }

        match check_name {
            "ATLASSIAN_API_TOKEN" | "ATLASSIAN_CONTAINER_TOKEN" => Self::AtlassianCredential,
            "Least-Privilege" => Self::LeastPrivilege,
            "Forge Runtime Version Policy Checker" => Self::RuntimeVersion,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn display(&self) -> &str {
        match self {
            Self::Authorization => "authorization scanner",
            Self::Authentication => "authentication scanner",
            Self::HardcodedSecret => "hardcoded secret scanner",
            Self::AtlassianCredential => "Atlassian credential scanner",
            Self::LeastPrivilege => "least privilege scanner",
            Self::RuntimeVersion => "Forge runtime version scanner",
            Self::Other(name) => name,
        }
    }
}

/// A single static analysis finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeFinding {
    pub checker: Checker,
    /// FSRT's raw `check_name`, retained so a finding can be traced back to the
    /// scanner's own report.
    pub check_name: String,
    pub description: String,
}

impl CodeFinding {
    pub fn new(check_name: impl Into<String>, description: impl Into<String>) -> Self {
        let check_name = check_name.into();
        Self {
            checker: Checker::from_check_name(&check_name),
            check_name,
            description: description.into(),
        }
    }
}

/// What a scan of the app's source found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CodeAnalysis {
    /// Checkers that actually ran. A clean result only means something for these.
    pub checkers_run: BTreeSet<Checker>,
    pub findings: Vec<CodeFinding>,
}

/// What a scan concluded about one checker's concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The checker did not run, so nothing can be concluded.
    NotRun,
    /// The checker ran and found nothing. Weak evidence of absence.
    Clean,
    /// The checker found problems. Good evidence of presence.
    Found,
}

impl CodeAnalysis {
    pub fn new(checkers_run: BTreeSet<Checker>, findings: Vec<CodeFinding>) -> Self {
        Self {
            checkers_run,
            findings,
        }
    }

    /// Build from an iterator of `(check_name, description)` pairs.
    pub fn from_findings<I, S, T>(checkers_run: BTreeSet<Checker>, findings: I) -> Self
    where
        I: IntoIterator<Item = (S, T)>,
        S: Into<String>,
        T: Into<String>,
    {
        Self::new(
            checkers_run,
            findings
                .into_iter()
                .map(|(check_name, description)| CodeFinding::new(check_name, description))
                .collect(),
        )
    }

    pub fn ran(&self, checker: &Checker) -> bool {
        self.checkers_run.contains(checker)
    }

    pub fn findings_by<'a>(
        &'a self,
        checker: &'a Checker,
    ) -> impl Iterator<Item = &'a CodeFinding> {
        self.findings
            .iter()
            .filter(move |finding| &finding.checker == checker)
    }

    /// What the scan concluded about a checker's concern.
    ///
    /// A finding is treated as proof the checker ran, even if the caller did not
    /// list it in [`Self::checkers_run`]. Some checkers are gated at runtime by
    /// conditions a caller cannot observe, so the finding is the more reliable
    /// signal.
    pub fn verdict(&self, checker: &Checker) -> Verdict {
        if self.findings_by(checker).next().is_some() {
            return Verdict::Found;
        }
        if !self.ran(checker) {
            return Verdict::NotRun;
        }
        Verdict::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_hashed_check_names_by_prefix() {
        assert_eq!(
            Checker::from_check_name("Custom-Check-Authorization-1234567890"),
            Checker::Authorization
        );
        assert_eq!(
            Checker::from_check_name("Custom-Check-Authentication-987"),
            Checker::Authentication
        );
        assert_eq!(
            Checker::from_check_name("Custom-Check-Hardcoded-Secret-42"),
            Checker::HardcodedSecret
        );
        // The OAuth provider variant extends the plain secret prefix.
        assert_eq!(
            Checker::from_check_name("Custom-Check-Hardcoded-Secret-OAuth-Provider-42"),
            Checker::HardcodedSecret
        );
    }

    #[test]
    fn classifies_fixed_check_names() {
        assert_eq!(
            Checker::from_check_name("ATLASSIAN_API_TOKEN"),
            Checker::AtlassianCredential
        );
        assert_eq!(
            Checker::from_check_name("ATLASSIAN_CONTAINER_TOKEN"),
            Checker::AtlassianCredential
        );
        assert_eq!(
            Checker::from_check_name("Least-Privilege"),
            Checker::LeastPrivilege
        );
        assert_eq!(
            Checker::from_check_name("Forge Runtime Version Policy Checker"),
            Checker::RuntimeVersion
        );
    }

    #[test]
    fn unrecognised_checkers_are_preserved_not_dropped() {
        assert_eq!(
            Checker::from_check_name("Some-New-Checker-7"),
            Checker::Other("Some-New-Checker-7".to_string())
        );
    }

    #[test]
    fn verdict_distinguishes_not_run_from_clean() {
        let empty = CodeAnalysis::default();
        assert_eq!(empty.verdict(&Checker::Authentication), Verdict::NotRun);

        let ran_clean = CodeAnalysis::new(BTreeSet::from([Checker::Authentication]), Vec::new());
        assert_eq!(ran_clean.verdict(&Checker::Authentication), Verdict::Clean);
        // A different checker still did not run.
        assert_eq!(
            ran_clean.verdict(&Checker::HardcodedSecret),
            Verdict::NotRun
        );

        let found = CodeAnalysis::from_findings(
            BTreeSet::from([Checker::Authentication]),
            [(
                "Custom-Check-Authentication-1",
                "Insufficient Authentication through webhook run in \"src/index.js\".",
            )],
        );
        assert_eq!(found.verdict(&Checker::Authentication), Verdict::Found);
    }

    #[test]
    fn findings_are_grouped_by_checker() {
        let analysis = CodeAnalysis::from_findings(
            BTreeSet::from([Checker::Authorization, Checker::HardcodedSecret]),
            [
                ("Custom-Check-Authorization-1", "bypass one"),
                ("Custom-Check-Authorization-2", "bypass two"),
                ("Custom-Check-Hardcoded-Secret-3", "a secret"),
            ],
        );
        assert_eq!(analysis.findings_by(&Checker::Authorization).count(), 2);
        assert_eq!(analysis.findings_by(&Checker::HardcodedSecret).count(), 1);
        assert_eq!(analysis.findings_by(&Checker::LeastPrivilege).count(), 0);
    }
}
