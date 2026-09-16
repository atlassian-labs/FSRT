//! Assembling the pre-filled submission.

use serde::Serialize;

use crate::answers::{self, AnsweredQuestion};
use crate::code_analysis::CodeAnalysis;
use crate::evidence::Basis;
use crate::facts::ManifestFacts;
use crate::flags::{self, Flag};
use crate::listing::{self, ListingField};
use crate::questionnaire::{AnswerValue, AppType, ReviewSignal};

/// The output format version. Bump on any breaking change to the shape, so
/// downstream consumers can pin.
pub const SCHEMA_VERSION: &str = "1.0";

/// Where the questionnaire encoded by this tool was transcribed from.
const QUESTIONNAIRE_SOURCE: &str =
    "https://developer.atlassian.com/platform/marketplace/app-security-questionnaires/";

/// The standing caveat attached to every report.
///
/// This exists because auto-answering a security questionnaire creates a real
/// governance hazard: the partner attests to the answers, so a confident wrong
/// answer transfers a tool's mistake onto a person's signature. Nothing here is
/// submitted automatically, and every answer not read directly out of the
/// manifest is marked for confirmation.
const ATTESTATION: &str = "This submission was pre-filled from the app manifest. It is a \
     draft, not an attestation. Every answer marked `confirm_before_submitting` must be \
     checked by the partner before submission, and the partner remains responsible for \
     the accuracy of all answers. Answers marked `requires_code_review` or \
     `requires_partner_input` have not been answered at all and must be completed.";

/// A pre-filled app approval submission.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ApprovalTemplate {
    pub schema_version: &'static str,
    pub app_type: AppType,
    pub questionnaire_source: &'static str,
    pub manifest_path: String,
    /// The scan the answers were informed by, if one was run. Recorded so a
    /// reviewer can see which checkers were consulted, and which were not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_analysis: Option<CodeAnalysis>,
    pub coverage: Coverage,
    pub flags: Vec<Flag>,
    pub listing: Vec<ListingField>,
    pub questionnaire: Vec<AnsweredQuestion>,
    pub attestation: &'static str,
}

/// How much of the submission the tool managed to fill in.
///
/// This is the measurement the task asks for: what a partner no longer has to
/// type, and what they still do.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Coverage {
    /// Every prompt in the questionnaire, including conditional sub-questions.
    pub total_prompts: usize,
    /// Prompts actually put to the partner, after conditional gating.
    pub asked: usize,
    /// Prompts that now carry an answer, including those ruled not applicable.
    pub resolved: usize,
    /// Prompts answered with a value read from or inferred from the manifest.
    pub prefilled: usize,
    /// Of which read directly from the manifest.
    pub deterministic: usize,
    /// Of which inferred from manifest signals.
    pub heuristic: usize,
    /// Ruled out because a parent question made them moot.
    pub not_applicable: usize,
    /// Left for static analysis of the app's source.
    pub requires_code_review: usize,
    /// Left for the partner.
    pub requires_partner_input: usize,
    /// [`Self::resolved`] as a percentage of [`Self::total_prompts`], to one
    /// decimal place.
    pub percent_resolved: f64,
    /// Derived answers that trip a blocking signal. Each is a likely rejection.
    pub blocking_signals_tripped: usize,
    /// Derived answers that trip a warning signal.
    pub warning_signals_tripped: usize,
}

impl Coverage {
    fn measure(answered: &[AnsweredQuestion]) -> Self {
        let count = |predicate: &dyn Fn(&AnsweredQuestion) -> bool| {
            answered.iter().filter(|a| predicate(a)).count()
        };

        let total_prompts = answered.len();
        let resolved = count(&|a| a.is_prefilled());
        let not_applicable = count(&|a| a.answer == AnswerValue::NotApplicable);

        let tripped = |signal: ReviewSignal| {
            count(&move |a| a.trips_signal && a.signal == signal && a.basis.is_derived())
        };

        Self {
            total_prompts,
            asked: count(&|a| a.asked),
            resolved,
            prefilled: resolved - not_applicable,
            deterministic: count(&|a| a.basis == Basis::Deterministic && a.is_prefilled()),
            heuristic: count(&|a| a.basis == Basis::Heuristic && a.is_prefilled()),
            not_applicable,
            requires_code_review: count(&|a| {
                a.basis == Basis::RequiresCodeReview && !a.is_prefilled()
            }),
            requires_partner_input: count(&|a| {
                a.basis == Basis::RequiresPartnerInput && !a.is_prefilled()
            }),
            percent_resolved: percentage(resolved, total_prompts),
            blocking_signals_tripped: tripped(ReviewSignal::Fail),
            warning_signals_tripped: tripped(ReviewSignal::Warning),
        }
    }
}

fn percentage(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    let raw = (part as f64 / whole as f64) * 100.0;
    (raw * 10.0).round() / 10.0
}

impl ApprovalTemplate {
    /// Pre-fill a submission from a parsed manifest, optionally informed by a
    /// scan of the app's source.
    pub fn build(
        facts: &ManifestFacts,
        code: Option<CodeAnalysis>,
        manifest_path: impl Into<String>,
    ) -> Self {
        let questionnaire = answers::answer_forge_questionnaire(facts, code.as_ref());
        Self {
            schema_version: SCHEMA_VERSION,
            app_type: AppType::Forge,
            questionnaire_source: QUESTIONNAIRE_SOURCE,
            manifest_path: manifest_path.into(),
            coverage: Coverage::measure(&questionnaire),
            flags: flags::check(facts, code.as_ref()),
            listing: listing::build(facts),
            questionnaire,
            code_analysis: code,
            attestation: ATTESTATION,
        }
    }

    /// Read a manifest and pre-fill a submission from it.
    pub fn from_manifest(
        source: &str,
        code: Option<CodeAnalysis>,
        manifest_path: impl Into<String>,
    ) -> Result<Self, crate::facts::Error> {
        Ok(Self::build(
            &ManifestFacts::from_yaml(source)?,
            code,
            manifest_path,
        ))
    }

    /// Flags that would block listing if submitted as-is.
    pub fn blocking_flags(&self) -> impl Iterator<Item = &Flag> {
        self.flags
            .iter()
            .filter(|flag| flag.severity == ReviewSignal::Fail)
    }

    /// Answers the partner must check before submitting.
    pub fn needs_confirmation(&self) -> impl Iterator<Item = &AnsweredQuestion> {
        self.questionnaire
            .iter()
            .filter(|answer| answer.confirm_before_submitting && answer.is_prefilled())
    }

    /// Listing fields the partner must still supply.
    pub fn outstanding_listing_fields(&self) -> impl Iterator<Item = &ListingField> {
        self.listing.iter().filter(|field| field.is_outstanding())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_analysis::Checker;
    use std::collections::BTreeSet;

    const VULNERABLE_APP: &str =
        include_str!("../../../test-apps/jira-damn-vulnerable-forge-app/manifest.yml");
    const BASIC_APP: &str = include_str!("../../../test-apps/basic/manifest.yml");

    fn template(source: &str) -> ApprovalTemplate {
        ApprovalTemplate::from_manifest(source, None, "manifest.yml").expect("parses")
    }

    fn answer(template: &ApprovalTemplate, id: &str) -> AnsweredQuestion {
        template
            .questionnaire
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("no question {id}"))
    }

    #[test]
    fn every_prompt_is_accounted_for() {
        let template = template(VULNERABLE_APP);
        assert_eq!(template.questionnaire.len(), 31);
        assert_eq!(template.coverage.total_prompts, 31);

        // The four dispositions partition the questionnaire exactly.
        let coverage = template.coverage;
        assert_eq!(
            coverage.prefilled
                + coverage.not_applicable
                + coverage.requires_code_review
                + coverage.requires_partner_input,
            coverage.total_prompts
        );
    }

    #[test]
    fn declarations_are_answered_deterministically() {
        let template = template(VULNERABLE_APP);
        for (id, expected) in [
            ("2", AnswerValue::Yes),  // declares a remote
            ("4", AnswerValue::Yes),  // declares a webtrigger
            ("5", AnswerValue::Yes),  // declares displayConditions
            ("6", AnswerValue::Yes),  // declares egress
            ("6a", AnswerValue::Yes), // egress is `*`
        ] {
            let answer = answer(&template, id);
            assert_eq!(answer.answer, expected, "question {id}");
            assert_eq!(answer.basis, Basis::Deterministic, "question {id}");
            assert!(!answer.confirm_before_submitting, "question {id}");
            assert!(!answer.evidence.is_empty(), "question {id} cites nothing");
        }
    }

    #[test]
    fn wildcard_egress_trips_the_documented_warning() {
        let answer = answer(&template(VULNERABLE_APP), "6a");
        assert_eq!(answer.signal, ReviewSignal::Warning);
        assert!(answer.trips_signal);
        assert_eq!(
            answer.evidence[0].pointer,
            "permissions.external.fetch.client[0]"
        );
    }

    #[test]
    fn code_behaviour_is_never_guessed() {
        let template = template(VULNERABLE_APP);
        // The questions FSRT's scanners would answer are left open, not assumed.
        for id in ["1a", "3", "4a", "5a", "8", "9", "11", "13"] {
            let answer = answer(&template, id);
            assert_eq!(answer.answer, AnswerValue::Unknown, "question {id}");
            assert_eq!(answer.basis, Basis::RequiresCodeReview, "question {id}");
            assert!(answer.rationale.is_some(), "question {id}");
        }
    }

    #[test]
    fn remote_host_questions_are_left_to_the_partner_with_context() {
        // The remotes[].auth block is not evidence of FIT validation, so 2a must
        // not be answered from it -- but the facts are still offered as context.
        let answer = answer(&template(VULNERABLE_APP), "2a");
        assert_eq!(answer.answer, AnswerValue::Unknown);
        assert_eq!(answer.basis, Basis::RequiresPartnerInput);
        assert!(answer.asked, "the app declares a remote, so 2a is asked");
        assert!(!answer.evidence.is_empty());
        assert!(answer.rationale.as_ref().unwrap().contains("FIT"));
    }

    #[test]
    fn sub_questions_are_dropped_when_the_parent_rules_them_out() {
        let template = template(BASIC_APP);
        // No remote, no webtrigger, no display conditions, no egress.
        for parent in ["2", "4", "5", "6"] {
            assert_eq!(answer(&template, parent).answer, AnswerValue::No);
        }
        for child in ["2a", "2b", "4a", "5a", "6a", "6b", "6c", "6d", "6d-i"] {
            let answer = answer(&template, child);
            assert_eq!(
                answer.answer,
                AnswerValue::NotApplicable,
                "question {child}"
            );
            assert!(!answer.asked, "question {child} should not be asked");
            assert!(!answer.trips_signal, "question {child}");
        }
    }

    #[test]
    fn a_simple_app_resolves_more_of_the_form_than_a_complex_one() {
        // Answering "yes" to a declaration question opens follow-ups that need
        // code review, so richer manifests resolve proportionally less.
        let simple = template(BASIC_APP).coverage;
        let complex = template(VULNERABLE_APP).coverage;
        assert!(
            simple.percent_resolved > complex.percent_resolved,
            "simple {} should resolve more than complex {}",
            simple.percent_resolved,
            complex.percent_resolved
        );
    }

    #[test]
    fn coverage_percentage_is_bounded() {
        for source in [VULNERABLE_APP, BASIC_APP] {
            let percent = template(source).coverage.percent_resolved;
            assert!((0.0..=100.0).contains(&percent), "{percent}");
        }
        assert_eq!(percentage(0, 0), 0.0);
        assert_eq!(percentage(1, 3), 33.3);
        assert_eq!(percentage(31, 31), 100.0);
    }

    #[test]
    fn wildcard_egress_is_also_raised_as_a_presubmission_flag() {
        let template = template(VULNERABLE_APP);
        assert!(template.flags.iter().any(|f| f.id == "egress.overly_broad"));
        assert!(
            template
                .flags
                .iter()
                .any(|f| f.id == "content_security.unsafe_directive")
        );
        // Nothing in this manifest is a blocking flag: the egress wildcard is a
        // warning, and there is no cleartext destination.
        assert_eq!(template.blocking_flags().count(), 0);
    }

    #[test]
    fn cleartext_egress_blocks_and_is_answered_no() {
        let source = "
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
  name: Reporting for Jira
modules:
  macro:
    - key: m
      function: main
permissions:
  external:
    fetch:
      backend:
        - 'http://metrics.example.com'
";
        let template = template(source);
        let answer = answer(&template, "6b");
        assert_eq!(answer.answer, AnswerValue::No);
        assert_eq!(answer.basis, Basis::Deterministic);
        assert!(answer.trips_signal);
        assert_eq!(answer.signal, ReviewSignal::Fail);

        let blocking: Vec<_> = template.blocking_flags().map(|f| f.id).collect();
        assert_eq!(blocking, vec!["egress.cleartext"]);
        assert_eq!(template.coverage.blocking_signals_tripped, 1);
    }

    #[test]
    fn a_trademark_prefixed_name_is_a_blocking_flag() {
        let source = "
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
  name: Jira Reporting Toolkit
modules:
  macro:
    - key: m
      function: main
";
        let blocking: Vec<_> = template(source)
            .blocking_flags()
            .map(|flag| flag.id)
            .collect();
        assert_eq!(blocking, vec!["naming.trademark_prefix"]);
    }

    #[test]
    fn outstanding_listing_fields_are_reported() {
        let template = template(VULNERABLE_APP);
        let outstanding: Vec<_> = template
            .outstanding_listing_fields()
            .map(|field| field.name)
            .collect();
        assert!(outstanding.contains(&"Privacy policy URL"));
        assert!(outstanding.contains(&"App name"));
    }

    #[test]
    fn only_inferred_answers_are_marked_for_confirmation() {
        let template = template(VULNERABLE_APP);
        for answer in template.needs_confirmation() {
            assert_eq!(answer.basis, Basis::Heuristic, "question {}", answer.id);
        }
    }

    /// Every checker having run and found nothing.
    fn clean_scan() -> CodeAnalysis {
        CodeAnalysis::new(
            BTreeSet::from([
                Checker::Authorization,
                Checker::Authentication,
                Checker::HardcodedSecret,
                Checker::AtlassianCredential,
                Checker::LeastPrivilege,
            ]),
            Vec::new(),
        )
    }

    fn scanned(source: &str, code: CodeAnalysis) -> ApprovalTemplate {
        ApprovalTemplate::from_manifest(source, Some(code), "manifest.yml").expect("parses")
    }

    #[test]
    fn a_clean_scan_resolves_the_code_questions() {
        let template = scanned(VULNERABLE_APP, clean_scan());
        for (id, expected) in [
            ("3", AnswerValue::Yes),  // no authorization bypass found
            ("4a", AnswerValue::Yes), // no unauthenticated web trigger found
            ("5a", AnswerValue::No),  // conditions are not the only gate
            ("7", AnswerValue::Yes),  // no unused declared scopes
            ("11", AnswerValue::No),  // no Atlassian credentials in code
            ("13", AnswerValue::No),  // no hardcoded secrets
        ] {
            let answer = answer(&template, id);
            assert_eq!(answer.answer, expected, "question {id}");
            // A clean scan is never proof, so it is never deterministic and
            // always needs confirming.
            assert_eq!(answer.basis, Basis::Heuristic, "question {id}");
            assert!(answer.confirm_before_submitting, "question {id}");
            assert!(!answer.trips_signal, "question {id}");
        }
    }

    #[test]
    fn scanning_raises_coverage_substantially() {
        let manifest_only = template(VULNERABLE_APP).coverage;
        let with_scan = scanned(VULNERABLE_APP, clean_scan()).coverage;

        assert_eq!(manifest_only.requires_code_review, 11);
        assert_eq!(with_scan.requires_code_review, 5);
        assert!(
            with_scan.percent_resolved > manifest_only.percent_resolved + 15.0,
            "expected a large uplift, got {} -> {}",
            manifest_only.percent_resolved,
            with_scan.percent_resolved
        );
    }

    #[test]
    fn findings_flip_answers_and_trip_blocking_signals() {
        let analysis = CodeAnalysis::from_findings(
            BTreeSet::from([
                Checker::Authorization,
                Checker::Authentication,
                Checker::HardcodedSecret,
                Checker::LeastPrivilege,
            ]),
            [
                (
                    "Custom-Check-Authorization-99",
                    "Authorization bypass detected through run in \"src/index.jsx\".",
                ),
                (
                    "Custom-Check-Authentication-98",
                    "Insufficient Authentication through webhook run in \"src/index.jsx\".",
                ),
                (
                    "Custom-Check-Hardcoded-Secret-97",
                    "Hardcoded secret found within codebase run in \"src/utils.js\".",
                ),
                (
                    "Least-Privilege",
                    "Unused permissions listed in manifest file.",
                ),
            ],
        );
        let template = scanned(VULNERABLE_APP, analysis);

        // Q13 is Fail-signalled and Yes is the non-conforming answer.
        let secrets = answer(&template, "13");
        assert_eq!(secrets.answer, AnswerValue::Yes);
        assert!(secrets.trips_signal);
        assert_eq!(secrets.signal, ReviewSignal::Fail);
        assert_eq!(secrets.evidence.len(), 1);
        assert_eq!(
            secrets.evidence[0].pointer,
            "Custom-Check-Hardcoded-Secret-97"
        );

        // Q3 is Fail-signalled and No is the non-conforming answer.
        let authz = answer(&template, "3");
        assert_eq!(authz.answer, AnswerValue::No);
        assert!(authz.trips_signal);

        // Q5a: display conditions plus an authorization bypass implies the
        // condition is the only gate.
        assert_eq!(answer(&template, "5a").answer, AnswerValue::Yes);
        assert!(answer(&template, "5a").trips_signal);

        assert_eq!(answer(&template, "4a").answer, AnswerValue::No);
        assert_eq!(answer(&template, "7").answer, AnswerValue::No);

        // Two Fail-signalled questions now answered the wrong way.
        assert_eq!(template.coverage.blocking_signals_tripped, 2);
    }

    #[test]
    fn display_condition_correlation_needs_display_conditions() {
        // The basic app declares none, so Q5a must not be answered from an
        // authorization finding alone.
        let analysis = CodeAnalysis::from_findings(
            BTreeSet::from([Checker::Authorization]),
            [("Custom-Check-Authorization-1", "bypass")],
        );
        let template = scanned(BASIC_APP, analysis);
        // Q5 is No, so Q5a is not applicable rather than answered.
        assert_eq!(answer(&template, "5a").answer, AnswerValue::NotApplicable);
    }

    #[test]
    fn an_end_of_life_runtime_becomes_a_flag() {
        let analysis = CodeAnalysis::from_findings(
            BTreeSet::from([Checker::RuntimeVersion]),
            [(
                "Forge Runtime Version Policy Checker",
                "The Forge app uses an end-of-life Node.js runtime.",
            )],
        );
        assert!(
            scanned(VULNERABLE_APP, analysis)
                .flags
                .iter()
                .any(|flag| flag.id == "runtime.end_of_life")
        );
    }

    #[test]
    fn checkers_that_did_not_run_leave_questions_open() {
        // Only the authentication checker ran, so only its question moves.
        let partial = CodeAnalysis::new(BTreeSet::from([Checker::Authentication]), Vec::new());
        let template = scanned(VULNERABLE_APP, partial);
        assert_eq!(answer(&template, "4a").answer, AnswerValue::Yes);
        assert_eq!(answer(&template, "13").answer, AnswerValue::Unknown);
        assert_eq!(answer(&template, "13").basis, Basis::RequiresCodeReview);
    }

    #[test]
    fn serialises_to_json() {
        let json = serde_json::to_value(template(VULNERABLE_APP)).expect("serialises");
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["app_type"], "forge");
        assert_eq!(json["questionnaire"][0]["id"], "1");
        assert!(json["attestation"].as_str().unwrap().contains("draft"));
    }
}
