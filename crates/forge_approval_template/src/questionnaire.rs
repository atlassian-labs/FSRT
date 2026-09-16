//! The Marketplace security questionnaire, encoded as data.
//!
//! # Provenance
//!
//! Transcribed from the public Atlassian developer documentation:
//! <https://developer.atlassian.com/platform/marketplace/app-security-questionnaires/>
//!
//! - Page "Last updated" stamp at time of transcription: **Jul 16, 2025**
//! - Transcribed: **2026-09-14**
//!
//! Only the **Forge** questionnaire is encoded here. The page also publishes
//! questionnaires for Connect, 3LO and Data Center apps; those app types are not
//! Forge manifests, so they are out of scope for a manifest-driven pre-fill.
//! [`AppType`] exists so the report can state which questionnaire it targeted.
//!
//! # Review signals
//!
//! The documentation defines three signals which describe the "potential actions
//! for responses against Atlassian standards":
//!
//! | Signal | Documented meaning |
//! |---|---|
//! | Info | No action needed. Does not block listing. |
//! | Warning | Security concern; Atlassian provides a recommendation. Does not block listing. |
//! | Fail | Security violation that must be addressed. **Blocks listing**; the approval ticket is rejected. |
//!
//! # A note on [`Question::nonconforming`]
//!
//! The published table pairs each question with a signal, but does *not* state
//! which answer trips that signal. That polarity is **our interpretation**, read
//! off the wording of each question, and it is what lets this tool say "your
//! manifest implies question 6a is `Yes`, which is a warning".
//!
//! It is recorded explicitly, per question, rather than inferred at runtime, so
//! that a reviewer can audit it. Where the wording does not imply a
//! non-conforming answer (informational questions and free-text prompts) it is
//! [`None`] and no signal is ever raised.

use serde::Serialize;

/// Which Marketplace questionnaire a report targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppType {
    Forge,
}

impl AppType {
    /// The questionnaire published for this app type.
    pub fn questions(self) -> &'static [Question] {
        match self {
            Self::Forge => FORGE_QUESTIONNAIRE,
        }
    }
}

/// The category headings used by the published questionnaire tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AuthenticationAndAuthorization,
    DataSecurity,
    ApplicationSecurity,
    SecretsManagement,
    VulnerabilityManagement,
}

impl Category {
    pub fn title(self) -> &'static str {
        match self {
            Self::AuthenticationAndAuthorization => "Authentication & Authorization",
            Self::DataSecurity => "Data Security",
            Self::ApplicationSecurity => "Application Security",
            Self::SecretsManagement => "Secrets Management",
            Self::VulnerabilityManagement => "Vulnerability Management",
        }
    }
}

/// The documented consequence of answering a question against Atlassian standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSignal {
    /// Informational. No action needed; does not block listing.
    Info,
    /// Security concern; a recommendation is provided. Does not block listing.
    Warning,
    /// Security violation that must be addressed. Blocks listing.
    Fail,
}

impl ReviewSignal {
    /// The icon the documentation uses for this signal.
    pub fn icon(self) -> &'static str {
        match self {
            Self::Info => "i",
            Self::Warning => "!",
            Self::Fail => "X",
        }
    }
}

/// The answer shape a question accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerKind {
    /// Yes / No.
    YesNo,
    /// Yes / No / Not Applicable.
    YesNoNotApplicable,
    /// Free text.
    OpenText,
    /// Select any of a fixed set of options.
    MultiSelect,
}

/// A value a question can be answered with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerValue {
    Yes,
    No,
    NotApplicable,
    /// Free-text answer.
    Text(String),
    /// The tool could not determine an answer. The partner must supply one.
    Unknown,
}

impl AnswerValue {
    pub fn as_display(&self) -> &str {
        match self {
            Self::Yes => "Yes",
            Self::No => "No",
            Self::NotApplicable => "Not Applicable",
            Self::Text(text) => text,
            Self::Unknown => "(unanswered)",
        }
    }
}

/// A single published question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Question {
    /// Stable identifier. Mirrors the numbering used by the published table, so
    /// `2a` here is question 2's first sub-question on the page.
    pub id: &'static str,
    /// The sub-question's parent, if any. Sub-questions are conditional: they are
    /// only asked when the parent is answered `Yes` ("If yes, ...").
    pub parent: Option<&'static str>,
    pub category: Category,
    /// The question text, transcribed verbatim minus the answer-shape suffix.
    pub prompt: &'static str,
    pub kind: AnswerKind,
    pub signal: ReviewSignal,
    /// The answer that trips [`Self::signal`]. **Our interpretation**, not
    /// published. See the module documentation.
    pub nonconforming: Option<NonConforming>,
}

/// The answer that trips a question's review signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NonConforming {
    Yes,
    No,
}

impl NonConforming {
    /// Whether `answer` is the non-conforming response.
    pub fn is_tripped_by(self, answer: &AnswerValue) -> bool {
        matches!(
            (self, answer),
            (Self::Yes, AnswerValue::Yes) | (Self::No, AnswerValue::No)
        )
    }
}

/// The parent answer that causes a sub-question to be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AskedWhen {
    /// The usual case: the published wording begins "If yes, ...".
    ParentIsYes,
    /// The published wording begins "If not, ...".
    ParentIsNo,
}

/// Sub-questions whose published wording begins "If not, ..." and which are
/// therefore asked when the parent is answered `No`.
///
/// Recorded as an explicit exception list rather than being guessed from the
/// prompt text, so the conditional logic is auditable.
const ASKED_WHEN_PARENT_IS_NO: &[&str] = &["12a-i"];

impl Question {
    /// Look up a question by [`Self::id`] within an app type's questionnaire.
    pub fn lookup(app_type: AppType, id: &str) -> Option<&'static Question> {
        app_type.questions().iter().find(|q| q.id == id)
    }

    /// When this question is asked, for sub-questions. [`None`] for top-level
    /// questions, which are always asked.
    pub fn asked_when(&self) -> Option<AskedWhen> {
        self.parent?;
        Some(if ASKED_WHEN_PARENT_IS_NO.contains(&self.id) {
            AskedWhen::ParentIsNo
        } else {
            AskedWhen::ParentIsYes
        })
    }
}

use AnswerKind::{MultiSelect, OpenText, YesNo, YesNoNotApplicable};
use Category::{
    ApplicationSecurity, AuthenticationAndAuthorization, DataSecurity, SecretsManagement,
    VulnerabilityManagement,
};
use NonConforming as Bad;
use ReviewSignal::{Fail, Info, Warning};

/// The Forge app security questionnaire.
///
/// 31 prompts: 17 numbered questions plus their conditional sub-questions.
pub const FORGE_QUESTIONNAIRE: &[Question] = &[
    Question {
        id: "1",
        parent: None,
        category: AuthenticationAndAuthorization,
        prompt: "Does your Forge app functionality include user interactions?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "1a",
        parent: Some("1"),
        category: AuthenticationAndAuthorization,
        prompt: "Does your app use asUser() method where applicable for actions performed by the user?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "2",
        parent: None,
        category: AuthenticationAndAuthorization,
        prompt: "Does your app use Forge remote?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "2a",
        parent: Some("2"),
        category: AuthenticationAndAuthorization,
        prompt: "Does your remote host validate authentication information from the Forge Invocation Token (FIT)?",
        kind: YesNo,
        signal: Fail,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "2b",
        parent: Some("2"),
        category: AuthenticationAndAuthorization,
        prompt: "Does your remote host execute user actions that require user context and appropriately validate whether the user has necessary permissions?",
        kind: YesNoNotApplicable,
        signal: Fail,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "3",
        parent: None,
        category: AuthenticationAndAuthorization,
        prompt: "Before invoking calls using asApp() on actions that require user-specific permissions, do you ensure that the user has necessary permissions by calling the permissions REST APIs?",
        kind: YesNoNotApplicable,
        signal: Fail,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "4",
        parent: None,
        category: AuthenticationAndAuthorization,
        prompt: "Does your Forge app use web triggers?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "4a",
        parent: Some("4"),
        category: AuthenticationAndAuthorization,
        prompt: "Do you perform authentication checks on the web trigger when invoking critical functions?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "5",
        parent: None,
        category: AuthenticationAndAuthorization,
        prompt: "Does your Forge app use display conditions?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "5a",
        parent: Some("5"),
        category: AuthenticationAndAuthorization,
        prompt: "Do you rely solely on these conditions and not check user permissions in your code?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::Yes),
    },
    Question {
        id: "6",
        parent: None,
        category: DataSecurity,
        prompt: "Does your Forge app egress data to external hosts?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "6a",
        parent: Some("6"),
        category: DataSecurity,
        prompt: "Does the egress domains include *.com or * in the Forge manifest file?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::Yes),
    },
    Question {
        id: "6b",
        parent: Some("6"),
        category: DataSecurity,
        prompt: "Are all communications with the remote host encrypted over TLS version 1.2 or above?",
        kind: YesNo,
        signal: Fail,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "6c",
        parent: Some("6"),
        category: DataSecurity,
        prompt: "Do you plan to renew the egress domain as well as its cert when they expire?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "6d",
        parent: Some("6"),
        category: DataSecurity,
        prompt: "Did you implement controls to safeguard customer data stored at rest on the remote host?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "6d-i",
        parent: Some("6d"),
        category: DataSecurity,
        prompt: "Please list all the controls in place.",
        kind: OpenText,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "7",
        parent: None,
        category: DataSecurity,
        prompt: "Does your Forge app adhere to the principle of least privilege by ensuring that the app's scope is limited to only the permissions necessary for its functionality?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "8",
        parent: None,
        category: DataSecurity,
        prompt: "Does your app log sensitive information (such as PII, credentials, access tokens, or API keys) in Forge logs?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::Yes),
    },
    Question {
        id: "9",
        parent: None,
        category: ApplicationSecurity,
        prompt: "Have you implemented controls in the app to validate and sanitize all user inputs in order to mitigate vulnerabilities related to injection attacks?",
        kind: YesNo,
        signal: Warning,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "9a",
        parent: Some("9"),
        category: ApplicationSecurity,
        prompt: "Please explain the input validations implemented on user inputs / URLs if applicable.",
        kind: OpenText,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "10",
        parent: None,
        category: ApplicationSecurity,
        prompt: "Did you review the app's 3rd party dependencies for vulnerabilities using automated tools? and, do you plan to keep these dependencies up to date?",
        kind: YesNo,
        signal: Fail,
        nonconforming: Some(Bad::No),
    },
    Question {
        id: "11",
        parent: None,
        category: SecretsManagement,
        prompt: "Does your app collect Atlassian user account credentials, such as passwords or API tokens?",
        kind: YesNo,
        signal: Fail,
        nonconforming: Some(Bad::Yes),
    },
    Question {
        id: "12",
        parent: None,
        category: SecretsManagement,
        prompt: "Does your app collect any 3rd party service's credentials or tokens?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "12a",
        parent: Some("12"),
        category: SecretsManagement,
        prompt: "Do you store them in Forge storage with encryption?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "12a-i",
        parent: Some("12a"),
        category: SecretsManagement,
        prompt: "If not, do you store them externally?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "13",
        parent: None,
        category: SecretsManagement,
        prompt: "Does your app expose any secrets in plain text in accessible locations like URLs, source code, or code repositories?",
        kind: YesNo,
        signal: Fail,
        nonconforming: Some(Bad::Yes),
    },
    Question {
        id: "14",
        parent: None,
        category: VulnerabilityManagement,
        prompt: "Do you perform vulnerability scans and review results?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "14a",
        parent: Some("14"),
        category: VulnerabilityManagement,
        prompt: "Please select the type of scans performed: software composition analysis (SCA), static application security testing (SAST), dynamic application security testing (DAST).",
        kind: MultiSelect,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "15",
        parent: None,
        category: VulnerabilityManagement,
        prompt: "Have you read our Marketplace Security Bug Fix policy?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "16",
        parent: None,
        category: VulnerabilityManagement,
        prompt: "Do you plan to notify customers and Atlassian in case of a security incident or a critical vulnerability on your app?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
    Question {
        id: "17",
        parent: None,
        category: VulnerabilityManagement,
        prompt: "Have you identified a security contact for the app and created an account on ecosystem.atlassian.net?",
        kind: YesNo,
        signal: Info,
        nonconforming: None,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique() {
        let mut seen = HashSet::new();
        for question in FORGE_QUESTIONNAIRE {
            assert!(seen.insert(question.id), "duplicate id {}", question.id);
        }
    }

    #[test]
    fn parents_resolve_and_precede_their_children() {
        let mut seen: HashSet<&str> = HashSet::new();
        for question in FORGE_QUESTIONNAIRE {
            if let Some(parent) = question.parent {
                assert!(
                    seen.contains(parent),
                    "{} references parent {parent} which does not precede it",
                    question.id
                );
            }
            seen.insert(question.id);
        }
    }

    #[test]
    fn informational_and_free_text_prompts_never_trip_a_signal() {
        for question in FORGE_QUESTIONNAIRE {
            if question.signal == Info {
                assert!(
                    question.nonconforming.is_none(),
                    "{} is informational but declares a non-conforming answer",
                    question.id
                );
            }
            if matches!(question.kind, OpenText | MultiSelect) {
                assert!(
                    question.nonconforming.is_none(),
                    "{} is free-form but declares a non-conforming answer",
                    question.id
                );
            }
        }
    }

    #[test]
    fn every_actionable_question_declares_its_polarity() {
        for question in FORGE_QUESTIONNAIRE {
            if question.signal != Info && matches!(question.kind, YesNo | YesNoNotApplicable) {
                assert!(
                    question.nonconforming.is_some(),
                    "{} raises a signal but does not say which answer trips it",
                    question.id
                );
            }
        }
    }

    #[test]
    fn transcription_is_complete() {
        // 17 numbered questions, plus 14 conditional sub-questions.
        assert_eq!(FORGE_QUESTIONNAIRE.len(), 31);
        assert_eq!(
            FORGE_QUESTIONNAIRE
                .iter()
                .filter(|q| q.parent.is_none())
                .count(),
            17
        );
    }
}
