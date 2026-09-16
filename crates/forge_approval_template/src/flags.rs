//! Pre-submission checks: things likely to get an app rejected, surfaced before
//! the partner submits.
//!
//! Two sources of truth, cited per flag so a partner can go and read the rule:
//!
//! - The security questionnaire's own review signals
//!   (<https://developer.atlassian.com/platform/marketplace/app-security-questionnaires/>).
//!   Where a manifest deterministically implies a non-conforming answer, that is
//!   raised here too, because it is a rejection risk and not merely a form field.
//! - The app approval guidelines
//!   (<https://developer.atlassian.com/platform/marketplace/app-approval-guidelines/>),
//!   whose criteria are quoted in [`FlagSource::ApprovalGuidelines`].
//!
//! Flags are conservative by design. A false alarm costs a partner time and
//! erodes trust in the tool, so a check is only included when the manifest states
//! the problem outright.

use serde::Serialize;

use crate::code_analysis::{Checker, CodeAnalysis};
use crate::evidence::Evidence;
use crate::facts::ManifestFacts;
use crate::questionnaire::ReviewSignal;

/// The rule a flag is derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlagSource {
    /// A question in the published security questionnaire.
    SecurityQuestionnaire { question: &'static str },
    /// A criterion in the published app approval guidelines, quoted.
    ApprovalGuidelines { criterion: &'static str },
}

/// Something worth fixing or checking before submitting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flag {
    /// Stable identifier, so downstream tooling can match on it.
    pub id: &'static str,
    /// Severity, expressed in the questionnaire's own vocabulary.
    pub severity: ReviewSignal,
    pub title: &'static str,
    pub detail: String,
    pub source: FlagSource,
    pub evidence: Vec<Evidence>,
}

/// Atlassian product names that must not lead an app name.
///
/// From the approval guidelines: "Jira App X would be rejected, but App X for
/// Jira would be approved." So position matters — the mark leading the name is
/// the rejection, and trailing "for <Product>" is explicitly allowed.
const ATLASSIAN_MARKS: &[&str] = &[
    "Jira Service Management",
    "Jira Product Discovery",
    "Jira Align",
    "Atlassian",
    "Jira",
    "Confluence",
    "Bitbucket",
    "Trello",
    "Compass",
    "Statuspage",
    "Opsgenie",
    "Sourcetree",
    "Bamboo",
    "Crucible",
    "Fisheye",
    "Crowd",
    "Loom",
    "Rovo",
];

/// The guideline the naming checks enforce, quoted.
const TRADEMARK_CRITERION: &str = "Doesn't infringe Atlassian trademarks: Trademark infringement \
     is an automatic rejection [...] This includes visual assets as well as naming conventions. \
     For example, Jira App X would be rejected, but App X for Jira would be approved.";

/// Run every pre-submission check.
pub fn check(facts: &ManifestFacts, code: Option<&CodeAnalysis>) -> Vec<Flag> {
    let mut flags = Vec::new();
    flags.extend(check_app_name(facts));
    flags.extend(check_egress(facts));
    flags.extend(check_content_security(facts));
    flags.extend(check_remotes(facts));
    flags.extend(check_runtime_version(code));
    // Most severe first, so a blocking flag is never buried under advice.
    flags.sort_by_key(|flag| std::cmp::Reverse(flag.severity));
    flags
}

/// An end-of-life Node.js runtime is a listing risk in its own right, and is not
/// covered by any questionnaire question.
fn check_runtime_version(code: Option<&CodeAnalysis>) -> Vec<Flag> {
    let evidence: Vec<Evidence> = code
        .into_iter()
        .flat_map(|code| code.findings_by(&Checker::RuntimeVersion))
        .map(|finding| Evidence::new(finding.check_name.clone(), finding.description.clone()))
        .collect();

    if evidence.is_empty() {
        return Vec::new();
    }

    Vec::from([Flag {
        id: "runtime.end_of_life",
        severity: ReviewSignal::Warning,
        title: "App declares an end-of-life Node.js runtime",
        detail: "FSRT's runtime scanner reports that `app.runtime.name` names a Node.js \
                 version that is out of support. Move to a supported runtime before \
                 submitting."
            .to_string(),
        source: FlagSource::ApprovalGuidelines {
            criterion: "Fulfill the security requirements outlined in the security workflow",
        },
        evidence,
    }])
}

fn check_app_name(facts: &ManifestFacts) -> Vec<Flag> {
    let Some(name) = facts.app_name.as_deref() else {
        return vec![Flag {
            id: "listing.app_name_missing",
            severity: ReviewSignal::Info,
            title: "App name is not declared in the manifest",
            detail: "The manifest has no `app.name`, so the Marketplace listing name \
                     could not be read and the trademark naming check could not run. \
                     Check the name you submit against the brand guidelines yourself."
                .to_string(),
            source: FlagSource::ApprovalGuidelines {
                criterion: TRADEMARK_CRITERION,
            },
            evidence: Vec::new(),
        }];
    };

    let evidence = vec![Evidence::new("app.name", name)];

    if let Some(mark) = leading_mark(name) {
        return vec![Flag {
            id: "naming.trademark_prefix",
            severity: ReviewSignal::Fail,
            title: "App name begins with an Atlassian product name",
            detail: format!(
                "The name starts with \"{mark}\". The approval guidelines give this \
                 exact shape as an automatic rejection. Rename it so the product \
                 name trails instead, for example \"<Your app> for {mark}\"."
            ),
            source: FlagSource::ApprovalGuidelines {
                criterion: TRADEMARK_CRITERION,
            },
            evidence,
        }];
    }

    if let Some(mark) = unqualified_mark(name) {
        return vec![Flag {
            id: "naming.trademark_mention",
            severity: ReviewSignal::Warning,
            title: "App name mentions an Atlassian product name",
            detail: format!(
                "The name contains \"{mark}\" somewhere other than a trailing \
                 \"for {mark}\". This may be acceptable, but check it against the \
                 brand guidelines for Marketplace Partners before submitting."
            ),
            source: FlagSource::ApprovalGuidelines {
                criterion: TRADEMARK_CRITERION,
            },
            evidence,
        }];
    }

    Vec::new()
}

/// The Atlassian mark an app name begins with, if any. Longest match wins, so
/// "Jira Service Management Helper" reports the full product name.
fn leading_mark(name: &str) -> Option<&'static str> {
    let name = name.trim();
    ATLASSIAN_MARKS
        .iter()
        .filter(|mark| starts_with_word(name, mark))
        .max_by_key(|mark| mark.len())
        .copied()
}

/// An Atlassian mark used somewhere other than a trailing "for <Product>".
fn unqualified_mark(name: &str) -> Option<&'static str> {
    let name = name.trim();
    ATLASSIAN_MARKS
        .iter()
        .filter(|mark| contains_word(name, mark) && !ends_with_qualifier(name, mark))
        .max_by_key(|mark| mark.len())
        .copied()
}

/// Whether `name` ends with "for <mark>", the form the guidelines approve.
fn ends_with_qualifier(name: &str, mark: &str) -> bool {
    let lower = name.to_lowercase();
    let suffix = format!("for {}", mark.to_lowercase());
    lower.ends_with(&suffix)
}

fn starts_with_word(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.to_lowercase(), needle.to_lowercase());
    haystack.strip_prefix(&needle).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|next| !next.is_alphanumeric())
    })
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.to_lowercase(), needle.to_lowercase());
    haystack.match_indices(&needle).any(|(index, matched)| {
        let before_ok = index == 0
            || !haystack[..index]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric);
        let after = &haystack[index + matched.len()..];
        let after_ok = after
            .chars()
            .next()
            .is_none_or(|next| !next.is_alphanumeric());
        before_ok && after_ok
    })
}

fn check_egress(facts: &ManifestFacts) -> Vec<Flag> {
    let mut flags = Vec::new();

    let broad: Vec<Evidence> = facts
        .overly_broad_egress()
        .map(|entry| Evidence::new(entry.pointer.clone(), entry.value.clone()))
        .collect();
    if !broad.is_empty() {
        flags.push(Flag {
            id: "egress.overly_broad",
            severity: ReviewSignal::Warning,
            title: "Egress is declared to any host",
            detail: "The manifest permits egress to `*` or to an entire top-level \
                     domain. Question 6a asks about exactly this and carries a \
                     warning. Narrow the declaration to the hosts the app really \
                     contacts."
                .to_string(),
            source: FlagSource::SecurityQuestionnaire { question: "6a" },
            evidence: broad,
        });
    }

    let cleartext: Vec<Evidence> = facts
        .cleartext_egress()
        .map(|entry| Evidence::new(entry.pointer.clone(), entry.value.clone()))
        .collect();
    if !cleartext.is_empty() {
        flags.push(Flag {
            id: "egress.cleartext",
            severity: ReviewSignal::Fail,
            title: "Egress is declared over cleartext HTTP",
            detail: "A declared destination uses `http://`, which is unencrypted and \
                     cannot satisfy the TLS 1.2 requirement in question 6b. That \
                     question is a blocking signal. Move the destination to HTTPS."
                .to_string(),
            source: FlagSource::SecurityQuestionnaire { question: "6b" },
            evidence: cleartext,
        });
    }

    flags
}

fn check_content_security(facts: &ManifestFacts) -> Vec<Flag> {
    if facts.content_security_relaxations.is_empty() {
        return Vec::new();
    }

    Vec::from([Flag {
        id: "content_security.unsafe_directive",
        severity: ReviewSignal::Warning,
        title: "Content security policy is relaxed with an unsafe directive",
        detail: "`permissions.content` declares an `unsafe-` directive, which widens \
                 the app's content security policy and its exposure to injection. \
                 The published Forge questionnaire has no question on this, but the \
                 Connect questionnaire treats the equivalent relaxation as a warning \
                 and a reviewer is likely to ask about it. Remove it if the app does \
                 not need it."
            .to_string(),
        source: FlagSource::ApprovalGuidelines {
            criterion: "Fulfill the security requirements outlined in the security workflow",
        },
        evidence: facts
            .content_security_relaxations
            .iter()
            .map(Evidence::from)
            .collect(),
    }])
}

fn check_remotes(facts: &ManifestFacts) -> Vec<Flag> {
    let unresolvable: Vec<Evidence> = facts
        .remotes
        .iter()
        .filter(|remote| remote.base_url_is_interpolated)
        .enumerate()
        .map(|(index, remote)| {
            Evidence::new(
                format!("remotes[{index}].baseUrl"),
                remote.base_url.clone().unwrap_or_default(),
            )
        })
        .collect();

    if unresolvable.is_empty() {
        return Vec::new();
    }

    Vec::from([Flag {
        id: "remote.base_url_interpolated",
        severity: ReviewSignal::Info,
        title: "Remote base URL is set at deploy time",
        detail: "A remote's `baseUrl` is a `${...}` placeholder, so this tool cannot \
                 tell where the app actually sends data, and neither can a reviewer \
                 reading the manifest. State the real destination when you answer \
                 questions 6 and 6b."
            .to_string(),
        source: FlagSource::SecurityQuestionnaire { question: "6" },
        evidence: unresolvable,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_product_name_is_a_blocking_flag() {
        // The guidelines' own example of a rejection.
        assert_eq!(leading_mark("Jira App X"), Some("Jira"));
        assert_eq!(leading_mark("confluence toolkit"), Some("Confluence"));
        // Longest match wins.
        assert_eq!(
            leading_mark("Jira Service Management Helper"),
            Some("Jira Service Management")
        );
    }

    #[test]
    fn trailing_qualifier_is_allowed() {
        // The guidelines' own example of an approval.
        assert_eq!(leading_mark("App X for Jira"), None);
        assert_eq!(unqualified_mark("App X for Jira"), None);
        assert_eq!(unqualified_mark("Timesheets for Confluence"), None);
    }

    #[test]
    fn product_names_are_matched_on_word_boundaries() {
        // "Jiraffe" is not "Jira", and must not be flagged.
        assert_eq!(leading_mark("Jiraffe Reports"), None);
        assert_eq!(unqualified_mark("Jiraffe Reports"), None);
        assert_eq!(leading_mark("Compasses and Maps"), None);
    }

    #[test]
    fn mid_name_mention_is_only_advisory() {
        let mark = unqualified_mark("Best Jira Reports Ever");
        assert_eq!(mark, Some("Jira"));
    }

    #[test]
    fn flags_are_ordered_most_severe_first() {
        let severities = [
            ReviewSignal::Info,
            ReviewSignal::Fail,
            ReviewSignal::Warning,
        ];
        let mut sorted = severities;
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(
            sorted,
            [
                ReviewSignal::Fail,
                ReviewSignal::Warning,
                ReviewSignal::Info
            ]
        );
    }
}
