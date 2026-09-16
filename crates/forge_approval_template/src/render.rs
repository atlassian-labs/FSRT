//! Rendering a report for a human.
//!
//! The JSON form is the machine contract. This is the form a partner reads
//! before submitting, and the form that pastes usefully into an approval ticket.

use std::fmt::Write as _;

use crate::answers::AnsweredQuestion;
use crate::evidence::Basis;
use crate::listing::ListingField;
use crate::questionnaire::{Category, ReviewSignal};
use crate::report::ApprovalTemplate;

/// The categories in published order.
const CATEGORY_ORDER: &[Category] = &[
    Category::AuthenticationAndAuthorization,
    Category::DataSecurity,
    Category::ApplicationSecurity,
    Category::SecretsManagement,
    Category::VulnerabilityManagement,
];

/// Render a report as Markdown.
pub fn to_markdown(template: &ApprovalTemplate) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "# Marketplace app approval — pre-filled submission\n");
    let _ = writeln!(
        out,
        "Generated from `{}`. Questionnaire transcribed from {}.\n",
        template.manifest_path, template.questionnaire_source
    );
    let _ = writeln!(out, "> {}\n", template.attestation);

    before_you_submit(&mut out, template);
    coverage(&mut out, template);
    listing(&mut out, template);
    questionnaire(&mut out, template);

    out
}

fn before_you_submit(out: &mut String, template: &ApprovalTemplate) {
    let _ = writeln!(out, "## Before you submit\n");

    if template.flags.is_empty() {
        let _ = writeln!(out, "No pre-submission issues found in the manifest.\n");
        return;
    }

    for flag in &template.flags {
        let _ = writeln!(
            out,
            "### [{}] {}\n",
            severity_label(flag.severity),
            flag.title
        );
        let _ = writeln!(out, "{}\n", flag.detail);
        if !flag.evidence.is_empty() {
            let _ = writeln!(out, "Evidence:\n");
            for evidence in &flag.evidence {
                let _ = writeln!(out, "- `{}` = `{}`", evidence.pointer, evidence.value);
            }
            let _ = writeln!(out);
        }
    }
}

fn coverage(out: &mut String, template: &ApprovalTemplate) {
    let coverage = &template.coverage;
    let _ = writeln!(out, "## Coverage\n");
    let _ = writeln!(out, "| Disposition | Prompts |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(
        out,
        "| Read from the manifest | {} |",
        coverage.deterministic
    );
    let _ = writeln!(
        out,
        "| Inferred from the manifest | {} |",
        coverage.heuristic
    );
    let _ = writeln!(
        out,
        "| Not applicable (ruled out by a parent answer) | {} |",
        coverage.not_applicable
    );
    let _ = writeln!(
        out,
        "| Needs code review | {} |",
        coverage.requires_code_review
    );
    let _ = writeln!(
        out,
        "| Needs your input | {} |",
        coverage.requires_partner_input
    );
    let _ = writeln!(
        out,
        "| **Total prompts** | **{}** |",
        coverage.total_prompts
    );
    let _ = writeln!(
        out,
        "\n**{}% resolved** ({} of {} prompts). {} blocking and {} warning signal(s) \
         tripped by the pre-filled answers.\n",
        coverage.percent_resolved,
        coverage.resolved,
        coverage.total_prompts,
        coverage.blocking_signals_tripped,
        coverage.warning_signals_tripped
    );
}

fn listing(out: &mut String, template: &ApprovalTemplate) {
    let _ = writeln!(out, "## Listing details\n");
    let _ = writeln!(out, "| Field | Value | Source |");
    let _ = writeln!(out, "|---|---|---|");

    for field in template.listing.iter().filter(|f| !f.is_outstanding()) {
        let value = field
            .value
            .as_ref()
            .map(|value| value.as_display())
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            field.name,
            escape_pipes(&value),
            field.basis.label()
        );
    }

    let outstanding: Vec<&ListingField> = template.outstanding_listing_fields().collect();
    if !outstanding.is_empty() {
        let _ = writeln!(out, "\n### Still needed from you\n");
        let _ = writeln!(out, "| Field | Required because |");
        let _ = writeln!(out, "|---|---|");
        for field in outstanding {
            let _ = writeln!(
                out,
                "| {} | {} |",
                field.name,
                escape_pipes(field.required_by.unwrap_or_default())
            );
        }
        let _ = writeln!(out);
    }
}

fn questionnaire(out: &mut String, template: &ApprovalTemplate) {
    let _ = writeln!(out, "## Security questionnaire\n");

    for category in CATEGORY_ORDER {
        let questions: Vec<&AnsweredQuestion> = template
            .questionnaire
            .iter()
            .filter(|answer| answer.category == *category)
            .collect();
        if questions.is_empty() {
            continue;
        }

        let _ = writeln!(out, "### {}\n", category.title());
        let _ = writeln!(out, "| # | Question | Answer | Source | Signal |");
        let _ = writeln!(out, "|---|---|---|---|---|");

        for answer in questions {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                answer.id,
                escape_pipes(answer.prompt),
                answer_cell(answer),
                answer.basis.label(),
                signal_cell(answer)
            );
        }
        let _ = writeln!(out);

        for answer in template
            .questionnaire
            .iter()
            .filter(|answer| answer.category == *category && !answer.evidence.is_empty())
        {
            let _ = writeln!(out, "**Evidence for {}**\n", answer.id);
            for evidence in &answer.evidence {
                let _ = writeln!(out, "- `{}` = `{}`", evidence.pointer, evidence.value);
            }
            if let Some(rationale) = &answer.rationale {
                let _ = writeln!(out, "\n{rationale}");
            }
            let _ = writeln!(out);
        }
    }
}

fn answer_cell(answer: &AnsweredQuestion) -> String {
    let value = answer.answer.as_display();
    if answer.confirm_before_submitting && answer.is_prefilled() {
        return format!("{value} (confirm)");
    }
    value.to_string()
}

fn signal_cell(answer: &AnsweredQuestion) -> String {
    if !answer.trips_signal {
        return "—".to_string();
    }
    match answer.signal {
        ReviewSignal::Fail => "BLOCKING".to_string(),
        ReviewSignal::Warning => "warning".to_string(),
        ReviewSignal::Info => "—".to_string(),
    }
}

fn severity_label(signal: ReviewSignal) -> &'static str {
    match signal {
        ReviewSignal::Fail => "BLOCKING",
        ReviewSignal::Warning => "warning",
        ReviewSignal::Info => "info",
    }
}

/// Keep table cells from breaking the Markdown table.
fn escape_pipes(text: &str) -> String {
    text.replace('|', "\\|")
}

/// Basis labels, exposed for callers that render their own summaries.
pub fn basis_label(basis: Basis) -> &'static str {
    basis.label()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE_APP: &str =
        include_str!("../../../test-apps/jira-damn-vulnerable-forge-app/manifest.yml");

    fn markdown() -> String {
        let template =
            ApprovalTemplate::from_manifest(VULNERABLE_APP, None, "manifest.yml").expect("parses");
        to_markdown(&template)
    }

    #[test]
    fn renders_all_sections() {
        let markdown = markdown();
        for heading in [
            "# Marketplace app approval",
            "## Before you submit",
            "## Coverage",
            "## Listing details",
            "## Security questionnaire",
            "### Authentication & Authorization",
            "### Vulnerability Management",
        ] {
            assert!(markdown.contains(heading), "missing {heading}");
        }
    }

    #[test]
    fn surfaces_evidence_pointers() {
        assert!(markdown().contains("`permissions.external.fetch.client[0]` = `*`"));
    }

    #[test]
    fn marks_inferred_answers_for_confirmation() {
        // Q1 is inferred, so its cell must say so.
        assert!(markdown().contains("Yes (confirm)"));
    }

    #[test]
    fn always_carries_the_attestation_caveat() {
        assert!(markdown().contains("draft, not an attestation"));
    }

    #[test]
    fn escapes_pipes_so_tables_survive() {
        assert_eq!(escape_pipes("a|b"), "a\\|b");
    }

    #[test]
    fn every_question_appears_exactly_once() {
        let markdown = markdown();
        for id in ["1", "6a", "12a-i", "17"] {
            let occurrences = markdown
                .lines()
                .filter(|line| line.starts_with(&format!("| {id} | ")))
                .count();
            assert_eq!(occurrences, 1, "question {id} appears {occurrences} times");
        }
    }
}
