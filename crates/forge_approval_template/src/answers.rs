//! Deriving questionnaire answers from manifest facts.
//!
//! # What this module will and will not claim
//!
//! A manifest describes what an app *declares*, not what its code *does*. That
//! boundary decides which questions can be pre-filled:
//!
//! - Declarations are pre-filled ([`Basis::Deterministic`]): does the app use a
//!   Forge remote, web triggers, display conditions, egress, and are the egress
//!   domains wildcards.
//! - Consequences of declarations are inferred ([`Basis::Heuristic`]): whether
//!   the app has user interactions, whether it handles third-party credentials.
//! - Behaviour of the app's own code is deferred
//!   ([`Basis::RequiresCodeReview`]): `asUser()` usage, permission checks before
//!   `asApp()`, web trigger authentication, input validation, secret handling.
//!   These are the questions FSRT's existing scanners already reason about, and
//!   are the natural next phase of this work.
//! - Behaviour of systems outside the app, and organisational commitments, are
//!   deferred to the partner ([`Basis::RequiresPartnerInput`]).
//!
//! The most important case in the last category is **Q2a/Q2b**. It is tempting
//! to answer Q2a ("does your remote host validate authentication information
//! from the FIT?") from the manifest's `remotes[].auth` block, but that block
//! controls which *additional* app tokens Forge forwards to the remote; it says
//! nothing about whether the partner's own server validates the invocation
//! token. The remote host is not part of the Forge app artefact, so the question
//! is unanswerable here. The manifest facts are still attached as evidence so
//! the partner answers with the relevant context in front of them.

use crate::code_analysis::{Checker, CodeAnalysis, Verdict};
use crate::evidence::{Basis, Evidence};
use crate::facts::ManifestFacts;
use crate::questionnaire::{
    AnswerKind, AnswerValue, AppType, AskedWhen, Category, Question, ReviewSignal,
};
use serde::Serialize;

/// A questionnaire question with whatever this tool could determine about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnsweredQuestion {
    pub id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<&'static str>,
    pub category: Category,
    pub prompt: &'static str,
    pub kind: AnswerKind,
    /// The documented consequence of answering against Atlassian standards.
    pub signal: ReviewSignal,
    pub answer: AnswerValue,
    pub basis: Basis,
    /// Whether this question is asked at all, given its parent's answer.
    pub asked: bool,
    /// Whether the derived answer is the one that trips [`Self::signal`].
    pub trips_signal: bool,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// The partner must check this answer before submitting.
    pub confirm_before_submitting: bool,
}

impl AnsweredQuestion {
    /// Whether the tool produced an answer the partner can work from.
    pub fn is_prefilled(&self) -> bool {
        !matches!(self.answer, AnswerValue::Unknown)
    }
}

/// A determination about a single question, before it is combined with the
/// published question metadata.
struct Determination {
    answer: AnswerValue,
    basis: Basis,
    evidence: Vec<Evidence>,
    rationale: Option<String>,
}

impl Determination {
    fn new(answer: AnswerValue, basis: Basis) -> Self {
        Self {
            answer,
            basis,
            evidence: Vec::new(),
            rationale: None,
        }
    }

    fn yes(basis: Basis) -> Self {
        Self::new(AnswerValue::Yes, basis)
    }

    fn no(basis: Basis) -> Self {
        Self::new(AnswerValue::No, basis)
    }

    /// The tool cannot answer; the question is left for a code reviewer.
    fn needs_code_review(reason: impl Into<String>) -> Self {
        Self::new(AnswerValue::Unknown, Basis::RequiresCodeReview).because(reason)
    }

    /// The tool cannot answer; the question is left for the partner.
    fn needs_partner(reason: impl Into<String>) -> Self {
        Self::new(AnswerValue::Unknown, Basis::RequiresPartnerInput).because(reason)
    }

    fn because(mut self, reason: impl Into<String>) -> Self {
        self.rationale = Some(reason.into());
        self
    }

    fn citing(mut self, evidence: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }
}

/// Answer as much of the Forge questionnaire as the manifest supports.
///
/// Questions are visited in published order so that a sub-question can see its
/// parent's answer.
pub fn answer_forge_questionnaire(
    facts: &ManifestFacts,
    code: Option<&CodeAnalysis>,
) -> Vec<AnsweredQuestion> {
    let mut answered: Vec<AnsweredQuestion> = Vec::new();

    for question in AppType::Forge.questions() {
        let (asked, determination) = match gate(question, &answered) {
            Gate::Asked => (true, derive(question, facts, code)),
            Gate::NotAsked { basis, reason } => (
                false,
                Determination::new(AnswerValue::NotApplicable, basis).because(reason),
            ),
        };

        let trips_signal = question
            .nonconforming
            .is_some_and(|bad| bad.is_tripped_by(&determination.answer));

        answered.push(AnsweredQuestion {
            id: question.id,
            parent: question.parent,
            category: question.category,
            prompt: question.prompt,
            kind: question.kind,
            signal: question.signal,
            confirm_before_submitting: determination.basis.requires_confirmation(),
            answer: determination.answer,
            basis: determination.basis,
            asked,
            trips_signal,
            evidence: determination.evidence,
            rationale: determination.rationale,
        });
    }

    answered
}

enum Gate {
    Asked,
    NotAsked { basis: Basis, reason: String },
}

/// Decide whether a question is asked, given its parent's answer.
fn gate(question: &Question, answered: &[AnsweredQuestion]) -> Gate {
    let (Some(parent_id), Some(asked_when)) = (question.parent, question.asked_when()) else {
        return Gate::Asked;
    };

    let Some(parent) = answered.iter().find(|a| a.id == parent_id) else {
        return Gate::Asked;
    };

    // A parent we could not answer leaves the sub-question open too.
    let required = match asked_when {
        AskedWhen::ParentIsYes => AnswerValue::Yes,
        AskedWhen::ParentIsNo => AnswerValue::No,
    };

    if parent.answer == required {
        return Gate::Asked;
    }

    // Only skip when the parent was actually answered the other way. An unknown
    // or not-applicable parent means we do not know, so keep asking.
    match parent.answer {
        AnswerValue::Yes | AnswerValue::No => Gate::NotAsked {
            basis: parent.basis,
            reason: format!(
                "Not asked: question {parent_id} is answered {}.",
                parent.answer.as_display()
            ),
        },
        AnswerValue::NotApplicable => Gate::NotAsked {
            basis: parent.basis,
            reason: format!("Not asked: question {parent_id} is not applicable."),
        },
        AnswerValue::Unknown | AnswerValue::Text(_) => Gate::Asked,
    }
}

/// The per-question derivation rules.
fn derive(
    question: &Question,
    facts: &ManifestFacts,
    code: Option<&CodeAnalysis>,
) -> Determination {
    // A scan of the app's source answers several questions the manifest cannot.
    // When no scan was run, or the relevant checker did not run, fall through to
    // the manifest-only rules below.
    if let Some(determination) = from_code_analysis(question, facts, code) {
        return determination;
    }

    match question.id {
        "1" => user_interactions(facts),
        "2" => forge_remote(facts),
        "4" => web_triggers(facts),
        "5" => display_conditions(facts),
        "6" => egress(facts),
        "6a" => wildcard_egress(facts),
        "6b" => transport_security(facts),
        "7" => least_privilege(facts),
        "12" => third_party_credentials(facts),

        // Behaviour of the app's own code. FSRT already reasons about all of
        // these; wiring its scanners in is the next phase.
        "1a" => Determination::needs_code_review(
            "Whether asUser() is used where applicable is a property of the app's \
             code, not its manifest.",
        ),
        "3" => Determination::needs_code_review(
            "Whether permissions REST APIs are called before asApp() actions is a \
             property of the app's code, not its manifest.",
        ),
        "4a" => Determination::needs_code_review(
            "Whether the web trigger authenticates its caller is a property of the \
             trigger's handler, not its declaration.",
        )
        .citing(facts.webtriggers.iter().map(Evidence::from)),
        "5a" => Determination::needs_code_review(
            "Whether permissions are also checked in code, rather than relying on \
             display conditions alone, is a property of the app's code.",
        )
        .citing(facts.display_conditions.iter().map(Evidence::from)),
        "8" => Determination::needs_code_review(
            "What the app writes to Forge logs is a property of its code.",
        ),
        "9" => Determination::needs_code_review(
            "Input validation and sanitisation are properties of the app's code.",
        ),
        "11" => Determination::needs_code_review(
            "Whether Atlassian account credentials are collected is a property of \
             the app's code.",
        ),
        "12a" => Determination::needs_code_review(
            "Whether third-party tokens are written to Forge storage, and whether \
             they are encrypted, is a property of the app's code.",
        ),
        "13" => Determination::needs_code_review(
            "Locating secrets committed in plain text requires scanning the app's \
             source and repository.",
        ),

        // The remote host is the partner's own service and is not part of the
        // Forge app artefact. See the module documentation.
        "2a" => Determination::needs_partner(
            "The remote host is not part of the Forge app, so the manifest cannot \
             show whether it validates the Forge Invocation Token. Note that the \
             remotes[].auth block governs which additional app tokens Forge \
             forwards; it is not evidence about FIT validation.",
        )
        .citing(remote_evidence(facts)),
        "2b" => Determination::needs_partner(
            "Permission checks performed by the remote host are outside the Forge \
             app artefact.",
        )
        .citing(remote_evidence(facts)),

        _ => Determination::needs_partner(default_partner_reason(question)),
    }
}

/// How a checker's verdict maps onto one question.
struct CodeRule {
    checker: Checker,
    /// The answer a finding implies.
    on_found: AnswerValue,
    /// The answer a clean run implies.
    on_clean: AnswerValue,
    found_reason: &'static str,
    clean_reason: &'static str,
}

/// Answer a question from static analysis, if a relevant checker ran.
///
/// Returns [`None`] when there was no scan, the relevant checker did not run, or
/// the question has no mapping — in which case the manifest-only rules apply.
fn from_code_analysis(
    question: &Question,
    facts: &ManifestFacts,
    code: Option<&CodeAnalysis>,
) -> Option<Determination> {
    let code = code?;
    let rule = code_rule(question.id, facts)?;

    let (answer, reason) = match code.verdict(&rule.checker) {
        Verdict::NotRun => return None,
        Verdict::Found => (rule.on_found, rule.found_reason),
        Verdict::Clean => (rule.on_clean, rule.clean_reason),
    };

    // Always heuristic. FSRT's analysis is neither sound nor complete, so neither
    // a finding nor a clean run is proof, and the partner must confirm.
    Some(
        Determination::new(answer, Basis::Heuristic)
            .because(reason)
            .citing(code.findings_by(&rule.checker).map(|finding| {
                Evidence::new(finding.check_name.clone(), finding.description.clone())
            })),
    )
}

fn code_rule(question_id: &str, facts: &ManifestFacts) -> Option<CodeRule> {
    Some(match question_id {
        // Q3 asks whether permissions are checked before privileged calls, which
        // is exactly the bypass AuthZChecker looks for.
        "3" => CodeRule {
            checker: Checker::Authorization,
            on_found: AnswerValue::No,
            on_clean: AnswerValue::Yes,
            found_reason: "FSRT's authorization scanner found a path reaching a privileged \
                 call without an authorisation check.",
            clean_reason: "FSRT's authorization scanner found no unauthorised path to a \
                 privileged call. A clean scan is not a proof; confirm the app checks \
                 permissions before acting as the app.",
        },
        "4a" => CodeRule {
            checker: Checker::Authentication,
            on_found: AnswerValue::No,
            on_clean: AnswerValue::Yes,
            found_reason: "FSRT's authentication scanner found a web trigger reaching an \
                 API call without authenticating its caller.",
            clean_reason: "FSRT's authentication scanner found no unauthenticated web \
                 trigger path. A clean scan is not a proof; confirm each trigger \
                 authenticates its caller.",
        },
        // Only meaningful when the app actually declares display conditions. An
        // authorisation bypass in an app that gates modules by display condition
        // is good evidence the condition is the only check.
        "5a" if !facts.display_conditions.is_empty() => CodeRule {
            checker: Checker::Authorization,
            on_found: AnswerValue::Yes,
            on_clean: AnswerValue::No,
            found_reason: "The app gates modules with display conditions, and FSRT's \
                 authorization scanner also found a path with no authorisation check \
                 in code — so the display condition is likely the only gate.",
            clean_reason: "The app gates modules with display conditions, and FSRT's \
                 authorization scanner found no path lacking an authorisation check in \
                 code.",
        },
        // PermissionChecker reports scopes declared in the manifest but never
        // used, which is the concrete form of the least-privilege question.
        "7" => CodeRule {
            checker: Checker::LeastPrivilege,
            on_found: AnswerValue::No,
            on_clean: AnswerValue::Yes,
            found_reason: "FSRT's least privilege scanner found scopes declared in the \
                 manifest that the app never uses. Remove them, or justify each one.",
            clean_reason: "FSRT's least privilege scanner found no declared scope that \
                 the app never uses.",
        },
        "11" => CodeRule {
            checker: Checker::AtlassianCredential,
            on_found: AnswerValue::Yes,
            on_clean: AnswerValue::No,
            found_reason: "FSRT found an Atlassian API or container token used directly in \
                 the app. This is a blocking finding.",
            clean_reason: "FSRT found no direct use of an Atlassian API or container token.",
        },
        "13" => CodeRule {
            checker: Checker::HardcodedSecret,
            on_found: AnswerValue::Yes,
            on_clean: AnswerValue::No,
            found_reason: "FSRT's secret scanner found a hardcoded secret in the app. This \
                 is a blocking finding.",
            clean_reason: "FSRT's secret scanner found no hardcoded secret. It cannot see \
                 secrets committed elsewhere in the repository's history.",
        },
        _ => return None,
    })
}

fn default_partner_reason(question: &Question) -> &'static str {
    match question.category {
        Category::VulnerabilityManagement => {
            "An organisational commitment, not a property of the app artefact."
        }
        _ => "Not derivable from the app artefact; the partner must answer.",
    }
}

/// Q1. Does your Forge app functionality include user interactions?
///
/// Inferred from whether any declared module type can surface a UI. Heuristic,
/// because a module type is evidence of a *surface*, not proof that a user acts
/// through it.
fn user_interactions(facts: &ManifestFacts) -> Determination {
    if facts.declared_module_types.is_empty() {
        return Determination::needs_partner("The manifest declares no modules.");
    }

    if facts.user_facing_module_types.is_empty() {
        return Determination::no(Basis::Heuristic)
            .because(
                "Every declared module type is background plumbing (functions, \
                 triggers, resources), none of which surfaces a user interface.",
            )
            .citing(
                facts
                    .declared_module_types
                    .iter()
                    .map(|module| Evidence::new(format!("modules.{module}"), module.clone())),
            );
    }

    Determination::yes(Basis::Heuristic)
        .because("The app declares module types that surface a user interface.")
        .citing(
            facts
                .user_facing_module_types
                .iter()
                .map(|module| Evidence::new(format!("modules.{module}"), module.clone())),
        )
}

/// Q2. Does your app use Forge remote?
fn forge_remote(facts: &ManifestFacts) -> Determination {
    if facts.remotes.is_empty() {
        return Determination::no(Basis::Deterministic)
            .because("The manifest declares no `remotes`.");
    }

    Determination::yes(Basis::Deterministic)
        .because(format!(
            "The manifest declares {} remote(s).",
            facts.remotes.len()
        ))
        .citing(remote_evidence(facts))
}

/// Q4. Does your Forge app use web triggers?
fn web_triggers(facts: &ManifestFacts) -> Determination {
    if facts.webtriggers.is_empty() {
        return Determination::no(Basis::Deterministic)
            .because("The manifest declares no `webtrigger` module.");
    }

    Determination::yes(Basis::Deterministic)
        .because(format!(
            "The manifest declares {} web trigger(s).",
            facts.webtriggers.len()
        ))
        .citing(facts.webtriggers.iter().map(Evidence::from))
}

/// Q5. Does your Forge app use display conditions?
fn display_conditions(facts: &ManifestFacts) -> Determination {
    if facts.display_conditions.is_empty() {
        return Determination::no(Basis::Deterministic)
            .because("No module declares `displayConditions`.");
    }

    Determination::yes(Basis::Deterministic)
        .because(format!(
            "{} module(s) declare `displayConditions`.",
            facts.display_conditions.len()
        ))
        .citing(facts.display_conditions.iter().map(Evidence::from))
}

/// Q6. Does your Forge app egress data to external hosts?
fn egress(facts: &ManifestFacts) -> Determination {
    if !facts.egresses_data() {
        return Determination::no(Basis::Deterministic).because(
            "The manifest declares no `permissions.external` destinations and no \
             `remotes`.",
        );
    }

    let mut evidence: Vec<Evidence> = facts
        .external_egress
        .iter()
        .map(|entry| Evidence::new(entry.pointer.clone(), entry.value.clone()))
        .collect();
    evidence.extend(remote_evidence(facts));

    Determination::yes(Basis::Deterministic)
        .because("The manifest declares external destinations, a Forge remote, or both.")
        .citing(evidence)
}

/// Q6a. Does the egress domains include `*.com` or `*` in the Forge manifest file?
///
/// Deterministic: this question is about the spelling of the manifest, which is
/// exactly what can be checked here.
fn wildcard_egress(facts: &ManifestFacts) -> Determination {
    let broad: Vec<Evidence> = facts
        .overly_broad_egress()
        .map(|entry| {
            Evidence::new(
                entry.pointer.clone(),
                format!("{} ({:?})", entry.value, entry.pattern),
            )
        })
        .collect();

    if broad.is_empty() {
        return Determination::no(Basis::Deterministic).because(
            "No declared egress destination is `*` or a whole top-level-domain \
             wildcard.",
        );
    }

    Determination::yes(Basis::Deterministic)
        .because(
            "At least one declared egress destination is `*` or a whole \
             top-level-domain wildcard. Narrow it to the specific hosts the app \
             contacts.",
        )
        .citing(broad)
}

/// Q6b. Are all communications with the remote host encrypted over TLS 1.2 or above?
///
/// A cleartext `http://` destination settles this in the negative. Otherwise the
/// manifest names hosts, not the TLS versions they negotiate, so the partner must
/// answer.
fn transport_security(facts: &ManifestFacts) -> Determination {
    let cleartext: Vec<Evidence> = facts
        .cleartext_egress()
        .map(|entry| Evidence::new(entry.pointer.clone(), entry.value.clone()))
        .collect();

    if !cleartext.is_empty() {
        return Determination::no(Basis::Deterministic)
            .because(
                "A declared destination uses the `http://` scheme, which is not \
                 encrypted and therefore cannot meet the TLS 1.2 requirement.",
            )
            .citing(cleartext);
    }

    Determination::needs_partner(
        "The manifest names destinations but not the TLS versions they negotiate. \
         Confirm the remote host requires TLS 1.2 or above.",
    )
}

/// Q7. Does your app adhere to the principle of least privilege?
///
/// Deliberately not answered. Deciding whether a declared scope is *necessary*
/// needs the app's call graph compared against the scope each call requires —
/// which is what `forge_permission_resolver` and FSRT's permission scanner do.
/// Answering `Yes` from a scope list alone would be an unfounded attestation on
/// a question that carries a warning signal.
fn least_privilege(facts: &ManifestFacts) -> Determination {
    if facts.scopes.is_empty() {
        return Determination::yes(Basis::Heuristic)
            .because("The app declares no permission scopes, so it cannot be over-scoped.");
    }

    let elevated: Vec<Evidence> = facts
        .elevated_scopes()
        .map(|scope| Evidence::new("permissions.scopes", scope.raw.clone()))
        .collect();

    let all: Vec<Evidence> = facts
        .scopes
        .iter()
        .map(|scope| Evidence::new("permissions.scopes", scope.raw.clone()))
        .collect();

    let reason = if elevated.is_empty() {
        format!(
            "The app declares {} scope(s), all read-only. Whether each is actually \
             used still needs the call-graph comparison that FSRT's permission \
             scanner performs.",
            facts.scopes.len()
        )
    } else {
        format!(
            "The app declares {} scope(s), of which {} grant more than read \
             access. Confirm each is required; FSRT's permission scanner can \
             compare declared scopes against the scopes the code actually uses.",
            facts.scopes.len(),
            elevated.len()
        )
    };

    Determination::needs_code_review(reason).citing(all)
}

/// Q12. Does your app collect any 3rd party service's credentials or tokens?
///
/// A declared external OAuth provider means the app takes part in a third-party
/// authorisation flow, which implies handling that party's tokens.
fn third_party_credentials(facts: &ManifestFacts) -> Determination {
    if facts.oauth_providers.is_empty() {
        return Determination::needs_code_review(
            "The manifest declares no external OAuth provider, but an app can still \
             collect third-party credentials directly in code.",
        );
    }

    Determination::yes(Basis::Heuristic)
        .because(
            "The app declares external OAuth provider(s), so it takes part in a \
             third-party authorisation flow and handles that party's tokens.",
        )
        .citing(
            facts
                .oauth_providers
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    Evidence::new(format!("providers.auth[{index}].key"), key.clone())
                }),
        )
}

fn remote_evidence(facts: &ManifestFacts) -> Vec<Evidence> {
    facts
        .remotes
        .iter()
        .enumerate()
        .map(|(index, remote)| {
            Evidence::new(
                format!("remotes[{index}]"),
                format!(
                    "key={}, baseUrl={}, appUserToken={}, appSystemToken={}",
                    remote.key,
                    remote.base_url.as_deref().unwrap_or("(unset)"),
                    remote.passes_user_token,
                    remote.passes_system_token
                ),
            )
        })
        .collect()
}
