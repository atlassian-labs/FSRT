//! The listing half of the submission.
//!
//! The security questionnaire is only part of what a partner fills in. The
//! approval guidelines
//! (<https://developer.atlassian.com/platform/marketplace/app-approval-guidelines/>)
//! list criteria every app must meet, several of which are listing metadata.
//!
//! A manifest supplies very little of it — chiefly the app id, the modules and
//! the scopes. The value of enumerating the rest is not automation but
//! *completeness*: the partner gets one list showing what has been filled in,
//! what is still outstanding, and which published criterion demands each
//! outstanding item. Fields with no manifest source are therefore included
//! deliberately, with a `null` value and a citation, rather than omitted.

use serde::Serialize;

use crate::evidence::{Basis, Evidence};
use crate::facts::ManifestFacts;

/// A pre-filled or outstanding listing field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListingField {
    pub name: &'static str,
    /// The value, or [`None`] when nothing in the app artefact supplies it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    pub basis: Basis,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// The published approval criterion that requires this field, quoted, for
    /// fields the partner must supply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_by: Option<&'static str>,
}

/// A listing field's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Text(String),
    List(Vec<String>),
}

impl Value {
    /// Render on one line, for tables.
    pub fn as_display(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::List(items) if items.is_empty() => "(none)".to_string(),
            Self::List(items) => items.join(", "),
        }
    }
}

impl ListingField {
    fn derived(name: &'static str, value: Value, basis: Basis, evidence: Vec<Evidence>) -> Self {
        Self {
            name,
            value: Some(value),
            basis,
            evidence,
            required_by: None,
        }
    }

    fn outstanding(name: &'static str, required_by: &'static str) -> Self {
        Self {
            name,
            value: None,
            basis: Basis::RequiresPartnerInput,
            evidence: Vec::new(),
            required_by: Some(required_by),
        }
    }

    /// Whether the partner still has to supply this field.
    pub fn is_outstanding(&self) -> bool {
        self.value.is_none()
    }
}

/// Build the listing section.
pub fn build(facts: &ManifestFacts) -> Vec<ListingField> {
    let mut fields = Vec::new();

    if let Some(app_id) = &facts.app_id {
        fields.push(ListingField::derived(
            "App ID",
            Value::Text(app_id.clone()),
            Basis::Deterministic,
            vec![Evidence::new("app.id", app_id.clone())],
        ));
    }

    match &facts.app_name {
        Some(name) => fields.push(ListingField::derived(
            "App name",
            Value::Text(name.clone()),
            Basis::Deterministic,
            vec![Evidence::new("app.name", name.clone())],
        )),
        None => fields.push(ListingField::outstanding(
            "App name",
            "Doesn't infringe Atlassian trademarks [...] This includes visual assets \
             as well as naming conventions.",
        )),
    }

    // A Forge manifest is by definition a cloud app on the Forge platform. This
    // is the one listing field the artefact settles outright.
    fields.push(ListingField::derived(
        "Deployment model",
        Value::Text("Cloud (Forge)".to_string()),
        Basis::Deterministic,
        vec![],
    ));

    if let Some(runtime) = &facts.runtime {
        fields.push(ListingField::derived(
            "Forge runtime",
            Value::Text(runtime.clone()),
            Basis::Deterministic,
            vec![Evidence::new("app.runtime.name", runtime.clone())],
        ));
    }

    fields.push(ListingField::derived(
        "Host products",
        Value::List(
            facts
                .host_products
                .iter()
                .map(|product| product.display().to_string())
                .collect(),
        ),
        // Inferred from module type prefixes rather than stated by the manifest.
        Basis::Heuristic,
        facts
            .declared_module_types
            .iter()
            .map(|module| Evidence::new(format!("modules.{module}"), module.clone()))
            .collect(),
    ));

    fields.push(ListingField::derived(
        "Declared modules",
        Value::List(facts.declared_module_types.clone()),
        Basis::Deterministic,
        vec![],
    ));

    fields.push(ListingField::derived(
        "Permission scopes",
        Value::List(facts.scopes.iter().map(|scope| scope.raw.clone()).collect()),
        Basis::Deterministic,
        facts
            .scopes
            .iter()
            .map(|scope| Evidence::new("permissions.scopes", scope.raw.clone()))
            .collect(),
    ));

    fields.push(ListingField::derived(
        "External egress destinations",
        Value::List(
            facts
                .external_egress
                .iter()
                .map(|entry| entry.value.clone())
                .collect(),
        ),
        Basis::Deterministic,
        facts
            .external_egress
            .iter()
            .map(|entry| Evidence::new(entry.pointer.clone(), entry.value.clone()))
            .collect(),
    ));

    fields.push(ListingField::derived(
        "Forge remotes",
        Value::List(
            facts
                .remotes
                .iter()
                .map(|remote| match &remote.base_url {
                    Some(url) => format!("{} ({url})", remote.key),
                    None => remote.key.clone(),
                })
                .collect(),
        ),
        Basis::Deterministic,
        vec![],
    ));

    // Everything below has no source in the app artefact. Listed so the partner
    // can see exactly what is left, each against the criterion that demands it.
    fields.extend(
        OUTSTANDING_FIELDS
            .iter()
            .map(|(name, required_by)| ListingField::outstanding(name, required_by)),
    );

    fields
}

/// Listing fields no app artefact can supply, with the approval criterion that
/// requires each one, quoted from the published guidelines.
const OUTSTANDING_FIELDS: &[(&str, &str)] = &[
    (
        "Summary and description",
        "Performs as described: Your app does what it advertises.",
    ),
    (
        "Category",
        "Performs as described: Your app does what it advertises.",
    ),
    ("Privacy policy URL", "Create a privacy policy."),
    (
        "Documentation URL",
        "Provide documentation: Your listing should reference documentation that \
         describes how to set up and use your app.",
    ),
    (
        "Marketing assets (logo, banner, screenshots)",
        "Provide marketing assets like a logo, banner, and screenshots [...] Declare \
         these assets in the app descriptor.",
    ),
    (
        "Pricing model",
        "Reasonable pricing: Your paid app should be reasonably and competitively \
         priced.",
    ),
    (
        "Source code URL and licence (open-source apps)",
        "Available source code for open-source apps: [...] Include a license file in \
         your source code that matches what you report in the Marketplace.",
    ),
    (
        "Support contact email",
        "Valid company email address for paid-via-Atlassian apps: Personal or generic \
         domains (like Gmail or Yahoo) are not permitted for paid-via-Atlassian apps.",
    ),
    (
        "Security contact with an ecosystem.atlassian.net account",
        "Fulfill the security requirements outlined in the security workflow. \
         (Security questionnaire question 17.)",
    ),
    (
        "Developer Community registration",
        "Register with our Developer Community: At least one contact from your partner \
         profile is registered with the Atlassian Developer Community.",
    ),
    (
        "Marketplace Partner Agreement accepted",
        "Accept the Marketplace Partner Agreement: Upon submission, accept the \
         Marketplace Partner Agreement.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE_APP: &str =
        include_str!("../../../test-apps/jira-damn-vulnerable-forge-app/manifest.yml");

    fn fields() -> Vec<ListingField> {
        build(&ManifestFacts::from_yaml(VULNERABLE_APP).expect("parses"))
    }

    fn field(name: &str) -> ListingField {
        fields()
            .into_iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("no listing field named {name}"))
    }

    #[test]
    fn app_id_is_read_from_the_manifest() {
        let app_id = field("App ID");
        assert_eq!(app_id.basis, Basis::Deterministic);
        assert_eq!(
            app_id.value,
            Some(Value::Text(
                "ari:cloud:ecosystem::app/22948e9c-8414-4d24-bd45-f0dc7428608f".to_string()
            ))
        );
    }

    #[test]
    fn a_missing_app_name_becomes_an_outstanding_field() {
        let name = field("App name");
        assert!(name.is_outstanding());
        assert_eq!(name.basis, Basis::RequiresPartnerInput);
        assert!(name.required_by.is_some());
    }

    #[test]
    fn host_products_are_marked_as_inferred_not_read() {
        let products = field("Host products");
        assert_eq!(products.basis, Basis::Heuristic);
        assert_eq!(products.value, Some(Value::List(vec!["Jira".to_string()])));
    }

    #[test]
    fn every_outstanding_field_cites_a_criterion() {
        for field in fields().iter().filter(|field| field.is_outstanding()) {
            assert!(
                field.required_by.is_some(),
                "{} is outstanding but cites no criterion",
                field.name
            );
        }
    }

    #[test]
    fn deployment_model_is_settled_by_the_artefact() {
        let model = field("Deployment model");
        assert_eq!(model.basis, Basis::Deterministic);
        assert_eq!(model.value, Some(Value::Text("Cloud (Forge)".to_string())));
    }

    #[test]
    fn empty_lists_render_readably() {
        assert_eq!(Value::List(vec![]).as_display(), "(none)");
        assert_eq!(
            Value::List(vec!["a".to_string(), "b".to_string()]).as_display(),
            "a, b"
        );
    }
}
