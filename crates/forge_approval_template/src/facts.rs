//! Everything this tool can learn from a Forge `manifest.yml`.
//!
//! # Why this is not just `forge_loader::manifest::ForgeManifest`
//!
//! [`ForgeManifest`] is modelled for the *analyser*: it captures what is needed to
//! find function entrypoints and reason about authorisation. It deliberately does
//! not model several things the approval submission asks about, and serde silently
//! discards them:
//!
//! | Needed for | Not modelled by `ForgeManifest` |
//! |---|---|
//! | Q6 / Q6a egress | `permissions.external.*` — there is no `external` field on `Perms` |
//! | Q6b TLS | `remotes[].baseUrl` — `Remotes` captures only `key`, `auth`, `operations` |
//! | Q5 display conditions | `displayConditions` on any module |
//! | Host product inference | the module type keys — ~120 of `ForgeModules`' fields are private |
//!
//! So this module runs **two passes** over the same document and keeps the
//! strengths of each:
//!
//! 1. A **typed pass** through [`ForgeManifest`], reused for the things it models
//!    well and has already got right — notably `permissions.scopes`, which has a
//!    custom deserialiser handling both the sequence and mapping spellings, and
//!    remote auth semantics via `Remotes::passes_user_auth`/`passes_system_auth`.
//! 2. A **generic pass** over [`serde_yaml::Value`] for the rest.
//!
//! The generic pass is not a workaround, it is the right tool: new Forge module
//! types and new `permissions` blocks appear in the manifest reference regularly,
//! and a generic walk reports them the day they ship instead of silently dropping
//! them until someone adds a struct field.
//!
//! Every fact carries the manifest path it came from (see [`Located`]) so that an
//! answer can cite its evidence.

use std::collections::{BTreeSet, HashSet};

use forge_loader::manifest::ForgeManifest;
use serde::Serialize;
use serde_yaml::Value;

/// A fact together with the manifest path it was read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Located<T> {
    /// Dotted path into the manifest, e.g. `permissions.external.fetch.client[0]`.
    pub pointer: String,
    pub value: T,
}

impl<T> Located<T> {
    pub fn new(pointer: impl Into<String>, value: T) -> Self {
        Self {
            pointer: pointer.into(),
            value,
        }
    }
}

/// A host product a module belongs to.
///
/// Inferred from the module type key's prefix. `Other` keeps forward
/// compatibility: a module type for a product this tool has never heard of is
/// reported rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostProduct {
    Jira,
    JiraServiceManagement,
    Confluence,
    Compass,
    Bitbucket,
    Rovo,
    Other(String),
}

impl HostProduct {
    pub fn display(&self) -> &str {
        match self {
            Self::Jira => "Jira",
            Self::JiraServiceManagement => "Jira Service Management",
            Self::Confluence => "Confluence",
            Self::Compass => "Compass",
            Self::Bitbucket => "Bitbucket",
            Self::Rovo => "Rovo",
            Self::Other(name) => name,
        }
    }

    /// Infer the host product a module type belongs to.
    ///
    /// Returns [`None`] for product-agnostic module types (`function`,
    /// `webtrigger`, `scheduledTrigger`, ...) which say nothing about the host.
    fn from_module_type(module_type: &str) -> Option<Self> {
        if PRODUCT_AGNOSTIC_MODULES.contains(&module_type) {
            return None;
        }

        // `macro` is a Confluence module and is spelled without a prefix.
        if module_type == "macro" {
            return Some(Self::Confluence);
        }

        let prefix = module_type.split(':').next()?;
        Some(match prefix {
            "jira" => Self::Jira,
            "jiraServiceManagement" => Self::JiraServiceManagement,
            "confluence" => Self::Confluence,
            "compass" => Self::Compass,
            "bitbucket" => Self::Bitbucket,
            "rovo" => Self::Rovo,
            // An unprefixed module type that is not on the agnostic list, or a
            // prefix we do not recognise. Report it verbatim.
            other => Self::Other(other.to_string()),
        })
    }
}

/// Module types that exist in every product and therefore imply no host product.
const PRODUCT_AGNOSTIC_MODULES: &[&str] = &[
    "function",
    "webtrigger",
    "trigger",
    "scheduledTrigger",
    "consumer",
    "apiRoute",
    "endpoint",
    "resource",
    "remote",
    "action",
    "dataProvider",
    "graphql",
];

/// Module types that cannot surface a user interface, and so do not by
/// themselves imply user interaction (questionnaire Q1).
///
/// Treated as a deny list rather than an allow list on purpose: an unrecognised
/// module type is assumed to be user facing, which drives Q1 to `Yes` and keeps
/// the `asUser()` follow-up (Q1a) in play. Erring the other way would silently
/// suppress a question a reviewer expects to see answered.
const NON_USER_FACING_MODULES: &[&str] = &[
    "function",
    "webtrigger",
    "trigger",
    "scheduledTrigger",
    "consumer",
    "apiRoute",
    "endpoint",
    "resource",
    "remote",
    "dataProvider",
];

/// The verb of a Forge scope, e.g. the `manage` in `manage:jira-configuration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeVerb {
    Read,
    Write,
    Delete,
    Manage,
    Admin,
    /// Any other verb, e.g. `storage` in `storage:app`.
    Other,
}

impl ScopeVerb {
    fn parse(scope: &str) -> Self {
        match scope.split(':').next().unwrap_or_default() {
            "read" => Self::Read,
            "write" => Self::Write,
            "delete" => Self::Delete,
            "manage" => Self::Manage,
            "admin" => Self::Admin,
            _ => Self::Other,
        }
    }

    /// Whether this verb grants more than read access.
    ///
    /// Used only to *rank* declared scopes for the least-privilege question
    /// (Q7). It is not a judgement that the scope is unnecessary — deciding that
    /// needs the call-graph analysis in [`forge_permission_resolver`], which this
    /// crate deliberately does not attempt.
    ///
    /// [`forge_permission_resolver`]: https://github.com/atlassian-labs/FSRT
    pub fn is_elevated(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Delete | Self::Manage | Self::Admin
        )
    }
}

/// A declared permission scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Scope {
    pub raw: String,
    pub verb: ScopeVerb,
}

/// How an egress destination is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPattern {
    /// Exactly `*` — any host.
    AnyHost,
    /// A wildcard covering a whole top-level domain, e.g. `*.com`.
    WildcardTopLevel,
    /// A wildcard scoped to a domain the partner plausibly controls,
    /// e.g. `*.example.com`.
    WildcardScoped,
    /// A single fixed host or URL.
    Fixed,
    /// Contains a `${...}` placeholder resolved at deploy time, so its real
    /// value is not knowable from the manifest.
    Interpolated,
}

/// An external destination the app may talk to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressEntry {
    pub pointer: String,
    pub value: String,
    pub pattern: EgressPattern,
    /// URL scheme, when the entry is spelled as a URL.
    pub scheme: Option<String>,
}

impl EgressEntry {
    fn new(pointer: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        let scheme = value
            .split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_lowercase());
        let pattern = classify_egress(&value);
        Self {
            pointer: pointer.into(),
            value,
            pattern,
            scheme,
        }
    }

    /// Whether the entry is one of the two spellings Q6a asks about
    /// (`*` or a whole-TLD wildcard such as `*.com`).
    pub fn is_overly_broad(&self) -> bool {
        matches!(
            self.pattern,
            EgressPattern::AnyHost | EgressPattern::WildcardTopLevel
        )
    }

    /// Whether the entry names a cleartext transport, which cannot satisfy the
    /// TLS 1.2 requirement in Q6b.
    pub fn is_cleartext(&self) -> bool {
        self.scheme.as_deref() == Some("http")
    }
}

fn classify_egress(value: &str) -> EgressPattern {
    if value.contains("${") {
        return EgressPattern::Interpolated;
    }

    // Strip scheme and any path so `https://*.com/x` classifies as `*.com`.
    let host = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();

    if host == "*" {
        return EgressPattern::AnyHost;
    }

    if let Some(suffix) = host.strip_prefix("*.") {
        // `*.com` covers an entire TLD; `*.example.com` does not.
        return if suffix.contains('.') {
            EgressPattern::WildcardScoped
        } else {
            EgressPattern::WildcardTopLevel
        };
    }

    EgressPattern::Fixed
}

/// A declared Forge remote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Remote {
    pub key: String,
    pub base_url: Option<String>,
    /// `baseUrl` is a `${...}` placeholder, so its real value is set at deploy
    /// time and cannot be checked here.
    pub base_url_is_interpolated: bool,
    pub operations: Vec<String>,
    /// An `auth` block is present.
    pub declares_auth: bool,
    /// `auth.appUserToken.enabled` is true, so the app can forward a Forge
    /// Invocation Token carrying user context.
    pub passes_user_token: bool,
    /// `auth.appSystemToken.enabled` is true, so the app can forward an app
    /// system token.
    pub passes_system_token: bool,
}

impl Remote {
    /// Whether any token is forwarded to the remote.
    ///
    /// When no token is forwarded, the remote host has nothing to validate, so
    /// Q2a ("does your remote host validate authentication information from the
    /// FIT?") cannot be answered `Yes`.
    pub fn forwards_a_token(&self) -> bool {
        self.passes_user_token || self.passes_system_token
    }
}

/// Everything read out of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestFacts {
    pub app_id: Option<String>,
    pub app_name: Option<String>,
    pub runtime: Option<String>,
    /// The keys under `modules:`, in manifest order.
    pub declared_module_types: Vec<String>,
    pub host_products: Vec<HostProduct>,
    /// Declared module types that can surface a user interface.
    pub user_facing_module_types: Vec<String>,
    pub scopes: Vec<Scope>,
    /// `key` of every `webtrigger` module.
    pub webtriggers: Vec<Located<String>>,
    /// Every `displayConditions` block found under `modules`.
    pub display_conditions: Vec<Located<String>>,
    pub remotes: Vec<Remote>,
    /// Destinations from `permissions.external.*`.
    pub external_egress: Vec<EgressEntry>,
    /// `providers.auth[].key` — third-party OAuth providers.
    pub oauth_providers: Vec<String>,
    /// `unsafe-inline` / `unsafe-eval` style relaxations in
    /// `permissions.content`.
    pub content_security_relaxations: Vec<Located<String>>,
    pub resource_keys: Vec<String>,
}

/// Failure to read a manifest.
#[derive(Debug)]
pub enum Error {
    /// The document is not valid YAML, or does not match the Forge manifest shape.
    Yaml(serde_yaml::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yaml(error) => write!(f, "could not parse manifest: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Yaml(error) => Some(error),
        }
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(error: serde_yaml::Error) -> Self {
        Self::Yaml(error)
    }
}

impl ManifestFacts {
    /// Read every fact this tool understands out of a `manifest.yml`.
    pub fn from_yaml(source: &str) -> Result<Self, Error> {
        let typed: ForgeManifest<'_> = serde_yaml::from_str(source)?;
        let raw: Value = serde_yaml::from_str(source)?;

        let declared_module_types = declared_module_types(&raw);

        let host_products: Vec<HostProduct> = declared_module_types
            .iter()
            .filter_map(|module_type| HostProduct::from_module_type(module_type))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let user_facing_module_types = declared_module_types
            .iter()
            .filter(|module_type| !NON_USER_FACING_MODULES.contains(&module_type.as_str()))
            .cloned()
            .collect();

        Ok(Self {
            app_id: non_empty(typed.app.id),
            app_name: typed.app.name.and_then(non_empty),
            runtime: runtime_name(&raw),
            declared_module_types,
            host_products,
            user_facing_module_types,
            scopes: typed
                .permissions
                .scopes
                .iter()
                .map(|raw| Scope {
                    raw: raw.clone(),
                    verb: ScopeVerb::parse(raw),
                })
                .collect(),
            webtriggers: webtriggers(&raw),
            display_conditions: display_conditions(&raw),
            remotes: remotes(&typed, &raw),
            external_egress: external_egress(&raw),
            oauth_providers: oauth_providers(&typed),
            content_security_relaxations: content_security_relaxations(&raw),
            resource_keys: typed
                .resources
                .iter()
                .map(|resource| resource.key.to_string())
                .collect(),
        })
    }

    /// Whether the app declares any external destination, by remote or by
    /// `permissions.external`.
    pub fn egresses_data(&self) -> bool {
        !self.remotes.is_empty() || !self.external_egress.is_empty()
    }

    /// Egress destinations spelled `*` or `*.<tld>`.
    pub fn overly_broad_egress(&self) -> impl Iterator<Item = &EgressEntry> {
        self.external_egress
            .iter()
            .filter(|entry| entry.is_overly_broad())
    }

    /// Egress destinations that name a cleartext transport.
    pub fn cleartext_egress(&self) -> impl Iterator<Item = &EgressEntry> {
        self.external_egress
            .iter()
            .filter(|entry| entry.is_cleartext())
    }

    /// Declared scopes granting more than read access.
    pub fn elevated_scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter().filter(|scope| scope.verb.is_elevated())
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn runtime_name(raw: &Value) -> Option<String> {
    raw.get("app")?
        .get("runtime")?
        .get("name")?
        .as_str()
        .and_then(non_empty)
}

fn declared_module_types(raw: &Value) -> Vec<String> {
    let Some(Value::Mapping(modules)) = raw.get("modules") else {
        return Vec::new();
    };

    modules
        .iter()
        .filter_map(|(key, _)| key.as_str().map(str::to_string))
        .collect()
}

fn webtriggers(raw: &Value) -> Vec<Located<String>> {
    let Some(Value::Sequence(triggers)) = raw.get("modules").and_then(|m| m.get("webtrigger"))
    else {
        return Vec::new();
    };

    triggers
        .iter()
        .enumerate()
        .map(|(index, trigger)| {
            let key = trigger
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("(unnamed)");
            Located::new(format!("modules.webtrigger[{index}].key"), key.to_string())
        })
        .collect()
}

fn display_conditions(raw: &Value) -> Vec<Located<String>> {
    let mut found = Vec::new();
    if let Some(modules) = raw.get("modules") {
        collect_key("modules", modules, "displayConditions", &mut found);
    }
    found
}

/// Find every occurrence of `wanted` as a mapping key, at any depth.
fn collect_key(path: &str, value: &Value, wanted: &str, out: &mut Vec<Located<String>>) {
    match value {
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let Some(key) = key.as_str() else { continue };
                let child_path = format!("{path}.{key}");
                if key == wanted {
                    out.push(Located::new(child_path.clone(), summarise(child)));
                    // Do not descend: the whole block has been captured.
                    continue;
                }
                collect_key(&child_path, child, wanted, out);
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_key(&format!("{path}[{index}]"), item, wanted, out);
            }
        }
        _ => {}
    }
}

/// Render a YAML value as a single line, for display in evidence.
fn summarise(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(bool) => bool.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => string.clone(),
        Value::Sequence(items) => items.iter().map(summarise).collect::<Vec<_>>().join(", "),
        Value::Mapping(mapping) => mapping
            .iter()
            .map(|(key, value)| format!("{}: {}", summarise(key), summarise(value)))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Tagged(tagged) => summarise(&tagged.value),
    }
}

fn remotes(typed: &ForgeManifest<'_>, raw: &Value) -> Vec<Remote> {
    let Some(declared) = typed.remotes.as_ref() else {
        return Vec::new();
    };

    // `Remotes` does not model `baseUrl`, so read it positionally from the raw
    // document. Both views deserialise the same sequence, so indices line up.
    let raw_remotes = raw.get("remotes").and_then(Value::as_sequence);

    declared
        .iter()
        .enumerate()
        .map(|(index, remote)| {
            let base_url = raw_remotes
                .and_then(|remotes| remotes.get(index))
                .and_then(|remote| remote.get("baseUrl"))
                .and_then(Value::as_str)
                .and_then(non_empty);

            Remote {
                key: remote.key.clone(),
                base_url_is_interpolated: base_url.as_deref().is_some_and(|url| url.contains("${")),
                base_url,
                operations: remote.operations.clone(),
                declares_auth: remote.contains_auth(),
                passes_user_token: remote.passes_user_auth(),
                passes_system_token: remote.passes_system_auth(),
            }
        })
        .collect()
}

fn oauth_providers(typed: &ForgeManifest<'_>) -> Vec<String> {
    typed
        .providers
        .as_ref()
        .and_then(|providers| providers.auth.as_ref())
        .map(|providers| {
            providers
                .iter()
                .map(|provider| provider.key.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Keys under `permissions.external` whose string leaves are not destinations.
const NON_DESTINATION_KEYS: &[&str] = &["inspector"];

fn external_egress(raw: &Value) -> Vec<EgressEntry> {
    let Some(external) = raw
        .get("permissions")
        .and_then(|permissions| permissions.get("external"))
    else {
        return Vec::new();
    };

    let mut leaves = Vec::new();
    collect_string_leaves(
        "permissions.external",
        external,
        NON_DESTINATION_KEYS,
        &mut leaves,
    );

    let mut seen = HashSet::new();
    leaves
        .into_iter()
        .filter(|leaf| seen.insert((leaf.pointer.clone(), leaf.value.clone())))
        .map(|leaf| EgressEntry::new(leaf.pointer, leaf.value))
        .collect()
}

fn content_security_relaxations(raw: &Value) -> Vec<Located<String>> {
    let Some(content) = raw
        .get("permissions")
        .and_then(|permissions| permissions.get("content"))
    else {
        return Vec::new();
    };

    let mut leaves = Vec::new();
    collect_string_leaves("permissions.content", content, &[], &mut leaves);
    leaves
        .into_iter()
        .filter(|leaf| leaf.value.starts_with("unsafe-"))
        .collect()
}

/// Collect every string leaf under `value`, skipping subtrees keyed by
/// `skip_keys`.
fn collect_string_leaves(
    path: &str,
    value: &Value,
    skip_keys: &[&str],
    out: &mut Vec<Located<String>>,
) {
    match value {
        Value::String(string) => {
            if let Some(string) = non_empty(string) {
                out.push(Located::new(path, string));
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_string_leaves(&format!("{path}[{index}]"), item, skip_keys, out);
            }
        }
        Value::Mapping(mapping) => {
            for (key, child) in mapping {
                let Some(key) = key.as_str() else { continue };
                if skip_keys.contains(&key) {
                    continue;
                }
                collect_string_leaves(&format!("{path}.{key}"), child, skip_keys, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE_APP: &str =
        include_str!("../../../test-apps/jira-damn-vulnerable-forge-app/manifest.yml");
    const BASIC_APP: &str = include_str!("../../../test-apps/basic/manifest.yml");

    fn read(source: &str) -> ManifestFacts {
        ManifestFacts::from_yaml(source).expect("manifest should parse")
    }

    #[test]
    fn reads_app_identity() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(
            facts.app_id.as_deref(),
            Some("ari:cloud:ecosystem::app/22948e9c-8414-4d24-bd45-f0dc7428608f")
        );
        // This manifest declares no `app.name`, which the listing section must
        // then ask the partner for.
        assert_eq!(facts.app_name, None);
    }

    #[test]
    fn infers_host_product_from_module_prefixes() {
        assert_eq!(read(VULNERABLE_APP).host_products, vec![HostProduct::Jira]);
        // `macro` is a Confluence module spelled without a prefix.
        assert_eq!(read(BASIC_APP).host_products, vec![HostProduct::Confluence]);
    }

    #[test]
    fn product_agnostic_modules_imply_no_host() {
        assert_eq!(HostProduct::from_module_type("function"), None);
        assert_eq!(HostProduct::from_module_type("webtrigger"), None);
        assert_eq!(
            HostProduct::from_module_type("jira:issuePanel"),
            Some(HostProduct::Jira)
        );
        assert_eq!(
            HostProduct::from_module_type("jiraServiceManagement:portalHeader"),
            Some(HostProduct::JiraServiceManagement)
        );
        // Forward compatibility: an unknown prefix is reported, not dropped.
        assert_eq!(
            HostProduct::from_module_type("newproduct:page"),
            Some(HostProduct::Other("newproduct".to_string()))
        );
    }

    #[test]
    fn finds_webtriggers() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(facts.webtriggers.len(), 1);
        assert_eq!(facts.webtriggers[0].value, "authenticated-webtrigger");
        assert_eq!(facts.webtriggers[0].pointer, "modules.webtrigger[0].key");
        assert!(read(BASIC_APP).webtriggers.is_empty());
    }

    #[test]
    fn finds_display_conditions_at_any_depth() {
        let facts = read(VULNERABLE_APP);
        // Five modules in this manifest carry `displayConditions`: globalPage,
        // issuePanel, projectPage, projectSettingsPage and dashboardGadget.
        assert_eq!(facts.display_conditions.len(), 5);
        assert!(
            facts
                .display_conditions
                .iter()
                .all(|condition| condition.value == "isAdmin: true")
        );
        assert_eq!(
            facts.display_conditions[0].pointer,
            "modules.jira:globalPage[0].displayConditions"
        );
        assert!(read(BASIC_APP).display_conditions.is_empty());
    }

    #[test]
    fn reads_remote_auth_and_base_url() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(facts.remotes.len(), 1);
        let remote = &facts.remotes[0];
        assert_eq!(remote.key, "remote-ssot-micros");
        assert_eq!(remote.base_url.as_deref(), Some("${REMOTE_URL}"));
        assert!(remote.base_url_is_interpolated);
        assert!(remote.declares_auth);
        assert!(remote.passes_system_token);
        assert!(!remote.passes_user_token);
        assert!(remote.forwards_a_token());
        assert_eq!(remote.operations, vec!["compute".to_string()]);
    }

    #[test]
    fn reads_external_egress_that_the_typed_model_drops() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(facts.external_egress.len(), 1);
        let entry = &facts.external_egress[0];
        assert_eq!(entry.value, "*");
        assert_eq!(entry.pointer, "permissions.external.fetch.client[0]");
        assert_eq!(entry.pattern, EgressPattern::AnyHost);
        assert!(entry.is_overly_broad());
        assert!(facts.egresses_data());
    }

    #[test]
    fn classifies_egress_patterns() {
        assert_eq!(classify_egress("*"), EgressPattern::AnyHost);
        assert_eq!(classify_egress("*.com"), EgressPattern::WildcardTopLevel);
        assert_eq!(classify_egress("*.io"), EgressPattern::WildcardTopLevel);
        assert_eq!(
            classify_egress("*.example.com"),
            EgressPattern::WildcardScoped
        );
        assert_eq!(classify_egress("api.example.com"), EgressPattern::Fixed);
        assert_eq!(
            classify_egress("https://api.example.com/v1"),
            EgressPattern::Fixed
        );
        // A wildcard TLD is still a wildcard TLD when spelled as a URL.
        assert_eq!(
            classify_egress("https://*.com/path"),
            EgressPattern::WildcardTopLevel
        );
        assert_eq!(
            classify_egress("${REMOTE_URL}"),
            EgressPattern::Interpolated
        );
    }

    #[test]
    fn detects_cleartext_egress() {
        let entry = EgressEntry::new("p", "http://api.example.com");
        assert_eq!(entry.scheme.as_deref(), Some("http"));
        assert!(entry.is_cleartext());
        assert!(!EgressEntry::new("p", "https://api.example.com").is_cleartext());
        // A bare domain names no transport, so it is not evidence of cleartext.
        assert!(!EgressEntry::new("p", "api.example.com").is_cleartext());
    }

    #[test]
    fn finds_content_security_relaxations() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(facts.content_security_relaxations.len(), 1);
        assert_eq!(facts.content_security_relaxations[0].value, "unsafe-inline");
        assert_eq!(
            facts.content_security_relaxations[0].pointer,
            "permissions.content.styles[0]"
        );
    }

    #[test]
    fn classifies_scope_verbs() {
        let facts = read(VULNERABLE_APP);
        assert_eq!(
            facts
                .scopes
                .iter()
                .map(|s| s.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["read:user:jira", "read:jira-work"]
        );
        assert!(facts.scopes.iter().all(|s| s.verb == ScopeVerb::Read));
        assert_eq!(facts.elevated_scopes().count(), 0);

        assert_eq!(
            ScopeVerb::parse("manage:jira-configuration"),
            ScopeVerb::Manage
        );
        assert_eq!(ScopeVerb::parse("delete:issue:jira"), ScopeVerb::Delete);
        assert_eq!(ScopeVerb::parse("storage:app"), ScopeVerb::Other);
        assert!(ScopeVerb::Manage.is_elevated());
        assert!(!ScopeVerb::Read.is_elevated());
    }

    #[test]
    fn scopes_written_as_a_mapping_are_still_read() {
        // Reuses `forge_loader`'s custom scope deserialiser, which accepts this
        // spelling as well as a plain sequence.
        let source = "
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
modules:
  macro:
    - key: m
      function: main
permissions:
  scopes:
    read:jira-work:
    write:jira-work:
";
        let facts = read(source);
        assert_eq!(facts.scopes.len(), 2);
        assert_eq!(facts.elevated_scopes().count(), 1);
    }

    #[test]
    fn app_with_no_egress_reports_none() {
        let facts = read(BASIC_APP);
        assert!(!facts.egresses_data());
        assert!(facts.external_egress.is_empty());
        assert!(facts.remotes.is_empty());
        assert!(facts.scopes.is_empty());
    }

    #[test]
    fn user_facing_modules_exclude_plumbing() {
        let facts = read(VULNERABLE_APP);
        assert!(
            facts
                .declared_module_types
                .contains(&"function".to_string())
        );
        assert!(
            !facts
                .user_facing_module_types
                .contains(&"function".to_string())
        );
        assert!(
            !facts
                .user_facing_module_types
                .contains(&"webtrigger".to_string())
        );
        assert!(
            facts
                .user_facing_module_types
                .contains(&"jira:issuePanel".to_string())
        );
    }

    #[test]
    fn oauth_providers_are_read() {
        let source = "
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
modules:
  macro:
    - key: m
      function: main
providers:
  auth:
    - key: github
      actions: {}
";
        assert_eq!(read(source).oauth_providers, vec!["github".to_string()]);
    }

    #[test]
    fn malformed_yaml_is_an_error_not_a_panic() {
        let error = ManifestFacts::from_yaml("app: [this is not a mapping").unwrap_err();
        assert!(error.to_string().contains("could not parse manifest"));
    }
}
