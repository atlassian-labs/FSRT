#![allow(dead_code, unused)]
use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashSet},
    hash::Hash,
    path::{Path, PathBuf},
};

use crate::Error;
use forge_utils::FxHashMap;
use itertools::Itertools;
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;
use tracing::trace;

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthProviders<'a> {
    #[serde(borrow)]
    auth: Vec<&'a str>,
}

// Abstracting away key, function, and resolver into a single struct for reuse whoo!
// And helper functions for ease of use
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
struct CommonKey<'a> {
    key: &'a str,
    function: Option<&'a str>,
    resolver: Option<Resolver<'a>>,
}

trait HasFunctions<'a> {
    fn append_functions<I: Extend<&'a str>>(&self, funcs: &mut I);
}

impl<'a> HasFunctions<'a> for CommonKey<'a> {
    fn append_functions<I: Extend<&'a str>>(&self, funcs: &mut I) {
        funcs.extend(self.function);

        if let Some(Resolver {
            function,
            method: _,
            endpoint: _,
        }) = self.resolver
        {
            funcs.extend(function);
        }
    }
}

impl<'a> HasFunctions<'a> for JustFunc<'a> {
    fn append_functions<I: Extend<&'a str>>(&self, funcs: &mut I) {
        funcs.extend(self.function);
    }
}

impl<'a, I, E: HasFunctions<'a>> HasFunctions<'a> for I
where
    for<'c> &'c I: IntoIterator<Item = &'c E>,
{
    fn append_functions<B: Extend<&'a str>>(&self, funcs: &mut B) {
        // iterating over &I
        for e in self {
            e.append_functions(funcs);
        }
    }
}
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct Resolver<'a> {
    pub function: Option<&'a str>,
    pub method: Option<&'a str>,
    pub endpoint: Option<&'a str>,
}

// Implementing a struct for structs with 1 value (function)

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct JustFunc<'a> {
    pub function: Option<&'a str>,
}

// Common Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FunctionMod<'a> {
    pub key: &'a str,
    pub handler: &'a str,
    #[serde(borrow)]
    pub providers: Option<AuthProviders<'a>>,
}

// https://developer.atlassian.com/platform/forge/manifest-reference/modules/consumer/
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Consumer<'a> {
    key: &'a str,
    queue: &'a str,
    #[serde(default, borrow)]
    pub function: Option<&'a str>,
    #[serde(default, borrow)]
    pub resolver: Resolver<'a>,
}

// Trigger Modules
// https://developer.atlassian.com/platform/forge/manifest-reference/modules/scheduled-trigger/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Interval {
    Hour,
    Day,
    Week,
    #[serde(rename = "fiveMinute")]
    FiveMinute,
}

// Maps to Scheduled Trigger under Common Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScheduledTrigger<'a> {
    key: &'a str,
    #[serde(default, borrow)]
    function: Option<&'a str>,
    #[serde(default, borrow)]
    endpoint: Option<&'a str>,
    interval: Interval,
}

// Maps to Web Trigger under Common Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
struct RawTrigger<'a> {
    key: &'a str,
    function: &'a str,
}

// maps to Trigger under Common Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EventTrigger<'a> {
    key: &'a str,
    #[serde(default, borrow)]
    function: Option<&'a str>,
    #[serde(default, borrow)]
    endpoint: Option<&'a str>,
    #[serde(borrow)]
    events: Vec<&'a str>,
}

// Compass Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CompassAdminPage<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ComponentPage<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}
// #[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
// pub struct DataProvider<'a> {
//     #[serde(flatten, borrow)]
//     common_keys: CommonKey<'a>,
//     callback: Option<JustFunc<'a>>,
// }

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CompassGlobalPage<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TeamPage<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

// Confluence Modules
#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContentAction<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContentByLineItem<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    #[serde(borrow, rename = "dynamicProperties")]
    dynamic_properties: JustFunc<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
#[serde(untagged)]
#[serde(bound(deserialize = "'de: 'a"))]
enum MacroConfig<'a> {
    Enabled(bool),
    Object(JustFunc<'a>),
}

impl<'a> HasFunctions<'a> for MacroConfig<'a> {
    fn append_functions<I: Extend<&'a str>>(&self, funcs: &mut I) {
        if let Self::Object(config) = self {
            config.append_functions(funcs);
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct MacroMod<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    config: Option<MacroConfig<'a>>,
    export: Option<JustFunc<'a>>,
}

// Jira Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
#[serde(untagged)]
#[serde(bound(deserialize = "'de: 'a"))]
enum LocalizedText<'a> {
    Text(&'a str),
    I18n { i18n: &'a str },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct JiraAdminPage<'a> {
    title: LocalizedText<'a>,
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CustomField<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    value: Option<JustFunc<'a>>,
    edit: Option<JustFunc<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CustomFieldType<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    value: Option<JustFunc<'a>>,
    edit: Option<JustFunc<'a>>,
    context_config: Option<JustFunc<'a>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DashboardGadget<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    edit: Option<JustFunc<'a>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueClass<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    dynamic_properties: Option<JustFunc<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UiModificatons<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowValidator<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowPostFunction<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
}

// Jira Service Management Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssetsImportType<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    on_delete_import: Option<JustFunc<'a>>,
    start_import: JustFunc<'a>,
    stop_import: JustFunc<'a>,
    import_status: JustFunc<'a>,
}

// Rovo Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RovoAgent<'a> {
    pub key: &'a str,
    pub name: &'a str,
    pub description: Option<String>,
    pub icon: Option<&'a str>,
    pub prompt: String, // as may be multiline
    #[serde(default, rename = "conversationStarters")]
    pub conversation_starters: Vec<String>,
    #[serde(default, borrow)]
    pub actions: Vec<&'a str>,
    #[serde(rename = "followUpPrompt")]
    pub follow_up_prompt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Action<'a> {
    pub key: &'a str,
    // Action can have either an "endpoint" property or a "function" property
    #[serde(rename = "function", default)]
    pub function: Option<&'a str>,
    #[serde(rename = "endpoint", default)]
    pub endpoint: Option<&'a str>,
}

// Add more structs here for deserializing forge modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForgeModules<'a> {
    // deserializing non user-invocable modules

    // Common Modules including triggers
    #[serde(rename = "consumer", default, borrow)]
    pub consumers: Vec<Consumer<'a>>,
    #[serde(rename = "function", default, borrow)]
    pub functions: Vec<FunctionMod<'a>>,
    #[serde(rename = "webtrigger", default, borrow)]
    webtriggers: Vec<RawTrigger<'a>>,
    #[serde(rename = "trigger", default, borrow)]
    event_triggers: Vec<EventTrigger<'a>>,
    #[serde(rename = "scheduledTrigger", default, borrow)]
    scheduled_triggers: Vec<ScheduledTrigger<'a>>,
    #[serde(rename = "apiRoute", default, borrow)]
    api_routes: Vec<JustFunc<'a>>,

    // Compass Modules
    #[serde(rename = "compass:adminPage", default, borrow)]
    compass_admin_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:componentPage", default, borrow)]
    component_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:globalPage", default, borrow)]
    compass_global_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:teamPage", default, borrow)]
    team_page: Vec<CommonKey<'a>>,

    // Confluence Modules
    #[serde(rename = "confluence:contentAction", default, borrow)]
    content_action: Vec<CommonKey<'a>>,
    #[serde(rename = "confluence:contentByLineItem", default, borrow)]
    content_by_line_item: Vec<ContentByLineItem<'a>>,
    #[serde(rename = "confluence:contextMenu", default, borrow)]
    context_menu: Vec<CommonKey<'a>>,
    #[serde(rename = "confluence:globalPage", default, borrow)]
    confluence_global_page: Vec<CommonKey<'a>>,
    #[serde(rename = "confluence:homepageFeed", default, borrow)]
    homepage_feed: Vec<CommonKey<'a>>,
    #[serde(rename = "confluence:spacePage", default, borrow)]
    space_page: Vec<CommonKey<'a>>,
    #[serde(rename = "confluence:spaceSettings", default, borrow)]
    space_settings: Vec<CommonKey<'a>>,
    #[serde(rename = "macro", default, borrow)]
    macros: Vec<MacroMod<'a>>,

    // Jira Modules
    #[serde(rename = "jira:adminPage", default, borrow)]
    pub jira_admin_page: Vec<JiraAdminPage<'a>>,
    #[serde(rename = "jira:customField", default, borrow)]
    pub custom_field: Vec<CustomField<'a>>,
    #[serde(rename = "jira:customFieldType", default, borrow)]
    custom_field_type: Vec<CustomFieldType<'a>>,
    #[serde(rename = "jira:dashboardBackgroundScript", default, borrow)]
    dashboard_background_script: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:dashboardGadget", default, borrow)]
    dashboard_gadget: Vec<DashboardGadget<'a>>,
    #[serde(rename = "jira:globalPage", default, borrow)]
    jira_global_page: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:issueAction", default, borrow)]
    issue_action: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:issueContext", default, borrow)]
    issue_context: Vec<IssueClass<'a>>,
    #[serde(rename = "jira:issueGlance", default, borrow)]
    issue_glance: Vec<IssueClass<'a>>,
    #[serde(rename = "jira:issuePanel", default, borrow)]
    issue_panel: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:issueViewBackgroundScript", default, borrow)]
    issue_view_background_script: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:jqlFunction", default, borrow)]
    jql_function: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:projectPage", default, borrow)]
    project_page: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:projectSettingsPage", default, borrow)]
    project_settings_page: Vec<CommonKey<'a>>,
    #[serde(rename = "jira:uiModificatons", default, borrow)]
    pub ui_modifications: Vec<UiModificatons<'a>>,
    #[serde(rename = "jira:workflowValidator", default, borrow)]
    pub workflow_validator: Vec<WorkflowValidator<'a>>,
    #[serde(rename = "jira:workflowPostFunction", default, borrow)]
    pub workflow_post_function: Vec<WorkflowPostFunction<'a>>,

    // Jira Service Management Modules
    #[serde(rename = "jiraServiceManagement:assetsImportType", default, borrow)]
    assets_import_type: Vec<AssetsImportType<'a>>,
    #[serde(rename = "jiraServiceManagement:organizationPanel", default, borrow)]
    org_panel: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalFooter", default, borrow)]
    portal_footer: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalHeader", default, borrow)]
    portal_header: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalProfilePanel", default, borrow)]
    portal_profile_panel: Vec<CommonKey<'a>>,
    #[serde(
        rename = "jiraServiceManagement:portalRequestCreatePropertyPanel",
        default,
        borrow
    )]
    portal_req: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalRequestDetail", default, borrow)]
    portal_request_detail: Vec<CommonKey<'a>>,
    #[serde(
        rename = "jiraServiceManagement:portalRequestDetailPanel",
        default,
        borrow
    )]
    portal_request_detail_panel: Vec<CommonKey<'a>>,
    #[serde(
        rename = "jiraServiceManagement:portalRequestViewAction",
        default,
        borrow
    )]
    portal_request_view_action: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalSubheader", default, borrow)]
    portal_subheader: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:portalUserMenuAction", default, borrow)]
    portal_header_menu_action: Vec<CommonKey<'a>>,
    #[serde(rename = "jiraServiceManagement:queuePage", default, borrow)]
    queue_page: Vec<CommonKey<'a>>,

    // Rovo Modules
    #[serde(rename = "rovo:agent", default, borrow)]
    pub rovo_agent: Vec<RovoAgent<'a>>,
    #[serde(rename = "action", default, borrow)]
    pub action: Vec<Action<'a>>,

    // deserializing admin pages
    #[serde(flatten)]
    extra: FxHashMap<String, Vec<Module<'a>>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Content<'a> {
    #[serde(default, borrow)]
    scripts: Vec<&'a str>,
    #[serde(default, borrow)]
    styles: Vec<&'a str>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Perms<'a> {
    #[serde(default, deserialize_with = "deserialize_scopes")]
    pub scopes: Vec<String>,
    #[serde(default, borrow)]
    content: Content<'a>,
}

fn deserialize_scopes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Null => Ok(vec![]),
        Value::Sequence(scopes) => scopes
            .into_iter()
            .map(|scope| match scope {
                Value::String(scope) => Ok(scope),
                other => Err(serde::de::Error::custom(format!(
                    "expected scope string, got {other:?}"
                ))),
            })
            .collect(),
        Value::Mapping(scopes) => scopes
            .into_iter()
            .map(|(scope, _)| match scope {
                Value::String(scope) => Ok(scope),
                other => Err(serde::de::Error::custom(format!(
                    "expected scope key string, got {other:?}"
                ))),
            })
            .collect(),
        other => Err(serde::de::Error::custom(format!(
            "expected scopes sequence or mapping, got {other:?}"
        ))),
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthEntry {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteAuth {
    #[serde(default, rename = "appUserToken")]
    pub app_user_token: Option<AuthEntry>,

    #[serde(default, rename = "appSystemToken")]
    pub app_system_token: Option<AuthEntry>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Remotes {
    #[serde(default)]
    pub key: String,

    #[serde(default)]
    pub auth: Option<RemoteAuth>,

    #[serde(default)]
    pub operations: Vec<String>,
}

impl Remotes {
    pub fn contains_auth(&self) -> bool {
        self.auth.is_some()
    }

    pub fn passes_user_auth(&self) -> bool {
        let Some(auth) = &self.auth else { return false };

        let Some(user_auth) = &auth.app_user_token else {
            return false;
        };

        user_auth.enabled
    }

    pub fn passes_system_auth(&self) -> bool {
        let Some(auth) = &self.auth else { return false };

        let Some(system_auth) = &auth.app_system_token else {
            return false;
        };

        system_auth.enabled
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Providers {
    #[serde(default)]
    pub auth: Option<Vec<OAuthProvider>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthProvider {
    pub key: String,
    #[serde(default)]
    pub actions: Option<OAuthActions>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthActions {
    #[serde(default)]
    pub authorization: Option<AuthorizationAction>,
    #[serde(default)]
    pub exchange: Option<ExchangeAction>,
    #[serde(default)]
    pub refresh: Option<RefreshAction>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthorizationAction {
    #[serde(default, rename = "queryParameters")]
    pub query_params: Option<FxHashMap<String, String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExchangeAction {
    #[serde(default)]
    pub overrides: Option<OAuthOverride>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RefreshAction {
    #[serde(default)]
    pub overrides: Option<OAuthOverride>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthOverride {
    #[serde(default)]
    pub headers: Option<FxHashMap<String, String>>,
    #[serde(default)]
    pub body: Option<FxHashMap<String, String>>,
}

impl OAuthProvider {
    fn parse_for_secrets(
        &self,
        map: &FxHashMap<String, String>,
        path: &str,
        sensitive_keywords: &[&str],
        secrets: &mut Vec<String>,
    ) {
        for (key, value) in map {
            if sensitive_keywords
                .iter()
                .any(|s| key.to_lowercase().contains(s))
                && is_hardcoded_variable(value)
            {
                secrets.push(format!("{}.{}", path, key));
            }
        }
    }

    fn parse_overrides_for_secrets(
        &self,
        overrides: &OAuthOverride,
        path: &str,
        sensitive_keywords: &[&str],
        secrets: &mut Vec<String>,
    ) {
        if let Some(headers) = &overrides.headers {
            self.parse_for_secrets(
                headers,
                &format!("{}.headers", path),
                sensitive_keywords,
                secrets,
            );
        }
        if let Some(body) = &overrides.body {
            self.parse_for_secrets(body, &format!("{}.body", path), sensitive_keywords, secrets);
        }
    }

    pub fn find_hardcoded_secrets(&self) -> Vec<String> {
        let mut secrets = Vec::new();
        let sensitive_keywords = [
            "secret",
            "token",
            "password",
            "authorization",
            "api-key",
            "apikey",
            "credential",
        ];

        if let Some(actions) = &self.actions {
            // Checking if there are hardcoded secrets in the query parameters
            if let Some(authorization) = &actions.authorization
                && let Some(query_params) = &authorization.query_params
            {
                self.parse_for_secrets(
                    query_params,
                    &format!(
                        "providers.auth[{}].actions.authorization.queryParams",
                        self.key
                    ),
                    &sensitive_keywords,
                    &mut secrets,
                );
            }
            // Checking if there are hardcoded secrets in the exchange action
            if let Some(exchange) = &actions.exchange
                && let Some(overrides) = &exchange.overrides
            {
                self.parse_overrides_for_secrets(
                    overrides,
                    &format!("providers.auth[{}].actions.exchange.overrides", self.key),
                    &sensitive_keywords,
                    &mut secrets,
                );
            }

            // Checking if there are hardcoded secrets in the refresh action
            if let Some(refresh) = &actions.refresh
                && let Some(overrides) = &refresh.overrides
            {
                self.parse_overrides_for_secrets(
                    overrides,
                    &format!("providers.auth[{}].actions.refresh.overrides", self.key),
                    &sensitive_keywords,
                    &mut secrets,
                );
            }
        }

        secrets
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AppInfo<'a> {
    pub name: Option<&'a str>,
    pub id: &'a str,
    #[serde(default, borrow)]
    pub runtime: Option<Runtime<'a>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Runtime<'a> {
    pub name: Option<&'a str>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Module<'a> {
    #[serde(default, borrow)]
    pub function: Option<&'a str>,
    #[serde(default)]
    pub resolver: Option<Resolver<'a>>,
    #[serde(flatten)]
    extra: FxHashMap<String, serde_yaml::Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Resource<'a> {
    pub key: &'a str,
    pub path: String,
}

/// The representation of a Forge app's `manifest.yml`
///
/// Contains the [properties] that are needed to find function entrypoints
///
/// [properties]: https://developer.atlassian.com/platform/forge/manifest-reference/
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForgeManifest<'a> {
    #[serde(borrow)]
    pub app: AppInfo<'a>,
    #[serde(borrow)]
    pub modules: ForgeModules<'a>,
    #[serde(default, borrow)]
    pub permissions: Perms<'a>,
    pub remotes: Option<Vec<Remotes>>,
    #[serde(default, borrow)]
    pub resources: Vec<Resource<'a>>,
    #[serde(default)]
    pub providers: Option<Providers>,
}

impl<'a> ForgeManifest<'a> {
    pub fn create_manifest_with_func_mod(function_mod: FunctionMod<'a>) -> Self {
        let mut forge_manifest_test = ForgeManifest::default();
        forge_manifest_test.modules.functions.push(function_mod);
        forge_manifest_test
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Resolved;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Unresolved;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct FunctionRef<'a, S = Unresolved> {
    func: &'a str,
    key: &'a str,
    path: PathBuf,
    status: S,
}

// Add an extra variant to the FunctionTy enum for non user invocable functions
// Indirect: functions indirectly invoked by user :O So kewl.
// TODO: change this to struct with bools
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionTy<T> {
    Invokable(T),
    WebTrigger(T),
}

/// A manifest module type, identified by its manifest key (for example
/// `jira:adminPage`). Entry points record every module type that exposes them,
/// so exposure questions are answered by inspecting those types rather than by
/// carrying a separate boolean for each one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ModuleKind(&'static str);

impl ModuleKind {
    pub const API_ROUTE: Self = Self("apiRoute");
    pub const COMPASS_ADMIN_PAGE: Self = Self("compass:adminPage");
    pub const COMPASS_COMPONENT_PAGE: Self = Self("compass:componentPage");
    pub const COMPASS_GLOBAL_PAGE: Self = Self("compass:globalPage");
    pub const COMPASS_TEAM_PAGE: Self = Self("compass:teamPage");
    pub const CONFLUENCE_CONTENT_ACTION: Self = Self("confluence:contentAction");
    pub const CONFLUENCE_CONTENT_BY_LINE_ITEM: Self = Self("confluence:contentByLineItem");
    pub const CONFLUENCE_CONTEXT_MENU: Self = Self("confluence:contextMenu");
    pub const CONFLUENCE_GLOBAL_PAGE: Self = Self("confluence:globalPage");
    pub const CONFLUENCE_GLOBAL_SETTINGS: Self = Self("confluence:globalSettings");
    pub const CONFLUENCE_HOMEPAGE_FEED: Self = Self("confluence:homepageFeed");
    pub const CONFLUENCE_SPACE_PAGE: Self = Self("confluence:spacePage");
    pub const CONFLUENCE_SPACE_SETTINGS: Self = Self("confluence:spaceSettings");
    pub const MACRO: Self = Self("macro");
    pub const JIRA_ADMIN_PAGE: Self = Self("jira:adminPage");
    pub const JIRA_CUSTOM_FIELD: Self = Self("jira:customField");
    pub const JIRA_DASHBOARD_BACKGROUND_SCRIPT: Self = Self("jira:dashboardBackgroundScript");
    pub const JIRA_DASHBOARD_GADGET: Self = Self("jira:dashboardGadget");
    pub const JIRA_GLOBAL_PAGE: Self = Self("jira:globalPage");
    pub const JIRA_ISSUE_ACTION: Self = Self("jira:issueAction");
    pub const JIRA_ISSUE_CONTEXT: Self = Self("jira:issueContext");
    pub const JIRA_ISSUE_GLANCE: Self = Self("jira:issueGlance");
    pub const JIRA_ISSUE_PANEL: Self = Self("jira:issuePanel");
    pub const JIRA_ISSUE_VIEW_BACKGROUND_SCRIPT: Self = Self("jira:issueViewBackgroundScript");
    pub const JIRA_JQL_FUNCTION: Self = Self("jira:jqlFunction");
    pub const JIRA_PROJECT_PAGE: Self = Self("jira:projectPage");
    pub const JIRA_PROJECT_SETTINGS_PAGE: Self = Self("jira:projectSettingsPage");
    pub const JIRA_UI_MODIFICATIONS: Self = Self("jira:uiModificatons");
    pub const JIRA_WORKFLOW_VALIDATOR: Self = Self("jira:workflowValidator");
    pub const JSM_ASSETS_IMPORT_TYPE: Self = Self("jiraServiceManagement:assetsImportType");
    pub const JSM_ORGANIZATION_PANEL: Self = Self("jiraServiceManagement:organizationPanel");
    pub const JSM_PORTAL_FOOTER: Self = Self("jiraServiceManagement:portalFooter");
    pub const JSM_PORTAL_HEADER: Self = Self("jiraServiceManagement:portalHeader");
    pub const JSM_PORTAL_PROFILE_PANEL: Self = Self("jiraServiceManagement:portalProfilePanel");
    pub const JSM_PORTAL_REQUEST_CREATE_PROPERTY_PANEL: Self =
        Self("jiraServiceManagement:portalRequestCreatePropertyPanel");
    pub const JSM_PORTAL_REQUEST_DETAIL: Self = Self("jiraServiceManagement:portalRequestDetail");
    pub const JSM_PORTAL_REQUEST_DETAIL_PANEL: Self =
        Self("jiraServiceManagement:portalRequestDetailPanel");
    pub const JSM_PORTAL_REQUEST_VIEW_ACTION: Self =
        Self("jiraServiceManagement:portalRequestViewAction");
    pub const JSM_PORTAL_SUBHEADER: Self = Self("jiraServiceManagement:portalSubheader");
    pub const JSM_PORTAL_USER_MENU_ACTION: Self =
        Self("jiraServiceManagement:portalUserMenuAction");
    pub const JSM_QUEUE_PAGE: Self = Self("jiraServiceManagement:queuePage");
    pub const ROVO_ACTION: Self = Self("action");
    pub const WEB_TRIGGER: Self = Self("webtrigger");

    /// The key this module appears under in `manifest.yml`.
    pub fn manifest_key(self) -> &'static str {
        self.0
    }

    /// Modules whose resolver invocations the platform itself restricts to admin
    /// users, so the app is not expected to authorize the caller. Sharing such a
    /// resolver with any other module removes that restriction.
    pub fn is_platform_admin_gated(self) -> bool {
        matches!(self, Self::JIRA_ADMIN_PAGE | Self::COMPASS_ADMIN_PAGE)
    }

    /// Admin-scoped surfaces that are *not* known to carry a platform-enforced
    /// permission check on resolver invocation. They are treated as reachable by
    /// any authenticated user, which is the conservative assumption.
    pub fn is_admin_scoped(self) -> bool {
        matches!(
            self,
            Self::JIRA_PROJECT_SETTINGS_PAGE
                | Self::CONFLUENCE_SPACE_SETTINGS
                | Self::CONFLUENCE_GLOBAL_SETTINGS
        )
    }

    pub fn is_web_trigger(self) -> bool {
        self == Self::WEB_TRIGGER
    }

    /// Reachable by any authenticated user who can use the app.
    pub fn is_user_invokable(self) -> bool {
        !self.is_platform_admin_gated() && !self.is_web_trigger()
    }
}

/// Records which module types expose each function key. Used through
/// [`Exposures::of`], which hands out an [`Extend`] sink tagged with one module
/// type, so the existing [`HasFunctions`] implementations stay unchanged.
#[derive(Default, Debug)]
struct Exposures<'a> {
    by_function: FxHashMap<&'a str, BTreeSet<ModuleKind>>,
}

impl<'a> Exposures<'a> {
    fn of(&mut self, kind: ModuleKind) -> ExposureSink<'_, 'a> {
        ExposureSink {
            by_function: &mut self.by_function,
            kind,
        }
    }

    fn modules_for(&self, function: &str) -> BTreeSet<ModuleKind> {
        self.by_function.get(function).cloned().unwrap_or_default()
    }
}

struct ExposureSink<'e, 'a> {
    by_function: &'e mut FxHashMap<&'a str, BTreeSet<ModuleKind>>,
    kind: ModuleKind,
}

impl<'a> Extend<&'a str> for ExposureSink<'_, 'a> {
    fn extend<T: IntoIterator<Item = &'a str>>(&mut self, iter: T) {
        for function in iter {
            self.by_function
                .entry(function)
                .or_default()
                .insert(self.kind);
        }
    }
}

// Struct used for tracking what scan a function requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrypoint<'a, S = Unresolved> {
    pub function: FunctionRef<'a, S>,
    /// Module types that name this function key. Exposure predicates are derived
    /// from this rather than stored alongside it, so a new module type only has
    /// to be classified in one place.
    pub modules: BTreeSet<ModuleKind>,
    /// Module types that name any function key sharing this function's handler,
    /// and so expose the same code. A superset of `modules`; used for questions
    /// about what the handler exposes rather than what this key is.
    pub handler_modules: BTreeSet<ModuleKind>,
}

impl<S> Entrypoint<'_, S> {
    /// Exposed by at least one module any authenticated user can reach.
    pub fn invokable(&self) -> bool {
        self.modules
            .iter()
            .copied()
            .any(ModuleKind::is_user_invokable)
    }

    pub fn web_trigger(&self) -> bool {
        self.modules.iter().copied().any(ModuleKind::is_web_trigger)
    }

    /// Exposed by a module whose resolver the platform restricts to admins.
    pub fn platform_admin_gated(&self) -> bool {
        self.modules
            .iter()
            .copied()
            .any(ModuleKind::is_platform_admin_gated)
    }

    /// This function's handler is exposed by an admin module *and* by a module
    /// any user can reach. Sharing removes the platform's admin restriction, so
    /// the functions written for the admin page become callable by anyone.
    ///
    /// Judged over `handler_modules` because apps share an admin resolver by
    /// pointing two function keys at one handler as often as by naming one key
    /// in two modules.
    pub fn shared_admin_resolver(&self) -> bool {
        self.handler_modules
            .iter()
            .copied()
            .any(ModuleKind::is_platform_admin_gated)
            && self
                .handler_modules
                .iter()
                .copied()
                .any(ModuleKind::is_user_invokable)
    }

    /// The manifest keys of every module exposing this function's handler, for
    /// reporting.
    pub fn module_keys(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.handler_modules
            .iter()
            .copied()
            .map(ModuleKind::manifest_key)
    }
}

impl<T> AsRef<T> for FunctionTy<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        match self {
            FunctionTy::Invokable(t) | FunctionTy::WebTrigger(t) => t,
        }
    }
}

impl<'a> ForgeModules<'a> {
    // TODO: function returns iterator where each item is some specified type.
    pub fn into_analyzable_functions(self) -> impl Iterator<Item = Entrypoint<'a>> {
        // destructuring ForgeModules to remember to add new modules to this
        let Self {
            mut webtriggers,
            custom_field,
            consumers,
            functions,
            event_triggers: _,
            scheduled_triggers: _,
            api_routes,
            compass_admin_page,
            component_page,
            compass_global_page,
            team_page,
            content_action,
            content_by_line_item,
            context_menu,
            confluence_global_page,
            homepage_feed,
            space_page,
            space_settings,
            macros,
            jira_admin_page,
            custom_field_type: _,
            dashboard_background_script,
            dashboard_gadget,
            jira_global_page,
            issue_action,
            issue_context,
            issue_glance,
            issue_panel,
            issue_view_background_script,
            jql_function,
            project_page,
            project_settings_page,
            ui_modifications,
            workflow_validator,
            workflow_post_function: _,
            assets_import_type,
            extra: _,
            org_panel,
            portal_footer,
            portal_header,
            portal_profile_panel,
            portal_req,
            portal_request_detail,
            portal_request_detail_panel,
            portal_request_view_action,
            portal_subheader,
            queue_page,
            portal_header_menu_action,
            rovo_agent: _,
            action,
        } = self;

        // number of webtriggers are usually low, so it's better to just sort them and reuse
        webtriggers.sort_unstable_by_key(|trigger| trigger.function);
        // Get all the Triggers and represent them as a new struct thing where "webtrigger" attribute is true
        // for all trigger things

        let mut exposures = Exposures::default();
        exposures
            .of(ModuleKind::WEB_TRIGGER)
            .extend(webtriggers.iter().map(|trigger| trigger.function));

        api_routes.append_functions(&mut exposures.of(ModuleKind::API_ROUTE));

        // Compass Module Functions

        component_page.append_functions(&mut exposures.of(ModuleKind::COMPASS_COMPONENT_PAGE));

        compass_global_page.append_functions(&mut exposures.of(ModuleKind::COMPASS_GLOBAL_PAGE));
        team_page.append_functions(&mut exposures.of(ModuleKind::COMPASS_TEAM_PAGE));

        // Confluence Module Functions
        // get user invokable modules that have additional exposure endpoints.
        // ie macros has config and export fields on top of resolver fields that are functions
        content_action.iter().for_each(|content_action| {
            content_action
                .append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_CONTENT_ACTION))
        });

        content_by_line_item.iter().for_each(|by_line_item| {
            by_line_item
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_CONTENT_BY_LINE_ITEM));
            exposures
                .of(ModuleKind::CONFLUENCE_CONTENT_BY_LINE_ITEM)
                .extend(by_line_item.dynamic_properties.function)
        });

        context_menu.append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_CONTEXT_MENU));

        confluence_global_page
            .append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_GLOBAL_PAGE));

        homepage_feed.append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_HOMEPAGE_FEED));

        space_page.append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_SPACE_PAGE));

        space_settings.append_functions(&mut exposures.of(ModuleKind::CONFLUENCE_SPACE_SETTINGS));

        for m in macros {
            m.common_keys
                .append_functions(&mut exposures.of(ModuleKind::MACRO));
            m.config
                .append_functions(&mut exposures.of(ModuleKind::MACRO));
            m.export
                .append_functions(&mut exposures.of(ModuleKind::MACRO));
        }

        // Jira Module Functions
        custom_field.into_iter().for_each(|customfield| {
            customfield
                .value
                .append_functions(&mut exposures.of(ModuleKind::JIRA_CUSTOM_FIELD));

            customfield
                .value
                .append_functions(&mut exposures.of(ModuleKind::JIRA_CUSTOM_FIELD));
            customfield
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_CUSTOM_FIELD));
        });

        dashboard_background_script
            .append_functions(&mut exposures.of(ModuleKind::JIRA_DASHBOARD_BACKGROUND_SCRIPT));

        for gadget in dashboard_gadget {
            gadget
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_DASHBOARD_GADGET));
            gadget
                .edit
                .append_functions(&mut exposures.of(ModuleKind::JIRA_DASHBOARD_GADGET));
        }

        jira_global_page.append_functions(&mut exposures.of(ModuleKind::JIRA_GLOBAL_PAGE));

        issue_action.append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_ACTION));

        for issue in issue_context {
            issue
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_CONTEXT));
            issue
                .dynamic_properties
                .append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_CONTEXT));
        }

        for issue in issue_glance {
            issue
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_GLANCE));
            issue
                .dynamic_properties
                .append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_GLANCE));
        }

        issue_panel.append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_PANEL));

        issue_view_background_script
            .append_functions(&mut exposures.of(ModuleKind::JIRA_ISSUE_VIEW_BACKGROUND_SCRIPT));

        jql_function.append_functions(&mut exposures.of(ModuleKind::JIRA_JQL_FUNCTION));

        project_page.append_functions(&mut exposures.of(ModuleKind::JIRA_PROJECT_PAGE));

        project_settings_page
            .append_functions(&mut exposures.of(ModuleKind::JIRA_PROJECT_SETTINGS_PAGE));

        for ui in ui_modifications {
            ui.common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_UI_MODIFICATIONS));
        }

        for valid in workflow_validator {
            valid
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_WORKFLOW_VALIDATOR));
        }

        // Rovo Module Functions
        // No invokable functions for Rovo Agents but Action can have numerous user invokable functions
        action.iter().for_each(|action| {
            exposures
                .of(ModuleKind::ROVO_ACTION)
                .extend(action.function);
            // "Endpoint" variant of Action not being considered as an invokable function
        });

        // JSM Module Functions
        for assets in assets_import_type {
            assets
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JSM_ASSETS_IMPORT_TYPE));

            assets
                .on_delete_import
                .append_functions(&mut exposures.of(ModuleKind::JSM_ASSETS_IMPORT_TYPE));

            assets
                .stop_import
                .append_functions(&mut exposures.of(ModuleKind::JSM_ASSETS_IMPORT_TYPE));

            assets
                .start_import
                .append_functions(&mut exposures.of(ModuleKind::JSM_ASSETS_IMPORT_TYPE));

            assets
                .import_status
                .append_functions(&mut exposures.of(ModuleKind::JSM_ASSETS_IMPORT_TYPE));
        }
        org_panel.iter().for_each(|panel| {
            panel.append_functions(&mut exposures.of(ModuleKind::JSM_ORGANIZATION_PANEL))
        });

        org_panel.append_functions(&mut exposures.of(ModuleKind::JSM_ORGANIZATION_PANEL));

        portal_footer.append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_FOOTER));
        portal_header.append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_HEADER));
        portal_profile_panel
            .append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_PROFILE_PANEL));

        portal_req.append_functions(
            &mut exposures.of(ModuleKind::JSM_PORTAL_REQUEST_CREATE_PROPERTY_PANEL),
        );

        portal_request_detail
            .append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_REQUEST_DETAIL));

        portal_request_detail_panel
            .append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_REQUEST_DETAIL_PANEL));

        portal_request_view_action
            .append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_REQUEST_VIEW_ACTION));

        portal_subheader.append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_SUBHEADER));

        portal_header_menu_action
            .append_functions(&mut exposures.of(ModuleKind::JSM_PORTAL_USER_MENU_ACTION));

        queue_page.append_functions(&mut exposures.of(ModuleKind::JSM_QUEUE_PAGE));

        compass_admin_page.append_functions(&mut exposures.of(ModuleKind::COMPASS_ADMIN_PAGE));
        for admin_page in &jira_admin_page {
            admin_page
                .common_keys
                .append_functions(&mut exposures.of(ModuleKind::JIRA_ADMIN_PAGE));
        }

        // Two function keys pointing at the same handler reach the same code, so
        // whichever modules expose either key expose that code. Apps share an admin
        // resolver this way more often than by naming one key in two modules — e.g.
        // `admin-resolver` and `import-resolver` both handled by `index.resolver`.
        let mut modules_by_handler: FxHashMap<&str, BTreeSet<ModuleKind>> = FxHashMap::default();
        for func in &functions {
            modules_by_handler
                .entry(func.handler)
                .or_default()
                .extend(exposures.modules_for(func.key));
        }

        functions.into_iter().flat_map(move |func| {
            let modules = exposures.modules_for(func.key);
            let mut handler_modules = modules.clone();
            if let Some(shared) = modules_by_handler.get(func.handler) {
                handler_modules.extend(shared.iter().copied());
            }

            Ok::<_, Error>(Entrypoint {
                function: FunctionRef::try_from(func)?,
                modules,
                handler_modules,
            })
        })
    }
}

impl<S> FunctionRef<'_, S> {
    const VALID_EXTS: [&'static str; 4] = ["jsx", "tsx", "ts", "js"];
}

impl<'a> FunctionRef<'a> {
    pub fn try_resolve<P>(
        self,
        paths: &HashSet<P>,
        working_dir: &P,
    ) -> Result<FunctionRef<'a, Resolved>, Error>
    where
        P: Borrow<Path> + Eq + Hash,
    {
        Self::VALID_EXTS
            .iter()
            .find_map(|&ext| {
                let path = working_dir.borrow().join(self.path.with_extension(ext));
                trace!(?path);
                paths.contains(&path).then_some(FunctionRef {
                    func: self.func,
                    key: self.key,
                    path,
                    status: Resolved,
                })
            })
            .ok_or_else(|| Error::FileNotFound {
                function: self.func.to_owned(),
                path: self.path.to_owned(),
            })
    }
}

impl<'a, Resolved> FunctionRef<'a, Resolved> {
    #[inline]
    pub fn into_func_path(self) -> (&'a str, PathBuf) {
        (self.func, self.path)
    }
}

impl<'a> TryFrom<FunctionMod<'a>> for FunctionRef<'a> {
    type Error = Error;

    fn try_from(func_handler: FunctionMod<'a>) -> Result<Self, Self::Error> {
        let (file, func) = func_handler
            .handler
            .splitn(2, '.')
            .collect_tuple()
            .ok_or_else(|| Error::InvalidFuncHandler(func_handler.key.to_owned()))?;
        let mut path = PathBuf::from("src");
        path.push(file);
        Ok(Self {
            func,
            key: func_handler.key,
            path,
            status: Unresolved,
        })
    }
}

fn is_hardcoded_variable(value: &str) -> bool {
    if let Some(start) = value.find("{{") {
        !(value[start + 2..].contains("}}"))
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_deserialize() {
        let json = r#"{
            "app": {
                "name": "My App",
                "id": "my-app"
            },
            "modules": {
                "macro": [
                {
                    "key": "my-macro",
                    "function": "My Macro"
                }
                ],
                "function": [
                {
                    "key": "my-function",
                    "handler": "my-function-handler",
                    "providers": {
                        "auth": ["my-auth-provider"]
                    }
                }
                ],
                "webtrigger": [
                {
                    "key": "my-webtrigger",
                    "function": "my-webtrigger-handler"
                }
                ]
            },
            "permissions": {
                "scopes": [
                    "my-scope"
                ],
                "content": {
                    "scripts": [
                        "my-script.js"
                    ],
                    "styles": [
                        "my-style.css"
                    ]
                }
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.app.name, Some("My App"));
        assert_eq!(manifest.app.id, "my-app");
        assert_eq!(manifest.modules.macros.len(), 1);
        assert_eq!(manifest.modules.macros[0].common_keys.key, "my-macro");
        // assert_eq!(manifest.modules.macros[0].function, "my-macro");
        assert_eq!(manifest.modules.functions.len(), 1);
        assert_eq!(
            manifest.modules.functions[0],
            FunctionMod {
                key: "my-function",
                handler: "my-function-handler",
                providers: Some(AuthProviders {
                    auth: vec!["my-auth-provider"]
                }),
            }
        );
    }

    #[test]
    fn test_function_handler_parsing() {
        let func_handler = FunctionMod {
            key: "my-function",
            handler: "my-function-handler.app",
            providers: Some(AuthProviders {
                auth: vec!["my-auth-provider"],
            }),
        };
        let func_ref: FunctionRef<'_> = FunctionRef::try_from(func_handler).unwrap();
        assert_eq!(
            func_ref,
            FunctionRef {
                func: "app",
                key: "my-function",
                path: "src/my-function-handler".into(),
                status: Unresolved,
            }
        );
    }

    // Modified specific deserialization schemes for modules. Checking that new schemes can deserialize function values.
    #[test]
    fn test_new_deserialize() {
        let json = r#"{
            "app": {
                "name": "My App",
                "id": "my-app"
            },
            "modules": {
                "macro": [
                {
                    "key": "my-macro",
                    "title": "My Macro",
                    "function": "Catch-me-if-you-can0", 
                    "resolver": {
                        "function": "Catch-me-if-you-can1"
                    },
                    "config": {
                        "function": "Catch-me-if-you-can2"
                    },
                    "export": {
                        "function": "Catch-me-if-you-can3"
                    }
                }
                ],
                "function": [
                {
                    "key": "my-function",
                    "handler": "my-function-handler",
                    "providers": {
                        "auth": ["my-auth-provider"]
                    }
                }
                ],
                "webtrigger": [
                {
                    "key": "my-webtrigger",
                    "function": "my-webtrigger-handler"
                }
                ]
            },
            "permissions": {
                "scopes": [
                    "my-scope"
                ],
                "content": {
                    "scripts": [
                        "my-script.js"
                    ],
                    "styles": [
                        "my-style.css"
                    ]
                }
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.modules.macros.len(), 1);
        if let Some(string) = manifest.modules.macros[0].common_keys.function {
            assert_eq!(string, "Catch-me-if-you-can0");
        }

        let Some(ref resolver) = manifest.modules.macros[0].common_keys.resolver else {
            panic!("No dice!")
        };

        if let Some(string) = resolver.function {
            assert_eq!(string, "Catch-me-if-you-can1");
        }
        if let Some(MacroConfig::Object(justfunc)) = manifest.modules.macros[0].config {
            let func = justfunc.function.unwrap();
            assert_eq!(func, "Catch-me-if-you-can2");
        } else {
            panic!("No config function found")
        }

        if let Some(justfunc) = manifest.modules.macros[0].export {
            let func = justfunc.function.unwrap();
            assert_eq!(func, "Catch-me-if-you-can3");
        }
    }

    // Test checking whether jira:adminPage gets flagged.
    #[test]
    fn test_deserialize_admin_check() {
        let json = r#"{
            "app": { "name": "My App", "id": "my-app" },
            "modules": {
                "jira:adminPage": [
                { "key": "testing-admin-tag", "function": "main1", "title": "writing-a-test-for-admin-flag" }
                ],
                "macro": [ { "key": "my-macro", "function": "main2" } ],
                "function": [
                { "key": "main1", "handler": "index.run" },
                { "key": "main2", "handler": "src.run" }
                ]
            },
            "permissions": { "scopes": ["my-scope"] }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let entries = manifest
            .modules
            .into_analyzable_functions()
            .collect::<Vec<_>>();

        let admin = &entries[0];
        assert_eq!(admin.function.key, "main1");
        assert!(admin.platform_admin_gated());
        assert!(!admin.invokable());
        assert!(!admin.shared_admin_resolver());
        assert_eq!(
            admin.module_keys().collect::<Vec<_>>(),
            vec!["jira:adminPage"]
        );

        let macro_entry = &entries[1];
        assert_eq!(macro_entry.function.key, "main2");
        assert!(macro_entry.invokable());
        assert!(!macro_entry.platform_admin_gated());
    }

    // Custom UI admin pages declare their entry point under `resolver.function`
    // instead of `function`, and must still be recognised as an admin page.
    #[test]
    fn test_deserialize_admin_resolver_check() {
        let json = r#"{
            "app": { "id": "my-app" },
            "modules": {
                "jira:adminPage": [
                    { "key": "admin", "resolver": { "function": "resolver-fn" }, "title": "admin" }
                ],
                "function": [ { "key": "resolver-fn", "handler": "index.handler" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let entry = manifest.modules.into_analyzable_functions().next().unwrap();

        assert_eq!(entry.function.key, "resolver-fn");
        assert!(entry.platform_admin_gated());
        assert!(!entry.invokable());
        assert!(!entry.shared_admin_resolver());
    }

    // A `compass:adminPage` resolver used only by the admin page is not a shared
    // resolver, even though `compass:adminPage` is itself a page users navigate to.
    #[test]
    fn test_compass_admin_page_only_resolver_is_not_shared() {
        let json = r#"{
            "app": { "id": "my-app" },
            "modules": {
                "compass:adminPage": [
                    { "key": "admin-page", "resolver": { "function": "resolver-fn" } }
                ],
                "function": [ { "key": "resolver-fn", "handler": "index.handler" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let entry = manifest.modules.into_analyzable_functions().next().unwrap();

        assert!(entry.platform_admin_gated());
        assert!(!entry.invokable());
        assert!(!entry.shared_admin_resolver());
    }

    // The documented exposure: one key named by both an admin page and another
    // module.
    #[test]
    fn test_admin_resolver_shared_with_other_module() {
        let json = r#"{
            "app": { "id": "my-app" },
            "modules": {
                "compass:adminPage": [
                    { "key": "admin-page", "resolver": { "function": "resolver-fn" } }
                ],
                "compass:globalPage": [
                    { "key": "global-page", "resolver": { "function": "resolver-fn" } }
                ],
                "function": [ { "key": "resolver-fn", "handler": "index.handler" } ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let entry = manifest.modules.into_analyzable_functions().next().unwrap();

        assert!(entry.shared_admin_resolver());
        assert_eq!(
            entry.module_keys().collect::<Vec<_>>(),
            vec!["compass:adminPage", "compass:globalPage"]
        );
    }

    // How apps actually share an admin resolver: two function keys pointing at one
    // handler. From atlassian-labs/gitlab-for-compass before PR #87, where
    // `admin-resolver` and `import-resolver` were both handled by `index.resolver`.
    #[test]
    fn test_admin_and_non_admin_keys_sharing_a_handler_are_shared() {
        let json = r#"{
            "app": { "id": "my-app" },
            "modules": {
                "compass:adminPage": [
                    { "key": "admin-page-ui", "resolver": { "function": "admin-resolver" } }
                ],
                "compass:componentPage": [
                    { "key": "import-page-ui", "resolver": { "function": "import-resolver" } }
                ],
                "function": [
                    { "key": "admin-resolver", "handler": "index.resolver" },
                    { "key": "import-resolver", "handler": "index.resolver" }
                ]
            }
        }"#;
        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let entries = manifest
            .modules
            .into_analyzable_functions()
            .collect::<Vec<_>>();

        // Both keys reach the same handler, so both are shared admin resolvers.
        for entry in &entries {
            assert!(
                entry.shared_admin_resolver(),
                "{} was not treated as a shared admin resolver",
                entry.function.key
            );
        }
    }

    // Test to check if Rovo modules can be deserialized properly from a sample manifest file.
    #[test]
    fn test_rovo_agent_deserialize() {
        let json = r#"{
            "app": {
                "runtime": {
                    "name": "nodejs18.x"
                },
                "id": "ari:cloud:ecosystem::app/test-id"
            },
            "modules": {
                "rovo:agent": [{
                    "key": "data-discoverability",
                    "name": "Data Discoverability",
                    "description": "Test description",
                    "prompt": "You are a helpful assistant that helps users manage their project risks. \nYou can retrieve risks from the risk register, create new risks and update existing ones.",
                    "conversationStarters": [
                        "starter1",
                        "starter2",
                        "starter3"
                    ],
                    "actions": [
                        "indexing-compass"
                    ]
                }],
                "action": [{
                    "key": "indexing-compass",
                    "function": "compass-fn",
                    "name": "example action",
                    "actionVerb": "GET",
                    "description": "Test action description",
                    "inputs": {
                        "data": {
                            "title": "Data",
                            "type": "string",
                            "required": true,
                            "description": "Test input description"
                        }
                    }
                }],
                "function": [{
                    "key": "compass-fn",
                    "handler": "index.compassDataProvider"
                }]
            },
            "permissions": {
                "scopes": [
                    "read:component:compass"
                ],
                "external": {
                    "fetch": {
                        "backend": [
                            "vnext-data-catalog.jira-dev.com"
                        ]
                    }
                }
            }
        }"#;

        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();

        // Verify RovoAgent
        assert_eq!(manifest.modules.rovo_agent.len(), 1);
        let agent = &manifest.modules.rovo_agent[0];
        assert_eq!(agent.key, "data-discoverability");
        assert_eq!(agent.name, "Data Discoverability");
        assert_eq!(agent.description.as_deref(), Some("Test description"));
        assert_eq!(
            agent.prompt,
            "You are a helpful assistant that helps users manage their project risks. \nYou can retrieve risks from the risk register, create new risks and update existing ones."
        );
        assert_eq!(
            agent.conversation_starters,
            vec!["starter1", "starter2", "starter3"]
        );
        assert_eq!(agent.actions, vec!["indexing-compass"]);

        // Verify Action
        assert_eq!(manifest.modules.action.len(), 1);
        let action = &manifest.modules.action[0];
        assert_eq!(action.key, "indexing-compass");
        assert_eq!(action.function, Some("compass-fn"));
        assert_eq!(action.endpoint, None);
    }

    #[test]
    fn test_permission_scopes_deserialize_from_mapping() {
        let yaml = r#"
app:
  id: my-app
modules:
  function:
    - key: functionHandler
      handler: jqlFunctions/functionProcessor.handleFunction
permissions:
  scopes:
    read:jira-work: &id001
      allowImpersonation: true
    write:jira-work: *id001
"#;

        let manifest: ForgeManifest<'_> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            manifest.permissions.scopes,
            vec!["read:jira-work".to_string(), "write:jira-work".to_string()]
        );
    }

    // Test to check if hardcoded secrets are detected properly in OAuth2 Provider
    #[test]
    fn test_oauth_provider_hardcoded_secrets() {
        let json = r#"{
            "app": {
                "name": "My App",
                "id": "ari:cloud:ecosystem::app/test-id"
            },
            "modules": {},
            "permissions": {
                "scopes": []
            },
            "providers": {
                "auth": [
                    {
                        "key": "oauth-provider-1",
                        "actions": {
                            "authorization": {
                                "queryParameters": {
                                    "client_id": "{{client_id}}",
                                    "client_secret": "hardcoded_secret_value"
                                }
                            },
                            "exchange": {
                                "overrides": {
                                    "headers": {
                                        "Authorization": "Bearer hardcoded_token_value"
                                    },
                                    "body": {
                                        "api_key": "{{api_key}}",
                                        "password": "hardcoded_password_value"
                                    }
                                }
                            },
                            "refresh": {
                                "overrides": {
                                    "headers": {
                                        "refresh-token": "hardcoded_token_value"
                                    },
                                    "body": {
                                        "client_secret": "hardcoded_refresh_secret_value"
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }"#;

        let manifest: ForgeManifest<'_> = serde_json::from_str(json).unwrap();
        let providers = manifest.providers.unwrap();
        let auth_providers = providers.auth.unwrap();

        let mut secrets_found = Vec::new();
        for provider in auth_providers {
            let findings = provider.find_hardcoded_secrets();
            secrets_found.extend(findings);
        }

        let secrets_expected = vec![
            "providers.auth[oauth-provider-1].actions.authorization.queryParams.client_secret"
                .to_string(),
            "providers.auth[oauth-provider-1].actions.exchange.overrides.headers.Authorization"
                .to_string(),
            "providers.auth[oauth-provider-1].actions.exchange.overrides.body.password".to_string(),
            "providers.auth[oauth-provider-1].actions.refresh.overrides.headers.refresh-token"
                .to_string(),
            "providers.auth[oauth-provider-1].actions.refresh.overrides.body.client_secret"
                .to_string(),
        ];

        assert_eq!(secrets_found, secrets_expected);

        assert!(!is_hardcoded_variable(
            "Basic {{http_basic_auth_credentials}}",
        ));
        assert!(!is_hardcoded_variable("{{prefix}}_{{suffix}}"));
        assert!(!is_hardcoded_variable("     {{client_secret}}     "));
    }
}
