use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashSet},
    hash::Hash,
    path::{Path, PathBuf},
};

use crate::Error;
use forge_utils::FxHashMap;
use itertools::Itertools;
use serde::Deserialize;
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Consumer<'a> {
    key: &'a str,
    queue: &'a str,
    #[serde(borrow)]
    pub resolver: Resolver<'a>,
}

// Trigger Modules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Interval {
    Hour,
    Day,
    Week,
}

// Maps to Scheduled Trigger under Common Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScheduledTrigger<'a> {
    #[serde(flatten, borrow)]
    raw: RawTrigger<'a>,
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
    #[serde(flatten, borrow)]
    raw: RawTrigger<'a>,
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

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct MacroMod<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    config: Option<JustFunc<'a>>,
    export: Option<JustFunc<'a>>,
}

// Jira Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Copy)]
pub struct JiraAdminPage<'a> {
    title: &'a str,
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
    // Compass Modules
    #[serde(rename = "compass:adminPage", default, borrow)]
    compass_admin_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:componentPage", default, borrow)]
    component_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:globalPage", default, borrow)]
    compass_global_page: Vec<CommonKey<'a>>,
    #[serde(rename = "compass:teamPage", default, borrow)]
    team_page: Vec<CommonKey<'a>>,
    // confluence Modules
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
    // jira modules
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
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, borrow)]
    content: Content<'a>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Remotes {
    #[serde(default)]
    pub auth: Value,
}

impl Remotes {
    pub fn contains_auth(self) -> bool {
        self.auth.is_mapping()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AppInfo<'a> {
    pub name: Option<&'a str>,
    pub id: &'a str,
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
    #[serde(borrow)]
    pub permissions: Perms<'a>,
    pub remotes: Option<Vec<Remotes>>,
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

// Struct used for tracking what scan a funtcion requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrypoint<'a, S = Unresolved> {
    pub function: FunctionRef<'a, S>,
    pub invokable: bool,
    pub web_trigger: bool,
    pub admin: bool,
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
            consumers: _,
            functions,
            event_triggers: _,
            scheduled_triggers: _,
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
            custom_field_type,
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
            workflow_post_function,
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
        } = self;

        // number of webtriggers are usually low, so it's better to just sort them and reuse
        webtriggers.sort_unstable_by_key(|trigger| trigger.function);
        // Get all the Triggers and represent them as a new struct thing where "webtrigger" attribute is true
        // for all trigger things

        let mut invokable_functions = BTreeSet::new();

        // Compass Module Functions
        compass_admin_page.append_functions(&mut invokable_functions);

        component_page.append_functions(&mut invokable_functions);

        compass_global_page.append_functions(&mut invokable_functions);
        team_page.append_functions(&mut invokable_functions);

        // Confluence Module Functions
        // get user invokable modules that have additional exposure endpoints.
        // ie macros has config and export fields on top of resolver fields that are functions
        content_action
            .iter()
            .for_each(|content_action| content_action.append_functions(&mut invokable_functions));

        content_by_line_item.iter().for_each(|by_line_item| {
            by_line_item
                .common_keys
                .append_functions(&mut invokable_functions);
            invokable_functions.extend(by_line_item.dynamic_properties.function)
        });

        context_menu.append_functions(&mut invokable_functions);

        confluence_global_page.append_functions(&mut invokable_functions);

        homepage_feed.append_functions(&mut invokable_functions);

        space_page.append_functions(&mut invokable_functions);

        space_settings.append_functions(&mut invokable_functions);

        for m in macros {
            m.common_keys.append_functions(&mut invokable_functions);
            m.config.append_functions(&mut invokable_functions);
            m.export.append_functions(&mut invokable_functions);
        }

        // Jira module functons
        custom_field.into_iter().for_each(|customfield| {
            customfield.value.append_functions(&mut invokable_functions);

            customfield.value.append_functions(&mut invokable_functions);
            customfield
                .common_keys
                .append_functions(&mut invokable_functions);
        });

        custom_field_type.into_iter().for_each(|custom_field_type| {
            custom_field_type
                .common_keys
                .append_functions(&mut invokable_functions);

            custom_field_type
                .edit
                .append_functions(&mut invokable_functions);
            custom_field_type
                .context_config
                .append_functions(&mut invokable_functions);

            custom_field_type
                .value
                .append_functions(&mut invokable_functions);
        });

        dashboard_background_script.append_functions(&mut invokable_functions);

        for gadget in dashboard_gadget {
            gadget
                .common_keys
                .append_functions(&mut invokable_functions);
            gadget.edit.append_functions(&mut invokable_functions);
        }

        jira_global_page.append_functions(&mut invokable_functions);

        issue_action.append_functions(&mut invokable_functions);

        for issue in issue_context {
            issue.common_keys.append_functions(&mut invokable_functions);
            issue
                .dynamic_properties
                .append_functions(&mut invokable_functions);
        }

        for issue in issue_glance {
            issue.common_keys.append_functions(&mut invokable_functions);
            issue
                .dynamic_properties
                .append_functions(&mut invokable_functions);
        }

        issue_panel.append_functions(&mut invokable_functions);

        issue_view_background_script.append_functions(&mut invokable_functions);

        jql_function.append_functions(&mut invokable_functions);

        project_page.append_functions(&mut invokable_functions);

        project_settings_page.append_functions(&mut invokable_functions);

        for ui in ui_modifications {
            ui.common_keys.append_functions(&mut invokable_functions);
        }

        for valid in workflow_validator {
            valid.common_keys.append_functions(&mut invokable_functions);
        }

        for post in workflow_post_function {
            post.common_keys.append_functions(&mut invokable_functions);
        }

        // JSM modules
        for assets in assets_import_type {
            assets
                .common_keys
                .append_functions(&mut invokable_functions);

            assets
                .on_delete_import
                .append_functions(&mut invokable_functions);

            assets
                .stop_import
                .append_functions(&mut invokable_functions);

            assets
                .start_import
                .append_functions(&mut invokable_functions);

            assets
                .import_status
                .append_functions(&mut invokable_functions);
        }
        org_panel
            .iter()
            .for_each(|panel| panel.append_functions(&mut invokable_functions));

        org_panel.append_functions(&mut invokable_functions);

        portal_footer.append_functions(&mut invokable_functions);
        portal_header.append_functions(&mut invokable_functions);
        portal_profile_panel.append_functions(&mut invokable_functions);

        portal_req.append_functions(&mut invokable_functions);

        portal_request_detail.append_functions(&mut invokable_functions);

        portal_request_detail_panel.append_functions(&mut invokable_functions);

        portal_request_view_action.append_functions(&mut invokable_functions);

        portal_subheader.append_functions(&mut invokable_functions);

        portal_header_menu_action.append_functions(&mut invokable_functions);

        queue_page.append_functions(&mut invokable_functions);

        functions.into_iter().flat_map(move |func| {
            let web_trigger = webtriggers
                .binary_search_by_key(&func.key, |trigger| trigger.function)
                .is_ok();
            let invokable = invokable_functions.contains(func.key);
            // this checks whether the funton being scanned is being used in an admin module. Rn it only checks for jira_admin page module.
            // optionally: compass:adminPage could also be considered.
            let admin = jira_admin_page
                .iter()
                .any(|admin_function| admin_function.common_keys.function == Some(func.key))
                || compass_admin_page
                    .iter()
                    .any(|admin_function| admin_function.function == Some(func.key));

            Ok::<_, Error>(Entrypoint {
                function: FunctionRef::try_from(func)?,
                invokable,
                web_trigger,
                admin,
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
        if let Some(justfunc) = manifest.modules.macros[0].config {
            let func = justfunc.function.unwrap();
            assert_eq!(func, "Catch-me-if-you-can2");
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
            "app": {
                "name": "My App",
                "id": "my-app"
            },
            "modules": {
                "jira:adminPage": [
                {
                    "key": "testing-admin-tag",
                    "function": "main1",
                    "title": "writing-a-test-for-admin-flag"
                }
                ],
                "macro": [
                {
                    "key": "my-macro",
                    "function": "main2"
                }
                ],
                "function": [
                {
                    "key": "main1",
                    "handler": "index.run"
                },
                {
                    "key": "main2",
                    "handler": "src.run"
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
        let mut admin_func = manifest.modules.into_analyzable_functions();

        assert_eq!(
            admin_func.next(),
            Some(Entrypoint {
                function: FunctionRef::try_from(FunctionMod {
                    key: "main1",
                    handler: "index.run",
                    providers: None,
                })
                .unwrap(),
                invokable: false,
                web_trigger: false,
                admin: true
            })
        );

        assert_eq!(
            admin_func.next(),
            Some(Entrypoint {
                function: FunctionRef::try_from(FunctionMod {
                    key: "main2",
                    handler: "src.run",
                    providers: None,
                })
                .unwrap(),
                invokable: true,
                web_trigger: false,
                admin: false
            })
        );
    }
}
