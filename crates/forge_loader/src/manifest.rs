use std::{
    borrow::Borrow,
    collections::HashSet,
    hash::Hash,
    path::{Path, PathBuf},
};

use crate::Error;
use forge_utils::FxHashMap;
use itertools::Itertools;
use serde::Deserialize;
use serde_json::map::Iter;
use tracing::{info, trace};

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuthProviders<'a> {
    #[serde(borrow)]
    auth: Vec<&'a str>,
}

// Abstracting away key, function, and resolver into a single struct for reuse whoo!
// And helper functions for ease of use
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct CommonKey<'a> {
    key: &'a str,
    function: Option<&'a str>,
    resolver: Option<Resolver<'a>>,
}

impl<'a> CommonKey<'a> {
    fn append_functions<I: Extend<&'a str>>(&self, funcs: &mut I) {
        funcs.extend(self.function);

        if let Some(Resolver {
            function,
            method,
            endpoint,
        }) = self.resolver
        {
            funcs.extend(function);
        }
    }
}
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Resolver<'a> {
    pub function: Option<&'a str>,
    pub method: Option<&'a str>,
    pub endpoint: Option<&'a str>,
}

// Implementing a struct for structs with 1 value (function)

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JustFunc<'a> {
    pub function: Option<&'a str>,
}

// Common Modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FunctionMod<'a> {
    key: &'a str,
    handler: &'a str,
    #[serde(borrow)]
    providers: Option<AuthProviders<'a>>,
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
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
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

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MacroMod<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    config: Option<JustFunc<'a>>,
    export: Option<JustFunc<'a>>,
}

// Jira Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
    #[serde(rename = "contentByLineItem", default, borrow)]
    content_by_line_item: Vec<ContentByLineItem<'a>>,
    #[serde(rename = "jira:issueGlance", default, borrow)]
    issue_glance: Vec<IssueGlance<'a>>,
    #[serde(rename = "jira:accessImportType", default, borrow)]
    access_import_type: Vec<AccessImportType<'a>>,
    // deserializing user invokable module functions
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
struct Content<'a> {
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
pub struct Entrypoint<'a> {
    function: &'a str,
    invokable: bool,
    web_trigger: bool,
}

impl<'a> ForgeModules<'a> {
    // TODO: function returns iterator where each item is some specified type.
    pub fn into_analyzable_functions(self) -> impl Iterator<Item = Entrypoint<'a>> {
        // destructuring ForgeModules to remember to add new modules to this
        let Self {
            mut webtriggers,
            ref custom_field,
            consumers: _,
            ref functions,
            event_triggers: _,
            scheduled_triggers: _,
            ref compass_admin_page,
            ref component_page,
            ref compass_global_page,
            ref team_page,
            ref content_action,
            ref content_by_line_item,
            ref context_menu,
            ref confluence_global_page,
            ref homepage_feed,
            ref space_page,
            ref space_settings,
            ref macros,
            ref jira_admin_page,
            ref custom_field_type,
            ref dashboard_background_script,
            ref dashboard_gadget,
            ref jira_global_page,
            ref issue_action,
            ref issue_context,
            ref issue_glance,
            ref issue_panel,
            ref issue_view_background_script,
            ref jql_function,
            ref project_page,
            ref project_settings_page,
            ref ui_modifications,
            ref workflow_validator,
            ref workflow_post_function,
            ref assets_import_type,
            extra: _,
            ref org_panel,
            ref portal_footer,
            ref portal_header,
            ref portal_profile_panel,
            ref portal_req,
            ref portal_request_detail,
            ref portal_request_detail_panel,
            ref portal_request_view_action,
            ref portal_subheader,
            ref queue_page,
            ref portal_header_menu_action,
        } = self;

        // number of webtriggers are usually low, so it's better to just sort them and reuse
        self.webtriggers
            .sort_unstable_by_key(|trigger| trigger.function);
        let mut invokable_functions = BTreeSet::new();

        // Compass Module Functions
        compass_admin_page
            .iter()
            .for_each(|compass_admin| compass_admin.append_functions(&mut invokable_functions));

        component_page
            .iter()
            .for_each(|component_page| component_page.append_functions(&mut invokable_functions));

        compass_global_page
            .iter()
            .for_each(|global_page| global_page.append_functions(&mut invokable_functions));

        team_page
            .iter()
            .for_each(|team_page| team_page.append_functions(&mut invokable_functions));

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

        context_menu
            .iter()
            .for_each(|context_menu| context_menu.append_functions(&mut invokable_functions));

        confluence_global_page
            .iter()
            .for_each(|global_page| global_page.append_functions(&mut invokable_functions));

        homepage_feed
            .iter()
            .for_each(|homepage_feed| homepage_feed.append_functions(&mut invokable_functions));

        space_page
            .iter()
            .for_each(|space_page| space_page.append_functions(&mut invokable_functions));

        space_settings
            .iter()
            .for_each(|space_settings| space_settings.append_functions(&mut invokable_functions));

        macros.clone().iter().for_each(|mac| {
            self.clone()
                .add_optional(mac.config, &mut invokable_functions);
            self.clone()
                .add_optional(mac.export, &mut invokable_functions);
            mac.common_keys.append_functions(&mut invokable_functions);
        });

        // Jira module functons
        custom_field.iter().for_each(|customfield| {
            self.clone()
                .add_optional(customfield.value, &mut invokable_functions);

            self.clone()
                .add_optional(customfield.edit, &mut invokable_functions);

            customfield
                .common_keys
                .append_functions(&mut invokable_functions);
        });

        custom_field_type.iter().for_each(|custom_field_type| {
            // invokable_functions.extend(custom_field_type.value);
            self.clone()
                .add_optional(custom_field_type.value, &mut invokable_functions);

            // invokable_functions.extend(custom_field_type.edit);
            self.clone()
                .add_optional(custom_field_type.edit, &mut invokable_functions);

            // invokable_functions.extend(custom_field_type.context_config);
            self.clone()
                .add_optional(custom_field_type.context_config, &mut invokable_functions);

            custom_field_type
                .common_keys
                .append_functions(&mut invokable_functions);
        });

        dashboard_background_script
            .iter()
            .for_each(|dbs| dbs.append_functions(&mut invokable_functions));

        dashboard_gadget.iter().for_each(|gadget| {
            // invokable_functions.extend(gadget.edit);
            self.clone()
                .add_optional(gadget.edit, &mut invokable_functions);

            gadget
                .common_keys
                .append_functions(&mut invokable_functions)
        });

        jira_global_page
            .iter()
            .for_each(|global_page| global_page.append_functions(&mut invokable_functions));

        issue_action
            .iter()
            .for_each(|issue| issue.append_functions(&mut invokable_functions));

        issue_context.iter().for_each(|issue| {
            self.clone()
                .add_optional(issue.dynamic_properties, &mut invokable_functions);

            issue.common_keys.append_functions(&mut invokable_functions)
        });

        issue_glance.iter().for_each(|issue| {
            issue.common_keys.append_functions(&mut invokable_functions);
            self.clone()
                .add_optional(issue.dynamic_properties, &mut invokable_functions);
        });

        issue_panel
            .iter()
            .for_each(|issue| issue.append_functions(&mut invokable_functions));

        issue_view_background_script
            .iter()
            .for_each(|issue| issue.append_functions(&mut invokable_functions));

        jql_function
            .iter()
            .for_each(|item| item.append_functions(&mut invokable_functions));

        project_page
            .iter()
            .for_each(|item| item.append_functions(&mut invokable_functions));

        project_settings_page
            .iter()
            .for_each(|item| item.append_functions(&mut invokable_functions));

        ui_modifications.iter().for_each(|ui| {
            ui.common_keys.append_functions(&mut invokable_functions);
        });

        workflow_validator.iter().for_each(|validator| {
            validator
                .common_keys
                .append_functions(&mut invokable_functions)
        });

        workflow_post_function.iter().for_each(|post_function| {
            post_function
                .common_keys
                .append_functions(&mut invokable_functions);
        });

        // JSM modules
        assets_import_type.iter().for_each(|access| {
            access
                .common_keys
                .append_functions(&mut invokable_functions);
            // let Some(func) = access.on_delete_import;
            // invokable_functions.extend(func.function);
            self.clone()
                .add_optional(access.on_delete_import, &mut invokable_functions);

            invokable_functions.extend(access.stop_import.function);
            invokable_functions.extend(access.start_import.function);
            invokable_functions.extend(access.import_status.function);
        });
        org_panel
            .iter()
            .for_each(|panel| panel.append_functions(&mut invokable_functions));

        portal_footer
            .iter()
            .for_each(|footer| footer.append_functions(&mut invokable_functions));

        portal_header
            .iter()
            .for_each(|header| header.append_functions(&mut invokable_functions));

        portal_profile_panel
            .iter()
            .for_each(|profile| profile.append_functions(&mut invokable_functions));

        portal_req
            .iter()
            .for_each(|req| req.append_functions(&mut invokable_functions));

        portal_request_detail
            .iter()
            .for_each(|req| req.append_functions(&mut invokable_functions));

        portal_request_detail_panel
            .iter()
            .for_each(|req| req.append_functions(&mut invokable_functions));

        portal_request_view_action
            .iter()
            .for_each(|req| req.append_functions(&mut invokable_functions));

        portal_subheader
            .iter()
            .for_each(|subheader| subheader.append_functions(&mut invokable_functions));
        portal_header_menu_action
            .iter()
            .for_each(|action| action.append_functions(&mut invokable_functions));

        queue_page
            .iter()
            .for_each(|page| page.append_functions(&mut invokable_functions));

        functions.into_iter().flat_map(move |func| {
            let web_trigger = webtriggers
                .binary_search_by_key(&func.key, |trigger| &trigger.function)
                .is_ok();
            let invokable = invokable_functions.contains(func.key);
            // this checks whether the funton being scanned is being used in an admin module. Rn it only checks for jira_admin page module.
            // optionally: compass:adminPage could also be considered.
            let admin = jira_admin_page.iter().any(|admin_function| {
                let Some(string) = admin_function.common_keys.function else {
                    return false;
                };
                return string == func.key;
            }) || compass_admin_page.iter().any(|admin_function| {
                let Some(string) = admin_function.function else {
                    return false;
                };
                return string == func.key;
            });

            Ok::<_, Error>(Entrypoint {
                function: FunctionRef::try_from(func)?,
                invokable,
                web_trigger,
                admin,
            })
        })
    }

    pub fn add_optional(self, optional: Option<JustFunc<'a>>, iter: &mut BTreeSet<&str>) {
        let Some(func) = optional;
        iter.extend(func.function);
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

impl<'a> TryFrom<FunctionMod<'a>> for &'a FunctionRef<'a> {
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
        let manifest: ForgeManifest = serde_json::from_str(json).unwrap();
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
        let func_ref: FunctionRef = func_handler.try_into().unwrap();
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
                    "resolver": [
                        "function": "Catch-me-if-you-can1", 
                    ]
                    "config": "Catch-me-if-you-can2",
                    "export": "Catch-me-if-you-can3"
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
        let manifest: ForgeManifest = serde_json::from_str(json).unwrap();
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
            let Some(func) = justfunc.function;
            assert_eq!(func, "Catch-me-if-you-can2");
        }

        if let Some(justfunc) = manifest.modules.macros[0].export {
            let Some(func) = justfunc.function;
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
        let manifest: ForgeManifest = serde_json::from_str(json).unwrap();
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
