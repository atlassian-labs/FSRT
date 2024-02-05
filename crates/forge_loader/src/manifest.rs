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
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DataProvider<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    callback: JustFunc<'a>,
}

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
    #[serde(borrow)]
    dynamic_properties: JustFunc<'a>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct MacroMod<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    config: JustFunc<'a>,
    export: JustFunc<'a>,
}

// Jira Modules
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JiraAdminPage<'a> {
    key: &'a str,
    function: &'a str,
    title: &'a str,
    resolver: Resolver<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CustomField<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    value: Option<&'a str>,
    search_suggestions: Option<&'a str>,
    edit: Option<&'a str>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct IssueGlance<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    dynamic_properties: JustFunc<'a>,
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
struct AssetsImportType<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    one_delete_import: JustFunc<'a>,
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
    #[serde(rename = "compass:dataProvider", default, borrow)]
    pub data_provider: Vec<DataProvider<'a>>,
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
    context_action: Vec<CommonKey<'a>>,
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
    #[serde(rename = "jira:customField", default, borrow)]
    pub custom_field: Vec<CustomField<'a>>,
    #[serde(rename = "jira:issueGlance", default, borrow)]
    issue_glance: Vec<IssueGlance<'a>>,
    #[serde(rename = "jira:uiModificatons", default, borrow)]
    pub ui_modifications: Vec<UiModificatons<'a>>,
    #[serde(rename = "jira:workflowValidator", default, borrow)]
    pub workflow_validator: Vec<WorkflowValidator<'a>>,
    #[serde(rename = "jira:workflowPostFunction", default, borrow)]
    pub workflow_post_function: Vec<WorkflowPostFunction<'a>>,
    // Jira Service Management Modules
    #[serde(rename = "jiraServiceManagement:assetsImportType", default, borrow)]
    access_import_type: Vec<AssetsImportType<'a>>,
    // deserializing admin pages
    #[serde(rename = "jira:adminPage", default, borrow)]
    pub jira_admin_page: Vec<JiraAdminPage<'a>>,
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
    pub fn into_analyzable_functions(mut self) -> impl Iterator<Item = Entrypoint<'a>> {
        // number of webtriggers are usually low, so it's better to just sort them and reuse
        self.webtriggers
            .sort_unstable_by_key(|trigger| trigger.function);
        let mut invokable_functions = BTreeSet::new();

        // Compass Module Functions
        self.compass_admin_page
            .iter()
            .for_each(|compass_admin| compass_admin.append_functions(&mut invokable_functions));

        self.component_page
            .iter()
            .for_each(|component_page| component_page.append_functions(&mut invokable_functions));

        self.data_provider.iter().for_each(|dataprovider| {
            invokable_functions.extend(dataprovider.callback.function);
        });

        self.compass_global_page
            .iter()
            .for_each(|global_page| global_page.append_functions(&mut invokable_functions));

        self.team_page
            .iter()
            .for_each(|team_page| team_page.append_functions(&mut invokable_functions));

        // Confluence Module Functions
        // get user invokable modules that have additional exposure endpoints.
        // ie macros has config and export fields on top of resolver fields that are functions
        self.content_action
            .iter()
            .for_each(|content_action| content_action.append_functions(&mut invokable_functions));

        self.content_by_line_item.iter().for_each(|by_line_item| {
            by_line_item
                .common_keys
                .append_functions(&mut invokable_functions);
            invokable_functions.extend(by_line_item.dynamic_properties.function)
        });

        self.macros.iter().for_each(|macros| {
            macros
                .common_keys
                .append_functions(&mut invokable_functions);

            invokable_functions.extend(macros.config.function);
            invokable_functions.extend(macros.export.function);
        });

        self.access_import_type.iter().for_each(|access| {
            access
                .common_keys
                .append_functions(&mut invokable_functions);
            invokable_functions.extend(access.one_delete_import.function);
            invokable_functions.extend(access.stop_import.function);
            invokable_functions.extend(access.start_import.function);
            invokable_functions.extend(access.import_status.function);
        });

        // Jira module functons
        self.custom_field.iter().for_each(|customfield| {
            invokable_functions.extend(customfield.value);
            invokable_functions.extend(customfield.search_suggestions);
            invokable_functions.extend(customfield.edit);
            customfield
                .common_keys
                .append_functions(&mut invokable_functions);
        });
        self.issue_glance.iter().for_each(|issue| {
            issue.common_keys.append_functions(&mut invokable_functions);
            invokable_functions.extend(issue.dynamic_properties.function);
        });

        self.ui_modifications.iter().for_each(|ui| {
            ui.common_keys.append_functions(&mut invokable_functions);
        });

        self.workflow_validator.iter().for_each(|validator| {
            validator
                .common_keys
                .append_functions(&mut invokable_functions)
        });

        self.workflow_post_function
            .iter()
            .for_each(|post_function| {
                post_function
                    .common_keys
                    .append_functions(&mut invokable_functions);
            });

        self.functions.into_iter().flat_map(move |func| {
            let web_trigger = self
                .webtriggers
                .binary_search_by_key(&func.key, |trigger| &trigger.function)
                .is_ok();
            let invokable = invokable_functions.contains(func.key);
            // this checks whether the funton being scanned is being used in an admin module. Rn it only checks for jira_admin page module.
            // optionally: compass:adminPage could also be considered.
            let admin = self
                .jira_admin_page
                .iter()
                .any(|admin_function| admin_function.function == func.key);
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
        if let Some(func) = manifest.modules.macros[0].config {
            assert_eq!(func, "Catch-me-if-you-can2");
        }

        if let Some(func) = manifest.modules.macros[0].export {
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
