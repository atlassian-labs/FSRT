use std::{
    borrow::Borrow,
    collections::{HashSet},
    hash::Hash,
    path::{Path, PathBuf}, str::pattern::SearchStep,
};

use crate::{forgepermissions::ForgePermissions, Error};
use forge_utils::FxHashMap;
use itertools::{Either, Itertools};
use serde::Deserialize;
use std::collections::BTreeMap;
use tracing::trace;

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct AuthProviders<'a> {
    #[serde(borrow)]
    auth: Vec<&'a str>,
}
// Maps the Functions Module in common Modules 
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FunctionMod<'a> {
    key: &'a str,
    handler: &'a str,
    #[serde(borrow)]
    providers: Option<AuthProviders<'a>>,
}

// Abstracting away key, function, and resolver into a single struct for reuse whoo!
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct CommonKey<'a> {
    key: &'a str,
    function: &'a str,
    resolver: Option<&'a str>,

}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct MacroMod<'a> { 
    #[serde(flatten, borrow)] 
    common_keys: CommonKey<'a>,
    config: Option<&'a str>,
    export: Option<&'a str>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContentByLineItem<'a> { 
    #[serde(flatten, borrow)] 
    common_keys: CommonKey<'a>,
    #[serde(borrow)] 
    dynamic_properties: Option<&'a str>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct IssueGlance<'a> { 
    #[serde(flatten, borrow)] 
    common_keys: CommonKey<'a>,
    dynamic_properties: Option<&'a str>,

}
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct AccessImportType<'a> { 
    #[serde(flatten, borrow)] 
    common_keys: CommonKey<'a>,
    one_delete_import: Option<&'a str>,
    start_import: Option<&'a str>,
    stop_import: Option<&'a str>,
    import_status: Option<&'a str>,

}

// WebTrigger => RawTrigger; WHY IS THIS NAMED DIFFERENTLY !? WHO CHANGED NAMES 
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawTrigger<'a> {
    key: &'a str,
    function: &'a str,
}

// Trigger => EventTriger; WHY IS THIS NAMED DIFFERENTLY !? WHO CHANGED NAMES 
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EventTrigger<'a> {
    #[serde(flatten, borrow)]
    raw: RawTrigger<'a>,
    #[serde(borrow)]
    events: Vec<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Interval {
    Hour,
    Day,
    Week,
}

// Thank you to whomeever kept this one the same. T.T 
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScheduledTrigger<'a> {
    #[serde(flatten, borrow)]
    raw: RawTrigger<'a>,
    interval: Interval,
}

// compass DataProvider module
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DataProvider<'a> {
    #[serde(flatten, borrow)]
    key: &'a str,    
    callback: Option<&'a str>,
}

// Struct for Custom field Module. Check that search suggestion gets read in correctly. 
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CustomField<'a> { 
    // all attributes below involve function calls
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>,
    value: Option<&'a str>,
    search_suggestions: Option<&'a str>,
    edit: Option<&'a str>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UiModificatons<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowValidator<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowPostFunction<'a> {
    #[serde(flatten, borrow)]
    common_keys: CommonKey<'a>
}

// Add more structs here for deserializing forge modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForgeModules<'a> {
    #[serde(rename = "macro", default, borrow)]
    macros: Vec<MacroMod<'a>>,
    #[serde(rename = "function", default, borrow)]
    pub functions: Vec<FunctionMod<'a>>,
    #[serde(rename = "contentByLineItem", default, borrow)]
    content_by_line_item: Vec<ContentByLineItem<'a>>,
    #[serde(rename = "jira:issueGlance", default, borrow)]
    issue_glance: Vec<IssueGlance<'a>>,
    #[serde(rename = "jira:accessImportType", default, borrow)]
    access_import_type: Vec<AccessImportType<'a>>,
    // deserializing non user-invocable modules
    #[serde(rename = "webtrigger", default, borrow)]
    webtriggers: Vec<RawTrigger<'a>>,
    #[serde(rename = "trigger", default, borrow)]
    event_triggers: Vec<EventTrigger<'a>>,
    #[serde(rename = "scheduledTrigger", default, borrow)]
    scheduled_triggers: Vec<ScheduledTrigger<'a>>,
    #[serde(rename = "consumer", default, borrow)]
    pub consumers: Vec<Consumer<'a>>,
    #[serde(rename = "compass:dataProvider", default, borrow)]
    pub data_provider: Vec<DataProvider<'a>>,
    #[serde(rename = "jira:customField", default, borrow)]
    pub custom_field: Vec<CustomField<'a>>,
    #[serde(rename = "jira:uiModificatons", default, borrow)]
    pub ui_modifications: Vec<UiModificatons<'a>>,
    #[serde(rename = "jira:workflowValidator", default, borrow)]
    pub workflow_validator: Vec<WorkflowValidator<'a>>,
    #[serde(rename = "jira:workflowPostFunction", default, borrow)]
    pub workflow_post_function: Vec<WorkflowPostFunction<'a>>,
    // deserializing user invokable module functions
    #[serde(rename = "compass:dataProvider", default, borrow)]
    pub data_provider: Vec<DataProvider<'a>>,
    #[serde(rename = "jira:customField", default, borrow)]
    pub custom_field: Vec<CustomField<'a>>,
    #[serde(rename = "jira:uiModificatons", default, borrow)]
    pub ui_modifications: Vec<UiModificatons<'a>>,
    #[serde(rename = "jira:workflowValidator", default, borrow)]
    pub workflow_validator: Vec<WorkflowValidator<'a>>,
    #[serde(rename = "jira:workflowPostFunction", default, borrow)]
    pub workflow_post_function: Vec<WorkflowPostFunction<'a>>,
    // deserializing user invokable module functions
    #[serde(flatten)]
    extra: FxHashMap<String, Vec<Module<'a>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Consumer<'a> {
    key: &'a str,
    queue: &'a str,
    #[serde(borrow)]
    pub resolver: Resolver<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Resolver<'a> {
    pub function: &'a str,
    method: Option<&'a str>,
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

// Struct used for tracking what scan a funtion requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrypoint<'a> {
    pub function: &'a str,
    pub invokable: bool,
    pub web_trigger: bool,
}


// Helper functions that help filter out which functions are what. 
impl<T> FunctionTy<T> {
    pub fn map<O>(self, f: impl FnOnce(T) -> O) -> FunctionTy<O> {
        match self {
            Self::Invokable(t) => FunctionTy::Invokable(f(t)),
            Self::WebTrigger(t) => FunctionTy::WebTrigger(f(t)),
        }
    }

//     #[inline]
//     pub fn into_inner(self) -> T {
//         match self {
//             FunctionTy::Invokable(t) | FunctionTy::WebTrigger(t) => t,
//         }
//     }

//     pub fn sequence<I: IntoIterator>(
//         self,
//         f: impl FnOnce(T) -> I,
//     ) -> impl Iterator<Item = FunctionTy<I::Item>> {
//         match self {
//             Self::Invokable(t) => Either::Left(f(t).into_iter().map(FunctionTy::Invokable)),
//             Self::WebTrigger(t) => Either::Right(f(t).into_iter().map(FunctionTy::WebTrigger)),
//         }
//     }
// }

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
    pub fn into_analyzable_functions (
        &mut self,
    ) -> BTreeMap<&'a str, Entrypoint<'a>>{
        // number of webtriggers are usually low, so it's better to just sort them and reuse
        self.webtriggers.sort_unstable_by_key(|trigger| trigger.function);

        // Get all the Triggers and represent them as a new struct thing where "webtrigger" attribute is true 
        // for all trigger things 

        let mut functions_to_scan = BTreeMap::new();

        // Get all functions for module from manifest.yml 
         self.functions.iter().for_each(|func| {
            functions_to_scan.insert(func.key, Entrypoint {
                function: func.key,
                invokable: false,
                web_trigger: false,
            });
            
        });


        self.webtriggers.iter().for_each(|webtriggers| {
            if functions_to_scan.contains_key(webtriggers.function) {
                if let Some(entry) = functions_to_scan.get_mut(webtriggers.function) {
                    entry.web_trigger = true;
                }   
            }
            
        });

        self.webtriggers.iter().for_each(|webtriggers| {
            if functions_to_scan.contains_key(webtriggers.function) {
                if let Some(entry) = functions_to_scan.get_mut(webtriggers.function) {
                    entry.web_trigger = true;
                }   
            }
            
        });


        self.event_triggers.iter().for_each(|event_triggers| {
            if functions_to_scan.contains_key(event_triggers.raw.function) {
                if let Some(entry) = functions_to_scan.get_mut(event_triggers.raw.function) {
                    entry.web_trigger = true;
                }   
            }
        });
        self.scheduled_triggers.iter().for_each(|schedule_triggers| {
            if functions_to_scan.contains_key(schedule_triggers.raw.function) {
                if let Some(entry) = functions_to_scan.get_mut(schedule_triggers.raw.function) {
                    entry.web_trigger = true;
                }   
            }
        });

        // create arrays representing functions that expose user non-invokable functions 
        // self.consumers.iter().for_each(|consumer| {
        //     if functions_to_scan.contains_key(consumer.resolver.function) {
        //         if let Some(entry) = functions_to_scan.get_mut(consumer.resolver.function) {
        //             entry.invokable = true;
        //         }   
        //     }
        // });

        self.data_provider.iter().for_each(|dataprovider| {
            if let Some(call) = dataprovider.callback {
                if let Some(entry) = functions_to_scan.get_mut(call) {
                    entry.invokable = true;
                }  
            }
            
        });

        self.custom_field.iter().for_each(|customfield| {
            if let Some(value)= customfield.value {
                if let Some(entry) = functions_to_scan.get_mut(value) {
                    entry.invokable = true;
                }  
            }
            
            if let Some(search) = customfield.search_suggestions {
                if let Some(entry) = functions_to_scan.get_mut(search) {
                    entry.invokable = true;
                }
                
            }  

            if let Some(entry) = functions_to_scan.get_mut(customfield.common_keys.function) {
                entry.invokable = true;
            }  

            if let Some(resolver) = customfield.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                } 
            }

            if let Some(edit) = customfield.edit {
                if let Some(entry) = functions_to_scan.get_mut(edit) {
                    entry.invokable = true;
                }

            }

        });

        self.ui_modifications.iter().for_each(|ui| {
            if let Some(entry) = functions_to_scan.get_mut(ui.common_keys.function) {
                entry.invokable = true;
            }

            if let Some(resolver) = ui.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }
        });

        self.workflow_validator.iter().for_each(|validator| {
            if let Some(entry) = functions_to_scan.get_mut(validator.common_keys.function) {
                entry.invokable = true;
            }

            if let Some(resolver) = validator.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }
        });
        
        self.workflow_post_function.iter().for_each(|post_function| {
            if let Some(entry) = functions_to_scan.get_mut(post_function.common_keys.function) {
                entry.invokable = true;
            }

            if let Some(resolver) = post_function.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }
        });

        // get user invokable modules that have additional exposure endpoints. 
        // ie macros has config and export fields on top of resolver fields that are functions
        self.macros.iter().for_each(|macros| {
            if let Some(resolver)= macros.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }

            if let Some(config)= macros.config {
                if let Some(entry) = functions_to_scan.get_mut(config) {
                    entry.invokable = true;
                }
            }

            if let Some(export)= macros.export {
                if let Some(entry) = functions_to_scan.get_mut(export) {
                    entry.invokable = true;
                }
            }

        });

        self.content_by_line_item.iter().for_each(|contentitem| {
            if let Some(entry) = functions_to_scan.get_mut(contentitem.common_keys.function) {
                entry.invokable = true;
            }


            if let Some(resolver)= contentitem.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }

            if let Some(dynamic_properties)= contentitem.dynamic_properties {
                if let Some(entry) = functions_to_scan.get_mut(dynamic_properties) {
                    entry.invokable = true;
                }
            }

        });

        self.issue_glance.iter().for_each(|issue| {
            if let Some(entry) = functions_to_scan.get_mut(issue.common_keys.function) {
                entry.invokable = true;
            }


            if let Some(resolver)= issue.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }

            if let Some(dynamic_properties)= issue.dynamic_properties {
                if let Some(entry) = functions_to_scan.get_mut(dynamic_properties) {
                    entry.invokable = true;
                }
            }

        });

        self.access_import_type.iter().for_each(|access| {
            if let Some(entry) = functions_to_scan.get_mut(access.common_keys.function) {
                entry.invokable = true;
            }

            if let Some(resolver) = access.common_keys.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver) {
                    entry.invokable = true;
                }
            }

            if let Some(delete) = access.one_delete_import {
                if let Some(entry) = functions_to_scan.get_mut(delete) {
                    entry.invokable = true;
                }
            }

            if let Some(start) = access.start_import {
                if let Some(entry) = functions_to_scan.get_mut(start) {
                    entry.invokable = true;
                }
            }

            if let Some(stop) = access.stop_import {
                if let Some(entry) = functions_to_scan.get_mut(stop) {
                    entry.invokable = true;
                }
            }

            if let Some(status)= access.import_status {
                if let Some(entry) = functions_to_scan.get_mut(status) {
                    entry.invokable = true;
                }
            }

        });
            
        // get array for user invokable module functions
        // make alternate_functions all user-invokable functions 
        for module in self.extra.clone().into_values().flatten() {
            if let Some(mod_function) = module.function {
                if let Some(entry) = functions_to_scan.get_mut(mod_function) {
                    entry.invokable = true;
                }
            }
           
            if let Some(resolver) = module.resolver {
                if let Some(entry) = functions_to_scan.get_mut(resolver.function) {
                    entry.invokable = true;
                }
            } 
        }
        
        functions_to_scan
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
        assert_eq!(manifest.modules.macros[0].common_keys.key, "My Macro");
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
        let manifest: ForgeManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.modules.macros.len(), 1);
        assert_eq!(manifest.modules.macros[0].common_keys.function, "Catch-me-if-you-can0");


        if let Some(func) = manifest.modules.macros[0].common_keys.resolver {
            assert_eq!(func, "Catch-me-if-you-can1");

        }

        if let Some(func) = manifest.modules.macros[0].config {
            assert_eq!(func, "Catch-me-if-you-can2");

        }

        if let Some(func) = manifest.modules.macros[0].export {
            assert_eq!(func, "Catch-me-if-you-can3");

        }   

    }
}
