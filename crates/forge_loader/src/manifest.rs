use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashSet},
    hash::Hash,
    path::{Path, PathBuf},
};

use crate::Error;
use forge_utils::FxHashMap;
use itertools::{Either, Itertools};
use serde::Deserialize;
use serde_json::map::Entry;
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

// Modified 
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct ModInfo<'a> {
    function: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct MacroMod<'a> { 
    #[serde(flatten, borrow)] 
    key: &'a str,
    function: &'a str,
    resolver: ModInfo<'a>,
    config: ModInfo<'a>,
    export: ModInfo<'a>,
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
    key: &'a str,
    #[serde(flatten, borrow)]
    callback: Callback<'a>,
}

// Struct for mapping functions defined one more level in whose value is {function: string}. Used to represent resolver types.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Callback<'a> {
    pub function: &'a str,
}

// Struct for Custom field Module. Check that search suggestion gets read in correctly. 
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CustomField<'a> {
    #[serde(flatten, borrow)]
    key: &'a str,
    search_suggestion: &'a str,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UiModificatons<'a> {
    #[serde(flatten, borrow)]
    key: &'a str,
    resolver: Callback<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowValidator<'a> {
    #[serde(flatten, borrow)]
    key: &'a str,
    functon: &'a str,
    resolver: Callback<'a>
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowPostFunction<'a> {
    #[serde(flatten, borrow)]
    key: &'a str,
    function: &'a str,
}

// Add more structs here for deserializing forge modules
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ForgeModules<'a> {
    #[serde(rename = "macro", default, borrow)]
    macros: Vec<MacroMod<'a>>,
    #[serde(rename = "function", default, borrow)]
    pub functions: Vec<FunctionMod<'a>>,
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
struct Perms<'a> {
    #[serde(default, borrow)]
    scopes: Vec<&'a str>,
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
    permissions: Perms<'a>,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Entrypoints<'a> {
    function: &'a str,
    invokable: bool,
    web_trigger: bool,
}

// Helper functions that help filter out which functions are what. 
impl<T> FunctionTy<T> {
    pub fn map<O>(self, f: impl FnOnce(T) -> O) -> FunctionTy<O> {
        match self {
            Self::Invokable(t) => FunctionTy::Invokable(f(t)),
            Self::WebTrigger(t) => FunctionTy::WebTrigger(f(t)),
        }
    }

    #[inline]
    pub fn into_inner(self) -> T {
        match self {
            FunctionTy::Invokable(t) | FunctionTy::WebTrigger(t) => t,
        }
    }

    pub fn sequence<I: IntoIterator>(
        self,
        f: impl FnOnce(T) -> I,
    ) -> impl Iterator<Item = FunctionTy<I::Item>> {
        match self {
            Self::Invokable(t) => Either::Left(f(t).into_iter().map(FunctionTy::Invokable)),
            Self::WebTrigger(t) => Either::Right(f(t).into_iter().map(FunctionTy::WebTrigger)),
        }
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

// TODO: fix return type whop
    pub fn into_analyzable_functions(
        mut self,
    ) -> impl Iterator<Item = Entrypoints<'a>> {
        // number of webtriggers are usually low, so it's better to just sort them and reuse
        self.webtriggers
            .sort_unstable_by_key(|trigger| trigger.function);

        // Get all the Triggers and represent them as a new struct thing where "webtrigger" attribute is true 
        // for all trigger things 
        let web = self.webtriggers.iter().for_each(|webtriggers| {
            Entrypoints {
                function: webtriggers.function,
                invokable: false,
                web_trigger: true,
            };
        });
        let event = self.event_triggers.iter().for_each(|event_triggers| {
            Entrypoints {
                function: event_triggers.raw.function,
                invokable: false,
                web_trigger: true,
            };
        });
        let schedule = self.scheduled_triggers.iter().for_each(|schedule_triggers| {
            Entrypoints {
                function: schedule_triggers.raw.function,
                invokable: false,
                web_trigger: true,
            };
        });

        // create arrays representing functions that expose user non-invokable functions 
        let consumer = self.consumers.iter().for_each(|consumers| {
            Entrypoints {
                function: consumers.resolver.function,
                invokable: true,
                web_trigger: false,
            };
        });

        let data_provider = self.data_provider.iter().for_each(|dataprovider| {
            Entrypoints {
                function: dataprovider.callback.function,
                invokable: true,
                web_trigger: false,
            };
        });

        let custom_field = self.custom_field.iter().for_each(|customfield| {
            Entrypoints {
                function: customfield.search_suggestion,
                invokable: true,
                web_trigger: false,
            };
        });

        let ui_mod = self.ui_modifications.iter().for_each(|ui| {
            Entrypoints {
                function: ui.resolver.function,
                invokable: true,
                web_trigger: false,
            };
        });

        let workflow_validator = self.workflow_validator.iter().for_each(|validator| {
            Entrypoints {
                function: validator.resolver.function,
                invokable: true,
                web_trigger: false,
            };
        });

        let workflow_post = self.workflow_post_function.iter().for_each(|post_function| {
            Entrypoints {
                function: post_function.function,
                invokable: true,
                web_trigger: false,
            };
        });

        
        // let user_invokable = self.extra.into_values().flatten().into_iter().for_each(|invokable| {

        //     if invokable.resolver != None {
        //         Entrypoints {
        //             function: invokable.resolver,
        //             invokable: true,
        //             web_trigger: false,
        //         };

        //     }
        //     Entrypoints {
        //         function: invokable.function,
        //         invokable: true,
        //         web_trigger: false,
        //     };
        // });
        
        // let mut ignored_functions: BTreeSet<_> = self
        //     .scheduled_triggers
        //     .into_iter()
        //     .map(|trigger| trigger.raw.function)
        //     .chain(
        //         self.event_triggers
        //             .into_iter()
        //             .map(|trigger| trigger.raw.function),
        //     )
        //     .collect();

        // get array for user invokable module functions
        // make alternate_functions all user-invokable functions 
        let mut alternate_functions = Vec::new();
        for module in self.extra.into_values().flatten() {
            if let Some(mod_function) = module.function {
                alternate_functions.push(Entrypoints {
                    function: mod_function,
                    invokable: true,
                    web_trigger: false
                });
            }
           
            if let Some(resolver) = module.resolver {
                alternate_functions.push(Entrypoints {
                    function: resolver.function,
                    invokable: true,
                    web_trigger: false
                });
            }
        }

        workflow_post
        // Iterate over Consumers and check that if consumers isn't in alternate functions, add consumer funtion to be ignored
        // assuming that alternate functions already has all user invokable functions. 
        // self.consumers.iter().for_each(|consumer| {
        //     if !alternate_functions.contains(&consumer.resolver.function) {
        //         ignored_functions.insert(consumer.resolver.function);
        //     }
        // });

        // TODO: Iterate through all deserialized entrypoints that are represented as a struct when deserialized 
        // Update Struct values to be true or not. If any part true, then scan. 
        // This solution fixes the problem that we only check known user invokable modules and also acccounts for non-invokable module entry points

        // return non-user invokable functions
        // self.functions.into_iter().filter_map(move |func| {
        //     if ignored_functions.contains(&func.key) {
        //         return None;
        //     }
        //     Some(
        //         if self
        //             .webtriggers
        //             .binary_search_by_key(&func.key, |trigger| trigger.function)
        //             .is_ok()
        //         {
        //             FunctionTy::WebTrigger(func)
        //         } else {
        //             FunctionTy::Invokable(func)
        //         },
        //     )
        // })
    }
}

impl<S> FunctionRef<'_, S> {
    const VALID_EXTS: [&str; 4] = ["jsx", "tsx", "ts", "js"];
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
                    "title": "My Macro"
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
        assert_eq!(manifest.modules.macros[0].key, "My Macro");
        assert_eq!(manifest.modules.macros[0].function, "my-macro");
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
                    "resolver": {
                        "function": Catch-me-if-you-can1
                    },
                    "config": {
                        "function": Catch-me-if-you-can2
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

    }
}
