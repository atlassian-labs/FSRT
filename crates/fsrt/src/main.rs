#![allow(clippy::type_complexity)]

mod forge_project;
#[cfg(test)]
mod test;

use clap::{Parser, ValueHint};
use forge_permission_resolver::{
    permissions_cache::CacheConfig,
    permissions_resolver::{
        get_permission_resolver_bitbucket, get_permission_resolver_compass,
        get_permission_resolver_confluence, get_permission_resolver_jira,
        get_permission_resolver_jira_any, get_permission_resolver_jira_service_management,
        get_permission_resolver_jira_software, PermMap,
    },
};
use glob::glob;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    env, fmt, fs,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use graphql_parser::{
    query::{Mutation, Query, SelectionSet},
    schema::{EnumType, EnumValue, ObjectType},
};

use graphql_parser::{
    parse_schema,
    query::{self, parse_query, Definition, Field, OperationDefinition, Selection, Type},
    schema::{ObjectTypeExtension, TypeDefinition, TypeExtension},
};
use tracing::{debug, warn};
use tracing_subscriber::{prelude::*, EnvFilter};
use tracing_tree::HierarchicalLayer;

use forge_analyzer::{
    checkers::{
        AuthZChecker, AuthenticateChecker, DefinitionAnalysisRunner, PermissionChecker,
        PermissionVuln, SecretChecker,
    },
    ctx::ModId,
    definitions::{Const, DefId, PackageData, Value},
    interp::Interp,
    reporter::{Report, Reporter},
};

use crate::forge_project::{ForgeProjectFromDir, ForgeProjectTrait};
use forge_loader::manifest::Entrypoint;
use walkdir::WalkDir;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    debug: bool,

    /// Dump the IR for the specified function
    #[arg(long)]
    dump_ir: Option<String>,

    /// Dump the Dominator Tree for specified file
    #[arg(long)]
    dump_dt: Option<String>,

    /// A specific function to scan. Must be an entrypoint specified in `manifest.yml`
    #[arg(short, long)]
    function: Option<String>,

    /// The Marketplace app key.
    #[arg(long)]
    appkey: Option<String>,

    /// A file to redirect output to.
    #[arg(short, long)]
    out: Option<PathBuf>,

    #[arg(long)]
    graphql_schema_path: Option<PathBuf>,

    /// If true, use cached permissions; otherwise, re-download and reparse Swagger files.
    #[arg(long)]
    cached_permissions: bool,

    /// Path to store or load cached permissions. If not provided, defaults to `~/.cache/fsrt`.
    #[arg(long)]
    cached_permissions_path: Option<PathBuf>,

    /// List of scanners to enable. Defaults to all of them.
    #[arg(long)]
    scanners: Option<String>,

    /// The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level
    /// directory, and that the source code is located in `src/`
    #[arg(name = "DIRS", default_values_os_t = std::env::current_dir(), value_hint = ValueHint::DirPath)]
    dirs: Vec<PathBuf>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ResolvedEntryPoint<'a> {
    func_name: &'a str,
    path: PathBuf,
    module: ModId,
    def_id: DefId,
    webtrigger: bool,
    invokable: bool,
    admin: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TranspiledAsyncError,
    UnableToReport,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TranspiledAsyncError => write!(f, "Could not scan due to transpiled async."),
            Error::UnableToReport => write!(f, "Could not report."),
        }
    }
}

struct PermissionsAndNextSelection<'a, 'b> {
    permission_vec: Vec<&'a str>,
    next_selection: NextSelection<'a, 'b>,
}

struct NextSelection<'a, 'b> {
    selection_set: &'b SelectionSet<'b, &'b str>,
    next_type: &'a str,
}

fn parse_grapqhql_schema<'a: 'b, 'b>(
    schema_doc: &'a [graphql_parser::schema::Definition<'a, &'a str>],
    query_doc: &'b [graphql_parser::query::Definition<'b, &'b str>],
) -> Vec<&'a str> {
    let mut permission_list = vec![];

    // dequeue of (parsed_query_selection: SelectionSet, schema_type_field: Field)
    let mut deq = VecDeque::from([]);

    let fragments: HashMap<&str, &Vec<graphql_parser::query::Selection<'_, &str>>> = query_doc
        .iter()
        .filter_map(|def| match def {
            Definition::Fragment(fragment) => {
                Some((fragment.name, fragment.selection_set.items.as_ref()))
            }
            _ => None,
        })
        .collect();

    query_doc.iter().for_each(|def| match def {
        Definition::Operation(OperationDefinition::Mutation(Mutation {
            selection_set, ..
        }))
        | Definition::Operation(OperationDefinition::Query(Query { selection_set, .. })) => deq
            .extend(selection_set.items.iter().filter_map(|item| {
                let definition =
                    if let Definition::Operation(OperationDefinition::Mutation(_)) = def {
                        "Mutation"
                    } else if let Definition::Operation(OperationDefinition::Query(_)) = def {
                        "Query"
                    } else {
                        "Unkown"
                    };

                if let Selection::Field(field) = &item {
                    if let Some(PermissionsAndNextSelection { next_selection, .. }) =
                        get_permissions_and_next_selection(field, schema_doc, definition)
                    {
                        return Some(next_selection);
                    };
                }
                None
            })),
        _ => {}
    });

    while let Some(NextSelection {
        next_type: schema_field,
        selection_set: query_set,
    }) = deq.pop_front()
    {
        deq.extend(
            query_set
                .items
                .iter()
                .filter_map(|item| {
                    if let Selection::Field(field) = &item {
                        if let Some(PermissionsAndNextSelection {
                            permission_vec,
                            next_selection,
                        }) = get_permissions_and_next_selection(field, schema_doc, schema_field)
                        {
                            permission_list.extend(permission_vec);
                            return Some(vec![next_selection]);
                        };
                    } else if let Selection::FragmentSpread(fragment_spread) = item {
                        // check to see if the fragment spread resolves as fragmemnt
                        if let Some(set) = fragments.get(&fragment_spread.fragment_name) {
                            return Some(
                                set.iter()
                                    .filter_map(|selection| {
                                        if let Selection::Field(field) = selection {
                                            if let Some(PermissionsAndNextSelection {
                                                permission_vec,
                                                next_selection,
                                            }) = get_permissions_and_next_selection(
                                                field,
                                                schema_doc,
                                                schema_field,
                                            ) {
                                                permission_list.extend(permission_vec);
                                                return Some(next_selection);
                                            };
                                        }
                                        None
                                    })
                                    .collect(),
                            );
                        }
                    }

                    None
                })
                .flatten(),
        )
    }

    permission_list
}

fn get_permissions_and_next_selection<'a, 'b>(
    field: &'b Field<'b, &'b str>,
    schema_doc: &'a [graphql_parser::schema::Definition<'a, &'a str>],
    schema_field: &'b str,
) -> Option<PermissionsAndNextSelection<'a, 'b>> {
    let field_type = get_type_or_typex_with_name(schema_doc, schema_field)
        .find(|sub_field| sub_field.name == field.name);

    if let Some(field_type) = field_type {
        if let Type::NamedType(name) = &&field_type.field_type {
            return Some(PermissionsAndNextSelection {
                permission_vec: get_field_directives(field_type),
                next_selection: NextSelection {
                    selection_set: &field.selection_set,
                    next_type: name,
                },
            });
        }
    }
    None
}

fn get_type_or_typex_with_name<'a, 'b>(
    definitions: &'a [graphql_parser::schema::Definition<'a, &'a str>],
    search_name: &'b str,
) -> impl Iterator<Item = &'a graphql_parser::schema::Field<'a, &'a str>> + use<'a, 'b> {
    definitions
        .iter()
        .filter_map(move |def| match def {
            graphql_parser::schema::Definition::TypeDefinition(TypeDefinition::Object(
                ObjectType { name, fields, .. },
            ))
            | graphql_parser::schema::Definition::TypeExtension(TypeExtension::Object(
                ObjectTypeExtension { name, fields, .. },
            )) => {
                if name == &search_name {
                    return Some(fields);
                }
                None
            }
            _ => None,
        })
        .flatten()
}

fn get_field_directives<'a>(field: &'a graphql_parser::schema::Field<'_, &'a str>) -> Vec<&'a str> {
    let mut perm_vec = vec![];
    field.directives.iter().for_each(|directive| {
        if directive.name == "scopes" {
            directive.arguments.iter().for_each(|arg| {
                if arg.0 == "required" {
                    if let query::Value::List(val) = &arg.1 {
                        val.iter().for_each(|val| {
                            if let query::Value::Enum(en) = val {
                                perm_vec.push(*en);
                            }
                        });
                    }
                }
            });
        }
    });
    perm_vec
}

fn check_graphql_and_perms<'a>(
    val: &'a Value,
    path: &'a graphql_parser::schema::Document<'a, &'a str>,
) -> Vec<&'a str> {
    let mut operations = vec![];

    match val {
        Value::Const(Const::Literal(s)) => {
            if let std::result::Result::Ok(query_doc) = parse_query::<&str>(s) {
                operations.extend(parse_grapqhql_schema(
                    &path.definitions,
                    &query_doc.definitions,
                ));
            }
        }
        Value::Phi(vals) => vals.iter().for_each(|val| match val {
            Const::Literal(s) => {
                if let std::result::Result::Ok(query_doc) = parse_query::<&str>(s) {
                    operations.extend(parse_grapqhql_schema(
                        &path.definitions,
                        &query_doc.definitions,
                    ));
                }
            }
        }),
        _ => {}
    }

    operations
}

fn is_js_file<P: AsRef<Path>>(path: P) -> bool {
    matches!(
        path.as_ref().extension().map(|s| s.as_bytes()),
        Some(b"jsx" | b"js" | b"tsx" | b"ts")
    )
}

fn collect_sourcefiles<P: AsRef<Path>>(root: P) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root)
        .min_depth(1)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| {
            let path = e.ok()?.into_path();
            is_js_file(&path).then_some(path)
        })
}

fn check_perm(perm: &str) -> bool {
    !matches!(perm, "storage:app" | "report:personal-data")
}

#[tracing::instrument(level = "debug")]
pub(crate) fn scan_directory<'a>(
    dir: PathBuf,
    opts: &mut Args,
    project: impl ForgeProjectTrait<'a> + std::fmt::Debug,
    secret_packages: &[PackageData],
) -> Result<Report> {
    let paths = project.get_paths();
    let manifest = project.get_manifest();
    let requested_permissions = manifest.permissions;
    let permissions_declared = requested_permissions
        .scopes
        .iter()
        .map(|s| s.replace('\"', ""))
        .filter(|s| check_perm(s))
        .collect::<Vec<_>>();
    let permset = permissions_declared
        .iter()
        .map(|s| s.as_str())
        .collect::<HashSet<_>>();
    let mut perm_map = PermMap::new(&permset);
    let contains_remote_auth_token = manifest
        .remotes
        .unwrap_or_default()
        .into_iter()
        .any(|remote| remote.contains_auth());

    let mut proj = project.with_files_and_sourceroot(
        Path::new("src"),
        paths.clone(),
        secret_packages,
        &mut perm_map,
    );

    let name = manifest.app.name.unwrap_or_default();

    let transpiled_async = paths.iter().any(|path| {
        if let Ok(data) = fs::read_to_string(path) {
            return data
                .lines()
                .next()
                .is_some_and(|data| data == "\"use strict\";" || data == "'use strict';");
        }
        false
    });

    if transpiled_async {
        warn!("Unable to scan due to transpiled async");
        Err(Error::TranspiledAsyncError)?;
    }
    let run_permission_checker = !transpiled_async;

    let funcrefs = manifest
        .modules
        .into_analyzable_functions()
        .flat_map(|entrypoint| {
            Ok::<_, forge_loader::Error>(Entrypoint {
                function: entrypoint.function.try_resolve(&paths, &dir)?,
                invokable: entrypoint.invokable,
                web_trigger: entrypoint.web_trigger,
                admin: entrypoint.admin,
            })
        });

    proj.add_funcs(funcrefs);
    // resolve_calls(&mut proj.ctx);
    if let Some(func) = opts.dump_ir.as_ref() {
        proj.env.dump_function(&mut std::io::stdout().lock(), func);
        std::process::exit(0);
    }

    if let Some(func) = opts.dump_dt.as_ref() {
        proj.env.dump_tree(&mut std::io::stdout().lock(), func);
        std::process::exit(0);
    }

    let permissions = permissions_declared
        .into_iter()
        .filter(|s| check_perm(s))
        .collect::<Vec<_>>();

    let config = CacheConfig::new(
        opts.cached_permissions || std::env::var_os("FSRT_CACHE").is_some_and(|s| !s.is_empty()),
        opts.cached_permissions_path.clone(),
    );

    let (jira_any_permission_resolver, jira_any_regex_map) =
        get_permission_resolver_jira_any(&config);
    let (jira_software_permission_resolver, jira_software_regex_map) =
        get_permission_resolver_jira_software(&config);
    let (jira_service_management_permission_resolver, jira_service_management_regex_map) =
        get_permission_resolver_jira_service_management(&config);
    let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira(&config);
    let (confluence_permission_resolver, confluence_regex_map) =
        get_permission_resolver_confluence(&config);
    let (bitbucket_permission_resolver, bitbucket_regex_map) =
        get_permission_resolver_bitbucket(&config);
    let compass_permission_resolver = get_permission_resolver_compass();

    let mut definition_analysis_interp = Interp::<DefinitionAnalysisRunner>::new(
        &proj.env,
        false,
        true,
        permissions.clone(),
        &jira_any_permission_resolver,
        &jira_any_regex_map,
        &jira_software_permission_resolver,
        &jira_software_regex_map,
        &jira_service_management_permission_resolver,
        &jira_service_management_regex_map,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
        &compass_permission_resolver,
    );

    let mut interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_any_permission_resolver,
        &jira_any_regex_map,
        &jira_software_permission_resolver,
        &jira_software_regex_map,
        &jira_service_management_permission_resolver,
        &jira_service_management_regex_map,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
        &compass_permission_resolver,
    );
    let mut authn_interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_any_permission_resolver,
        &jira_any_regex_map,
        &jira_software_permission_resolver,
        &jira_software_regex_map,
        &jira_service_management_permission_resolver,
        &jira_service_management_regex_map,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
        &compass_permission_resolver,
    );

    let mut reporter = Reporter::new();
    let mut secret_interp = Interp::<SecretChecker>::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_any_permission_resolver,
        &jira_any_regex_map,
        &jira_software_permission_resolver,
        &jira_software_regex_map,
        &jira_service_management_permission_resolver,
        &jira_service_management_regex_map,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
        &compass_permission_resolver,
    );
    reporter.add_app(opts.appkey.clone().unwrap_or_default(), name.to_owned());

    let mut perm_interp = Interp::<PermissionChecker<'_>>::new(
        &proj.env,
        false,
        true,
        permissions,
        &jira_any_permission_resolver,
        &jira_any_regex_map,
        &jira_software_permission_resolver,
        &jira_software_regex_map,
        &jira_service_management_permission_resolver,
        &jira_service_management_regex_map,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
        &compass_permission_resolver,
    );
    for func in &proj.funcs {
        let mut def_checker = DefinitionAnalysisRunner::new();
        if let Err(err) = definition_analysis_interp.run_checker(
            func.def_id,
            &mut def_checker,
            func.path.clone(),
            func.func_name.to_string(),
        ) {
            warn!(
                "error while scanning {:?} in {:?}: {err}",
                func.func_name, func.path,
            );
        }

        // if there is a remote backend that accepts an auth token, do not run
        if run_permission_checker && !contains_remote_auth_token {
            let mut checker = PermissionChecker::new();
            perm_interp.value_manager.varid_to_value =
                definition_analysis_interp.value_manager.varid_to_value;
            perm_interp.value_manager.varid_to_value_with_proj = definition_analysis_interp
                .value_manager
                .varid_to_value_with_proj;
            perm_interp.value_manager.defid_to_value =
                definition_analysis_interp.value_manager.defid_to_value;
            if let Err(err) = perm_interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_owned(),
            ) {
                warn!("error while running permission checker: {err}");
            }
            definition_analysis_interp.value_manager.varid_to_value =
                perm_interp.value_manager.varid_to_value;
            definition_analysis_interp
                .value_manager
                .varid_to_value_with_proj = perm_interp.value_manager.varid_to_value_with_proj;
            definition_analysis_interp.value_manager.defid_to_value =
                perm_interp.value_manager.defid_to_value;
        }

        let mut checker = SecretChecker::new();
        secret_interp.value_manager.varid_to_value =
            definition_analysis_interp.value_manager.varid_to_value;
        secret_interp.value_manager.varid_to_value_with_proj = definition_analysis_interp
            .value_manager
            .varid_to_value_with_proj;
        secret_interp.value_manager.defid_to_value =
            definition_analysis_interp.value_manager.defid_to_value;
        if let Err(err) = secret_interp.run_checker(
            func.def_id,
            &mut checker,
            func.path.clone(),
            func.func_name.to_owned(),
        ) {
            warn!("error while running secret checker: {err}");
        } else {
            reporter.add_vulnerabilities(checker.into_vulns());
        }
        definition_analysis_interp.value_manager.varid_to_value =
            secret_interp.value_manager.varid_to_value;
        definition_analysis_interp
            .value_manager
            .varid_to_value_with_proj = secret_interp.value_manager.varid_to_value_with_proj;
        definition_analysis_interp.value_manager.defid_to_value =
            secret_interp.value_manager.defid_to_value;

        if func.invokable {
            let mut checker = AuthZChecker::new();
            debug!("checking {:?} at {:?}", func.func_name, &func.path);
            if let Err(err) = interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_string(),
            ) {
                warn!(
                    "error while scanning {:?} in {:?}: {err}",
                    func.func_name, func.path,
                );
            }
            reporter.add_vulnerabilities(checker.into_vulns());
        } else if func.webtrigger {
            let mut checker = AuthenticateChecker::new();
            debug!(
                "checking webtrigger {:?} at {:?}",
                func.func_name, func.path,
            );
            if let Err(err) = authn_interp.run_checker(
                func.def_id,
                &mut checker,
                func.path.clone(),
                func.func_name.to_string(),
            ) {
                warn!(
                    "error while scanning {:?} in {:?}: {err}",
                    func.func_name, func.path,
                );
            }
            reporter.add_vulnerabilities(checker.into_vulns());
        }
    }

    let path = if let Some(ref mut path) = opts.graphql_schema_path {
        path
    } else {
        let mut path: PathBuf = env::var("XDG_CONFIG_HOME")
            .unwrap_or(env::var("HOME").unwrap_or_default() + "/.config")
            .into();

        path.push("fsrt/graphql-central-schema");
        &mut path.to_owned()
    };

    let mut scope_path = path.clone();

    scope_path.push("schema/shared/agg-shared-scopes.nadel");

    let scope_map = fs::read_to_string(&scope_path).unwrap_or_default();

    let ast = parse_schema::<&str>(&scope_map).unwrap_or_default();

    let mut scope_name_to_oauth = HashMap::new();

    ast.definitions.iter().for_each(|val| {
        if let graphql_parser::schema::Definition::TypeDefinition(TypeDefinition::Enum(
            EnumType { values, .. },
        )) = val
        {
            values.iter().for_each(
                |EnumValue {
                     directives, name, ..
                 }| {
                    if let Some(directive) = directives.first() {
                        if let graphql_parser::schema::Value::String(oauth_scope) = &directive
                            .arguments
                            .first()
                            .expect("Should only be one directive")
                            .1
                        {
                            scope_name_to_oauth.insert(*name, &**oauth_scope);
                        }
                    }
                },
            )
        }
    });

    path.push("schema/*/*.nadel");

    let joined_schema = glob(path.to_str().unwrap_or_default())
        .expect("Failed to read glob pattern")
        .map(|path| fs::read_to_string(path.unwrap()).unwrap_or_default())
        .collect::<Vec<String>>()
        .join("\n");

    // excess Forge storage scopes should not increase the severity of an AuthZ vuln
    // let mut final_perms: HashSet<&str> = perm_interp
    //     .permissions
    //     .iter()
    //     .map(|x| &**x)
    //     .filter(|x| *x != "report:personal-data" && *x != "storage:app")
    //     .collect();
    let ast = parse_schema::<&str>(&joined_schema);

    // Lack of coverage, since no apps use raw GraphQL currently.
    if let std::result::Result::Ok(doc) = ast {
        let mut used_graphql_perms: Vec<&str> = definition_analysis_interp
            .value_manager
            .varid_to_value_with_proj
            .values()
            .flat_map(|val| check_graphql_and_perms(val, &doc))
            .collect();

        let graphql_perms_varid: Vec<&str> = definition_analysis_interp
            .value_manager
            .varid_to_value
            .values()
            .flat_map(|val| check_graphql_and_perms(val, &doc))
            .collect();

        let graphql_perms_defid: Vec<&str> = definition_analysis_interp
            .value_manager
            .defid_to_value
            .values()
            .flat_map(|val| check_graphql_and_perms(val, &doc))
            .collect();

        used_graphql_perms.extend_from_slice(&graphql_perms_defid);
        used_graphql_perms.extend_from_slice(&graphql_perms_varid);

        // let oauth_scopes: HashSet<&str> = used_graphql_perms
        //     .iter()
        //     .copied()
        //     .filter_map(|val| {
        //         if !scope_name_to_oauth.contains_key(&val) {
        //             warn!("Scope is not contained in the scope definitions")
        //         }
        //
        //         scope_name_to_oauth.get(&val).copied()
        //     })
        //     .collect();

        //final_perms = &final_perms - &oauth_scopes;
    }
    debug!("perms: {:?}", perm_map.unused_scopes());
    // let final_perms = final_perms
    //     .into_iter()
    //     .filter(|&s| perm_map.unused_scopes().iter().any(|unused| unused == s)).collect::<Vec<_>>();
    //
    if run_permission_checker
        // && !final_perms.is_empty()
        && !perm_map.unused_scopes().is_empty()
        && perm_map.unused_scopes() != perm_map.declared_scopes()
    {
        reporter.add_vulnerabilities([PermissionVuln::new(
            perm_map.unused_scopes().iter().map(String::as_str),
        )]);
    }

    Ok(reporter.into_report())
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    tracing_subscriber::registry()
        .with(HierarchicalLayer::new(2))
        .with(EnvFilter::from_env("FORGE_LOG"))
        .init();
    let dirs = std::mem::take(&mut args.dirs);

    let secretdata_file = include_str!("../../../secretdata.yaml");
    let secret_packages: Vec<PackageData> =
        serde_yaml::from_str(secretdata_file).expect("Failed to deserialize packages");

    for dir in dirs {
        let mut manifest_file = dir.join("manifest.yaml");
        if !manifest_file.exists() {
            manifest_file.set_extension("yml");
        }
        debug!(?manifest_file);

        let manifest_text = fs::read_to_string(&manifest_file)?;

        let forge_project_from_dir = ForgeProjectFromDir {
            dir: dir.clone(),
            manifest_file_content: manifest_text,
        };

        debug!(?dir);
        let reporter_result =
            scan_directory(dir, &mut args, forge_project_from_dir, &secret_packages);
        match reporter_result {
            Result::Ok(report) => {
                let report = serde_json::to_string(&report)?;
                debug!("On the debug layer: Writing Report");
                match &args.out {
                    Some(path) => {
                        fs::write(path, &*report)?;
                    }
                    None => println!("{report}"),
                }
            }
            Result::Err(err) => {
                warn!("Could not scan due to {err}")
            }
        }
    }
    Ok(())
}
