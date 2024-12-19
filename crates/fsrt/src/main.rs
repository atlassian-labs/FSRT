#![allow(clippy::type_complexity)]

mod forge_project;
#[cfg(test)]
mod test;

use clap::{Parser, ValueHint};
use forge_permission_resolver::permissions_resolver::{
    get_permission_resolver_bitbucket, get_permission_resolver_confluence,
    get_permission_resolver_jira,
};

use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
};

use graphql_parser::query::{parse_query, Definition, OperationDefinition, Selection};
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

    // Run the permission checker
    #[arg(long)]
    check_permissions: bool,

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

fn check_graphql_and_perms(val: &Value) -> Vec<&str> {
    let mut operations = vec![];
    match val {
        Value::Const(Const::Literal(s)) => operations.extend(parse_graphql(s)),
        Value::Phi(vals) => vals.iter().for_each(|val| match val {
            Const::Literal(s) => operations.extend(parse_graphql(s)),
        }),
        _ => {}
    }
    // TODO : Build out permission resolver here

    let permissions_resolver: HashMap<(&str, &str), &str> =
        [(("compass", "searchTeams"), "read:component:compass")]
            .into_iter()
            .collect();

    operations
        .iter()
        .filter_map(|f| permissions_resolver.get(f).copied())
        .collect()
}

// returns (product, operationName)
fn parse_graphql(s: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut operations = vec![];

    // collect all fragments
    if let std::result::Result::Ok(doc) = parse_query::<&str>(s) {
        let fragments: HashMap<&str, &Vec<graphql_parser::query::Selection<'_, &str>>> = doc
            .definitions
            .iter()
            .filter_map(|def| match def {
                Definition::Fragment(fragment) => {
                    Some((fragment.name, fragment.selection_set.items.as_ref()))
                }
                _ => None,
            })
            .collect();

        doc.definitions.iter().for_each(|operation| {
            if let Definition::Operation(op) = operation {
                let possible_selection_set = match op {
                    OperationDefinition::Mutation(mutation) => Some(&mutation.selection_set),
                    OperationDefinition::Query(query) => Some(&query.selection_set),
                    OperationDefinition::SelectionSet(set) => Some(set),
                    _ => None,
                };
                // place all fragments in place of the fragment spread
                if let Some(selection_set) = possible_selection_set {
                    selection_set.items.iter().for_each(|selection| {
                        if let Selection::Field(type_field) = selection {
                            type_field
                                .selection_set
                                .items
                                .iter()
                                .for_each(|fragment_selections| {
                                    if let Selection::Field(operation) = fragment_selections {
                                        operations.push((type_field.name, operation.name))
                                    } else if let Selection::FragmentSpread(fragment_spread) =
                                        fragment_selections
                                    {
                                        // check to see if the fragment spread resolves as fragmemnt
                                        if let Some(set) =
                                            fragments.get(&fragment_spread.fragment_name)
                                        {
                                            set.iter().for_each(|operation_field| {
                                                if let Selection::Field(operation) = operation_field
                                                {
                                                    operations
                                                        .push((type_field.name, operation.name))
                                                }
                                            });
                                        }
                                    }
                                });
                        }
                    })
                }
            }
        })
    }

    operations.into_iter()
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

#[tracing::instrument(level = "debug")]
pub(crate) fn scan_directory<'a>(
    dir: PathBuf,
    opts: &Args,
    project: impl ForgeProjectTrait<'a> + std::fmt::Debug,
    secret_packages: &[PackageData],
) -> Result<Report> {
    let paths = project.get_paths();
    let manifest = project.get_manifest();
    let mut proj =
        project.with_files_and_sourceroot(Path::new("src"), paths.clone(), secret_packages);

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

    let requested_permissions = manifest.permissions;
    let permission_scopes = requested_permissions.scopes;
    let contains_remote_auth_token = manifest
        .remotes
        .unwrap_or_default()
        .into_iter()
        .any(|remote| remote.contains_auth());

    let run_permission_checker = opts.check_permissions && !transpiled_async;

    let permissions_declared: HashSet<String> =
        HashSet::from_iter(permission_scopes.iter().map(|s| s.replace('\"', "")));

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

    let permissions = permissions_declared.into_iter().collect::<Vec<_>>();

    let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira();
    let (confluence_permission_resolver, confluence_regex_map) =
        get_permission_resolver_confluence();
    let (bitbucket_permission_resolver, bitbucket_regex_map) = get_permission_resolver_bitbucket();

    let mut definition_analysis_interp = Interp::<DefinitionAnalysisRunner>::new(
        &proj.env,
        false,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
    );

    let mut interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
    );
    let mut authn_interp = Interp::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
    );

    let mut reporter = Reporter::new();
    let mut secret_interp = Interp::<SecretChecker>::new(
        &proj.env,
        false,
        false,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
    );
    reporter.add_app(opts.appkey.clone().unwrap_or_default(), name.to_owned());

    let mut perm_interp = Interp::<PermissionChecker>::new(
        &proj.env,
        false,
        true,
        permissions,
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
        &bitbucket_permission_resolver,
        &bitbucket_regex_map,
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

    let mut used_graphql_perms: Vec<&str> = definition_analysis_interp
        .value_manager
        .varid_to_value_with_proj
        .values()
        .flat_map(check_graphql_and_perms)
        .collect();

    let graphql_perms_varid: Vec<&str> = definition_analysis_interp
        .value_manager
        .varid_to_value
        .values()
        .flat_map(check_graphql_and_perms)
        .collect();

    let graphql_perms_defid: Vec<&str> = definition_analysis_interp
        .value_manager
        .defid_to_value
        .values()
        .flat_map(check_graphql_and_perms)
        .collect();

    used_graphql_perms.extend_from_slice(&graphql_perms_defid);
    used_graphql_perms.extend_from_slice(&graphql_perms_varid);

    let final_perms: Vec<&String> = perm_interp
        .permissions
        .iter()
        .filter(|f| !used_graphql_perms.contains(&&***f))
        .collect();

    if run_permission_checker && !final_perms.is_empty() {
        reporter.add_vulnerabilities([PermissionVuln::new(perm_interp.permissions)]);
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
        let reporter_result = scan_directory(dir, &args, forge_project_from_dir, &secret_packages);
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
