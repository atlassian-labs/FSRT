#![allow(clippy::type_complexity)]

mod forge_project;
#[cfg(test)]
mod test;

use clap::{Parser, ValueHint};
use forge_permission_resolver::permissions_resolver::{
    get_permission_resolver_confluence, get_permission_resolver_jira,
};

use forge_project::MockForgeProject;
use miette::{IntoDiagnostic, Result};
use std::{
    collections::HashSet,
    fs,
    os::unix::prelude::OsStrExt,
    path::{Path, PathBuf},
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
    definitions::DefId,
    interp::Interp,
    reporter::Reporter,
    resolver::resolve_calls,
};

use crate::forge_project::{ForgeProjectFromDir, ForgeProjectTrait};
use forge_analyzer::reporter::Vulnerability;
use forge_loader::manifest::Entrypoint;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    debug: bool,

    /// Dump a graphviz formatted callgraph
    #[arg(long)]
    callgraph: bool,

    /// Dump a graphviz formatted control flow graph of the function specified in `--function`
    #[arg(long)]
    cfg: bool,

    /// Dump the IR for the specified function
    #[arg(long)]
    dump_ir: Option<String>,

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

#[allow(dead_code)]
pub(crate) fn scan_directory_test(forge_test_proj: MockForgeProject<'_>) -> Option<Vec<Vulnerability>> {
    scan_directory(PathBuf::new(), &Args::parse(), forge_test_proj)
}

#[tracing::instrument(level = "debug")]
pub(crate) fn scan_directory<'a>(
    dir: PathBuf,
    opts: &Args,
    project: impl ForgeProjectTrait<'a> + std::fmt::Debug,
) -> Option<Vec<Vulnerability>> {
    let paths = project.get_paths();
    let manifest = project.get_manifest();
    let mut proj = project.with_files_and_sourceroot(Path::new("src"), paths.clone(), vec![]);

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
        return None;
    }

    let requested_permissions = manifest.permissions;
    let permission_scopes = requested_permissions.scopes;

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
    resolve_calls(&mut proj.ctx);
    if let Some(func) = opts.dump_ir.as_ref() {
        let mut lock = std::io::stdout().lock();
        proj.env.dump_function(&mut lock, func);
        return None;
    }

    let permissions = Vec::from_iter(permissions_declared.iter().cloned());

    let (jira_permission_resolver, jira_regex_map) = get_permission_resolver_jira();
    let (confluence_permission_resolver, confluence_regex_map) =
        get_permission_resolver_confluence();

    let mut definition_analysis_interp = Interp::<DefinitionAnalysisRunner>::new(
        &proj.env,
        false,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
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
    );
    reporter.add_app(opts.appkey.clone().unwrap_or_default(), name.to_owned());

    let mut perm_interp = Interp::<PermissionChecker>::new(
        &proj.env,
        false,
        true,
        permissions.clone(),
        &jira_permission_resolver,
        &jira_regex_map,
        &confluence_permission_resolver,
        &confluence_regex_map,
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

        if run_permission_checker {
            let mut checker = PermissionChecker::new();
            perm_interp.value_manager.varid_to_value =
                definition_analysis_interp.value_manager.varid_to_value;
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
            definition_analysis_interp.value_manager.defid_to_value =
                perm_interp.value_manager.defid_to_value;
        }

        let mut checker = SecretChecker::new();
        secret_interp.value_manager.varid_to_value =
            definition_analysis_interp.value_manager.varid_to_value;
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

    if run_permission_checker && !perm_interp.permissions.is_empty() {
        reporter.add_vulnerabilities([PermissionVuln::new(perm_interp.permissions)]);
    }
    let vulns = reporter.vulns.clone();
    let data = reporter.into_report();
    let report = serde_json::to_string(&data).into_diagnostic().ok()?;
    debug!("On the debug layer: Writing Report");
    match &opts.out {
        Some(path) => {
            fs::write(path, report.clone()).into_diagnostic().ok()?;
        }
        None => println!("{report}"),
    }

    Some(vulns)
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    tracing_subscriber::registry()
        .with(HierarchicalLayer::new(2))
        .with(EnvFilter::from_env("FORGE_LOG"))
        .init();
    let dirs = std::mem::take(&mut args.dirs);

    for dir in dirs {
        let mut manifest_file = dir.clone();
        manifest_file.push("manifest.yaml");
        if !manifest_file.exists() {
            manifest_file.set_extension("yml");
        }
        debug!(?manifest_file);

        let manifest_text = fs::read_to_string(&manifest_file)
            .into_diagnostic()
            .ok()
            .clone()
            .unwrap_or_default();

        let forge_project_from_dir = ForgeProjectFromDir {
            dir: dir.clone(),
            manifest_file_content: manifest_text,
        };

        debug!(?dir);
        scan_directory(dir, &args, forge_project_from_dir);
    }
    Ok(())
}
