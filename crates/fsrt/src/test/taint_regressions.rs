use super::*;

use forge_analyzer::{checkers::PrototypePollutionChecker, interp::Runner};
use forge_permission_resolver::permissions_resolver::PermMap;

fn prototype_pollution_found(body: &str) -> bool {
    let path = PathBuf::from("src/index.js");
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        path.clone(),
        format!(
            "import Resolver from '@forge/resolver';
             const resolver = new Resolver();
             resolver.define('test', request => {{ {body} }});
             export const run = resolver.getDefinitions();"
        ),
    );
    let permissions = HashSet::new();
    let mut permission_map = PermMap::new(&permissions);
    let lowered = project.with_files_and_sourceroot(
        Path::new("src"),
        vec![path.clone()],
        &[],
        &mut permission_map,
        &HashSet::new(),
    );
    let module = lowered.ctx.modid_from_path(&path).unwrap();
    let entry = lowered.env.module_export(module, "run").unwrap();
    let factory = crate::interpreter::InterpreterFactory::new(&lowered.env, vec![], None);
    let mut interp = factory.create::<PrototypePollutionChecker>(false);
    let mut checker = PrototypePollutionChecker;
    interp
        .run_checker(entry, &mut checker, path, "run".to_owned())
        .unwrap();
    let handlers = lowered.env.resolver_defs(entry);
    let (_, handler) = handlers.first().unwrap();
    let handler_body = *lowered.env.def_ref(*handler).as_body().unwrap();
    checker
        .visit_body(&interp, *handler, handler_body, &Vec::new())
        .is_break()
}

#[test]
fn prototype_pollution_uses_values_at_the_assignment() {
    for (body, expected) in [
        (
            "const target = {}; target[request.first][request.second] = 1;",
            true,
        ),
        (
            "const target = {}; const first = request.first; const second = request.second; target[first][second] = 1;",
            true,
        ),
        (
            "const target = {}; const first = request.first; const second = request.second; function write() { target[first][second] = 1; } write();",
            true,
        ),
        (
            "function write(first, second) { const target = {}; target[first][second] = 1; } write(request.first, request.second);",
            true,
        ),
        (
            "const target = {}; let first = request.first; let second = request.second; first = 'public'; second = 'public'; target[first][second] = 1;",
            false,
        ),
        (
            "const target = {}; let first = 'public'; let second = 'public'; target[first][second] = 1; first = request.first; second = request.second;",
            false,
        ),
        (
            "function write(first, second) { const target = {}; target[first][second] = 1; } write('public', 'public');",
            false,
        ),
    ] {
        assert_eq!(prototype_pollution_found(body), expected, "source: {body}");
    }
}

#[test]
fn secret_logging_preserves_captures_across_helper_calls() {
    for (functions, expected) in [
        (
            "const value = kvs.getSecret('key'); function log() { console.log(value); } export function run() { const copy = value; log(); }",
            1,
        ),
        (
            "const value = kvs.getSecret('key'); function log() { console.log(value); } export function run() { log(); const copy = value; }",
            1,
        ),
        (
            "const value = kvs.getSecret('key'); function log() { console.log(value); } function pass() { log(); } export function run() { const copy = value; pass(); }",
            1,
        ),
        (
            "let value = kvs.getSecret('key'); function log() { console.log(value); } function pass() { log(); } export function run() { value = 'public'; pass(); }",
            0,
        ),
        (
            "const value = kvs.getSecret('key'); function log() { console.log(value); } export function run() { const value = 'public'; log(); }",
            1,
        ),
    ] {
        let mut project = MockForgeProject::files_from_string("// src/index.js\n");
        project.add_file(
            "src/index.js",
            format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
        );
        let report = scan_directory_test_with_args(
            project,
            Args::parse_from(["fsrt", "--scanners", "secret-logging"]),
        );
        assert!(!report.has_errors());
        assert_eq!(
            report.into_vulns().len(),
            expected,
            "source: {functions}\n{report:#?}"
        );
    }
}
