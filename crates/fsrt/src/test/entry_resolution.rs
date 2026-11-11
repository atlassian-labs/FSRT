//! A manifest handler is followed to the function it names even when the entry file only
//! forwards it (`export { handler } from`, `export *`, `import` + `export`) or reaches it
//! through a directory index or a dotted file name. Entrypoints that still cannot be
//! followed are reported as coverage notes instead of silently dropped.

use super::*;

const MANIFEST: &str = "modules:
    macro:
      - key: resolver-macro
        function: main
        title: resolver
        handler: nothing
        description: Resolver backed macro
    function:
      - key: main
        handler: HANDLER
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
permissions:
    scopes: []";

/// A module whose `handler` export reaches an unguarded `asApp` request.
const RESOLVERS: &str = "import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
const resolver = new Resolver();
resolver.define('getIssue', async () => {
    return api.asApp().requestJira(route`/rest/api/3/issue/1`);
});
export const handler = resolver.getDefinitions();";

/// A second module that also exports an unguarded `handler`, but a different one.
const OTHER_RESOLVERS: &str = "import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
const resolver = new Resolver();
resolver.define('getProject', async () => {
    return api.asApp().requestJira(route`/rest/api/3/project/1`);
});
export const handler = resolver.getDefinitions();";

/// A module whose default export is an unguarded handler function.
const DEFAULT_FUNCTION: &str = "import api, { route } from '@forge/api';
export default async function () {
    return api.asApp().requestJira(route`/rest/api/3/issue/1`);
}";

fn scan_files(files: &[(&str, &str)], manifest_handler: &str) -> Report {
    let mut project = String::new();
    for (path, source) in files {
        project.push_str(&format!("// {path}\n{source}\n"));
    }
    let manifest = MANIFEST.replace("HANDLER", manifest_handler);
    project.push_str(&format!("// manifest.yaml\n{manifest}"));
    scan_directory_test(MockForgeProject::files_from_string(&project))
}

fn authz_findings(files: &[(&str, &str)]) -> usize {
    authz_findings_for(files, "index.handler")
}

fn authz_findings_for(files: &[(&str, &str)], manifest_handler: &str) -> usize {
    scan_files(files, manifest_handler)
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name().contains("Authorization"))
        .count()
}

fn coverage_reasons(files: &[(&str, &str)]) -> Vec<String> {
    scan_files(files, "index.handler")
        .coverage_notes()
        .iter()
        .map(|note| note.reason.clone())
        .collect()
}

#[test]
fn manifest_handler_pointing_at_the_defining_file_is_analyzed() {
    let files = [("src/resolvers.js", RESOLVERS)];
    assert_eq!(authz_findings_for(&files, "resolvers.handler"), 1);
}

#[test]
fn named_reexport_from_a_file_is_followed() {
    let files = [
        ("src/index.js", "export { handler } from './resolvers';"),
        ("src/resolvers.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn named_reexport_from_a_directory_index_is_followed() {
    let files = [
        ("src/index.js", "export { handler } from './resolvers';"),
        ("src/resolvers/index.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn export_star_is_followed() {
    let files = [
        ("src/index.js", "export * from './resolvers';"),
        ("src/resolvers.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn import_then_export_is_followed() {
    let files = [
        (
            "src/index.js",
            "import { handler } from './resolvers';\nexport { handler };",
        ),
        ("src/resolvers.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn import_of_a_directory_index_path_then_export_is_followed() {
    let files = [
        (
            "src/index.js",
            "import { handler } from './resolvers/index';\nexport { handler };",
        ),
        ("src/resolvers/index.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn import_of_a_directory_then_export_is_followed() {
    let files = [
        (
            "src/index.js",
            "import { handler } from './resolvers';\nexport { handler };",
        ),
        ("src/resolvers/index.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn reexport_from_a_dotted_file_name_is_followed() {
    let files = [
        ("src/index.ts", "export { handler } from './a.service';"),
        ("src/a.service.ts", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn reexport_under_a_different_name_is_followed() {
    let files = [
        (
            "src/index.js",
            "export { main as handler } from './resolvers';",
        ),
        (
            "src/resolvers.js",
            &RESOLVERS.replace("export const handler", "export const main"),
        ),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn reexport_of_a_default_export_as_handler_is_followed() {
    let files = [
        (
            "src/index.js",
            "export { default as handler } from './resolvers';",
        ),
        ("src/resolvers.js", DEFAULT_FUNCTION),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn reexport_chain_through_several_modules_is_followed() {
    let files = [
        ("src/index.js", "export * from './a';"),
        ("src/a.js", "export { handler } from './b';"),
        ("src/b/index.js", "export * from './c';"),
        ("src/b/c.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn own_export_wins_over_export_star() {
    let files = [
        (
            "src/index.js",
            "export * from './other';\nexport { handler } from './resolvers';",
        ),
        ("src/other.js", OTHER_RESOLVERS),
        ("src/resolvers.js", RESOLVERS),
    ];
    // exactly one of the two resolvers is analyzed: the explicit re-export
    let report = scan_files(&files, "index.handler");
    let descriptions: Vec<_> = report
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name().contains("Authorization"))
        .map(|vuln| vuln.proof().to_owned())
        .collect();
    assert_eq!(descriptions.len(), 1);
    assert!(descriptions[0].contains("getIssue"), "{descriptions:?}");
}

#[test]
fn file_wins_over_directory_of_the_same_name() {
    let files = [
        ("src/index.js", "export { handler } from './resolvers';"),
        ("src/resolvers.js", RESOLVERS),
        ("src/resolvers/index.js", OTHER_RESOLVERS),
    ];
    let report = scan_files(&files, "index.handler");
    let proofs: Vec<_> = report
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name().contains("Authorization"))
        .map(|vuln| vuln.proof().to_owned())
        .collect();
    assert_eq!(proofs.len(), 1);
    assert!(proofs[0].contains("getIssue"), "{proofs:?}");
}

#[test]
fn export_star_supplying_the_same_name_twice_is_ambiguous_and_unresolved() {
    let files = [
        (
            "src/index.js",
            "export * from './one';\nexport * from './two';",
        ),
        ("src/one.js", RESOLVERS),
        ("src/two.js", OTHER_RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 0);
    assert_eq!(
        coverage_reasons(&files),
        vec!["no export named `handler` could be found in src/index.js"]
    );
}

#[test]
fn export_star_reaching_the_same_binding_twice_is_not_ambiguous() {
    let files = [
        (
            "src/index.js",
            "export * from './one';\nexport * from './two';",
        ),
        ("src/one.js", "export { handler } from './resolvers';"),
        ("src/two.js", "export * from './resolvers';"),
        ("src/resolvers.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 1);
}

#[test]
fn export_star_does_not_forward_the_default_export() {
    let files = [
        ("src/index.js", "export * from './resolvers';"),
        ("src/resolvers.js", DEFAULT_FUNCTION),
    ];
    assert_eq!(authz_findings_for(&files, "index.default"), 0);
}

#[test]
fn circular_reexport_terminates_without_findings() {
    let files = [
        ("src/index.js", "export { handler } from './a';"),
        ("src/a.js", "export { handler } from './b';"),
        ("src/b.js", "export { handler } from './a';"),
    ];
    assert_eq!(authz_findings(&files), 0);
    assert_eq!(coverage_reasons(&files).len(), 1);
}

#[test]
fn circular_export_star_terminates_without_findings() {
    let files = [
        ("src/index.js", "export * from './a';"),
        ("src/a.js", "export * from './b';"),
        ("src/b.js", "export * from './a';"),
    ];
    assert_eq!(authz_findings(&files), 0);
}

#[test]
fn reexport_chain_deeper_than_the_depth_limit_is_left_unresolved() {
    let mut files = vec![(
        "src/index.js".to_owned(),
        "export * from './m0';".to_owned(),
    )];
    for i in 0..12 {
        files.push((
            format!("src/m{i}.js"),
            format!("export * from './m{}';", i + 1),
        ));
    }
    files.push(("src/m12.js".to_owned(), RESOLVERS.to_owned()));
    let files: Vec<_> = files
        .iter()
        .map(|(p, s)| (p.as_str(), s.as_str()))
        .collect();
    assert_eq!(authz_findings(&files), 0);
}

/// Known gap, deliberately out of scope: re-exporting through a new local binding.
#[test]
fn export_const_alias_of_an_imported_binding_is_still_unresolved() {
    let files = [
        (
            "src/index.js",
            "import { handler as h } from './resolvers';\nexport const handler = h;",
        ),
        ("src/resolvers.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 0);
    assert_eq!(coverage_reasons(&files).len(), 1);
}

#[test]
fn bare_package_specifier_never_resolves_to_a_directory_index() {
    let files = [
        ("src/index.js", "export { handler } from 'resolvers';"),
        ("src/resolvers/index.js", RESOLVERS),
    ];
    assert_eq!(authz_findings(&files), 0);
}

#[test]
fn missing_handler_file_is_reported_as_a_coverage_note() {
    let files = [("src/other.js", RESOLVERS)];
    let report = scan_files(&files, "index.handler");
    let notes = report.coverage_notes();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].function_key, "main");
    assert_eq!(notes[0].handler, "index.handler");
    assert_eq!(
        notes[0].reason,
        "the handler file was not found in the app source"
    );
}

#[test]
fn missing_export_is_reported_as_a_coverage_note() {
    let files = [("src/index.js", RESOLVERS)];
    let report = scan_files(&files, "index.missing");
    let notes = report.coverage_notes();
    assert_eq!(notes.len(), 1);
    assert_eq!(
        notes[0].reason,
        "no export named `missing` could be found in src/index.js"
    );
}

#[test]
fn export_that_is_not_a_function_is_reported_as_a_coverage_note() {
    let files = [(
        "src/index.js",
        "import Resolver from '@forge/resolver';\nconst resolver = new Resolver();\nexport const handler = resolver.getDefinitions();",
    )];
    assert_eq!(
        coverage_reasons(&files),
        vec![
            "`handler` in src/index.js is neither a function nor a resolver with registered callbacks"
        ]
    );
}

#[test]
fn resolved_entrypoints_produce_no_coverage_notes() {
    let files = [
        ("src/index.js", "export { handler } from './resolvers';"),
        ("src/resolvers/index.js", RESOLVERS),
    ];
    assert!(coverage_reasons(&files).is_empty());
}

#[test]
fn coverage_notes_are_serialized_only_when_present() {
    let resolved = [("src/index.js", RESOLVERS)];
    let json = serde_json::to_value(scan_files(&resolved, "index.handler")).unwrap();
    assert!(json.get("coverage_notes").is_none());

    let json = serde_json::to_value(scan_files(&resolved, "index.missing")).unwrap();
    assert_eq!(json["coverage_notes"][0]["function_key"], "main");
}
