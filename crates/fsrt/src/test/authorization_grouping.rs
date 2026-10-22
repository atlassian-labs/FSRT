//! An entry is one finding, identified by its first privileged operation, whose
//! proof lists the others; `--authorization-report-operations` reports each one.
use super::*;

fn scan(definitions: &str, report_operations: bool) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
             import api, {{route}} from '@forge/api';
             const resolver = new Resolver();
             async function second(key) {{
                 return api.asApp().requestJira(route`/rest/api/3/issue/${{key}}/comment`, {{method: 'POST'}});
             }}
             {definitions}
             export const handler = resolver.getDefinitions();"
        ),
    );
    project.manifest_file_content = Some(alias_manifest(false));
    let mut args = vec!["fsrt", "--scanners", "authorization"];
    if report_operations {
        args.push("--authorization-report-operations");
    }
    let report = scan_directory_test_with_args(project, Args::parse_from(args));
    assert!(!report.has_errors(), "{report:#?}");
    report
}

const TWO_OPERATIONS: &str = "resolver.define('both', async ({payload}) => {
        await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'PUT'});
        await second(payload.key);
        await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'DELETE'});
        return payload.key;
    });";

#[test]
fn an_entry_is_one_finding_that_lists_its_operations() {
    let report = scan(TWO_OPERATIONS, false);
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 1, "{vulns:#?}");
    let proof = vulns[0].proof();
    assert!(proof.contains("2 more privileged operation(s)"), "{proof}");
    assert!(
        proof.contains("POST /rest/api/3/issue/${}/comment in second"),
        "{proof}"
    );
    assert!(
        proof.contains("DELETE /rest/api/3/issue/${} in "),
        "{proof}"
    );
}

#[test]
fn the_entry_keeps_the_id_of_its_first_operation() {
    let operations = scan(TWO_OPERATIONS, true);
    assert_eq!(operations.into_vulns().len(), 3, "{operations:#?}");
    let grouped = scan(TWO_OPERATIONS, false);
    assert_eq!(
        grouped.into_vulns()[0].check_name(),
        operations.into_vulns()[0].check_name()
    );
}

#[test]
fn separate_entries_stay_separate() {
    let definitions = format!(
        "{TWO_OPERATIONS}
         resolver.define('single', async ({{payload}}) => {{
             await api.asApp().requestJira(route`/rest/api/3/issue/${{payload.key}}`, {{method: 'DELETE'}});
             return payload.key;
         }});"
    );
    let grouped = scan(&definitions, false);
    assert_eq!(grouped.into_vulns().len(), 2, "{grouped:#?}");
    let operations = scan(&definitions, true);
    assert_eq!(operations.into_vulns().len(), 4, "{operations:#?}");
}

#[test]
fn a_suppressed_operation_is_neither_reported_nor_listed() {
    let definitions = "resolver.define('mixed', async ({payload}) => {
        await api.asApp().requestJira(route`/rest/api/3/issuetype`);
        await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'DELETE'});
        return payload.key;
    });";
    let report = scan(definitions, false);
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 1, "{vulns:#?}");
    assert!(
        !vulns[0].proof().contains("more privileged"),
        "{}",
        vulns[0].proof()
    );
}

#[test]
fn operations_in_and_after_a_callback_that_returns_are_all_found() {
    // A `return` inside the callback used to be taken for the resolver's own, so
    // what the callback did, and everything after it, was lost.
    let definitions = "resolver.define('batch', async ({payload}) => {
        await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'DELETE'});
        const rows = await Promise.all(payload.keys.map(async (key) => {
            const response = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
            return response.json();
        }));
        await second(payload.key);
        return rows;
    });";
    let report = scan(definitions, false);
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 1, "{vulns:#?}");
    let proof = vulns[0].proof();
    assert!(proof.contains("2 more privileged operation(s)"), "{proof}");
    assert!(
        proof.contains("GET /rest/api/3/issue/${} in a callback (via handler.batch)"),
        "{proof}"
    );
    assert!(
        proof
            .contains("POST /rest/api/3/issue/${}/comment in second (via handler.batch -> second)"),
        "{proof}"
    );
    // The callback is part of the function that wrote it, not a call in the stack.
    assert!(!proof.contains("__CALLBACK"), "{proof}");
    let operations = scan(definitions, true);
    assert_eq!(operations.into_vulns().len(), 3, "{operations:#?}");
}
