use super::*;

/// Scans `body` (the contents of `run`, plus any helpers in `helpers`) with the authorization
/// scanner and returns `(check_name, proof)` for every finding.
fn authz_findings(helpers: &str, body: &str) -> Vec<(String, String)> {
    let source = format!(
        "// src/index.jsx
        import ForgeUI, {{ render, Macro, Fragment, Text }} from '@forge/ui';
        import api, {{ route, authorize }} from '@forge/api';
        {helpers}
        async function body(req) {{
            {body}
        }}
        function App() {{
            body({{}});
            return (<Fragment><Text>x</Text></Fragment>);
        }}
        export const run = render(<Macro app={{<App />}} />);

        // manifest.yaml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []"
    );
    let project = MockForgeProject::files_from_string(&source);
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(!report.has_errors(), "{report:#?}");
    let json = serde_json::to_value(&report).unwrap();
    json["vulns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vuln| {
            (
                vuln["check_name"].as_str().unwrap().to_owned(),
                vuln["proof"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

const HELPERS: &str = "
    async function readIssue() {
        return api.asApp().requestJira(route`/rest/api/3/issue/1`);
    }
    async function writeIssue(method) {
        return api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: 'POST' });
    }
    async function putIssue() {
        return api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: 'PUT' });
    }
    async function deleteIssue() {
        return api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: 'DELETE' });
    }
    async function unknownIssue(req) {
        return api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: req.method });
    }
";

fn only(findings: &[(String, String)]) -> &(String, String) {
    assert_eq!(findings.len(), 1, "{findings:#?}");
    &findings[0]
}

#[test]
fn get_then_write_reports_the_write() {
    let findings = authz_findings(HELPERS, "await readIssue(); await writeIssue();");
    assert!(
        only(&findings).1.contains("run -> writeIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn write_then_get_reports_the_write() {
    let findings = authz_findings(HELPERS, "await writeIssue(); await readIssue();");
    assert!(
        only(&findings).1.contains("run -> writeIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn get_only_reports_the_first_get() {
    let findings = authz_findings(HELPERS, "await readIssue(); await readIssue();");
    assert!(
        only(&findings).1.contains("run -> readIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn writes_only_report_the_earliest_write() {
    let findings = authz_findings(HELPERS, "await deleteIssue(); await writeIssue();");
    assert!(
        only(&findings).1.contains("run -> deleteIssue ->"),
        "{findings:#?}"
    );
    let findings = authz_findings(HELPERS, "await putIssue(); await deleteIssue();");
    assert!(
        only(&findings).1.contains("run -> putIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn unknown_method_is_not_a_write() {
    // A method the analyzer cannot resolve to a literal is not shown to write, so it ranks with
    // GET: the earliest of the two is reported, and a later write still wins.
    let findings = authz_findings(HELPERS, "await unknownIssue(req); await readIssue();");
    assert!(
        only(&findings).1.contains("run -> unknownIssue ->"),
        "{findings:#?}"
    );
    let findings = authz_findings(HELPERS, "await readIssue(); await unknownIssue(req);");
    assert!(
        only(&findings).1.contains("run -> readIssue ->"),
        "{findings:#?}"
    );
    let findings = authz_findings(HELPERS, "await unknownIssue(req); await deleteIssue();");
    assert!(
        only(&findings).1.contains("run -> deleteIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn inline_method_in_the_resolver_body_is_read() {
    let findings = authz_findings(
        "",
        "await api.asApp().requestJira(route`/rest/api/3/issue/1`);
         await api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: 'patch' });
         await api.asApp().requestJira(route`/rest/api/3/issue/2`, { method: 'DELETE' });",
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn authorized_write_does_not_displace_an_earlier_get() {
    let findings = authz_findings(
        &format!(
            "{HELPERS}
             async function guarded() {{
                 await authorize().onJiraIssue(1).canEdit();
                 return writeIssue();
             }}"
        ),
        "await readIssue(); await guarded();",
    );
    assert!(
        only(&findings).1.contains("run -> readIssue ->"),
        "{findings:#?}"
    );
}

#[test]
fn finding_identity_follows_the_reporting_call_stack() {
    let get_only = authz_findings(HELPERS, "await readIssue();");
    let get_then_write = authz_findings(HELPERS, "await readIssue(); await writeIssue();");
    let write_only = authz_findings(HELPERS, "await writeIssue();");
    // The reported finding is the write, and it is the finding the resolver has on its own with
    // only the write, not the one it has with only the GET.
    assert_ne!(only(&get_only).0, only(&get_then_write).0);
    assert_eq!(only(&get_then_write).0, only(&write_only).0);
}

#[test]
fn finding_identity_does_not_distinguish_calls_made_from_the_same_function() {
    // The check name hashes the file, the entry function and the names of the functions on the
    // call stack. It does not hash the call's location or method, so a GET and a write issued
    // directly from the same function share one check name.
    let get_only = authz_findings(
        "",
        "await api.asApp().requestJira(route`/rest/api/3/issue/1`);",
    );
    let get_then_write = authz_findings(
        "",
        "await api.asApp().requestJira(route`/rest/api/3/issue/1`);
         await api.asApp().requestJira(route`/rest/api/3/issue/1`, { method: 'DELETE' });",
    );
    assert_eq!(only(&get_only).0, only(&get_then_write).0);
}

const FIELDS: &str = "
    async function readFields() {
        return api.asApp().requestJira(route`/rest/api/3/field`);
    }
";

#[test]
fn a_suppressed_read_neither_displaces_nor_ends_the_walk() {
    let helpers = format!("{HELPERS}{FIELDS}");
    // A GET of instance metadata is not a finding (instance-metadata-route): after a GET that
    // is one, the first GET stays the entry's finding.
    let get = authz_findings(&helpers, "await readIssue();");
    let get_then_metadata = authz_findings(&helpers, "await readIssue(); await readFields();");
    assert_eq!(only(&get), only(&get_then_metadata));
    // Before a GET that is one, it changes nothing either.
    let metadata_then_get = authz_findings(&helpers, "await readFields(); await readIssue();");
    assert_eq!(only(&get), only(&metadata_then_get));
    // And a write that follows both is the finding, whatever came before it.
    let write = authz_findings(&helpers, "await writeIssue();");
    let all = authz_findings(
        &helpers,
        "await readFields(); await readIssue(); await readFields(); await writeIssue();",
    );
    assert_eq!(only(&write), only(&all));
    assert_ne!(only(&get).0, only(&all).0);
}

#[test]
fn a_read_after_the_write_is_not_reported() {
    let helpers = format!("{HELPERS}{FIELDS}");
    let write = authz_findings(&helpers, "await writeIssue();");
    let write_then_reads = authz_findings(
        &helpers,
        "await writeIssue(); await readIssue(); await readFields();",
    );
    assert_eq!(only(&write), only(&write_then_reads));
}
