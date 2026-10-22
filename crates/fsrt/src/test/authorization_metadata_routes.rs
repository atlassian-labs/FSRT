//! A GET of instance configuration metadata is not reported; everything else on
//! the same route class, and every request whose method or route is not proven,
//! still is.
use super::*;

fn scan_resolver(body: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
             import api, {{route}} from '@forge/api';
             const resolver = new Resolver();
             resolver.define('probe', async ({{payload}}) => {{
                 {body}
             }});
             export const handler = resolver.getDefinitions();"
        ),
    );
    project.manifest_file_content = Some(alias_manifest(false));
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(!report.has_errors(), "{report:#?}");
    report
}

fn returns(request: &str) -> String {
    format!("const response = await {request}; return response.json();")
}

#[test]
fn metadata_gets_are_not_reported() {
    for request in [
        "api.asApp().requestJira(route`/rest/api/3/field`)",
        "api.asApp().requestJira(route`/rest/api/2/field/search?query=${payload.query}`)",
        "api.asApp().requestJira(route`/rest/api/3/issue/createmeta?projectKeys=${payload.key}`, {method: 'GET'})",
        "api.asApp().requestJira(route`/rest/api/3/project/search`)",
        "api.asApp().requestJira(route`/rest/api/3/project/${payload.key}/statuses`)",
        "api.asApp().requestJira(route`/rest/api/3/field/${payload.id}/context`)",
        "api.asApp().requestJira(route`/rest/agile/1.0/board?name=${payload.name}`)",
        "api.asApp().requestConfluence(route`/wiki/api/v2/spaces?limit=25`)",
        "api.asApp().requestJira('/rest/api/3/status')",
    ] {
        let report = scan_resolver(&returns(request));
        assert!(report.contains_authz_vuln(0), "{request}\n{report:#?}");
    }
}

#[test]
fn metadata_routes_are_reported_for_other_methods_and_unproven_methods() {
    for request in [
        "api.asApp().requestJira(route`/rest/api/3/field`, {method: 'POST', body: JSON.stringify(payload.field)})",
        "api.asApp().requestJira(route`/rest/api/3/issuetype`, {method: 'DELETE'})",
        "api.asApp().requestJira(route`/rest/api/3/project/search`, {method: payload.method})",
        "api.asApp().requestJira(route`/rest/api/3/project/search`, payload.options)",
        "api.asApp().requestJira(route`/rest/api/3/project/search`, {...payload.options})",
        "api.asApp().requestConfluence(route`/wiki/api/v2/spaces`, {method: 'POST'})",
    ] {
        let report = scan_resolver(&returns(request));
        assert!(report.contains_authz_vuln(1), "{request}\n{report:#?}");
    }
}

#[test]
fn resources_and_unproven_routes_are_reported() {
    for request in [
        "api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)",
        "api.asApp().requestJira(route`/rest/api/3/project/${payload.key}`)",
        "api.asApp().requestJira(route`/rest/api/3/project/${payload.key}/role`)",
        "api.asApp().requestJira(route`/rest/api/3/field/${payload.id}`)",
        "api.asApp().requestJira(route`/rest/api/3/search/jql?jql=${payload.jql}`)",
        "api.asApp().requestJira(route`/rest/api/3/${payload.path}`)",
        "api.asApp().requestJira(route`/rest/api/3/fieldset`)",
        "api.asApp().requestJira(payload.route)",
        "api.asApp().requestJira(route`/rest/api/3/field/search/extra`)",
        "api.asApp().requestConfluence(route`/wiki/api/v2/pages/${payload.id}`)",
    ] {
        let report = scan_resolver(&returns(request));
        assert!(report.contains_authz_vuln(1), "{request}\n{report:#?}");
    }
}

#[test]
fn a_metadata_lookup_does_not_hide_the_write_that_follows() {
    let report = scan_resolver(
        "const fields = await api.asApp().requestJira(route`/rest/api/3/field`);
         const created = await api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST', body: JSON.stringify(payload.issue)});
         return created.json();",
    );
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}

#[test]
fn const_bound_routes_are_classified_like_inline_routes() {
    for (preamble, finding) in [
        ("const fields = route`/rest/api/3/field`;", 0),
        ("const FIELDS = '/rest/api/3/field';", 0),
        ("const issue = route`/rest/api/3/issue/ONE`;", 1),
        // `let` can be reassigned, so the route is unknown.
        ("let fields = route`/rest/api/3/field`;", 1),
    ] {
        let name = preamble.split(' ').nth(1).unwrap();
        let mut project = MockForgeProject::files_from_string("// src/index.js\n");
        project.add_file(
            "src/index.js",
            format!(
                "import Resolver from '@forge/resolver';
                 import api, {{route}} from '@forge/api';
                 const resolver = new Resolver();
                 {preamble}
                 resolver.define('probe', async () => {{
                     const response = await api.asApp().requestJira({name});
                     return response.json();
                 }});
                 export const handler = resolver.getDefinitions();"
            ),
        );
        project.manifest_file_content = Some(alias_manifest(false));
        let report = scan_directory_test_with_args(
            project,
            Args::parse_from(["fsrt", "--scanners", "authorization"]),
        );
        assert!(
            report.contains_authz_vuln(finding),
            "{preamble}\n{report:#?}"
        );
    }
}
