//! Request method and route are read from the call's arguments, including `const`
//! bindings, and every unprovable form stays the most privileged alternative.
//! The instance-metadata exemption is used as the observable policy: it only
//! applies to requests proven to be GETs of a metadata route.
use super::*;

fn scan_probe(preamble: &str, request: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
             import api, {{route}} from '@forge/api';
             const resolver = new Resolver();
             {preamble}
             resolver.define('probe', async ({{payload}}) => {{
                 await {request};
                 return 'done';
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

#[test]
fn request_method_is_read_from_inline_and_const_options() {
    for (preamble, request, findings) in [
        ("", "api.asApp().requestJira(route`/rest/api/3/field`)", 0),
        (
            "const read = { method: 'get', headers: { Accept: 'application/json' } };",
            "api.asApp().requestJira(route`/rest/api/3/field`, read)",
            0,
        ),
        // The route carries caller data: a write that carries none is not reported
        // by any policy (authorization_flow.rs).
        (
            "const write = { method: 'POST' };",
            "api.asApp().requestJira(route`/rest/api/3/field/${payload.key}`, write)",
            1,
        ),
        (
            "const route_ = '/rest/api/3/field';",
            "api.asApp().requestJira(route_)",
            0,
        ),
    ] {
        let report = scan_probe(preamble, request);
        assert!(
            report.contains_authz_vuln(findings),
            "{preamble} {request}\n{report:#?}"
        );
    }
}

#[test]
fn request_method_is_unknown_when_it_cannot_be_proven() {
    for (preamble, request) in [
        // Not `const`: the binding may be reassigned.
        (
            "let options = { method: 'GET' };",
            "api.asApp().requestJira(route`/rest/api/3/field`, options)",
        ),
        // A spread can supply the method.
        (
            "const options = { ...payload };",
            "api.asApp().requestJira(route`/rest/api/3/field`, options)",
        ),
        (
            "const options = { method: payload.method };",
            "api.asApp().requestJira(route`/rest/api/3/field`, options)",
        ),
        (
            "const options = { ['method']: 'DELETE' };",
            "api.asApp().requestJira(route`/rest/api/3/field`, options)",
        ),
        (
            "const options = { __proto__: { method: 'DELETE' } };",
            "api.asApp().requestJira(route`/rest/api/3/field`, options)",
        ),
        (
            "",
            "api.asApp().requestJira(route`/rest/api/3/field`, {method: 'GET'}, extra)",
        ),
        (
            "const args = [route`/rest/api/3/field`];",
            "api.asApp().requestJira(...args)",
        ),
    ] {
        let report = scan_probe(preamble, request);
        assert!(
            report.contains_authz_vuln(1),
            "{preamble} {request}\n{report:#?}"
        );
    }
}
