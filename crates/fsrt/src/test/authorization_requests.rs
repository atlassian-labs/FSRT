//! Request method and route are read from the call's arguments, including `const`
//! bindings, and every unprovable form stays the most privileged alternative.
//! The constant-return resolver exemption is used as the observable policy: it
//! only applies to requests proven to be GETs.
use super::*;

fn scan_constant_return(preamble: &str, request: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
             import api, {{route}} from '@forge/api';
             const resolver = new Resolver();
             {preamble}
             resolver.define('probe', async ({{payload}}) => {{
                 let outcome = 1;
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
        (
            "",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`)",
            0,
        ),
        (
            "const read = { method: 'get', headers: { Accept: 'application/json' } };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, read)",
            0,
        ),
        (
            "const write = { method: 'POST' };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, write)",
            1,
        ),
        (
            "const route_ = '/rest/api/3/issue/ONE';",
            "api.asApp().requestJira(route_)",
            0,
        ),
    ] {
        let report = scan_constant_return(preamble, request);
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
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, options)",
        ),
        // A spread can supply the method.
        (
            "const options = { ...payload };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, options)",
        ),
        (
            "const options = { method: payload.method };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, options)",
        ),
        (
            "const options = { ['method']: 'DELETE' };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, options)",
        ),
        (
            "const options = { __proto__: { method: 'DELETE' } };",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, options)",
        ),
        (
            "",
            "api.asApp().requestJira(route`/rest/api/3/issue/ONE`, {method: 'GET'}, extra)",
        ),
        (
            "const args = [route`/rest/api/3/issue/ONE`];",
            "api.asApp().requestJira(...args)",
        ),
    ] {
        let report = scan_constant_return(preamble, request);
        assert!(
            report.contains_authz_vuln(1),
            "{preamble} {request}\n{report:#?}"
        );
    }
}
