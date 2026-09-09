use super::*;

fn scan(source: &str, scanner: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    scan_directory_test_with_args(project, Args::parse_from(["fsrt", "--scanners", scanner]))
}

#[test]
fn captured_headers_respect_property_reassignment() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            const headers = {Authorization: 'Basic ' + process.env.API_TOKEN};
            function send() {
                headers.Authorization = request.publicHeader;
                return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
            }
            return send();
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(0), "{source}\n{report:#?}");
}

#[test]
fn captured_headers_detect_property_reassignment_to_api_token() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            const headers = {Authorization: request.publicHeader};
            function send() {
                headers.Authorization = 'Basic ' + process.env.API_TOKEN;
                return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
            }
            return send();
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
}

#[test]
fn captured_headers_keep_auth_scheme_when_another_property_changes() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            const headers = {Authorization: 'Basic ' + process.env.API_TOKEN};
            function send() {
                headers.Accept = 'application/json';
                return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
            }
            return send();
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
}

#[test]
fn captured_header_overwrites_preserve_branch_alternatives() {
    for (body, expected) in [
        (
            "if (request.clean) { headers.Authorization = request.publicHeader; }",
            1,
        ),
        (
            "if (request.clean) { headers.Authorization = request.publicHeader; } else { headers.Authorization = request.otherHeader; }",
            0,
        ),
        (
            "if (request.clean) { headers.Authorization = request.publicHeader; } else { headers.Authorization = 'Bearer ' + process.env.API_TOKEN; }",
            1,
        ),
        (
            "const alias = headers; alias.Authorization = request.publicHeader;",
            0,
        ),
        (
            "if (request.clean) { console.log('public'); } headers.Authorization = request.publicHeader;",
            0,
        ),
    ] {
        let source = format!(
            "import {{fetch}} from '@forge/api';
             export function run(request) {{
                 const headers = {{Authorization: 'Basic ' + process.env.API_TOKEN}};
                 function send() {{
                     {body}
                     return fetch('https://api.atlassian.com/rest/api/3/issue', {{headers}});
                 }}
                 return send();
             }}"
        );
        let report = scan(&source, "auth-header");
        assert!(
            report.contains_api_token_vuln(expected),
            "{source}\n{report:#?}"
        );
    }
}

#[test]
fn captured_header_reads_use_writes_before_the_fetch() {
    for (initial, body, expected) in [
        (
            "'Basic ' + process.env.API_TOKEN",
            "fetch(url, {headers}); headers.Authorization = request.publicHeader;",
            1,
        ),
        (
            "'Basic ' + process.env.API_TOKEN",
            "headers.Authorization = request.publicHeader; fetch(url, {headers});",
            0,
        ),
        (
            "request.publicHeader",
            "fetch(url, {headers}); headers.Authorization = 'Basic ' + process.env.API_TOKEN;",
            0,
        ),
        (
            "request.publicHeader",
            "headers.Authorization = 'Basic ' + process.env.API_TOKEN; fetch(url, {headers});",
            1,
        ),
        (
            "'Basic hardcoded-key'",
            "fetch(url, {headers}); headers.Authorization = request.publicHeader;",
            1,
        ),
        (
            "'Basic hardcoded-key'",
            "headers.Authorization = request.publicHeader; fetch(url, {headers});",
            0,
        ),
        (
            "'Basic hardcoded-key'",
            "fetch(url, {headers}); headers.Authorization = 'public';",
            1,
        ),
        (
            "'Basic hardcoded-key'",
            "headers.Authorization = 'public'; fetch(url, {headers});",
            0,
        ),
        (
            "'public'",
            "fetch(url, {headers}); headers.Authorization = 'Basic hardcoded-key';",
            0,
        ),
        (
            "'public'",
            "headers.Authorization = 'Basic hardcoded-key'; fetch(url, {headers});",
            1,
        ),
    ] {
        let source = format!(
            "import {{fetch}} from '@forge/api';
             export function run(request) {{
                 const headers = {{Authorization: {initial}}};
                 const url = 'https://api.atlassian.com/rest/api/3/issue';
                 function send() {{ {body} }}
                 return send();
             }}"
        );
        let report = scan(&source, "auth-header");
        assert!(
            report.contains_api_token_vuln(expected),
            "{source}\n{report:#?}"
        );
    }
}

#[test]
fn captured_nested_header_writes_do_not_inherit_sibling_auth_schemes() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            const options = {headers: {}, publicHeaders: {}};
            options.headers.Authorization = 'Basic ' + process.env.API_TOKEN;
            options.publicHeaders.Authorization = request.publicHeader;
            function send() {
                const headers = options.publicHeaders;
                return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
            }
            return send();
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(0), "{source}\n{report:#?}");
}

#[test]
fn captured_header_imports_use_writes_before_the_helper_call() {
    for (initial, body, expected) in [
        (
            "'Basic ' + process.env.API_TOKEN",
            "send(); headers.Authorization = request.publicHeader;",
            1,
        ),
        (
            "'Basic ' + process.env.API_TOKEN",
            "headers.Authorization = request.publicHeader; send();",
            0,
        ),
        (
            "request.publicHeader",
            "send(); headers.Authorization = 'Basic ' + process.env.API_TOKEN;",
            0,
        ),
        (
            "request.publicHeader",
            "headers.Authorization = 'Basic ' + process.env.API_TOKEN; send();",
            1,
        ),
        (
            "'Basic hardcoded-key'",
            "send(); headers.Authorization = 'public';",
            1,
        ),
        (
            "'Basic hardcoded-key'",
            "headers.Authorization = 'public'; send();",
            0,
        ),
        (
            "'public'",
            "send(); headers.Authorization = 'Basic hardcoded-key';",
            0,
        ),
        (
            "'public'",
            "headers.Authorization = 'Basic hardcoded-key'; send();",
            1,
        ),
        (
            "'Basic ' + process.env.API_TOKEN",
            "send(); headers.Authorization = request.publicHeader; send();",
            1,
        ),
        (
            "request.publicHeader",
            "send(); headers.Authorization = 'Basic ' + process.env.API_TOKEN; send();",
            1,
        ),
    ] {
        let source = format!(
            "import {{fetch}} from '@forge/api';
             export function run(request) {{
                 const headers = {{Authorization: {initial}}};
                 function send() {{
                     return fetch('https://api.atlassian.com/rest/api/3/issue', {{headers}});
                 }}
                 {body}
             }}"
        );
        let report = scan(&source, "auth-header");
        assert!(
            report.contains_api_token_vuln(expected),
            "{source}\n{report:#?}"
        );
    }
}

#[test]
fn local_header_branches_keep_a_possible_api_token() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            const headers = {};
            if (request.useApiToken) {
                headers.Authorization = 'Basic ' + process.env.API_TOKEN;
            } else {
                headers.Authorization = request.publicHeader;
            }
            return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
}

#[test]
fn projected_arguments_do_not_inherit_unrelated_auth_scheme() {
    let source = "import {fetch} from '@forge/api';
        function send(headers) {
            return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
        }
        export function run(request) {
            const options = {
                headers: {Authorization: 'Basic ' + process.env.API_TOKEN},
                publicHeaders: {Authorization: request.publicHeader}
            };
            return send(options.publicHeaders);
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(0), "{source}\n{report:#?}");
}
