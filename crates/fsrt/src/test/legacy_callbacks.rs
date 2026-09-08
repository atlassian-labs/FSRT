use super::*;

fn scan(source: &str, scanner: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    let args = ["fsrt", "--scanners", scanner];
    scan_directory_test_with_args(project, Args::parse_from(args))
}

#[test]
fn legacy_secret_binds_each_formal_once() {
    for (declaration, arguments) in [
        ("payload, key", "request, 'hardcoded-key'"),
        ("{payload}, key", "request, 'hardcoded-key'"),
        ("payload, {key}", "request, {key: 'hardcoded-key'}"),
    ] {
        let source = format!(
            "import jwt from 'jsonwebtoken';
                 function sign({declaration}) {{ return jwt.sign(payload, key); }}
                 export function run(request) {{ return sign({arguments}); }}"
        );
        let report = scan(&source, "secret");
        assert!(report.contains_secret_vuln(1), "{source}\n{report:#?}");
    }
}

#[test]
fn legacy_fulfillment_preserves_captured_headers() {
    for callback in [
        "() => fetch(url, {headers})",
        "function () { return fetch(url, {headers}); }",
        "() => Promise.resolve().then(() => fetch(url, {headers}))",
    ] {
        let source = format!(
            "import {{fetch}} from '@forge/api';
             export function run() {{
                 const url = 'https://api.atlassian.com/rest/api/3/issue';
                 const headers = {{Authorization: 'Basic ' + process.env.API_TOKEN}};
                 return Promise.resolve().then({callback});
             }}"
        );
        let report = scan(&source, "auth-header");
        assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
    }
}

#[test]
fn legacy_fulfillment_preserves_captured_secret_and_nested_objects() {
    for body in [
        "const key = 'hardcoded-key'; Promise.resolve().then(() => jwt.sign(request, key));",
        "const options = {headers: {Authorization: 'Basic hardcoded-key'}}; Promise.resolve().then(() => fetch('https://api.atlassian.com/rest/api/3/issue', options));",
    ] {
        let source = format!(
            "import jwt from 'jsonwebtoken'; import {{fetch}} from '@forge/api';
             export function run(request) {{ {body} }}"
        );
        let report = scan(&source, "secret");
        assert!(report.contains_secret_vuln(1), "{source}\n{report:#?}");
    }
}

#[test]
fn legacy_fulfillment_uses_reassigned_headers() {
    let source = "import {fetch} from '@forge/api';
        export function run(request) {
            let headers = {Authorization: 'Basic ' + process.env.API_TOKEN};
            return Promise.resolve().then(() => {
                headers = {Authorization: request.publicHeader};
                return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
            });
        }";
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(0), "{source}\n{report:#?}");
}
