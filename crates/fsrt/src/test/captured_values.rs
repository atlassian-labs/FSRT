use super::*;

fn scan(source: &str, scanner: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    scan_directory_test_with_args(project, Args::parse_from(["fsrt", "--scanners", scanner]))
}

#[test]
fn secret_preserves_module_key_when_caller_also_reads_it() {
    for entry in [
        "return sign(request);",
        "const k = KEY; return sign(request);",
        "console.log(KEY); return sign(request);",
        "const result = sign(request); const k = KEY; return result;",
    ] {
        let source = format!(
            "import jwt from 'jsonwebtoken';
             const KEY = 'hardcoded-key';
             function sign(payload) {{ return jwt.sign(payload, KEY); }}
             export function run(request) {{ {entry} }}"
        );
        let report = scan(&source, "secret");
        assert!(report.contains_secret_vuln(1), "{source}\n{report:#?}");
    }
}

#[test]
fn captures_preserve_module_objects_and_nested_properties() {
    for (declaration, argument, binding) in [
        (
            "const headers = {Authorization: 'Basic hardcoded-key'};",
            "{headers}",
            "headers",
        ),
        (
            "const options = {headers: {Authorization: 'Basic hardcoded-key'}};",
            "options",
            "options",
        ),
        (
            "const original = {headers: {Authorization: 'Basic hardcoded-key'}}; const options = original;",
            "options",
            "options",
        ),
    ] {
        for entry in [
            "return send();".to_string(),
            format!("const copy = {binding}; return send();"),
            format!("console.log({binding}); return send();"),
            format!("const result = send(); const copy = {binding}; return result;"),
        ] {
            let source = format!(
                "import {{fetch}} from '@forge/api';
                 {declaration}
                 function send() {{ return fetch('https://api.atlassian.com/rest/api/3/issue', {argument}); }}
                 export function run() {{ {entry} }}"
            );
            let report = scan(&source, "secret");
            assert!(report.contains_secret_vuln(1), "{source}\n{report:#?}");
            let report = scan(&source, "auth-header");
            assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
        }
    }
}

#[test]
fn secret_preserves_module_key_through_intermediate_captures() {
    let source = "import jwt from 'jsonwebtoken';
        const KEY = 'hardcoded-key';
        function sign(payload) { return jwt.sign(payload, KEY); }
        function forward(payload) { const k = KEY; return sign(payload); }
        export function run(request) { const k = KEY; return forward(request); }";
    let report = scan(source, "secret");
    assert!(report.contains_secret_vuln(1), "{report:#?}");
}

#[test]
fn captures_preserve_caller_assignments_including_unknown_values() {
    for declaration in ["let KEY = 'hardcoded-key';", "let KEY = process.env.KEY;"] {
        let source = format!(
            "import jwt from 'jsonwebtoken';
             {declaration}
             function sign(payload) {{ return jwt.sign(payload, KEY); }}
             export function run(request) {{ KEY = request.key; return sign(request); }}"
        );
        let report = scan(&source, "secret");
        assert!(report.contains_secret_vuln(0), "{source}\n{report:#?}");
    }
}

#[test]
fn captures_preserve_properties_written_by_the_caller() {
    let source = "import {fetch} from '@forge/api';
        const headers = {};
        function send() {
            return fetch('https://api.atlassian.com/rest/api/3/issue', {headers});
        }
        export function run() {
            headers.Authorization = 'Basic hardcoded-key';
            return send();
        }";
    let report = scan(source, "secret");
    assert!(report.contains_secret_vuln(1), "{report:#?}");
    let report = scan(source, "auth-header");
    assert!(report.contains_api_token_vuln(1), "{report:#?}");
}

#[test]
fn secret_preserves_captured_imports() {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/config.js", "export const KEY = 'hardcoded-key';");
    project.add_file(
        "src/index.js",
        "import jwt from 'jsonwebtoken';
         import {KEY} from './config';
         function sign(payload) { return jwt.sign(payload, KEY); }
         export function run(request) { const k = KEY; return sign(request); }",
    );
    let report =
        scan_directory_test_with_args(project, Args::parse_from(["fsrt", "--scanners", "secret"]));
    assert!(report.contains_secret_vuln(1), "{report:#?}");
}

#[test]
fn captures_preserve_dynamic_auth_headers_and_url_origins() {
    for header in [
        "'Basic ' + process.env.API_TOKEN",
        "`Basic ${process.env.API_TOKEN}`",
    ] {
        let source = format!(
            "import {{fetch}} from '@forge/api';
             const url = `https://api.atlassian.com/rest/api/3/issue/${{process.env.ISSUE}}`;
             const headers = {{Authorization: {header}}};
             function send() {{ return fetch(url, {{headers}}); }}
             export function run() {{ console.log(url); const copy = headers; return send(); }}"
        );
        let report = scan(&source, "auth-header");
        assert!(report.contains_api_token_vuln(1), "{source}\n{report:#?}");
        let report = scan(&source, "secret");
        assert!(report.contains_secret_vuln(0), "{source}\n{report:#?}");
    }
}
