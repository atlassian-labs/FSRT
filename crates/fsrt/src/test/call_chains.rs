//! The call chain a finding reports is read from the frames the interpreter
//! pushes for each call. These pin the text for nested calls, so a change to
//! what a frame records cannot silently rewrite what every scanner prints.
use super::*;

fn proofs(project: MockForgeProject<'_>, scanner: &str) -> Vec<String> {
    let args = Args::parse_from(["fsrt", "--scanners", scanner]);
    let report = scan_directory_test_with_args(project, args);
    report
        .into_vulns()
        .iter()
        .map(|vuln| vuln.proof().to_owned())
        .collect()
}

const MACRO_MANIFEST: &str = "// manifest.yml
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
            scopes: []";

fn macro_source(body: &str) -> String {
    format!(
        "// src/index.jsx
        import ForgeUI, {{ render, Macro, Fragment, Text }} from '@forge/ui';
        import api, {{ route }} from '@forge/api';
        import {{ kvs }} from '@forge/kvs';
        {body}
        function App() {{
            outer();
            logSecret();
            return <Fragment><Text>Hello world!</Text></Fragment>;
        }}
        export const run = render(<Macro app={{<App />}} />);
        {MACRO_MANIFEST}"
    )
}

const NESTED_CALLS: &str = "
        function leaf() { api.asApp().requestJira(route`/rest/api/3/issue`); }
        function middle() { leaf(); }
        function outer() { middle(); }
        async function logSecret() {
            const secret = await kvs.getSecret('key');
            deeper(secret);
        }
        function deeper(value) { console.log(value); }";

#[test]
fn authorization_chain_text_for_nested_calls() {
    let source = macro_source(NESTED_CALLS);
    let proofs = proofs(
        MockForgeProject::files_from_string(&source),
        "authorization",
    );
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    assert!(
        proofs[0].ends_with("found via run -> leaf -> middle -> outer -> App"),
        "{}",
        proofs[0]
    );
}

#[test]
fn secret_logging_chain_text_for_nested_calls() {
    let source = macro_source(NESTED_CALLS);
    let proofs = proofs(
        MockForgeProject::files_from_string(&source),
        "secret-logging",
    );
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    assert!(
        proofs[0].contains("call path: run -> App -> logSecret -> deeper;"),
        "{}",
        proofs[0]
    );
}

#[test]
fn authentication_chain_text_for_nested_calls() {
    let project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import api from '@forge/api';

        function leaf() { api.asApp().requestJira('/rest/api/3/issue/40'); }
        function middle() { leaf(); }
        function outer() { middle(); }
        export const src = () => { outer(); };

        // manifest.yml
        modules:
            webtrigger:
              - key: basic-hello-world
                function: main
            function:
              - key: main
                handler: index.src
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );
    let proofs = proofs(project, "authentication");
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    assert!(
        proofs[0].ends_with("found via src -> leaf -> middle -> outer"),
        "{}",
        proofs[0]
    );
}

#[test]
fn secret_chain_text_for_nested_calls() {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        "import jwt from 'jsonwebtoken';
         function sign(key) { return jwt.sign({}, key); }
         function wrapper() { return sign('hardcoded-key'); }
         export function run() { return wrapper(); }",
    );
    let proofs = proofs(project, "secret");
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    assert!(
        proofs[0].ends_with("found via run -> sign -> wrapper"),
        "{}",
        proofs[0]
    );
}
