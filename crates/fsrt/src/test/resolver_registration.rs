//! Resolver callbacks are registered under the function the code names, so every
//! scanner that enumerates a resolver's callbacks analyzes them.

use super::*;

const MANIFEST: &str = "// manifest.yaml
modules:
    macro:
      - key: resolver-macro
        function: main
        title: resolver
        handler: nothing
        description: Resolver backed macro
    function:
      - key: main
        handler: index.handler
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
permissions:
    scopes: []";

fn authz_findings(source: &str) -> usize {
    let files = format!("// src/index.js\n{source}\n{MANIFEST}");
    let project = MockForgeProject::files_from_string(&files);
    let report = scan_directory_test(project);
    report
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name().contains("Authorization"))
        .count()
}

const PREAMBLE: &str = "import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
const resolver = new Resolver();";

const EPILOGUE: &str = "export const handler = resolver.getDefinitions();";

#[test]
fn inline_resolver_callback_is_analyzed() {
    let source = format!(
        "{PREAMBLE}
        resolver.define('getIssue', async () => {{
            return api.asApp().requestJira(route`/rest/api/3/issue/1`);
        }});
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn named_resolver_callback_is_analyzed() {
    let source = format!(
        "{PREAMBLE}
        async function getIssueHandler() {{
            return api.asApp().requestJira(route`/rest/api/3/issue/1`);
        }}
        resolver.define('getIssue', getIssueHandler);
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn named_arrow_resolver_callback_is_analyzed() {
    let source = format!(
        "{PREAMBLE}
        const getIssueHandler = async () => api.asApp().requestJira(route`/rest/api/3/issue/1`);
        resolver.define('getIssue', getIssueHandler);
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn named_and_inline_resolver_callbacks_are_both_analyzed() {
    let source = format!(
        "{PREAMBLE}
        async function namedHandler() {{
            return api.asApp().requestJira(route`/rest/api/3/issue/1`);
        }}
        resolver.define('named', namedHandler);
        resolver.define('inline', async () => {{
            return api.asApp().requestJira(route`/rest/api/3/issue/2`);
        }});
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 2);
}

#[test]
fn member_of_a_known_object_is_analyzed_as_the_resolver_callback() {
    let source = format!(
        "{PREAMBLE}
        const handlers = {{
            async run() {{
                return api.asApp().requestJira(route`/rest/api/3/issue/1`);
            }},
        }};
        resolver.define('run', handlers.run);
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn define_with_a_dynamic_key_or_spread_registers_nothing() {
    for define in [
        "resolver.define(key, getIssueHandler);",
        "resolver.define(...args);",
    ] {
        let source = format!(
            "{PREAMBLE}
            async function getIssueHandler() {{
                return api.asApp().requestJira(route`/rest/api/3/issue/1`);
            }}
            {define}
            {EPILOGUE}"
        );
        assert_eq!(authz_findings(&source), 0, "{define}");
    }
}
