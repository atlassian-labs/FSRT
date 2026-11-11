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

#[test]
fn resolver_registered_inside_an_iife_is_analyzed() {
    for iife in [
        "(() => { DEFINE })()",
        "(function () { DEFINE })()",
        "(async () => { DEFINE })()",
    ] {
        let define = "resolver.define('run', async () => api.asApp().requestJira(route`/rest/api/3/issue/1`));";
        let iife = iife.replace("DEFINE", define);
        let source = format!(
            "{PREAMBLE}
            const init = {iife};
            {EPILOGUE}"
        );
        assert_eq!(authz_findings(&source), 1, "{iife}");
    }
}

const MAKE_RESOLVER_PREAMBLE: &str = "import { makeResolver } from '@forge/resolver';
import api, { route } from '@forge/api';";

const ISSUE_REQUEST: &str = "api.asApp().requestJira(route`/rest/api/3/issue/1`)";

#[test]
fn make_resolver_callbacks_are_analyzed() {
    for properties in [
        format!("getIssue: async () => {ISSUE_REQUEST}"),
        format!("getIssue: async function () {{ return {ISSUE_REQUEST}; }}"),
        format!("async getIssue() {{ return {ISSUE_REQUEST}; }}"),
        "getIssue: getIssueHandler".to_string(),
        "getIssue".to_string(),
    ] {
        let source = format!(
            "{MAKE_RESOLVER_PREAMBLE}
            async function getIssue() {{ return {ISSUE_REQUEST}; }}
            function getIssueHandler() {{ return {ISSUE_REQUEST}; }}
            export const handler = makeResolver({{ {properties} }});"
        );
        assert_eq!(authz_findings(&source), 1, "{properties}");
    }
}

#[test]
fn make_resolver_registers_every_property() {
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        async function named() {{ return {ISSUE_REQUEST}; }}
        export const handler = makeResolver({{
            named,
            inline: async () => {ISSUE_REQUEST},
            method() {{ return {ISSUE_REQUEST}; }},
        }});"
    );
    assert_eq!(authz_findings(&source), 3);
}

#[test]
fn make_resolver_follows_a_renamed_import() {
    let source = format!(
        "import {{ makeResolver as create }} from '@forge/resolver';
        import api, {{ route }} from '@forge/api';
        export const handler = create({{ getIssue: async () => {ISSUE_REQUEST} }});"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn make_resolver_not_imported_from_forge_resolver_registers_nothing() {
    let source = format!(
        "import api, {{ route }} from '@forge/api';
        function makeResolver(handlers) {{ return handlers; }}
        export const handler = makeResolver({{ getIssue: async () => {ISSUE_REQUEST} }});"
    );
    assert_eq!(authz_findings(&source), 0);
}

#[test]
fn make_resolver_with_a_dynamic_key_or_spread_registers_nothing_for_it() {
    for properties in ["[key]: async () => REQUEST", "...handlers"] {
        let properties = properties.replace("REQUEST", ISSUE_REQUEST);
        let source = format!(
            "{MAKE_RESOLVER_PREAMBLE}
            const key = 'getIssue';
            const handlers = {{}};
            export const handler = makeResolver({{ {properties} }});"
        );
        assert_eq!(authz_findings(&source), 0, "{properties}");
    }
}

#[test]
fn arrow_property_of_an_object_literal_is_lowered() {
    let source = format!(
        "{PREAMBLE}
        const helpers = {{
            fetchIssue: async () => {ISSUE_REQUEST},
        }};
        resolver.define('getIssue', async () => helpers.fetchIssue());
        {EPILOGUE}"
    );
    assert_eq!(authz_findings(&source), 1);
}

fn make_resolver_config_findings(config: &str, handler: &str) -> usize {
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        async function getIssue() {{ return {ISSUE_REQUEST}; }}
        {config}
        {handler}"
    );
    authz_findings(&source)
}

#[test]
fn make_resolver_with_an_identifier_analyzes_the_object_callbacks() {
    for config in [
        format!("const config = {{ getIssue: async () => {ISSUE_REQUEST} }};"),
        format!("const config = {{ async getIssue() {{ return {ISSUE_REQUEST}; }} }};"),
        "const config = { getIssue };".to_string(),
        "const config = { getIssue: getIssue };".to_string(),
        format!("export const config = {{ getIssue: async () => {ISSUE_REQUEST} }};"),
    ] {
        for handler in [
            "export const handler = makeResolver(config);",
            "const handler = makeResolver(config); export { handler };",
        ] {
            assert_eq!(
                make_resolver_config_findings(&config, handler),
                1,
                "{config} {handler}"
            );
        }
    }
}

#[test]
fn make_resolver_with_an_identifier_declared_later_analyzes_the_object_callbacks() {
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        export const handler = makeResolver(config);
        var config = {{ getIssue: async () => {ISSUE_REQUEST} }};"
    );
    assert_eq!(authz_findings(&source), 1);
}

#[test]
fn make_resolver_with_an_imported_identifier_analyzes_the_object_callbacks() {
    let files = format!(
        "// src/config.js
        import api, {{ route }} from '@forge/api';
        export const config = {{ getIssue: async () => {ISSUE_REQUEST} }};
        // src/index.js
        {MAKE_RESOLVER_PREAMBLE}
        import {{ config }} from './config';
        export const handler = makeResolver(config);
        {MANIFEST}"
    );
    let report = scan_directory_test(MockForgeProject::files_from_string(&files));
    let findings = report
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name().contains("Authorization"))
        .count();
    assert_eq!(findings, 1);
}

#[test]
fn object_never_passed_to_a_resolver_is_not_a_resolver() {
    // The manifest handler names a plain object, so none of its properties are entry points.
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        export const handler = {{ getIssue: async () => {ISSUE_REQUEST} }};"
    );
    assert_eq!(authz_findings(&source), 0);
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        const config = {{ getIssue: async () => {ISSUE_REQUEST} }};
        export const handler = config;"
    );
    assert_eq!(authz_findings(&source), 0);
}

#[test]
fn object_passed_to_a_makeresolver_lookalike_is_not_a_resolver() {
    let source = format!(
        "import api, {{ route }} from '@forge/api';
        function makeResolver(handlers) {{ return handlers; }}
        const config = {{ getIssue: async () => {ISSUE_REQUEST} }};
        export const handler = makeResolver(config);"
    );
    assert_eq!(authz_findings(&source), 0);
}

#[test]
fn make_resolver_object_that_is_filled_imperatively_registers_nothing() {
    for fill in [
        format!("handlers.getIssue = async () => {ISSUE_REQUEST};"),
        format!("handlers['getIssue'] = async () => {ISSUE_REQUEST};"),
        format!(
            "for (const name of ['getIssue']) {{ handlers[name] = async () => {ISSUE_REQUEST}; }}"
        ),
    ] {
        let source = format!(
            "{MAKE_RESOLVER_PREAMBLE}
            const handlers = {{}};
            {fill}
            export const handler = makeResolver(handlers);"
        );
        assert_eq!(authz_findings(&source), 0, "{fill}");
    }
}

#[test]
fn make_resolver_object_built_with_object_assign_registers_nothing() {
    let source = format!(
        "{MAKE_RESOLVER_PREAMBLE}
        const config = Object.assign({{}}, {{ getIssue: async () => {ISSUE_REQUEST} }});
        export const handler = makeResolver(config);"
    );
    assert_eq!(authz_findings(&source), 0);
}
