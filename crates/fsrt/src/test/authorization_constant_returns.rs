use super::*;

fn project() -> MockForgeProject<'static> {
    MockForgeProject::files_from_string(
        "// manifest.yaml
modules:
  jira:globalPage:
    - key: test-page
      title: Test
      resolver:
        function: main
  function:
    - key: main
      handler: index.run
app:
  id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
",
    )
}

fn scan(definitions: &str) -> Report {
    let mut project = project();
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
         import api, {{route}} from '@forge/api';
         const resolver = new Resolver();
         function read() {{ return api.asApp().requestJira(route`/rest/api/3/issue/DEMO-1`); }}
         function helper() {{ return read(); }}
         {definitions}
         export const run = resolver.getDefinitions();"
        ),
    );
    scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    )
}

fn expect(definitions: &str, count: usize) {
    let report = scan(definitions);
    assert!(
        report.contains_authz_vuln(count),
        "{definitions}\n{report:#?}"
    );
}

#[test]
fn authorization_constant_returns_suppress_reads_in_helpers() {
    for ending in [
        "",
        "return;",
        "return null;",
        "return true;",
        "return 42;",
        "return 'ok';",
        "if (payload.test) return 'ok';",
    ] {
        for callback in [
            format!("async ({{payload}}) => {{ await helper(); {ending} }}"),
            format!("async function ({{payload}}) {{ await helper(); {ending} }}"),
        ] {
            expect(&format!("resolver.define('internal', {callback});"), 0);
        }
    }
}

#[test]
fn authorization_constant_returns_exposed_and_conditional_results_still_report() {
    for body in [
        "return helper();",
        "const result = await helper(); return result;",
        "const result = await helper(); if (payload.test) return result;",
        // A returned value that does not come from the response is not an exposure of
        // it; the flow policy (authorization_flow.rs) handles those reads.
        // A caught error is not the response; see authorization_flow.rs.
    ] {
        expect(
            &format!("resolver.define('exposed', async ({{payload}}) => {{ {body} }});"),
            1,
        );
    }
}

#[test]
fn authorization_constant_returns_support_nested_literal_objects_and_arrays() {
    for value in [
        "{}",
        "[]",
        "{success: true}",
        "[1, 'ok', false, null]",
        "{items: [], result: {success: true, codes: [1, 2]}}",
        "[{success: true}, [], {nested: [null, {value: 'ok'}]}]",
        "{'status': 'ok', 0: false}",
        "[,,true]",
    ] {
        expect(
            &format!(
                "resolver.define('internal', async () => {{
            await helper(); return {value};
        }});"
            ),
            0,
        );
        // Constant containers must not exempt writes in the same resolver.
        expect(
            &format!(
                "resolver.define('write', async () => {{
            await helper();
            await api.asApp().requestJira(route`/rest/api/3/issue`, {{method: 'POST'}});
            return {value};
        }});"
            ),
            1,
        );
    }
}

#[test]
fn authorization_constant_returns_preserve_dynamic_container_returns() {
    for value in [
        "{result}",
        "{result: result}",
        "[result]",
        "{nested: [{value: result}]}",
        "[{nested: [result]}]",
        "{...result}",
        "[...result]",
        "{[result]: true}",
        "{['status']: 'ok'}",
        "{get value() { return result; }}",
        "{value() { return result; }}",
    ] {
        expect(
            &format!(
                "resolver.define('exposed', async () => {{
            const result = await helper(); return {value};
        }});"
            ),
            1,
        );
    }
    expect(
        "resolver.define('conditional', async ({payload}) => {
        const result = await helper();
        if (payload.test) return {result};
        return {success: true};
    });",
        1,
    );
}

#[test]
fn authorization_constant_returns_shared_helper_is_rechecked_per_resolver() {
    // Exercise both definition orders and both name orders: resolver iteration
    // order must not decide whether the exposed use is reported.
    for (internal, exposed) in [("a", "b"), ("b", "a")] {
        let hidden = format!(
            "resolver.define('{internal}', async () => {{ await helper(); return true; }});"
        );
        let visible = format!("resolver.define('{exposed}', () => helper());");
        for definitions in [
            format!("{hidden}\n{visible}"),
            format!("{visible}\n{hidden}"),
        ] {
            let report = scan(&definitions);
            assert!(report.contains_authz_vuln(1), "{definitions}\n{report:#?}");
            assert!(
                report
                    .into_vulns()
                    .iter()
                    .any(|vuln| vuln.check_name().contains("Authorization")
                        && vuln.description().contains(&format!("run.{exposed}"))),
                "{report:#?}"
            );
        }
    }
}

#[test]
fn authorization_constant_returns_only_proven_get_options_are_suppressed() {
    for (options, count) in [
        ("", 0),
        (", {}", 0),
        (", {method: 'GET'}", 0),
        (
            ", {'method': 'get', headers: {Accept: 'application/json'}}",
            0,
        ),
        (", {headers: {Accept: 'application/json'}}", 0),
        (", {method: 'POST'}", 1),
        (", {method: 'PUT'}", 1),
        (", {method: 'DELETE'}", 1),
        (", payload.options", 1),
        (", {method: payload.method}", 1),
        (", {...payload.options}", 1),
        (", {method: 'GET', ...payload.options}", 1),
        (", {[payload.key]: 'POST'}", 1),
        (", {__proto__: payload.options}", 1),
        (", {method: 'GET', method: 'POST'}", 1),
    ] {
        expect(
            &format!(
                "resolver.define('internal', async ({{payload}}) => {{
            await api.asApp().requestJira(route`/rest/api/3/issue/DEMO-1`{options});
            return true;
        }});"
            ),
            count,
        );
    }
}

#[test]
fn authorization_constant_returns_preserve_helper_writes_and_graphql() {
    for operation in [
        "api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST'})",
        "api.asApp().requestGraph('/graphql', {method: 'GET'})",
    ] {
        expect(&format!("function write() {{ return {operation}; }}
            resolver.define('internal', async () => {{ await helper(); await write(); return true; }});"), 1);
    }
}

#[test]
fn authorization_constant_returns_cover_rest_products() {
    for (method, route) in [
        ("requestJira", "/rest/agile/1.0/board/1"),
        ("requestJira", "/rest/servicedeskapi/request/TEST-1"),
        ("requestConfluence", "/wiki/api/v2/pages/123"),
        ("requestBitbucket", "/2.0/repositories/example/repo"),
    ] {
        expect(
            &format!(
                "resolver.define('internal', async () => {{
            await api.asApp().{method}(route`{route}`); return null;
        }});"
            ),
            0,
        );
    }
}

#[test]
fn authorization_constant_returns_ignore_nested_function_returns() {
    expect(
        "resolver.define('internal', async () => {
        function nested() { return read(); }
        const arrow = () => helper();
        await nested(); await arrow(); return true;
    });",
        0,
    );
}

#[test]
fn authorization_constant_returns_do_not_exempt_regular_function_entrypoints() {
    let mut project = project();
    project.add_file(
        "src/index.js",
        "import api, {route} from '@forge/api';
        export async function run() {
            await api.asApp().requestJira(route`/rest/api/3/issue/DEMO-1`);
            return true;
        }",
    );
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}
