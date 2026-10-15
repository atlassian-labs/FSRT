use super::*;

fn scan(body: &str) -> Report {
    scan_source(&format!(
        "import api, {{route, storage}} from '@forge/api';\nexport async function run(payload) {{ {body} }}"
    ))
}

fn scan_source(source: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    project.manifest_file_content = Some("modules:\n  macro:\n    - key: test\n      function: main\n      title: Test\n  function:\n    - key: main\n      handler: index.run\napp:\n  id: test-app\npermissions:\n  scopes: []\n".to_owned());
    scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    )
}

fn check(body: &str, expected: usize) {
    let report = scan(body);
    assert!(!report.has_errors(), "{report:#?}");
    assert!(report.contains_authz_vuln(expected), "{body}\n{report:#?}");
}

const GET: &str = "await api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`)";

#[test]
fn authorization_get_return_flows() {
    for (tail, expected) in [
        ("return undefined;", 0),
        ("return {ok:true};", 0),
        ("return response;", 1),
        ("return await response.json();", 1),
        ("return (await response.json()).id;", 1),
        ("const {id} = await response.json(); return id;", 1),
        ("return {nested: {data: response}};", 1),
        ("return [response];", 1),
        ("return response.id === payload.id;", 1),
        ("return !response.ok;", 1),
        ("return delete response.field;", 1),
        ("return void response;", 0),
        ("return Boolean(response.ok);", 1),
        ("return `${response.id}`;", 1),
        ("if (payload.test) return response;", 1),
        ("if (false) return response;", 0),
        ("let result = response; result = 'clean'; return result;", 0),
        (
            "const obj = {data: response, clean: true}; return obj.clean;",
            0,
        ),
        ("return await storage.get(response.id);", 0),
        (
            "await storage.set(response.id, {ok:true}); return {ok:true};",
            0,
        ),
        ("internalAction(response.id); return true;", 0),
        ("return unknownTransform(response);", 1),
        ("return response.then(value => value.json());", 1),
    ] {
        check(&format!("const response = {GET}; {tail}"), expected);
    }
}

#[test]
fn authorization_does_not_stop_at_an_internal_get() {
    let report = scan(&format!(
        "const ignored = {GET};\napi.asApp().requestJira(route`/rest/api/3/issue/ABC-2`, {{method:'POST'}});\nreturn {GET};"
    ));
    assert!(report.contains_authz_vuln(1), "{report:#?}");
    let write_only = scan(&format!(
        "const ignored = {GET};\napi.asApp().requestJira(route`/rest/api/3/issue/ABC-2`, {{method:'POST'}});\nreturn true;"
    ));
    assert_eq!(
        report.into_vulns()[0].check_name(),
        write_only.into_vulns()[0].check_name()
    );
}

#[test]
fn authorization_retains_writes_and_unknown_methods() {
    for options in [
        "{method:'POST'}",
        "{method:'PUT'}",
        "{method:'PATCH'}",
        "{method:'DELETE'}",
        "options",
        "{method:payload.method}",
        "{...payload.options}",
        "{method:'GET', ...payload.options}",
        "{['method']:'GET'}",
        "{method:'HEAD'}",
    ] {
        check(
            &format!("api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`, {options});"),
            1,
        );
    }
    for options in [
        "{}",
        "{method:'GET'}",
        "{method:'get'}",
        "{'method':'GET', headers:payload.headers}",
    ] {
        check(
            &format!("api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`, {options});"),
            0,
        );
    }
    check("api.asApp().requestGraph('query { issue }');", 1);
    // The legacy classifier also uses ApiCustomField for some GraphQL text.
    check("api.asApp().requestGraph('query { field }');", 1);
}

#[test]
fn authorization_tracks_helpers_and_isolates_get_analyses() {
    for (ret, expected) in [("return {ok:true};", 0), ("return response;", 1)] {
        let report = scan_source(&format!(
            "import api, {{route}} from '@forge/api';\nasync function read() {{ return {GET}; }}\nfunction wrap(value) {{ return {{data:value}}; }}\nexport async function run(payload) {{ const response = wrap(await read()); {ret} }}"
        ));
        assert!(report.contains_authz_vuln(expected), "{report:#?}");
    }
    let report = scan_source(&format!(
        "import api, {{route}} from '@forge/api';\nimport Resolver from '@forge/resolver';\nasync function readInternal() {{ return {GET}; }}\nasync function readExposed() {{ return {GET}; }}\nconst resolver = new Resolver();\nresolver.define('internal', async () => {{ await readInternal(); return true; }});\nresolver.define('exposed', async () => {{ return await readExposed(); }});\nexport const run = resolver.getDefinitions();"
    ));
    assert!(report.contains_authz_vuln(1), "{report:#?}");
    assert!(
        report.into_vulns()[0].description().contains("exposed"),
        "{report:#?}"
    );
}

#[test]
fn authorization_retains_unsupported_return_effects() {
    for body in [
        format!(
            "const response = {GET}; let result; function capture() {{ result = response; }} capture(); return result;"
        ),
        format!(
            "const response = {GET}; const result = {{}}; const alias = result; alias.data = response; return result;"
        ),
        format!("const response = {GET}; const result = []; result.push(response); return result;"),
        format!("const response = {GET}; throw response;"),
        format!("const response = {GET}; return response.then(value => value.json(), () => null);"),
        format!("const response = {GET}; return [response].map(value => value.id);"),
        format!("const response = {GET}; try {{ return true; }} catch (e) {{ return response; }}"),
    ] {
        check(&body, 1);
    }
}

#[test]
fn authorization_preserves_user_and_authorize_exemptions() {
    check(
        "return api.asUser().requestJira(route`/rest/api/3/issue/ABC-1`);",
        0,
    );
    check(
        "await api.asApp().requestJira(route`/rest/api/3/permissions`); return api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`);",
        0,
    );
}

#[test]
fn authorization_tracks_each_get_without_an_origin_limit() {
    let reads = (0..12)
        .map(|id| format!("const response{id} = {GET};"))
        .collect::<String>();
    check(&format!("{reads} return response11;"), 1);
    check(&format!("{reads} return [response0, response11];"), 1);
    check(&format!("{reads} return true;"), 0);
}

#[test]
fn authorization_unknown_effects_do_not_hide_returned_data() {
    check(
        &format!("const response = {GET}; let out = {{}}; unknown(out, response); return out;"),
        1,
    );
    check(
        &format!("const response = {GET}; let out = {{}}; unknown(out, response); return true;"),
        0,
    );
    check(
        &format!(
            "const response = {GET}; let out = {{data:'clean'}}; unknown(out, response); return out.data;"
        ),
        1,
    );
}

#[test]
fn authorization_preserves_loop_and_recursive_return_flows() {
    check(
        &format!("let result; while (payload.more) {{ result = {GET}; }} return result;"),
        1,
    );
    let report = scan_source(&format!(
        "import api, {{route}} from '@forge/api';\nfunction again(value, repeat) {{ if (repeat) return again(value, false); return value; }}\nexport async function run(payload) {{ const response = {GET}; return again(response, payload.again); }}"
    ));
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}

#[test]
fn authorization_gets_work_across_products_and_import_aliases() {
    for request in ["requestConfluence", "requestBitbucket", "requestJira"] {
        check(
            &format!("await api.asApp().{request}(route`/rest/api/3/issue/ABC-1`); return true;"),
            0,
        );
        check(
            &format!("return await api.asApp().{request}(route`/rest/api/3/issue/ABC-1`);"),
            1,
        );
    }
    let report = scan_source(
        "import {asApp as client, route} from '@forge/api'; export async function run() { return await client().requestJira(route`/rest/api/3/issue/ABC-1`); }",
    );
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}

#[test]
fn authorization_unknown_effects_follow_local_aliases() {
    check(
        &format!(
            "const response = {GET}; const out = {{data:'clean'}}; const alias = out; unknown(alias, response); return out.data;"
        ),
        1,
    );
    check(
        &format!(
            "const response = {GET}; const out = {{data:'clean'}}; const wrapper = {{out}}; unknown(wrapper, response); return out.data;"
        ),
        1,
    );
    check(
        &format!(
            "const response = {GET}; const out = {{}}; const alias = out; unknown(alias, response); return true;"
        ),
        0,
    );
}

#[test]
fn authorization_shared_helper_visitation_matches_baseline() {
    let report = scan_source(
        "import api, {route} from '@forge/api';
import Resolver from '@forge/resolver';
const resolver = new Resolver();
function write() { api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`, {method:'POST'}); }
resolver.define('first', () => { write(); write(); });
resolver.define('second', () => { write(); write(); });
export const run = resolver.getDefinitions();",
    );
    assert!(report.contains_authz_vuln(1), "{report:#?}");
    assert!(report.into_vulns()[0].description().contains("first"));
}

#[test]
fn authorization_first_finding_stop_still_checks_distinct_handlers() {
    let report = scan_source("import api, {route} from '@forge/api';
import Resolver from '@forge/resolver';
const resolver = new Resolver();
resolver.define('first', () => { api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`, {method:'POST'}); api.asApp().requestJira(route`/rest/api/3/issue/ABC-2`, {method:'DELETE'}); });
resolver.define('second', () => { api.asApp().requestJira(route`/rest/api/3/issue/ABC-3`, {method:'POST'}); });
export const run = resolver.getDefinitions();");
    assert!(report.contains_authz_vuln(2), "{report:#?}");
}
