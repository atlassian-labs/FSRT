use super::*;

fn scan(body: &str) -> Report {
    scan_source(&format!(
        "import api, {{route, storage, WhereConditions}} from '@forge/api';\nexport async function run(payload) {{ {body} }}"
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
fn authorization_ignores_unrelated_initializer_lowering_but_keeps_reachable_jsx() {
    let report = scan_source(&format!(
        "import api, {{route}} from '@forge/api';\nexport const AdminConfigPage = () => <div />;\nexport const adminRender = <AdminConfigPage />;\nexport async function run(payload) {{ const ignored = {GET}; return true; }}"
    ));
    assert!(!report.has_errors(), "{report:#?}");
    assert!(report.contains_authz_vuln(0), "{report:#?}");

    let reachable = scan_source(&format!(
        "import api, {{route}} from '@forge/api';\nexport async function run(payload) {{ const response = {GET}; return render(response); }}\nfunction render(value) {{ return <div>{{value}}</div>; }}"
    ));
    assert!(reachable.contains_authz_vuln(1), "{reachable:#?}");
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

#[test]
fn authorization_internal_gets_with_terminal_literal_or_rethrow_catches() {
    for catch in [
        "throw e;",
        "return;",
        "return null;",
        "return {ok:false, data:[1, true]};",
    ] {
        check(
            &format!(
                "try {{ const response = {GET}; internalAction(response.id); return true; }} catch (e) {{ {catch} }}"
            ),
            0,
        );
        check(
            &format!("try {{ const response = {GET}; return response; }} catch (e) {{ {catch} }}"),
            1,
        );
    }
}

#[test]
fn authorization_retains_unresolved_exception_dependencies() {
    for body in [
        format!("const response = {GET}; try {{ return true; }} catch (e) {{ return e.message; }}"),
        format!(
            "const response = {GET}; try {{ return true; }} catch (e) {{ return {{response}}; }}"
        ),
        format!(
            "let response = {GET}; try {{ mayThrow(); response = 'clean'; }} catch (e) {{}} return response;"
        ),
        format!("const response = {GET}; try {{ return true; }} catch (e) {{ throw response; }}"),
        format!("const response = {GET}; try {{ return true; }} catch (e) {{ log(e); throw e; }}"),
        format!(
            "const response = {GET}; try {{ internalAction(response); }} catch (e) {{ throw e; }} finally {{ return response; }}"
        ),
        format!(
            "const response = {GET}; try {{ return true; }} catch (e) {{ return {{[response.id]:true}}; }}"
        ),
        format!(
            "const response = {GET}; try {{ return true; }} catch (e) {{ return {{...response}}; }}"
        ),
    ] {
        check(&body, 1);
    }
}

#[test]
fn authorization_preserves_response_data_in_object_spreads() {
    for tail in [
        "return {...response};",
        "return {ok:true, ...response.data};",
        "const out = {ok:true, ...response.data}; return out.ok;",
        "return {nested:{...response}};",
        "return {...response, ...payload.extra};",
        "try { return {ok:true, ...response.data}; } catch (e) { return {ok:false}; }",
    ] {
        check(&format!("const response = {GET}; {tail}"), 1);
    }
    check(
        &format!("const response = {GET}; internalAction({{...response}}); return true;"),
        0,
    );
    check(
        &format!("const response = {GET}; const out = {{...response, ok:true}}; return out.ok;"),
        0,
    );
}

#[test]
fn authorization_retains_unsupported_aggregate_dependencies() {
    for tail in [
        "return {[response.id]:true};",
        "const out = [1, ...response, 'clean']; return out[2];",
        "const out = {get data() { return response; }}; return out.data;",
        "const out = {data() { return response; }}; return out.data();",
    ] {
        check(&format!("const response = {GET}; {tail}"), 1);
    }
}

#[test]
fn authorization_local_mutations_preserve_return_exposure() {
    for (tail, expected) in [
        ("const out = {}; out.data = response; return true;", 0),
        ("const out = {}; out.data = response; return out;", 1),
        (
            "const out = {data:'clean'}; const alias = out; alias.data = response; return out.data;",
            1,
        ),
        (
            "const out = {data:'clean'}; const alias = out; alias.data = response; return true;",
            0,
        ),
        (
            "const out = {data:{}}; const alias = out.data; alias.value = response; return out;",
            1,
        ),
        (
            "const out = {data:{}}; const alias = out.data; alias.value = response; return true;",
            0,
        ),
        (
            "const data = payload.data; data.id = response.id; await storage.set('key', {...data}); return 'saved';",
            0,
        ),
        (
            "const data = payload.data; data.id = response.id; return payload;",
            1,
        ),
        ("response.flag = true; return true;", 0),
        (
            "const out = {}; if (payload.test) out.data = response; return out;",
            1,
        ),
    ] {
        check(&format!("const response = {GET}; {tail}"), expected);
    }
}

#[test]
fn authorization_retains_mutations_across_helper_boundaries() {
    for helper in [
        "function fill(out, value) { out.data = value; }",
        "function fill(out, value) { const alias = out; alias.data = value; }",
        "function fill(out, value) { unknown(out, value); }",
        "function fill(out, value) { const alias = out; unknown(alias, value); }",
    ] {
        let report = scan_source(&format!(
            "import api, {{route}} from '@forge/api'; {helper}\nexport async function run() {{ const response = {GET}; const out = {{data:'clean'}}; fill(out, response); return out.data; }}"
        ));
        assert!(report.contains_authz_vuln(1), "{report:#?}");
    }
    check(
        &format!(
            "const response = {GET}; const out = {{}}; function fill() {{ const alias = out; alias.data = response; }} fill(); return out;"
        ),
        1,
    );
}

#[test]
fn authorization_storage_builders_are_response_boundaries() {
    for operation in [
        "storage.entity('items').set(response.id, {...response})",
        "storage.entity('items').get(response.id)",
        "storage.entity('items').query().index('by-id').where(response.id).cursor(payload.cursor).getMany()",
        "storage.query().where(response.id).limit(10).getMany()",
    ] {
        check(
            &format!("const response = {GET}; return await {operation};"),
            0,
        );
        check(
            &format!(
                "try {{ const response = {GET}; const data = payload.data; data.id = response.id; await {operation}; return 'saved'; }} catch (e) {{ throw e; }}"
            ),
            0,
        );
    }
    for import in [
        "import {kvs as store} from '@forge/kvs';",
        "import store from '@forge/kvs';",
        "import {storage as store} from '@forge/api';",
    ] {
        let report = scan_source(&format!(
            "import api, {{route}} from '@forge/api'; {import} export async function run() {{ const response = {GET}; return await store.entity('items').query().index('by-id').where(response.id).getMany(); }}"
        ));
        assert!(report.contains_authz_vuln(0), "{report:#?}");
    }
}

#[test]
fn authorization_storage_names_alone_do_not_prove_boundaries() {
    for operation in [
        "payload.storage.entity('items').query().where(response.id).getMany()",
        "storage.unknownBuilder(response).getMany()",
        "storage.entity('items')[payload.method](response)",
        "storage.entity('items').get(response.id).then(value => response)",
    ] {
        check(
            &format!("const response = {GET}; return await {operation};"),
            1,
        );
    }
    let report = scan_source(&format!(
        "import api, {{route}} from '@forge/api'; import {{notStorage as storage}} from '@forge/kvs'; export async function run() {{ const response = {GET}; return storage.entity('items').get(response.id); }}"
    ));
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}

// Minimized from bdq.rs addSign and bdq.fsm GetIssueVisits in the scanned corpus.
#[test]
fn authorization_bdq_internal_ids_do_not_disclose_product_responses() {
    let report = scan_source(
        "import api, {route, storage} from '@forge/api';
import Resolver from '@forge/resolver';
const resolver = new Resolver();
resolver.define('addSign', async ({context, payload}) => {
    try {
        const data = payload.signData;
        const issue = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.request.key}`).then(res => res.json());
        const desk = await api.asApp().requestJira(route`/rest/servicedeskapi/servicedesk/${context.extension.portal.id}`).then(res => res.json());
        data.projectid = Number(desk.projectId);
        data.issueid = Number(issue.id);
        await storage.entity('signs').set(data.id, {...data});
        return 'Signature Added';
    } catch (e) { throw e; }
});
export const run = resolver.getDefinitions();",
    );
    assert!(report.contains_authz_vuln(0), "{report:#?}");
    check(
        &format!(
            "const issue = {GET}.then(res => res.json()); const id = Number(issue.id); let allResults = []; let nextCursor = null; try {{ do {{ const {{results, nextCursor: currentCursor}} = await storage.entity('visits').query().index('by-issueid').where(WhereConditions.equalsTo(id)).cursor(nextCursor).getMany(); allResults = allResults.concat(results); nextCursor = currentCursor; }} while (nextCursor); return allResults; }} catch (e) {{ throw e; }}"
        ),
        0,
    );
}

#[test]
fn authorization_storage_predicates_propagate_returned_data_without_mutating_inputs() {
    check(
        &format!(
            "const response = {GET}; const predicate = WhereConditions.equalsTo(response.id); return predicate;"
        ),
        1,
    );
    check(
        &format!(
            "const response = {GET}; const predicate = WhereConditions.equalsTo(response.id); return true;"
        ),
        0,
    );
    check(
        &format!(
            "const response = {GET}; const out = {{}}; WhereConditions.unknownMethod(out, response); return out;"
        ),
        1,
    );
    check(
        &format!(
            "const response = {GET}; const out = {{}}; payload.WhereConditions.equalsTo(out, response); return out;"
        ),
        1,
    );
}

#[test]
fn authorization_shared_internal_get_does_not_hide_later_exposure() {
    for wrapper in ["return read();", "return wrap();"] {
        let report = scan_source(&format!(
            "import api, {{route}} from '@forge/api';
import Resolver from '@forge/resolver';
const resolver = new Resolver();
async function read() {{ return {GET}; }}
async function wrap() {{ return read(); }}
resolver.define('internal', async () => {{ await wrap(); return true; }});
resolver.define('exposed', async () => {{ {wrapper} }});
resolver.define('alsoExposed', async () => {{ return read(); }});
export const run = resolver.getDefinitions();"
        ));
        assert!(report.contains_authz_vuln(1), "{report:#?}");
        assert!(
            report.into_vulns()[0]
                .description()
                .contains("handler.exposed")
                || report.into_vulns()[0].description().contains("run.exposed"),
            "{report:#?}"
        );
    }
}

#[test]
fn authorization_public_reference_get_is_operation_scoped() {
    check(
        "return api.asApp().requestJira(route`/rest/api/3/jql/autocompletedata`);",
        0,
    );
    check(
        "return api.asApp().requestJira(route`/rest/api/3/jql/autocompletedata`, {method:'GET', headers:{Accept:'application/json'}});",
        0,
    );
    for tail in [
        "return api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`);",
        "return api.asApp().requestJira(route`/rest/api/3/issue/ABC-1`, {method:'PUT'});",
    ] {
        check(
            &format!(
                "await api.asApp().requestJira(route`/rest/api/3/jql/autocompletedata`); {tail}"
            ),
            1,
        );
    }
    for options in ["{method:'POST'}", "options", "{...payload.options}"] {
        check(
            &format!(
                "return api.asApp().requestJira(route`/rest/api/3/jql/autocompletedata`, {options});"
            ),
            1,
        );
    }
    for path in [
        "/rest/api/3/jql/autocompletedata/suggestions",
        "/rest/api/3/jql/autocompletedata?fieldName=secret",
        "/rest/api/3/jql/${payload.operation}",
        "/rest/api/3/field",
    ] {
        check(
            &format!("return api.asApp().requestJira(route`{path}`);"),
            1,
        );
    }
    check(
        "return api.asApp().requestConfluence(route`/rest/api/3/jql/autocompletedata`);",
        1,
    );
}

#[test]
fn authorization_public_reference_get_requires_known_route_tag() {
    let aliased = scan_source(
        "import api, {route as path} from '@forge/api'; export async function run() { return api.asApp().requestJira(path`/rest/api/3/jql/autocompletedata`); }",
    );
    assert!(aliased.contains_authz_vuln(0), "{aliased:#?}");
    let shadowed = scan_source(
        "import api from '@forge/api'; export async function run(route) { return api.asApp().requestJira(route`/rest/api/3/jql/autocompletedata`); }",
    );
    assert!(shadowed.contains_authz_vuln(1), "{shadowed:#?}");
}
