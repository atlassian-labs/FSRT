//! Reads that cannot hand the caller data they could not read: the request is
//! bound to the module context the platform supplied, or its response goes
//! nowhere the caller can see it. Every shape the analysis cannot follow, and
//! every write, must still be reported.
use super::*;

fn scan(body: &str) -> Report {
    scan_with("", body)
}

fn scan_with(helpers: &str, body: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            "import Resolver from '@forge/resolver';
             import api, {{route, storage, fetch}} from '@forge/api';
             const resolver = new Resolver();
             let cache;
             {helpers}
             resolver.define('probe', async ({{payload, context}}) => {{
                 {body}
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

fn check(cases: &[(&str, usize)]) {
    for (body, findings) in cases {
        let report = scan(body);
        assert!(
            report.contains_authz_vuln(*findings),
            "expected {findings} finding(s) for:\n{body}\n{report:#?}"
        );
    }
}

#[test]
fn reads_bound_to_the_module_context_are_not_reported() {
    check(&[
        (
            "const key = context.extension.issue.key;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/user?accountId=${context.accountId}`);
             return response.json();",
            0,
        ),
        (
            "const { extension } = context;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${extension.issue.id}/comment`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/search/jql`, {
                 method: 'POST',
                 body: JSON.stringify({jql: `project = ${context.extension.project.key}`}),
             });
             return response.json();",
            0,
        ),
        // The second read is bound to the response of the first.
        (
            "const issue = await (await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`)).json();
             const parent = await api.asApp().requestJira(route`/rest/api/3/issue/${issue.fields.parent.key}`);
             return parent.json();",
            0,
        ),
    ]);
}

#[test]
fn context_binding_is_not_credited_when_anything_else_reaches_the_request() {
    check(&[
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             return response.json();",
            1,
        ),
        (
            "const key = payload.key || context.extension.issue.key;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/${payload.part}`);
             return response.json();",
            1,
        ),
        // `jobId` is not set by the platform.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.jobId}`);
             return response.json();",
            1,
        ),
        (
            "const key = await storage.get('key');
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
             return response.json();",
            1,
        ),
        // No context at all: nothing scopes the read.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1`);
             return response.json();",
            1,
        ),
        // A route that came back from a read the caller steered. Only the second
        // read is reported: the first one's response names the next resource.
        (
            "const issue = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const parent = await api.asApp().requestJira(route`/rest/api/3/issue/${issue.fields.parent.key}`);
             return parent.json();",
            1,
        ),
        (
            "const issue = await (await api.asUser().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`)).json();
             const parent = await api.asApp().requestJira(route`/rest/api/3/issue/${issue.fields.parent.key}`);
             return parent.json();",
            1,
        ),
        // Context never makes a write that carries caller data safe.
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method: 'PUT', body: JSON.stringify({fields: payload.fields})});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method: 'DELETE'});
             return 1;",
            1,
        ),
    ]);
}

#[test]
fn a_helper_shared_with_a_caller_controlled_call_keeps_the_finding() {
    let helpers = "async function load(key) {
        const response = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
        return response.json();
    }";
    let from_context = scan_with(helpers, "return load(context.extension.issue.key);");
    assert!(from_context.contains_authz_vuln(0), "{from_context:#?}");
    let from_payload = scan_with(helpers, "return load(payload.key);");
    assert!(from_payload.contains_authz_vuln(1), "{from_payload:#?}");
    let both = scan_with(
        helpers,
        "const own = await load(context.extension.issue.key); return [own, await load(payload.key)];",
    );
    assert!(both.contains_authz_vuln(1), "{both:#?}");
}

#[test]
fn responses_that_never_leave_the_resolver_are_not_reported() {
    check(&[
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/search/jql?jql=${payload.jql}`);
             const data = await response.json();
             return data.issues.length;",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             return {exists: response.ok};",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             const data = await response.json();
             return data.fields.summary === payload.summary;",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             console.log(await response.json());
             return 'done';",
            0,
        ),
        // A search names the next resource in the body of a read-only POST.
        (
            "const board = await (await api.asApp().requestJira(route`/rest/agile/1.0/board/${payload.id}/configuration`)).json();
             const issues = await api.asApp().requestJira(route`/rest/api/3/search/jql`, {method: 'POST', body: JSON.stringify({jql: `filter = ${board.filter.id}`})});
             return issues.json();",
            1,
        ),
        // The response only names the next resource; what that returns is reported.
        (
            "const board = await (await api.asApp().requestJira(route`/rest/agile/1.0/board/${payload.id}/configuration`)).json();
             const response = await api.asApp().requestJira(route`/rest/api/3/filter/${board.filter.id}`);
             return response.json();",
            1,
        ),
    ]);
}

#[test]
fn a_returned_value_that_does_not_come_from_the_response_is_not_an_exposure() {
    // Reduced from the constant-return policy's tests: the helper reads, the
    // caller gets something else.
    let helpers =
        "function read() { return api.asApp().requestJira(route`/rest/api/3/issue/DEMO-1`); }
        function helper() { return read(); }";
    for body in [
        "await helper(); return payload.test;",
        "await helper(); const ok = true; return ok;",
        "const undefined = payload.test; await helper(); return undefined;",
        // Neither a caught error nor a prototype is the response. Errors the runtime
        // raises, such as a JSON syntax error that quotes the body, are not followed.
        "try { await helper(); return true; } catch (error) { return error; }",
        "const result = await helper(); return {__proto__: {ok: true}};",
    ] {
        let report = scan_with(helpers, body);
        assert!(report.contains_authz_vuln(0), "{body}\n{report:#?}");
    }
    for body in [
        "return helper();",
        "const result = await helper(); return {[result]: true};",
        "const result = await helper(); return {...result};",
        "const result = await helper(); return [result];",
    ] {
        let report = scan_with(helpers, body);
        assert!(report.contains_authz_vuln(1), "{body}\n{report:#?}");
    }
}

#[test]
fn responses_that_can_reach_the_caller_or_another_system_are_reported() {
    check(&[
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             return response.json();",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             return {summary: data.fields.summary};",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const out = [];
             out.push(data.fields);
             return out;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const out = {};
             Object.assign(out, data);
             return out;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const out = [];
             for (const field of data.fields) { out.push(field); }
             return out;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             return data.issues.map((issue) => issue.fields.summary);",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const names = [];
             data.issues.forEach((issue) => names.push(issue.key));
             return names;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             await storage.set('last', data);
             return payload.key;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             await fetch('https://example.invalid/hook', {method: 'POST', body: JSON.stringify(data)});
             return payload.key;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             await api.asUser().requestJira(route`/rest/api/3/issue/${payload.other}/comment`, {method: 'POST', body: JSON.stringify(data)});
             return payload.key;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             cache = data;
             return payload.key;",
            1,
        ),
        // Through a helper's return value, and through a closure that fills a captured array.
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const pick = (issue) => ({summary: issue.fields.summary});
             return pick(data);",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             const out = [];
             const add = (value) => out.push(value);
             add(data);
             return out;",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             try { JSON.parse('{'); } catch (error) { return data; }
             return 'ok';",
            1,
        ),
        (
            "const data = await (await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`)).json();
             try { throw new Error(JSON.stringify(data)); } catch (error) { return error.message; }",
            1,
        ),
    ]);
}

#[test]
fn a_write_is_not_excused_by_what_it_returns() {
    check(&[
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'DELETE'});
             return 'done';",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}/comment`, {method: 'POST', body: JSON.stringify(payload.body)});
             return response.ok;",
            1,
        ),
    ]);
}

#[test]
fn a_write_that_carries_no_caller_data_is_not_reported() {
    check(&[
        // Constant route and body.
        (
            "await api.asApp().requestJira(route`/rest/api/3/field`, {method: 'POST', body: JSON.stringify({name: 'Rank', type: 'text'})});
             return {ok: true};",
            0,
        ),
        // The platform context may choose the target and the content.
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method: 'PUT', body: JSON.stringify({fields: {}})});
             return {ok: true};",
            0,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/comment`, {method: 'POST', body: JSON.stringify({body: context.extension.issue.id})});
             return {ok: true};",
            0,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1`, {method: 'PATCH', body: JSON.stringify({id: context.accountId})});
             return {ok: true};",
            0,
        ),
        // What a write returns does not make it a different write.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issuetype`, {method: 'POST', body: JSON.stringify({name: 'Test'})});
             return response.json();",
            0,
        ),
        // A POST that reads (a search with a fixed query) is a POST all the same.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/search/jql`, {method: 'POST', body: JSON.stringify({jql: 'project = ONE'})});
             return response.json();",
            0,
        ),
        // GraphQL has no method the scanner reads: it is judged by what it sends.
        (
            "const response = await api.asApp().requestGraph('/graphql', {method: 'POST', body: JSON.stringify({query: 'mutation { ping }'})});
             return response.json();",
            0,
        ),
    ]);
}

#[test]
fn a_write_that_carries_caller_or_stored_data_is_reported() {
    check(&[
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'PUT', body: JSON.stringify({fields: {}})});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method: 'PUT', body: JSON.stringify(payload.fields)});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1`, {method: 'POST', body: JSON.stringify({id: context.extension.issue.id, extra: payload.extra})});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue`, {method: payload.method, body: '{}'});
             return {ok: true};",
            1,
        ),
        // Data the app stored may have been put there by another caller.
        (
            "const stored = await storage.get('draft');
             await api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST', body: JSON.stringify(stored)});
             return {ok: true};",
            1,
        ),
        (
            "const key = await storage.get('key');
             await api.asApp().requestJira(route`/rest/api/3/issue/${key}`, {method: 'PUT', body: '{}'});
             return {ok: true};",
            1,
        ),
        // So may what an asUser or a fetch request returned.
        (
            "const other = await (await api.asUser().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`)).json();
             await api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST', body: JSON.stringify(other)});
             return {ok: true};",
            1,
        ),
        (
            "const other = await (await fetch('https://example.com/draft')).json();
             await api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST', body: JSON.stringify(other)});
             return {ok: true};",
            1,
        ),
        // A method the analysis cannot read may be a DELETE: the finding is kept.
        (
            "let method = 'POST';
             await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method, body: JSON.stringify({fields: {}})});
             return {ok: true};",
            1,
        ),
        (
            "const options = { ['method']: 'DELETE' };
             await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1`, options);
             return {ok: true};",
            1,
        ),
        // A fixed DELETE is deliberately kept, with or without context.
        (
            "await api.asApp().requestJira(route`/rest/api/3/issuetype/10001`, {method: 'DELETE'});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}`, {method: 'DELETE'});
             return {ok: true};",
            1,
        ),
    ]);
}

#[test]
fn a_write_helper_is_judged_by_what_each_call_gives_it() {
    let helpers = "async function create(data) {
        return api.asApp().requestJira(route`/rest/api/3/issue`, {method: 'POST', body: JSON.stringify(data)});
    }";
    let fixed = scan_with(helpers, "await create({fields: {summary: 'x'}}); return 1;");
    assert!(fixed.contains_authz_vuln(0), "{fixed:#?}");
    let from_payload = scan_with(helpers, "await create(payload.issue); return 1;");
    assert!(from_payload.contains_authz_vuln(1), "{from_payload:#?}");
    let both = scan_with(
        helpers,
        "await create({fields: {summary: 'x'}}); await create(payload.issue); return 1;",
    );
    assert!(both.contains_authz_vuln(1), "{both:#?}");
}

#[test]
fn a_write_the_analysis_cannot_follow_keeps_the_finding() {
    let write =
        "await api.asApp().requestJira(route`/rest/api/3/field`, {method: 'POST', body: '{}'});";
    for (name, tail) in [
        (
            "request escape",
            "console.log(Object.keys(arguments[0])); return 1;",
        ),
        (
            "class",
            "class Box { value() { return 1; } } return new Box().value();",
        ),
        (
            "function value",
            "const get = payload.flag ? () => 1 : () => 2; return get();",
        ),
        (
            "dynamic import",
            "const module = await import('./other'); return module.run().length;",
        ),
    ] {
        let report = scan(&format!("{write} {tail}"));
        assert!(report.contains_authz_vuln(1), "{name}\n{report:#?}");
    }
    // The same write, followed, is not reported.
    let report = scan(&format!("{write} return 1;"));
    assert!(report.contains_authz_vuln(0), "{report:#?}");
}

#[test]
fn a_get_is_not_judged_by_the_write_rule() {
    check(&[
        // No context in it: the unscoped read is kept.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/filter/search`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1`, {method: 'GET'});
             return response.json();",
            1,
        ),
        // Caller data in a read is kept as before.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
             return response.json();",
            1,
        ),
    ]);
}

#[test]
fn a_property_whose_key_the_caller_does_not_choose_is_not_reported() {
    check(&[
        // The app's property on the issue or project the caller has open.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/properties/app-config`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/project/${context.extension.project.key}/properties`);
             return response.json();",
            0,
        ),
        // Fixed keys: the app's own.
        (
            "const response = await api.asApp().requestJira(route`/rest/forge/1/app/properties/config`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1/properties/config`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestConfluence(route`/wiki/api/v2/pages/${context.extension.content.id}/properties`);
             return response.json();",
            0,
        ),
        // The value may come from the caller: only the key is judged.
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/properties/settings`, {method: 'PUT', body: JSON.stringify(payload.value)});
             return {ok: true};",
            0,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/project/${context.extension.project.key}/properties/settings`, {method: 'PUT', body: JSON.stringify({value: payload.value})});
             return {ok: true};",
            0,
        ),
        // Any method: a property the app owns is deleted by the app.
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/properties/settings`, {method: 'DELETE'});
             return {ok: true};",
            0,
        ),
    ]);
}

#[test]
fn a_property_route_with_caller_data_in_it_is_reported() {
    check(&[
        // The key, the entity and the query string are all the route.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/properties/${payload.key}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.issue}/properties/app-config`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/project/${context.extension.project.key}/properties?keys=${payload.keys}`);
             return response.json();",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${payload.issue}/properties/settings`, {method: 'PUT', body: '{}'});
             return {ok: true};",
            1,
        ),
        (
            "await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.key}/properties/${payload.key}`, {method: 'DELETE'});
             return {ok: true};",
            1,
        ),
        // Not the caller's context.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.jobId}/properties/app-config`);
             return response.json();",
            1,
        ),
        // A route the scanner cannot read is not taken for a property route.
        (
            "const path = 'issue/ONE-1/properties/config';
             const response = await api.asApp().requestJira(route`/rest/api/3/${path}`);
             return response.json();",
            1,
        ),
        // Other routes of the same entity are not properties.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1/comment`);
             return response.json();",
            1,
        ),
    ]);
}

#[test]
fn a_property_the_analysis_cannot_follow_keeps_the_finding() {
    let read = "const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE-1/properties/config`);
                const data = await response.json();";
    let report = scan(&format!(
        "{read} console.log(Object.keys(arguments[0])); return data;"
    ));
    assert!(report.contains_authz_vuln(1), "{report:#?}");
}

#[test]
fn constructs_the_analysis_cannot_follow_keep_the_finding() {
    let unexposed =
        "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`);
         const data = await response.json();";
    for (name, tail) in [
        // The request escapes: `payload` and `context` can no longer be told apart.
        (
            "request escape",
            "console.log(Object.keys(arguments[0])); return data;",
        ),
        (
            "object spread",
            "const copy = {...(await payload.load())}; return copy.id;",
        ),
        (
            "class",
            "class Box { value() { return data; } } return new Box().value().length;",
        ),
        (
            "function value",
            "const get = payload.flag ? () => 1 : () => 2; return get();",
        ),
        (
            "dynamic import",
            "const module = await import('./other'); return module.run(data).length;",
        ),
    ] {
        let report = scan(&format!("{unexposed} {tail}"));
        assert!(report.contains_authz_vuln(1), "{name}\n{report:#?}");
    }
}

#[test]
fn content_users_edit_is_not_the_platforms_to_vouch_for() {
    check(&[
        // Identifiers of the page the caller opened.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.issue.id}`);
             return response.json();",
            0,
        ),
        (
            "const {issue} = context.extension;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${issue.key}`);
             return response.json();",
            0,
        ),
        (
            "const response = await api.asApp().requestConfluence(route`/wiki/api/v2/pages/${context.extension.content.id}`);
             return response.json();",
            0,
        ),
    ]);
    check(&[
        // Content users edit, delivered in the context.
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.fieldValue}`);
             return response.json();",
            1,
        ),
        (
            "const keys = context.extension.fieldValue.split(',');
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${keys[0]}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.extension.gadgetConfiguration.issue}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestConfluence(route`/wiki/api/v2/pages/${context.extension.macro.config.page}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/servicedeskapi/request/${context.extension.request.properties.related}`);
             return response.json();",
            1,
        ),
        (
            "const response = await api.asApp().requestJira(route`/rest/api/3/issue/${context.jobId}`);
             return response.json();",
            1,
        ),
        // Through an alias or a destructuring.
        (
            "const {fieldValue} = context.extension;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${fieldValue}`);
             return response.json();",
            1,
        ),
        (
            "const extension = context.extension;
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${extension.fieldValue}`);
             return response.json();",
            1,
        ),
    ]);
}
