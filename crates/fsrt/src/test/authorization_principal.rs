use super::*;

// Reduced from Epic Clone / Epic Clone Pro: fifth argument, literal default,
// imported helpers, retries, loops, and asApp-only attachment helpers.
fn fixture(roots: &str, mutation: &str) -> MockForgeProject<'static> {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        format!(
            r#"
        import Resolver from '@forge/resolver';
        import {{cloneParent}} from './cloning';
        const resolver = new Resolver();
        {roots}
        export const handler = resolver.getDefinitions();
    "#
        ),
    );
    project.add_file("src/cloning.js", format!(r#"
        import api, {{route}} from '@forge/api';
        import {{copyAttachmentsAsApp, editDescription}} from './attachments';
        export async function cloneParent(sourceKey, body, config, issueData, asApp = false) {{
            {mutation}
            let response;
            try {{
                if (!asApp) {{
                    response = await api.asUser().requestJira(route`/rest/api/3/issue`, {{method:'POST', body:JSON.stringify(body)}});
                }} else {{
                    for (const value of issueData.parts) {{ console.log(value.text); }}
                    response = await api.asApp().requestJira(route`/rest/api/3/issue`, {{method:'POST', body:JSON.stringify(body)}});
                }}
            }} catch (error) {{ console.log(error); return {{error:String(error)}}; }}
            if (config.attachments && asApp) await copyAttachmentsAsApp(sourceKey);
            await editDescription(sourceKey, asApp);
            return response.json();
        }}
    "#));
    project.add_file("src/attachments.js", r#"
        import api, {route} from '@forge/api';
        export async function copyAttachmentsAsApp(key) {
            return api.asApp().requestJira(route`/rest/api/3/issue/${key}/attachments`, {method:'POST'});
        }
        export async function editDescription(key, asApp = false) {
            if (asApp) return api.asApp().requestJira(route`/rest/api/3/issue/${key}`, {method:'PUT'});
            return api.asUser().requestJira(route`/rest/api/3/issue/${key}`, {method:'PUT'});
        }
    "#);
    project.manifest_file_content = Some(alias_manifest(false));
    project
}

fn root(name: &str, argument: &str) -> String {
    format!(
        "resolver.define('{name}', async ({{payload}}) => cloneParent(payload.key, payload.body, payload.config, payload.issueData{argument}));"
    )
}

fn scan(project: MockForgeProject<'_>) -> Report {
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(!report.has_errors(), "{report:#?}");
    report
}

#[test]
fn authorization_principal_epic_clone_false_and_defaults() {
    for argument in [", false", "", ", undefined"] {
        let report = scan(fixture(&root("clone", argument), ""));
        assert!(report.contains_authz_vuln(0), "{argument}: {report:#?}");
    }
}

#[test]
fn authorization_principal_arrow_helpers_and_unrelated_spreads() {
    let mut project = fixture(
        r#"
        const forward = async (key, body, config, issueData, asApp = false) => {
            const copy = [...issueData.parts];
            copy.push(...issueData.more);
            return cloneParent(key, body, config, issueData, asApp);
        };
        resolver.define('clone', async ({payload}) => forward(payload.key, {}, {}, payload.issueData, false));
    "#,
        "",
    );
    let report = scan(project.clone());
    assert!(report.contains_authz_vuln(0), "{report:#?}");
    project.add_file(
        "src/index.js",
        r#"
        import Resolver from '@forge/resolver';
        import {cloneParent} from './cloning';
        const resolver = new Resolver();
        resolver.define('clone', async ({payload}) => {
            const undefined = payload.flag;
            return cloneParent(payload.key, {}, {}, {}, undefined);
        });
        export const handler = resolver.getDefinitions();
    "#,
    );
    let report = scan(project);
    assert!(report.contains_authz_vuln(3), "{report:#?}");
}

#[test]
fn authorization_principal_keeps_true_unknown_and_unsupported_actuals() {
    for argument in [
        ", true",
        ", payload.asApp",
        ", () => false",
        ", payload.flag && false",
        ", ...payload.args",
    ] {
        let report = scan(fixture(&root("clone", argument), ""));
        assert!(report.contains_authz_vuln(3), "{argument}: {report:#?}");
    }
}

#[test]
fn authorization_principal_does_not_assume_member_call_positions() {
    for call in [
        "cloneParent.call(null, payload.key, {}, {}, false, true)",
        "cloneParent.apply(null, payload.args)",
    ] {
        let roots = format!("resolver.define('clone', async ({{payload}}) => {call});");
        let report = scan(fixture(&roots, ""));
        assert!(report.contains_authz_vuln(3), "{call}: {report:#?}");
    }
}

#[test]
fn authorization_principal_rejects_parameter_mutations_including_omitted_ir() {
    for mutation in [
        "asApp = issueData.flag;",
        "asApp ||= issueData.flag;",
        "asApp++;",
        "try { throw 1; } catch (error) { asApp = true; }",
        "function change() { asApp = true; } change();",
        "[1].forEach(() => { asApp = true; });",
        "for (asApp of issueData.flags) {}",
        "arguments[4] = true;",
        "eval(issueData.code);",
        "var asApp = true;",
        "function asApp() {}",
    ] {
        let report = scan(fixture(&root("clone", ", false"), mutation));
        assert!(report.contains_authz_vuln(3), "{mutation}: {report:#?}");
    }
}

#[test]
fn authorization_principal_preserves_other_resolvers_and_call_contexts() {
    for roots in [
        format!("{} {}", root("caller", ", false"), root("app", ", true")),
        format!("{} {}", root("app", ", true"), root("caller", ", false")),
        "resolver.define('mixed', async ({payload}) => { await cloneParent(payload.key, {}, {}, {}, false); return cloneParent(payload.key, {}, {}, {}, payload.flag); });".into(),
    ] {
        let report = scan(fixture(&roots, ""));
        assert!(report.contains_authz_vuln(3), "{roots}: {report:#?}");
        assert!(report.into_vulns().iter().all(|v| !v.description().contains("handler.caller")), "{report:#?}");
    }
}

#[test]
fn authorization_principal_does_not_assume_exported_entry_defaults() {
    let mut project = fixture("", "");
    project.manifest_file_content = Some("modules:\n  jira:globalPage:\n    - key: page\n      resolver: {function: main}\n  function:\n    - key: main\n      handler: cloning.cloneParent\napp: {id: test}\npermissions: {scopes: []}\n".into());
    let report = scan(project);
    assert!(report.contains_authz_vuln(3), "{report:#?}");
}

#[test]
fn authorization_principal_keeps_conditional_returns_and_writes() {
    let report = scan_resolver_permission_presence(
        r#"
        resolver.define('conditional', async ({payload}) => {
            const result = await read();
            if (payload.test) return result;
        });
        resolver.define('write', async ({payload}) => {
            await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method:'POST'});
            return {success:true};
        });
    "#,
    );
    assert!(report.contains_authz_vuln(2), "{report:#?}");
}
