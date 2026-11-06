//! Functions reachable only by administrators or by the platform are not
//! entrypoints for an unprivileged caller; a function an ordinary module also
//! exposes still is.
use super::*;

fn scan_with_modules(modules: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file(
        "src/index.js",
        "import Resolver from '@forge/resolver';
         import api, {route} from '@forge/api';
         const resolver = new Resolver();
         resolver.define('write', async ({payload}) => {
             const response = await api.asApp().requestJira(route`/rest/api/3/issue/${payload.key}`, {method: 'PUT', body: JSON.stringify(payload.body)});
             return response.status;
         });
         export const handler = resolver.getDefinitions();",
    );
    project.manifest_file_content = Some(format!(
        "modules:\n{modules}  function:\n    - {{ key: resolver, handler: index.handler }}\napp: {{ id: test-app }}\npermissions: {{ scopes: [] }}\n"
    ));
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(!report.has_errors(), "{report:#?}");
    report
}

#[test]
fn privileged_modules_alone_do_not_expose_a_resolver() {
    for modules in [
        "  jiraServiceManagement:assetsImportType:\n    - { key: import, resolver: { function: resolver }, onDeleteImport: { function: resolver }, stopImport: { function: resolver }, startImport: { function: resolver }, importStatus: { function: resolver } }\n",
        "  jira:adminPage:\n    - { key: admin, title: Admin, resource: main, resolver: { function: resolver } }\n",
    ] {
        let report = scan_with_modules(modules);
        assert!(report.contains_authz_vuln(0), "{modules}\n{report:#?}");
    }
}

#[test]
fn an_ordinary_module_keeps_the_resolver_reachable() {
    for modules in [
        // Project and space administrators are not product administrators.
        "  jira:projectSettingsPage:\n    - { key: settings, resource: main, resolver: { function: resolver } }\n",
        "  confluence:spaceSettings:\n    - { key: settings, resource: main, resolver: { function: resolver } }\n",
        "  jiraServiceManagement:assetsImportType:\n    - { key: import, resolver: { function: resolver }, onDeleteImport: { function: resolver }, stopImport: { function: resolver }, startImport: { function: resolver }, importStatus: { function: resolver } }\n  jira:globalPage:\n    - { key: page, resource: main, resolver: { function: resolver } }\n",
        "  jira:projectPage:\n    - { key: page, resource: main, resolver: { function: resolver } }\n",
        "  jira:issuePanel:\n    - { key: panel, resource: main, resolver: { function: resolver } }\n  confluence:spaceSettings:\n    - { key: settings, resource: main, resolver: { function: resolver } }\n",
    ] {
        let report = scan_with_modules(modules);
        assert!(report.contains_authz_vuln(1), "{modules}\n{report:#?}");
    }
}

#[test]
fn an_action_is_reachable_only_through_a_rovo_agent_that_lists_it() {
    let action = "  action:\n    - { key: act, function: resolver, name: Act, actionVerb: GET, description: x }\n";
    let agent =
        "  rovo:agent:\n    - { key: helper, name: Helper, prompt: help, actions: [act] }\n";
    let page = "  jira:globalPage:\n    - { key: page, resource: main, resolver: { function: resolver } }\n";
    for (modules, findings) in [
        (action.to_owned(), 0),
        (format!("{action}{agent}"), 1),
        (format!("{action}{page}"), 1),
    ] {
        let report = scan_with_modules(&modules);
        assert!(
            report.contains_authz_vuln(findings),
            "{modules}\n{report:#?}"
        );
    }
}
