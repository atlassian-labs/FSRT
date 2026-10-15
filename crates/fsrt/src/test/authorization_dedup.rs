use super::*;

#[test]
fn authorization_findings_deduplicate_manifest_aliases_only() {
    let source = r#"
        import api, { route } from '@forge/api';
        export const first = async () => {
            const response = await api.asApp().requestJira(route`/rest/api/3/issue/ONE`);
            return response.json();
        };
        export const second = async () => {
            const response = await api.asApp().requestJira(route`/rest/api/3/issue/TWO`);
            return response.json();
        };
    "#;
    let manifest = r#"
modules:
  jira:globalPage:
    - key: first-page
      resource: main
      resolver: { function: first }
  jira:projectPage:
    - key: second-page
      resource: main
      resolver: { function: second }
  jira:issuePanel:
    - key: first-alias-page
      resource: main
      resolver: { function: first-alias }
  function:
    - key: first
      handler: index.first
    - key: first-alias
      handler: index.first
    - key: second
      handler: index.second
app:
  id: test-app
permissions:
  scopes: []
"#;
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    project.manifest_file_content = Some(manifest.to_owned());

    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );

    assert!(!report.has_errors(), "{report:#?}");
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 2, "{report:#?}");
    let check_names: HashSet<_> = vulns.iter().map(|v| v.check_name()).collect();
    assert_eq!(
        check_names.len(),
        2,
        "distinct handler findings must remain"
    );
}
