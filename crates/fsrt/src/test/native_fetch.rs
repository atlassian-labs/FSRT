use super::*;
use forge_analyzer::ir::{Inst, Intrinsic, Rvalue};
use forge_permission_resolver::permissions_resolver::PermMap;

#[test]
fn native_fetch_token_detection_survives_preceding_calls() {
    for name in ["fetch", "forgeFetch"] {
        for preceding in [false, true] {
            let health = if preceding {
                format!("const health = {name}('https://example.com/health');")
            } else {
                String::new()
            };
            let source = format!(
                "// src/index.js
                export function run() {{
                    {health}
                    const response = {name}('api.atlassian.com/rest/api/3/issue', {{
                        headers: {{ Authorization: 'Basic ' + process.env.API_TOKEN }}
                    }});
                    return response;
                }}"
            );
            let mut project = MockForgeProject::files_from_string("// src/index.js\n");
            project.add_file("src/index.js", source.clone());
            let report = scan_directory_test_with_args(
                project,
                Args::parse_from(["fsrt", "--scanners", "auth-header"]),
            );
            let findings: Vec<_> = report
                .into_vulns()
                .iter()
                .filter(|v| v.check_name() == "ATLASSIAN_API_TOKEN")
                .collect();
            assert_eq!(findings.len(), 1, "{source}: {report:#?}");
            assert_eq!(findings[0].severity(), Severity::Critical);
        }
    }
}

#[test]
fn native_fetch_lowering_preserves_identity_and_shadowing() {
    for (setup, parameter, local, expected) in [
        ("", "", "", 2),
        ("", "fetch", "", 0),
        ("function fetch() {}", "", "", 0),
        ("", "", "let fetch;", 0),
        ("", "", "const fetch = () => {};", 0),
        ("import { fetch } from '@forge/api';", "", "", 2),
        ("import { fetch } from 'another-package';", "", "", 0),
    ] {
        let source = format!(
            "// src/index.js
{setup}
export function run({parameter}) {{
                {local}
                fetch('https://example.com/health');
                fetch('api.atlassian.com/rest/api/3/issue', {{
                    headers: {{ Authorization: 'Basic ' + process.env.API_TOKEN }}
                }});
            }}"
        );
        let mut project = MockForgeProject::files_from_string("// src/index.js\n");
        project.add_file("src/index.js", source.clone());
        let permissions = HashSet::new();
        let mut perm_map = PermMap::new(&permissions, &crate::CacheConfig::default());
        let lowered = project
            .with_files_and_sourceroot(
                Path::new("src"),
                project.get_paths(),
                &[],
                &mut perm_map,
                &HashSet::new(),
            )
            .unwrap();
        let fetches = lowered
            .env
            .bodies()
            .flat_map(|body| body.blocks.iter())
            .flat_map(|block| block.insts.iter())
            .filter(|inst| {
                matches!(
                    inst,
                    Inst::Assign(_, Rvalue::Intrinsic(Intrinsic::Fetch, _))
                        | Inst::Expr(Rvalue::Intrinsic(Intrinsic::Fetch, _))
                )
            })
            .count();
        assert_eq!(fetches, expected, "{source}");
    }
}
