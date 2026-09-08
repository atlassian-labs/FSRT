use super::*;

fn scan(source: &str) -> Report {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.manifest_file_content = Some("modules:\n  macro:\n    - key: test\n      function: main\n      title: Test\n  function:\n    - key: main\n      handler: index.run\napp:\n  id: test-app\npermissions:\n  scopes: []\n".to_owned());
    project.add_file("src/index.js", source);
    scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "secret-logging"]),
    )
}

#[test]
fn secret_logging_distinguishes_fulfillment_sink_bodies() {
    let report = scan(
        "import { kvs } from '@forge/kvs';
         export function run() {
             kvs.getSecret('first').then(value => console.log(value));
             kvs.getSecret('second').then(value => console.log(value));
         }",
    );
    assert!(!report.has_errors());
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 2, "{report:#?}");
    assert_ne!(vulns[0].check_name(), vulns[1].check_name());
    let diagnostics = serde_json::to_value(vulns).unwrap();
    assert_ne!(diagnostics[0]["proof"], diagnostics[1]["proof"]);
    for diagnostic in diagnostics.as_array().unwrap() {
        assert!(diagnostic["proof"].as_str().unwrap().contains("IR body:"));
    }
}

#[test]
fn secret_logging_tracks_sparse_sinks_in_large_straight_line_body() {
    let mut source =
        String::from("import { kvs } from '@forge/kvs'; export async function run() {\n");
    for id in 0..8_000 {
        use std::fmt::Write;
        writeln!(source, "const x{id} = Math.random();").unwrap();
    }
    source.push_str(
        "console.log(x7999);\n\
         let value = await kvs.getSecret('key');\n\
         console.log(value);\n\
         value = 'redacted';\n\
         console.log(value);\n\
         }",
    );
    let report = scan(&source);
    assert!(!report.has_errors());
    assert_eq!(report.into_vulns().len(), 1, "{report:#?}");
}
