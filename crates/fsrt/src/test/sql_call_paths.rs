use super::*;

fn proof(source: &str) -> String {
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source);
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "sql-injection"]),
    );
    let vulns = report.into_vulns();
    assert_eq!(vulns.len(), 1, "{vulns:#?}");
    vulns[0].proof().to_owned()
}

#[test]
fn proof_names_the_caller_and_call_site_of_each_hop() {
    let proof = proof(
        "import sql from '@forge/sql';
         function leaf(text) { return sql.prepare(text); }
         function middle(text) { return leaf(text); }
         export function run(payload) { return middle(payload.query); }",
    );
    assert!(
        proof.starts_with(
            "Propagation path: run -> call from run at src/index.js:4:48 \
             -> call from middle at src/index.js:3:41 -> leaf."
        ),
        "{proof}"
    );
}
