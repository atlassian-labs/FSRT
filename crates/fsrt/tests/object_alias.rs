use std::process::Command;

#[test]
fn object_alias_cycle_from_repeated_calls_terminates() {
    let output = Command::new(env!("CARGO_BIN_EXE_fsrt"))
        .args(["--scanners", "secret"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-apps/object-alias-cycle"
        ))
        .env_remove("FORGE_LOG")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["errors"], false);
    assert_eq!(report["vulns"], serde_json::json!([]));
}
