use std::process::Command;

#[test]
fn captured_help_advertises_parseable_scanner_choices() {
    let binary = env!("CARGO_BIN_EXE_fsrt");
    let output = Command::new(binary).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    // Keep the format consumed by scan_fsrt.py, including wrapped help lines.
    let pattern = regex::Regex::new(r"(?s)--scanners\b.*?\[possible values:\s*([^\]]+)\]").unwrap();
    let choices = pattern.captures(&help).expect("missing scanner choices");
    let names: Vec<_> = choices[1].split(',').map(str::trim).collect();
    assert_eq!(
        names,
        [
            "authentication",
            "authorization",
            "auth-header",
            "permission",
            "secret",
            "secret-logging",
            "runtime-version",
            "sql-injection"
        ]
    );
    let parsed = Command::new(binary)
        .args(["--scanners", &names.join(","), "--help"])
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
}
