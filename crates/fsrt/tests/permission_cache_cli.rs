use std::{path::PathBuf, process::Command};

/// Runs a scan whose Swagger downloads would fail, against a cache that does not exist.
fn fsrt_offline(test_name: &str, args: &[&str]) -> (std::process::Output, PathBuf) {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-apps/jira-damn-vulnerable-forge-app");
    let cache = std::env::temp_dir().join(format!(
        "fsrt-{test_name}-{}-missing-cache",
        std::process::id()
    ));
    assert!(!cache.exists(), "test cache must start empty: {cache:?}");
    let unreachable_proxy = "http://127.0.0.1:1";
    let output = Command::new(env!("CARGO_BIN_EXE_fsrt"))
        .arg(app)
        .arg("--cached-permissions-path")
        .arg(&cache)
        .args(args)
        // Also isolate loaders that fall back to $HOME/.cache/fsrt.
        .env("HOME", cache.join("home"))
        .env("https_proxy", unreachable_proxy)
        .env("HTTPS_PROXY", unreachable_proxy)
        .env("ALL_PROXY", unreachable_proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    (output, cache)
}

#[test]
fn scanning_without_permission_scanner_skips_swagger_specs() {
    let (output, cache) = fsrt_offline("no-permission", &["--scanners", "authorization,secret"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!cache.exists());
}

#[test]
fn dumping_ir_skips_swagger_specs() {
    let (output, cache) = fsrt_offline("dump-ir", &["--dump-ir", "runWebTrigger"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("IR for runWebTrigger"), "{stdout}");
    assert!(!cache.exists());
}
