use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn parses_arguments_from_file_with_default_prefix() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let argfile = std::env::temp_dir().join(format!("fsrt-{unique}.args"));
    fs::write(&argfile, "--version\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fsrt"))
        .arg(format!(
            "{}{path}",
            argfile::PREFIX,
            path = argfile.display()
        ))
        .output()
        .unwrap();

    fs::remove_file(argfile).unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "fsrt 0.1.0\n");
}
