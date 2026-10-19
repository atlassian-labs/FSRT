use std::process::Command;

fn fsrt(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fsrt"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_lists_secret_logging_options_with_defaults() {
    let output = fsrt(&["--help"]);
    // Compare without the terminal-dependent line wrapping.
    let help = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(output.status.success());
    assert!(help.contains("Secret logging (--scanners secret-logging):"));
    assert!(help.contains("[default: password passwd pwd secret token apikey privatekey]"));
    assert!(help.contains("[default: pagetoken]"));
}
