use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};
use serde_json::Value;

use crate::{Result, forge_project::find_manifest_path};

use super::parse_json;

const REDACTED_FCT: &str = "<FCT selected at runtime>";

/// `mint-fit` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFitArgs {
    /// Deployed module key used when an FCT must be minted.
    #[arg(
        long = "module",
        value_name = "MODULE_KEY",
        required_unless_present = "fct",
        conflicts_with = "fct"
    )]
    module_key: Option<String>,

    /// Forge remote key to sign the invocation for.
    #[arg(name = "REMOTE_KEY")]
    remote_key: String,

    /// Force a new FCT with this inline JSON object as its context.
    #[arg(
        long = "ctx",
        value_parser = parse_json,
        requires = "module_key",
        conflicts_with = "fct"
    )]
    ctx: Option<Value>,

    /// Existing FCT to pass in.
    #[arg(long, conflicts_with_all = ["module_key", "ctx"])]
    fct: Option<String>,

    /// Forge app directory.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Authenticate, query metadata, and print redacted FIT variables without minting.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl MintFitArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &MintFitArgs) -> Result<()> {
    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config)?;
    if args.dry_run {
        let request = tester.mint_fit_request(REDACTED_FCT, &args.remote_key)?;
        println!("variables={:#}", request.variables);
        return Ok(());
    }

    let fct = if let Some(module_key) = args.module_key.as_deref() {
        let ctx = args.ctx.clone().unwrap_or_else(|| serde_json::json!({}));
        tester.mint_fct(module_key, &ctx)?
    } else {
        args.fct
            .clone()
            .expect("clap requires either MODULE_KEY or an existing FCT")
    };
    let token = tester.mint_fit(&args.remote_key, &fct)?;
    println!("{token}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestArgs {
        #[command(flatten)]
        fit: MintFitArgs,
    }

    #[test]
    fn accepts_fct_input_modes() {
        assert!(TestArgs::try_parse_from(["fsrt", "remote-key", "--fct", "provided-fct"]).is_ok());
        assert!(
            TestArgs::try_parse_from(["fsrt", "remote-key", "--module", "module-key",]).is_ok()
        );
        assert!(
            TestArgs::try_parse_from([
                "fsrt",
                "remote-key",
                "--module",
                "module-key",
                "--ctx",
                r#"{"issueKey":"TEST-1"}"#,
            ])
            .is_ok()
        );
    }

    #[test]
    fn rejects_conflicting_fct_input_modes() {
        for args in [
            &[
                "fsrt",
                "remote-key",
                "--fct",
                "provided-fct",
                "--module",
                "module-key",
            ][..],
            &[
                "fsrt",
                "remote-key",
                "--fct",
                "provided-fct",
                "--module",
                "module-key",
                "--ctx",
                r#"{"issueKey":"TEST-1"}"#,
            ][..],
            &[
                "fsrt",
                "remote-key",
                "--fct",
                "provided-fct",
                "--ctx",
                r#"{"issueKey":"TEST-1"}"#,
            ][..],
        ] {
            let error = TestArgs::try_parse_from(args).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn rejects_incomplete_or_positional_module_inputs() {
        assert!(TestArgs::try_parse_from(["fsrt", "remote-key"]).is_err());
        assert!(
            TestArgs::try_parse_from(["fsrt", "remote-key", "--ctx", r#"{"issueKey":"TEST-1"}"#,])
                .is_err()
        );
        assert!(
            TestArgs::try_parse_from([
                "fsrt",
                "remote-key",
                "--ctx",
                r#"{"issueKey":"TEST-1"}"#,
                "--fct",
                "provided-fct",
            ])
            .is_err()
        );
        assert!(TestArgs::try_parse_from(["fsrt", "module-key", "remote-key"]).is_err());
    }
}
