use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};
use serde_json::Value;

use crate::{Result, forge_project::find_manifest_path};

use super::parse_ctx;

const REDACTED_FCT: &str = "<FCT selected at runtime>";

/// `mint-fit` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFitArgs {
    /// Deployed module key used when an FCT must be minted.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Forge remote key to sign the invocation for.
    #[arg(name = "REMOTE_KEY")]
    remote_key: String,

    /// Force a new FCT with this inline JSON object as its context.
    #[arg(long = "ctx", value_parser = parse_ctx)]
    ctx: Option<Value>,

    /// Existing FCT to pass in.
    #[arg(long)]
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
        let request = tester.mint_fit_request(&args.module_key, REDACTED_FCT, &args.remote_key)?;
        println!("variables={:#}", request.variables);
        return Ok(());
    }

    let token = tester.mint_fit(
        &args.module_key,
        &args.remote_key,
        args.ctx.as_ref(),
        args.fct.as_deref(),
    )?;
    println!("{}", token.jwt());

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
    fn parses_required_keys_and_optional_fit_inputs() {
        let args = TestArgs::try_parse_from([
            "fsrt",
            "module-key",
            "remote-key",
            "--ctx",
            r#"{"issueKey":"TEST-1"}"#,
            "--fct",
            "provided-fct",
            "--dry-run",
        ])
        .unwrap()
        .fit;

        assert_eq!(args.module_key, "module-key");
        assert_eq!(args.remote_key, "remote-key");
        assert_eq!(args.ctx, Some(serde_json::json!({ "issueKey": "TEST-1" })));
        assert_eq!(args.fct.as_deref(), Some("provided-fct"));
        assert!(args.dry_run);
        assert!(args.diagnostic_logging_requested());
    }

    #[test]
    fn omits_context_by_default() {
        let args = TestArgs::try_parse_from(["fsrt", "module-key", "remote-key"])
            .unwrap()
            .fit;

        assert_eq!(args.ctx, None);
        assert_eq!(args.fct, None);
        assert!(!args.diagnostic_logging_requested());
    }

    #[test]
    fn rejects_missing_keys_and_invalid_context_before_execution() {
        assert!(TestArgs::try_parse_from(["fsrt", "module-key"]).is_err());
        for context in ["not-json", "[]", "null", r#""string""#] {
            assert!(
                TestArgs::try_parse_from(["fsrt", "module-key", "remote-key", "--ctx", context,])
                    .is_err(),
                "context unexpectedly accepted: {context}"
            );
        }
    }
}
