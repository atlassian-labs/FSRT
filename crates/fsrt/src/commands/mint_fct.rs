use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};
use tracing::info;

use crate::{Result, forge_project::find_manifest_path};

/// `mint-fct` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFctArgs {
    /// Deployed module key.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Forge app directory.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// JSON object to include in the extension context.
    #[arg(long, value_name = "JSON", value_parser = parse_ctx)]
    ctx: Option<serde_json::Value>,

    /// Query metadata and print the GraphQL request without minting.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn parse_ctx(value: &str) -> std::result::Result<serde_json::Value, String> {
    let ctx: serde_json::Value =
        serde_json::from_str(value).map_err(|error| format!("invalid JSON: {error}"))?;

    if !ctx.is_object() {
        return Err("ctx must be a JSON object".to_string());
    }

    Ok(ctx)
}

impl MintFctArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &MintFctArgs) -> Result<()> {
    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config)?;
    let ctx = args.ctx.clone().unwrap_or_else(|| serde_json::json!({}));
    if args.dry_run {
        let request = tester.mint_fct_request(&args.module_key, &ctx)?;
        let variables = format!("{:#}", request.variables);
        info!(variables = %variables, "FCT GraphQL variables");
    } else {
        let fct = tester.mint_fct(&args.module_key, &ctx)?;
        println!("{fct}");
    }

    Ok(())
}
