use std::path::PathBuf;

use clap::{Args, ValueHint};
use tracing::info;

use crate::Result;

use super::{parse_json, resolve_app_id};

/// `mint-fct` arguments.
#[derive(Args, Debug)]
pub(crate) struct MintFctArgs {
    /// Deployed module key.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Forge app ID. Does not require a local manifest.
    #[arg(long, value_name = "APP_ID", conflicts_with = "app_dir")]
    app_id: Option<String>,

    /// Forge app directory. Defaults to the current directory when --app-id is omitted.
    #[arg(long, value_hint = ValueHint::DirPath, conflicts_with = "app_id")]
    app_dir: Option<PathBuf>,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// JSON object to include in the extension context.
    #[arg(long, value_name = "JSON", value_parser = parse_json)]
    ctx: Option<serde_json::Value>,

    /// Query metadata and print the GraphQL request without minting.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl MintFctArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &MintFctArgs) -> Result<()> {
    let app_id = resolve_app_id(args.app_id.as_deref(), args.app_dir.as_deref())?;
    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&app_id, config)?;
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
