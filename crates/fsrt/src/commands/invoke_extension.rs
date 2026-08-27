use std::path::PathBuf;

use clap::{Args, ValueHint};
use serde_json::Value as JsonValue;
use tracing::info;

use crate::Result;

use super::{parse_json, resolve_app_id};

const REDACTED_FCT: &str = "<FCT selected at runtime>";

/// `invoke-extension` arguments.
#[derive(Args, Debug)]
pub(crate) struct InvokeExtensionArgs {
    /// Resolver function key, optionally prefixed with `resolver.`.
    #[arg(name = "FUNCTION")]
    function: String,

    /// Deployed resolver module key.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Optional invocation payload as a JSON object.
    #[arg(long, value_name = "JSON", value_parser = parse_json)]
    payload: Option<JsonValue>,

    /// Invocation context as a JSON object (defaults to {}).
    #[arg(long, value_name = "JSON", value_parser = parse_json)]
    ctx: Option<JsonValue>,

    /// Existing FCT to use instead of minting one.
    #[arg(long)]
    fct: Option<String>,

    /// Forge app ID. Does not require a local manifest.
    #[arg(long, value_name = "APP_ID", conflicts_with = "app_dir")]
    app_id: Option<String>,

    /// Forge app directory. Defaults to the current directory when --app-id is omitted.
    #[arg(long, value_hint = ValueHint::DirPath, conflicts_with = "app_id")]
    app_dir: Option<PathBuf>,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Resolve metadata and print redacted variables without invoking.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl InvokeExtensionArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &InvokeExtensionArgs) -> Result<()> {
    let app_id = resolve_app_id(args.app_id.as_deref(), args.app_dir.as_deref())?;
    let module_key = args.module_key.as_str();

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&app_id, config)?;
    let ctx = args.ctx.clone().unwrap_or_else(|| serde_json::json!({}));

    if args.dry_run {
        let request = tester.invoke_extension_request(
            module_key,
            &args.function,
            args.payload.as_ref(),
            &ctx,
            REDACTED_FCT,
        )?;
        println!("{}", serde_json::to_string_pretty(&request.variables)?);
        return Ok(());
    }

    let (context_token, fct_source) = match args.fct.as_deref() {
        Some(fct) => (fct.to_string(), "supplied"),
        None => (tester.mint_fct(module_key, &ctx)?, "minted"),
    };
    info!(fct_source, "selected FCT for extension invocation");

    let outcome = tester.invoke_extension(
        module_key,
        &args.function,
        args.payload.as_ref(),
        &ctx,
        &context_token,
    )?;
    match outcome.response() {
        Some(response) => println!("{}", serde_json::to_string_pretty(response)?),
        None => println!("null"),
    }

    Ok(())
}
