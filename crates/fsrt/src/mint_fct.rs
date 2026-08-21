//! Forge Context Token (FCT) minting — `fsrt mint-fct` subcommand.
//!
//! All shared types and functions live in `mint_common`.

use super::mint_common::{
    DEFAULT_CONFLUENCE_MUTATION, DEFAULT_GLOBAL_APP_MUTATION, Product, build_auth_headers,
    extract_manifest_context, load_config, load_manifest, mint_fct_jwt, resolve_environment,
};

use forge_loader::manifest::ForgeManifest;
use tracing::{debug, info};

// CLI arguments
#[derive(Debug, clap::Args)]
pub struct MintFctArgs {
    #[arg(
        long,
        value_hint = clap::ValueHint::DirPath,
        default_value = ".",
        help = "OPTIONAL: Forge app dir containing manifest.yml."
    )]
    pub app_dir: std::path::PathBuf,

    #[arg(
        long,
        value_hint = clap::ValueHint::FilePath,
        default_value = "./fsrt-remote.toml",
        help = "OPTIONAL: config TOML path."
    )]
    pub config: std::path::PathBuf,

    #[arg(
        long,
        default_value_t = false,
        help = "OPTIONAL: print the request but do not call GraphQL.\nDefault: false."
    )]
    pub dry_run: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "OPTIONAL: print diagnostic logs to stderr.\n\
                The FORGE_LOG env var, if set, takes precedence.\nDefault: false."
    )]
    pub verbose: bool,
}

// Returns `Box<dyn std::error::Error>` so it can propagate both MintError
// and any other errors (e.g. config parse errors) back to main().
pub fn run_mint_fct(args: &MintFctArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Load and parse the TOML config file
    let config = load_config(&args.config)?;

    // Load manifest
    let manifest_text = load_manifest(&args.app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // Extract manifest context
    let config_module_key = match config.product {
        Product::Confluence => config
            .confluence
            .as_ref()
            .and_then(|c| c.module_key.as_deref()),
        Product::Global => config.global.as_ref().and_then(|g| g.module_key.as_deref()),
    };

    let mut manifest_ctx = extract_manifest_context(&manifest, config_module_key);

    // Diagnostics go to stderr; only the JWT is written to stdout.
    let default_mutation = match config.product {
        Product::Confluence => DEFAULT_CONFLUENCE_MUTATION,
        Product::Global => DEFAULT_GLOBAL_APP_MUTATION,
    };
    info!(
        product = %config.product,
        app_id = %manifest_ctx.app_id,
        app_id_bare = %manifest_ctx.app_id_bare,
        app_name = ?manifest_ctx.app_name,
        module_key = ?manifest_ctx.module_key,
        module_type = ?manifest_ctx.module_type,
        endpoint = %config.graphql_endpoint,
        "derived manifest context"
    );
    debug!(
        mutation = %config.mutation.as_deref().unwrap_or(default_mutation),
        "FCT GraphQL mutation"
    );

    // Dry-run exit: render and log the variables for inspection without any
    // network calls.
    if args.dry_run {
        let variables = super::mint_common::build_variables(&config, &manifest_ctx)?;
        info!(
            variables = %serde_json::to_string_pretty(&variables)?,
            "dry run requested — not sending GraphQL request"
        );
        return Ok(());
    }

    // Build auth headers
    let auth_headers = build_auth_headers(&config.auth)?;

    // Resolve environment_id + app_version (may hit the network)
    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    // Mint the FCT — does the POST and returns the JWT string, or an error.
    let jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;

    // The token is the command's result: print it to stdout only.
    info!("successfully minted Forge Context Token");
    println!("{}", jwt);

    Ok(())
}
