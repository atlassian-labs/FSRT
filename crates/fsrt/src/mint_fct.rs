//! Forge Context Token (FCT) minting — `fsrt mint-fct` subcommand.
//!
//! This is a Rust port of `scripts/mint_fct_spike.py`.
//! All shared types and functions live in `mint_common`. This module contains
//! only what is specific to the `mint-fct` subcommand:
//!   - `MintFctArgs` — the CLI argument struct
//!   - `run_mint_fct()` — the top-level entry point

// ============================================================================
// Imports
// ============================================================================

// Everything shared with mint_fit lives in mint_common.
// `super::` means "the parent module" — in Rust's module tree, mint_fct and
// mint_common are siblings under the same crate root (main.rs).
use super::mint_common::{
    DEFAULT_CONFLUENCE_MUTATION, DEFAULT_GLOBAL_APP_MUTATION, Product, build_auth_headers,
    extract_manifest_context, load_config, load_manifest, mint_fct_jwt, resolve_environment,
};

use forge_loader::manifest::ForgeManifest;

// ============================================================================
// CLI arguments
// ============================================================================

// `#[derive(Debug, clap::Args)]`:
//   Debug      → printable for logging
//   clap::Args → clap parses these fields from the CLI flags
//
// The user runs:
//   fsrt mint-fct [--app-dir ./my-app] [--config ./cfg.toml] [--dry-run]
//   (--app-dir defaults to ".", --config to "./fsrt-remote.toml")
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
}

// ============================================================================
// run_mint_fct()
// ============================================================================
// Top-level entry point for `fsrt mint-fct`.
// Called from main.rs after clap parses the CLI arguments.
//
// Returns `Box<dyn std::error::Error>` so it can propagate both MintError
// and any other errors (e.g. config parse errors) back to main().
pub fn run_mint_fct(args: &MintFctArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // --- 1. Load and parse the TOML config file ---
    // load_config() uses the `config` crate to read fsrt-remote.toml and
    // deserialise it into MintFctConfig.
    let config = load_config(&args.config)?;

    // --- 2. Load manifest.yml ---
    // load_manifest() reads the file exactly once and returns its raw text.
    // We parse it a single time into a typed ForgeManifest (which borrows from
    // manifest_text); all module details are read through typed accessors.
    let manifest_text = load_manifest(&args.app_dir)?;
    let manifest: ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    // --- 3. Extract manifest context ---
    // Use the module_key from the product-specific config section if provided,
    // otherwise auto-detect from the manifest.
    let config_module_key = match config.product {
        Product::Confluence => config
            .confluence
            .as_ref()
            .and_then(|c| c.module_key.as_deref()),
        Product::Global => config.global.as_ref().and_then(|g| g.module_key.as_deref()),
    };

    let mut manifest_ctx = extract_manifest_context(&manifest, config_module_key);

    // --- 4. Build auth headers ---
    let auth_headers = build_auth_headers(&config.auth)?;

    // --- 4b. Resolve environment_id + app_version ---
    // If the config didn't provide environment_id, look it up from the Forge
    // platform (using environment_key, default "development"). This is a
    // read-only query and populates manifest_ctx for build_variables().
    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    // --- 5. Print diagnostic info ---
    println!("\n=== Product ===");
    println!("  {}", config.product);
    println!("\n=== Derived manifest context ===");
    println!("  app_id:      {}", manifest_ctx.app_id);
    println!("  app_id_bare: {}", manifest_ctx.app_id_bare);
    println!("  app_name:    {:?}", manifest_ctx.app_name);
    println!("  module_key:  {:?}", manifest_ctx.module_key);
    println!("  module_type: {:?}", manifest_ctx.module_type);
    println!("\n=== GraphQL endpoint ===");
    println!("{}", config.graphql_endpoint);
    println!("\n=== GraphQL mutation ===");
    let default_mutation = match config.product {
        Product::Confluence => DEFAULT_CONFLUENCE_MUTATION,
        Product::Global => DEFAULT_GLOBAL_APP_MUTATION,
    };
    println!("{}", config.mutation.as_deref().unwrap_or(default_mutation));

    // --- 6. Dry-run exit ---
    // Build and print variables for inspection, but don't send the request.
    if args.dry_run {
        let variables = super::mint_common::build_variables(&config, &manifest_ctx)?;
        println!("\n=== GraphQL variables ===");
        println!("{}", serde_json::to_string_pretty(&variables)?);
        println!("\nDry run requested — not sending GraphQL request.");
        return Ok(());
    }

    // --- 7. Mint the FCT ---
    // mint_fct_jwt() does the POST and returns the JWT string, or an error.
    // This same function is also called by run_mint_fit() in mint_fit.rs.
    let jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;

    // --- 8. Print success output ---
    println!("\n=== SUCCESS: Forge Context Token ===");
    println!("jwt: {}", jwt);

    Ok(())
}
