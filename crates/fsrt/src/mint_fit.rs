//! Forge Invocation Token (FIT) minting — `fsrt mint-fit` subcommand.
//!
//! The FCT is minted internally and used as input to the FIT mutation.

use super::mint_common::{
    MintError, Product, build_auth_headers, detect_remote_key, extract_manifest_context,
    load_config, load_manifest, mint_fct_jwt, post_graphql, resolve_environment,
};

use forge_loader::manifest::ForgeManifest;
use serde_json::Value as JsonValue;
use tracing::{info, warn};

// GraphQL mutation for FIT minting
const FIT_MUTATION: &str = r#"mutation SignInvocationTokenForUI($input: SignInvocationTokenForUIInput!) {
  signInvocationTokenForUI(input: $input) {
    forgeInvocationToken {
      jwt
      expiresAt
    }
  }
}"#;

const FIT_OPERATION_NAME: &str = "SignInvocationTokenForUI";

// CLI arguments
#[derive(Debug, clap::Args)]
pub struct MintFitArgs {
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

pub fn run_mint_fit(args: &MintFitArgs) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Load and parse the TOML config file
    let config = load_config(&args.config)?;

    // Load manifest.yml
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

    // Which remote the FIT targets, fall back to first remote in manifest.
    let remote_key_override = match config.product {
        Product::Confluence => config
            .confluence
            .as_ref()
            .and_then(|c| c.remote_key.as_deref()),
        Product::Global => config.global.as_ref().and_then(|g| g.remote_key.as_deref()),
    };

    let remote_key = detect_remote_key(&manifest, remote_key_override).ok_or_else(|| {
        MintError::Config(
            "No remotes declared in manifest.yml. \
             FIT minting requires a remote backend. \
             Add a `remotes:` section with a `key:` field to your manifest."
                .to_string(),
        )
    })?;

    // Auto-detection warning
    if remote_key_override.is_none() {
        warn!(
            remote_key = %remote_key,
            "no remote_key configured — targeting the first remote declared in the manifest"
        );
    }

    // Diagnostics go to stderr; only the JWT is written to stdout.
    info!(
        app_id = %manifest_ctx.app_id,
        app_id_bare = %manifest_ctx.app_id_bare,
        app_name = ?manifest_ctx.app_name,
        module_key = ?manifest_ctx.module_key,
        module_type = ?manifest_ctx.module_type,
        remote_key = %remote_key,
        endpoint = %config.graphql_endpoint,
        "derived manifest context"
    );

    // Dry-run exit: log the request shape for inspection without any network calls.
    if args.dry_run {
        // We can't show the real FCT JWT without minting it, so show the shape.
        let preview_vars = serde_json::json!({
            "input": {
                "forgeContextToken": "<FCT JWT — minted at runtime>",
                "remoteKey": remote_key,
            }
        });
        info!(
            mutation = %FIT_MUTATION,
            variables = %serde_json::to_string_pretty(&preview_vars)?,
            "dry run requested — not sending GraphQL request"
        );
        return Ok(());
    }

    // Build auth headers
    let auth_headers = build_auth_headers(&config.auth)?;

    // Resolve environment_id + app_version (may hit the network)
    resolve_environment(&config, &mut manifest_ctx, &auth_headers)?;

    // Step 1: mint the FCT.
    info!("step 1: minting FCT");
    let fct_jwt = mint_fct_jwt(&config, &manifest_ctx, &auth_headers)?;
    info!("FCT minted successfully");

    // Step 2: mint the FIT using the FCT.
    info!(operation = FIT_OPERATION_NAME, "step 2: minting FIT");

    let fit_variables = serde_json::json!({
        "input": {
            "forgeContextToken": fct_jwt,
            "remoteKey": remote_key,
        }
    });

    // Send the FIT minting request
    let (status, body) = post_graphql(
        &config.graphql_endpoint,
        FIT_OPERATION_NAME,
        &auth_headers,
        FIT_MUTATION,
        &fit_variables,
    )?;

    // Parse the response.
    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        warn!(response_body = %body, "FIT response was not valid JSON");
        MintError::Json(e)
    })?;
    info!(
        http_status = status,
        response = %serde_json::to_string_pretty(&parsed).unwrap_or_default(),
        "FIT GraphQL response"
    );

    // Navigate to the FIT fields in the response.
    // data.signInvocationTokenForUI.forgeInvocationToken → { jwt, expiresAt }
    let fit_obj = parsed
        .get("data")
        .and_then(|d| d.get("signInvocationTokenForUI"))
        .and_then(|r| r.get("forgeInvocationToken"));

    if let Some(errors) = parsed.get("errors").and_then(|e| e.as_array())
        && !errors.is_empty()
    {
        let messages: Vec<&str> = errors
            .iter()
            .filter_map(|err| err.get("message").and_then(|m| m.as_str()))
            .collect();
        return Err(MintError::FitFailed(format!(
            "FIT minting failed: {}",
            if messages.is_empty() {
                "server returned errors with no messages".to_string()
            } else {
                messages.join("; ")
            }
        ))
        .into());
    }

    // Extract the JWT
    let token = fit_obj.ok_or_else(|| {
        MintError::FitFailed(
            "signInvocationTokenForUI.forgeInvocationToken missing from response".into(),
        )
    })?;
    let jwt = token.get("jwt").and_then(|v| v.as_str()).ok_or_else(|| {
        MintError::FitFailed("forgeInvocationToken returned but `jwt` field is missing".into())
    })?;
    let expires_at = token
        .get("expiresAt")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");

    info!(expires_at, "successfully minted Forge Invocation Token");

    // Print token to stdout
    println!("{}", jwt);

    Ok(())
}
