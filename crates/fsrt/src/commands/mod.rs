use std::{fs, path::Path};

use clap::Subcommand;

use crate::{Result, forge_project::find_manifest_path};

pub(crate) mod invoke_extension;
#[cfg(feature = "mint_cookie")]
pub(crate) mod mint_cookie;
pub(crate) mod mint_fct;
pub(crate) mod mint_fit;

const APP_ID_ARI_PREFIX: &str = "ari:cloud:ecosystem::app/";

/// Accepts an app ID as either a bare `{uuid}` or a full
/// `ari:cloud:ecosystem::app/{uuid}` ARI and returns the ARI form the deployment
/// GraphQL API expects.
fn normalize_app_id(app_id: &str) -> String {
    let app_id = app_id.trim();
    if app_id.starts_with(APP_ID_ARI_PREFIX) {
        app_id.to_string()
    } else {
        format!("{APP_ID_ARI_PREFIX}{app_id}")
    }
}

/// Resolves the Forge app ID.
///
/// Precedence is the `--app-id` CLI argument, then `app_id` in the config file,
/// then the `app.id` read from the app manifest. The manifest is consulted only
/// when neither the CLI nor the config supplies an ID, so a deployed app can be
/// targeted without a local checkout.
fn resolve_app_id(
    cli_app_id: Option<&str>,
    config_app_id: Option<&str>,
    app_dir: Option<&Path>,
) -> Result<String> {
    let supplied = cli_app_id
        .or(config_app_id)
        .map(str::trim)
        .filter(|app_id| !app_id.is_empty());
    if let Some(app_id) = supplied {
        return Ok(normalize_app_id(app_id));
    }

    let app_dir = app_dir.unwrap_or_else(|| Path::new("."));
    let manifest_path = find_manifest_path(app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;
    Ok(manifest.app.id.to_string())
}

fn parse_json(value: &str) -> std::result::Result<serde_json::Value, String> {
    let json: serde_json::Value =
        serde_json::from_str(value).map_err(|error| format!("invalid JSON: {error}"))?;

    if !json.is_object() {
        return Err("must be a JSON object".to_string());
    }

    Ok(json)
}

/// CLI subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Interact with deployed Forge apps.
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
}

/// Deployed Forge app interaction subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum RemoteCommand {
    /// Invoke a deployed extension with a custom payload.
    InvokeExtension(invoke_extension::InvokeExtensionArgs),

    /// Mint an FCT for a deployed module.
    MintFct(mint_fct::MintFctArgs),

    /// Mint a FIT for a deployed module and Forge remote.
    MintFit(mint_fit::MintFitArgs),

    /// Save an Atlassian session cookie through a browser login.
    #[cfg(feature = "mint_cookie")]
    MintCookie(mint_cookie::MintCookieArgs),
}

impl Command {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::Remote { command } => command.diagnostic_logging_requested(),
        }
    }

    pub(crate) fn run(&self) -> Result<()> {
        match self {
            Self::Remote { command } => command.run(),
        }
    }
}

impl RemoteCommand {
    fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::InvokeExtension(args) => args.diagnostic_logging_requested(),
            Self::MintFct(args) => args.diagnostic_logging_requested(),
            Self::MintFit(args) => args.diagnostic_logging_requested(),
            #[cfg(feature = "mint_cookie")]
            Self::MintCookie(args) => args.diagnostic_logging_requested(),
        }
    }

    fn run(&self) -> Result<()> {
        match self {
            Self::InvokeExtension(args) => invoke_extension::run(args),
            Self::MintFct(args) => mint_fct::run(args),
            Self::MintFit(args) => mint_fit::run(args),
            #[cfg(feature = "mint_cookie")]
            Self::MintCookie(args) => mint_cookie::run(args),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARI: &str = "ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986";
    const UUID: &str = "07b89c0f-949a-4905-9de9-6c9521035986";

    #[test]
    fn normalizes_bare_uuid_and_preserves_ari() {
        assert_eq!(normalize_app_id(UUID), ARI);
        assert_eq!(normalize_app_id(ARI), ARI);
        assert_eq!(normalize_app_id(&format!("  {UUID}  ")), ARI);
    }

    #[test]
    fn cli_app_id_wins_over_config_and_manifest() {
        // A non-existent app_dir proves the manifest is never read.
        let app_dir = Path::new("/nonexistent/fsrt/app/dir");
        assert_eq!(
            resolve_app_id(Some(UUID), Some("config-value"), Some(app_dir)).unwrap(),
            ARI
        );
        assert_eq!(resolve_app_id(Some(ARI), None, Some(app_dir)).unwrap(), ARI);
    }

    #[test]
    fn config_app_id_used_when_cli_absent() {
        let app_dir = Path::new("/nonexistent/fsrt/app/dir");
        assert_eq!(
            resolve_app_id(None, Some(UUID), Some(app_dir)).unwrap(),
            ARI
        );
        assert_eq!(resolve_app_id(None, Some(ARI), Some(app_dir)).unwrap(), ARI);
    }

    #[test]
    fn blank_ids_fall_through_to_manifest() {
        // With no usable ID and a missing manifest, resolution must error rather
        // than silently producing a prefix-only ARI.
        let app_dir = Path::new("/nonexistent/fsrt/app/dir");
        assert!(resolve_app_id(Some("   "), Some(""), Some(app_dir)).is_err());
    }
}
