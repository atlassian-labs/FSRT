use std::{fs, path::Path};

use clap::Subcommand;

use crate::{Result, forge_project::find_manifest_path};

pub(crate) mod invoke_extension;
#[cfg(feature = "mint_cookie")]
pub(crate) mod mint_cookie;
pub(crate) mod mint_fct;
pub(crate) mod mint_fit;

fn resolve_app_id(app_id: Option<&str>, app_dir: Option<&Path>) -> Result<String> {
    if let Some(app_id) = app_id {
        return Ok(app_id.to_string());
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
    /// Run dynamic application security testing commands.
    Dast {
        #[command(subcommand)]
        command: DastCommand,
    },
}

/// Dynamic application security testing subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum DastCommand {
    /// Invoke a deployed extension with a tester-controlled payload.
    InvokeExtension(invoke_extension::InvokeExtensionArgs),

    /// Mint an FCT for a deployed module.
    MintFct(mint_fct::MintFctArgs),

    /// Mint a FIT for a deployed module and Forge remote.
    MintFit(mint_fit::MintFitArgs),

    /// Harvest an Atlassian session cookie through a browser login.
    #[cfg(feature = "mint_cookie")]
    MintCookie(mint_cookie::MintCookieArgs),
}

impl Command {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::Dast { command } => command.diagnostic_logging_requested(),
        }
    }

    pub(crate) fn run(&self) -> Result<()> {
        match self {
            Self::Dast { command } => command.run(),
        }
    }
}

impl DastCommand {
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
