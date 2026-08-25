use clap::Subcommand;

use crate::Result;

pub(crate) mod mint_fct;
pub(crate) mod mint_fit;

fn parse_ctx(value: &str) -> std::result::Result<serde_json::Value, String> {
    let ctx: serde_json::Value =
        serde_json::from_str(value).map_err(|error| format!("invalid JSON: {error}"))?;

    if !ctx.is_object() {
        return Err("ctx must be a JSON object".to_string());
    }

    Ok(ctx)
}

/// CLI subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Mint an FCT for a deployed module.
    MintFct(mint_fct::MintFctArgs),

    /// Mint a FIT for a deployed module and Forge remote.
    MintFit(mint_fit::MintFitArgs),
}

impl Command {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::MintFct(args) => args.diagnostic_logging_requested(),
            Self::MintFit(args) => args.diagnostic_logging_requested(),
        }
    }

    pub(crate) fn run(&self) -> Result<()> {
        match self {
            Self::MintFct(args) => mint_fct::run(args),
            Self::MintFit(args) => mint_fit::run(args),
        }
    }
}
