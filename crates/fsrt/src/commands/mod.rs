use clap::Subcommand;

use crate::Result;

pub(crate) mod mint_fct;

/// CLI subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Mint an FCT for a deployed module.
    MintFct(mint_fct::MintFctArgs),
}

impl Command {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        match self {
            Self::MintFct(args) => args.diagnostic_logging_requested(),
        }
    }

    pub(crate) fn run(&self) -> Result<()> {
        match self {
            Self::MintFct(args) => mint_fct::run(args),
        }
    }
}
