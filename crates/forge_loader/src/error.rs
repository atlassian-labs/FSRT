use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Diagnostic, Error)]
pub enum Error {
    #[error("could not find file at {path} for function `{function}`")]
    #[diagnostic(help(
        "try adding a file with a .jsx,.js,.tx,.tsx extension in the src directory"
    ))]
    FileNotFound { function: String, path: PathBuf },
    #[error("function handler {0} should contain a period")]
    #[diagnostic(help("try adding a period separating the file name and function name"))]
    InvalidFuncHandler(String),
}

pub type Result<T> = core::result::Result<T, Error>;
