use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not find file at {path} for function `{function}`")]
    FileNotFound { function: String, path: PathBuf },
    #[error("function handler {0} should contain a period")]
    InvalidFuncHandler(String),
}

pub type Result<T> = core::result::Result<T, Error>;
