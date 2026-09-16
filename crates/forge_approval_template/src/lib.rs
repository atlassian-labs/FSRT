//! Pre-fill a Marketplace app approval submission from a Forge app manifest.
//!
//! See [`ApprovalTemplate`] for the entry point, and the [`answers`] module for
//! the rules governing what is pre-filled and what is deliberately left open.

pub mod answers;
pub mod code_analysis;
pub mod evidence;
pub mod facts;
pub mod flags;
pub mod listing;
pub mod questionnaire;
pub mod render;
pub mod report;

pub use code_analysis::{Checker, CodeAnalysis, CodeFinding};
pub use facts::ManifestFacts;
pub use render::to_markdown;
pub use report::ApprovalTemplate;
