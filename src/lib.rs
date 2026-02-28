pub mod cache;
pub mod cli;
pub mod collectors;
pub mod config;
pub mod detection;
pub mod models;
pub mod reporting;

use thiserror::Error;

/// Top-level error type for Simple Key Sentry.
/// Extended by later blocks as each subsystem adds its own error variants.
#[derive(Debug, Error)]
pub enum SksError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Collector error: {0}")]
    Collector(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Report error: {0}")]
    Report(String),
}
