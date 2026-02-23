//! Output reporters: terminal (human) and JSON (machine).
//!
//! Both implement the [`Reporter`] trait from `crate::models`. The terminal
//! reporter is the default and produces ANSI-colored, severity-grouped output.
//! The JSON reporter emits a single JSON object suitable for piping to `jq` or
//! downstream tooling.

pub mod json;
pub mod terminal;

pub use json::JsonReporter;
pub use terminal::TerminalReporter;
