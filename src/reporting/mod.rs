//! Output reporters: terminal (human), JSON (machine), and HTML (shareable).
//!
//! All implement the [`Reporter`] trait from `crate::models`. The terminal
//! reporter is the default and produces ANSI-colored, severity-grouped output.
//! The JSON reporter emits a single JSON object suitable for piping to `jq` or
//! downstream tooling. The HTML reporter produces a self-contained single-file
//! report with embedded CSS/JS for filtering and searching.

pub mod html;
pub mod json;
pub mod terminal;

pub use html::HtmlReporter;
pub use json::JsonReporter;
pub use terminal::TerminalReporter;
