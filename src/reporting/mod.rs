//! Output reporters: terminal (human), JSON (machine), HTML (shareable),
//! and SARIF (IDE/CI integration).
//!
//! All implement the [`Reporter`] trait from `crate::models`. The terminal
//! reporter is the default and produces ANSI-colored, severity-grouped output.
//! The JSON reporter emits a single JSON object suitable for piping to `jq` or
//! downstream tooling. The HTML reporter produces a self-contained single-file
//! report with embedded CSS/JS for filtering and searching. The SARIF reporter
//! emits SARIF v2.1.0 JSON for VS Code, GitHub code scanning, and other tools.

pub mod html;
pub mod json;
pub mod sarif;
pub mod terminal;

pub use html::HtmlReporter;
pub use json::JsonReporter;
pub use sarif::SarifReporter;
pub use terminal::TerminalReporter;
