//! Interactive mode for guided secret scanning.
//!
//! Provides a step-by-step terminal interface for users who prefer a guided
//! experience over CLI flags. Launched when `sks` is run with no arguments
//! in an interactive terminal.
//!
//! The session flows through five screens:
//! 1. Welcome & explanation
//! 2. Scan target selection
//! 3. Scan execution (with progress)
//! 4. Results review
//! 5. Report generation offer

use std::io::IsTerminal;
use std::path::PathBuf;

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, MultiSelect};

use crate::models::ScanResult;
use crate::SksError;

/// Convert a dialoguer error into an SksError.
fn dialoguer_err(e: dialoguer::Error) -> SksError {
    match e {
        dialoguer::Error::IO(io_err) => SksError::Io(io_err),
    }
}

// ---------------------------------------------------------------------------
// ScanTarget
// ---------------------------------------------------------------------------

/// A scan source the user can enable/disable in interactive mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTarget {
    ShellHistory,
    Dotfiles,
    EnvFiles,
    CloudConfigs,
    AppConfigs,
    SshKeys,
    Clipboard,
    BrowserStorage,
}

impl ScanTarget {
    /// Human-readable label for the target selection screen.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ShellHistory => "Shell history (bash, zsh, fish)",
            Self::Dotfiles => "Dotfiles (~/.bashrc, ~/.zshrc, etc.)",
            Self::EnvFiles => "Environment files (.env)",
            Self::CloudConfigs => "Cloud CLI configs (AWS, GCP, Azure)",
            Self::AppConfigs => "App configs (Docker, k8s, npm, pip)",
            Self::SshKeys => "SSH keys (~/.ssh/)",
            Self::Clipboard => "Clipboard history (privacy-sensitive)",
            Self::BrowserStorage => "Browser localStorage (privacy-sensitive)",
        }
    }

    /// Whether this target is pre-selected by default.
    /// Clipboard and browser storage are opt-in only.
    pub fn default_enabled(&self) -> bool {
        !matches!(self, Self::Clipboard | Self::BrowserStorage)
    }

    /// Whether this target requires explicit confirmation before scanning.
    pub fn requires_confirmation(&self) -> bool {
        matches!(self, Self::Clipboard | Self::BrowserStorage)
    }

    /// All available scan targets in display order.
    pub fn all() -> Vec<ScanTarget> {
        vec![
            Self::ShellHistory,
            Self::Dotfiles,
            Self::EnvFiles,
            Self::CloudConfigs,
            Self::AppConfigs,
            Self::SshKeys,
            Self::Clipboard,
            Self::BrowserStorage,
        ]
    }
}

// ---------------------------------------------------------------------------
// InteractiveState
// ---------------------------------------------------------------------------

/// Mutable state threaded through the interactive session screens.
pub struct InteractiveState {
    /// Which scan targets the user selected.
    pub targets: Vec<ScanTarget>,
    /// The scan result, populated after the scan screen.
    pub scan_result: Option<ScanResult>,
    /// Path where the report was saved, if any.
    pub report_path: Option<PathBuf>,
}

impl Default for InteractiveState {
    fn default() -> Self {
        Self {
            targets: ScanTarget::all()
                .into_iter()
                .filter(|t| t.default_enabled())
                .collect(),
            scan_result: None,
            report_path: None,
        }
    }
}

impl InteractiveState {
    /// Whether clipboard scanning was selected.
    pub fn has_clipboard(&self) -> bool {
        self.targets.contains(&ScanTarget::Clipboard)
    }

    /// Whether browser storage scanning was selected.
    pub fn has_browser(&self) -> bool {
        self.targets.contains(&ScanTarget::BrowserStorage)
    }
}

// ---------------------------------------------------------------------------
// InteractiveSession
// ---------------------------------------------------------------------------

/// Manages the interactive mode flow through five screens.
pub struct InteractiveSession {
    state: InteractiveState,
    theme: ColorfulTheme,
}

impl Default for InteractiveSession {
    fn default() -> Self {
        Self::new()
    }
}

impl InteractiveSession {
    /// Create a new interactive session with default state.
    pub fn new() -> Self {
        Self {
            state: InteractiveState::default(),
            theme: ColorfulTheme::default(),
        }
    }

    /// Returns true if stdout and stdin are both interactive terminals.
    pub fn is_terminal() -> bool {
        std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
    }

    /// Run the full interactive session. Returns an exit code.
    ///
    /// Exit codes: 0 = clean/cancelled, 1 = findings found, 2 = error.
    pub fn run(&mut self) -> i32 {
        match self.run_inner() {
            Ok(code) => code,
            Err(e) => {
                // Check if this is a user cancellation (Ctrl+C).
                if let SksError::Io(ref io_err) = e {
                    if io_err.kind() == std::io::ErrorKind::Other {
                        // dialoguer signals Ctrl+C as ErrorKind::Other
                        println!();
                        return 0;
                    }
                }
                eprintln!("\nsks error: {e}");
                2
            }
        }
    }

    fn run_inner(&mut self) -> Result<i32, SksError> {
        // Screen 1: Welcome
        if !self.screen_welcome()? {
            return Ok(0);
        }

        // Screen 2: Target selection
        if !self.screen_select_targets()? {
            return Ok(0);
        }

        // Screen 3: Scan execution
        self.screen_scan()?;

        // Screen 4: Results review
        self.screen_review()?;

        // Screen 5: Report generation
        self.screen_report()?;

        // Exit code based on findings
        Ok(match &self.state.scan_result {
            Some(r) if !r.findings.is_empty() => 1,
            _ => 0,
        })
    }

    // --- Screen 1: Welcome ---

    fn screen_welcome(&self) -> Result<bool, SksError> {
        println!();
        println!("  Simple Key Sentry");
        println!("  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
        println!();
        println!("  Scan your machine for leaked secrets: API keys, tokens,");
        println!("  passwords, and credentials in shell history, config files,");
        println!("  and more.");
        println!();
        println!("  Everything stays on your machine.");
        println!("  No data is sent anywhere. No files are modified.");
        println!();

        match Confirm::with_theme(&self.theme)
            .with_prompt("Ready to start?")
            .default(true)
            .interact_opt()
            .map_err(dialoguer_err)?
        {
            Some(true) => Ok(true),
            _ => Ok(false),
        }
    }

    // --- Screen 2: Target selection ---

    fn screen_select_targets(&mut self) -> Result<bool, SksError> {
        let all = ScanTarget::all();
        let labels: Vec<&str> = all.iter().map(|t| t.label()).collect();
        let defaults: Vec<bool> = all.iter().map(|t| t.default_enabled()).collect();

        println!();

        let selections = match MultiSelect::with_theme(&self.theme)
            .with_prompt("Select scan targets (space to toggle, enter to confirm)")
            .items(&labels)
            .defaults(&defaults)
            .interact_opt()
            .map_err(dialoguer_err)?
        {
            Some(sel) => sel,
            None => return Ok(false), // Ctrl+C
        };

        if selections.is_empty() {
            println!();
            println!("  No targets selected.");
            return Ok(false);
        }

        let selected: Vec<ScanTarget> = selections.into_iter().map(|i| all[i]).collect();

        // Confirm opt-in targets if any were selected.
        let has_sensitive = selected.iter().any(|t| t.requires_confirmation());
        if has_sensitive {
            let sensitive: Vec<&ScanTarget> = selected
                .iter()
                .filter(|t| t.requires_confirmation())
                .collect();
            println!();
            println!("  You selected privacy-sensitive sources:");
            for t in &sensitive {
                println!("    \u{2022} {}", t.label());
            }
            println!();

            let confirmed = match Confirm::with_theme(&self.theme)
                .with_prompt("Confirm scanning these sources?")
                .default(false)
                .interact_opt()
                .map_err(dialoguer_err)?
            {
                Some(v) => v,
                None => return Ok(false), // Ctrl+C
            };

            if confirmed {
                self.state.targets = selected;
            } else {
                // Remove sensitive targets, keep the rest.
                self.state.targets = selected
                    .into_iter()
                    .filter(|t| !t.requires_confirmation())
                    .collect();
            }
        } else {
            self.state.targets = selected;
        }

        Ok(true)
    }

    // --- Screen 3: Scan execution (placeholder) ---

    fn screen_scan(&mut self) -> Result<(), SksError> {
        println!();
        println!("  Scanning {} target(s)...", self.state.targets.len());
        for target in &self.state.targets {
            println!("    \u{2022} {}", target.label());
        }
        println!();
        println!("  [Scan execution will be implemented in Block 27]");
        println!();
        Ok(())
    }

    // --- Screen 4: Results review (placeholder) ---

    fn screen_review(&self) -> Result<(), SksError> {
        match &self.state.scan_result {
            Some(result) => {
                let count = result.findings.len();
                if count == 0 {
                    println!("  No secrets found. Your machine looks clean!");
                } else {
                    println!("  Found {} potential secret(s).", count);
                }
            }
            None => {
                println!("  [Results review will be implemented in Block 27]");
            }
        }
        println!();
        Ok(())
    }

    // --- Screen 5: Report generation (placeholder) ---

    fn screen_report(&mut self) -> Result<(), SksError> {
        println!("  [Report generation will be implemented in Block 27]");
        println!();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ScanTarget ---

    #[test]
    fn all_targets_returns_eight() {
        assert_eq!(ScanTarget::all().len(), 8);
    }

    #[test]
    fn default_enabled_excludes_opt_in() {
        assert!(!ScanTarget::Clipboard.default_enabled());
        assert!(!ScanTarget::BrowserStorage.default_enabled());
    }

    #[test]
    fn default_enabled_includes_standard() {
        assert!(ScanTarget::ShellHistory.default_enabled());
        assert!(ScanTarget::Dotfiles.default_enabled());
        assert!(ScanTarget::EnvFiles.default_enabled());
        assert!(ScanTarget::CloudConfigs.default_enabled());
        assert!(ScanTarget::AppConfigs.default_enabled());
        assert!(ScanTarget::SshKeys.default_enabled());
    }

    #[test]
    fn requires_confirmation_matches_opt_in() {
        for target in ScanTarget::all() {
            assert_eq!(
                target.requires_confirmation(),
                matches!(target, ScanTarget::Clipboard | ScanTarget::BrowserStorage),
                "Mismatch for {:?}",
                target
            );
        }
    }

    #[test]
    fn label_is_nonempty() {
        for target in ScanTarget::all() {
            assert!(!target.label().is_empty(), "Empty label for {:?}", target);
        }
    }

    #[test]
    fn opt_in_targets_are_last() {
        let all = ScanTarget::all();
        assert_eq!(all[6], ScanTarget::Clipboard);
        assert_eq!(all[7], ScanTarget::BrowserStorage);
    }

    // --- InteractiveState ---

    #[test]
    fn default_state_has_six_targets() {
        let state = InteractiveState::default();
        assert_eq!(state.targets.len(), 6);
    }

    #[test]
    fn default_state_excludes_clipboard_and_browser() {
        let state = InteractiveState::default();
        assert!(!state.has_clipboard());
        assert!(!state.has_browser());
    }

    #[test]
    fn default_state_has_no_results() {
        let state = InteractiveState::default();
        assert!(state.scan_result.is_none());
        assert!(state.report_path.is_none());
    }

    #[test]
    fn state_with_clipboard_target() {
        let mut state = InteractiveState::default();
        state.targets.push(ScanTarget::Clipboard);
        assert!(state.has_clipboard());
        assert!(!state.has_browser());
    }

    #[test]
    fn state_with_browser_target() {
        let mut state = InteractiveState::default();
        state.targets.push(ScanTarget::BrowserStorage);
        assert!(!state.has_clipboard());
        assert!(state.has_browser());
    }

    #[test]
    fn state_with_all_targets() {
        let mut state = InteractiveState::default();
        state.targets.push(ScanTarget::Clipboard);
        state.targets.push(ScanTarget::BrowserStorage);
        assert!(state.has_clipboard());
        assert!(state.has_browser());
        assert_eq!(state.targets.len(), 8);
    }

    // --- InteractiveSession ---

    #[test]
    fn session_creates_with_default_targets() {
        let session = InteractiveSession::new();
        assert_eq!(session.state.targets.len(), 6);
    }

    #[test]
    fn session_default_has_no_results() {
        let session = InteractiveSession::new();
        assert!(session.state.scan_result.is_none());
        assert!(session.state.report_path.is_none());
    }
}
