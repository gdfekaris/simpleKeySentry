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
use std::path::{Path, PathBuf};

use console::{Key, Term};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, MultiSelect};
use indicatif::{ProgressBar, ProgressStyle};

use crate::models::{Finding, ScanResult, SecretType, Severity, SourceType};
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
// Helpers
// ---------------------------------------------------------------------------

/// Map interactive scan targets to SourceType values for collector filtering.
pub fn targets_to_source_types(targets: &[ScanTarget]) -> Vec<SourceType> {
    targets
        .iter()
        .flat_map(|t| match t {
            ScanTarget::ShellHistory => vec![SourceType::ShellHistory],
            ScanTarget::Dotfiles => vec![SourceType::Dotfile],
            ScanTarget::EnvFiles => vec![SourceType::EnvFile],
            ScanTarget::CloudConfigs => vec![SourceType::CloudConfig],
            ScanTarget::AppConfigs => vec![SourceType::ApplicationConfig],
            ScanTarget::SshKeys => vec![SourceType::SshKey],
            ScanTarget::Clipboard => vec![SourceType::Clipboard],
            ScanTarget::BrowserStorage => vec![SourceType::BrowserStorage],
        })
        .collect()
}

/// Human-readable explanation of what a secret type means.
pub fn secret_type_explanation(st: &SecretType) -> &'static str {
    match st {
        SecretType::AwsAccessKey => {
            "An AWS access key ID that can be used to authenticate to Amazon Web Services."
        }
        SecretType::AwsSecretKey => {
            "An AWS secret access key that provides full access to the associated AWS account."
        }
        SecretType::GitHubPat => {
            "A GitHub personal access token that can access repositories and account data."
        }
        SecretType::GitHubOAuth => {
            "A GitHub OAuth token that grants access to GitHub resources on behalf of a user."
        }
        SecretType::StripeKey => {
            "A Stripe API key that can process payments and access financial data."
        }
        SecretType::SlackToken => {
            "A Slack token that can read messages, post content, and manage workspaces."
        }
        SecretType::PrivateKey => {
            "A private cryptographic key (SSH, PGP, etc.) used for authentication or signing."
        }
        SecretType::Jwt => {
            "A JSON Web Token containing encoded claims, possibly including sensitive session data."
        }
        SecretType::DatabaseUrl => {
            "A database connection string that may contain credentials for database access."
        }
        SecretType::GenericApiKey => {
            "An API key or token that could grant access to a third-party service."
        }
        SecretType::GenericHighEntropy => {
            "A high-entropy string that looks like it could be a secret or credential."
        }
        SecretType::Custom(_) => "A secret matched by a user-defined detection rule.",
    }
}

/// ANSI-colored severity badge for terminal display.
pub fn severity_badge(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m[CRITICAL]\x1b[0m",
        Severity::High => "\x1b[1;33m[HIGH]\x1b[0m",
        Severity::Medium => "\x1b[33m[MEDIUM]\x1b[0m",
        Severity::Low => "\x1b[2m[LOW]\x1b[0m",
        Severity::Info => "\x1b[2m[INFO]\x1b[0m",
    }
}

/// Count findings by severity level.
/// Returns (critical, high, medium, low, info).
pub fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut crit = 0;
    let mut high = 0;
    let mut med = 0;
    let mut low = 0;
    let mut info = 0;
    for f in findings {
        match f.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }
    (crit, high, med, low, info)
}

/// Collapse the home directory prefix to `~` for display.
pub fn display_path(path: &Path) -> String {
    if let Ok(home) = std::env::var("HOME") {
        let home_path = Path::new(&home);
        if let Ok(relative) = path.strip_prefix(home_path) {
            return format!("~/{}", relative.display());
        }
    }
    path.display().to_string()
}

/// Print a single finding card to stdout.
fn print_finding(finding: &Finding, index: usize, total: usize) {
    println!();
    println!(
        "  Finding {}/{} {}",
        index + 1,
        total,
        severity_badge(&finding.severity)
    );
    println!("  {}", "\u{2500}".repeat(50));

    // Secret type
    let type_name = match &finding.secret_type {
        SecretType::Custom(name) => name.as_str(),
        other => match other {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::GitHubPat => "GitHub Personal Access Token",
            SecretType::GitHubOAuth => "GitHub OAuth Token",
            SecretType::StripeKey => "Stripe API Key",
            SecretType::SlackToken => "Slack Token",
            SecretType::PrivateKey => "Private Key",
            SecretType::Jwt => "JSON Web Token",
            SecretType::DatabaseUrl => "Database URL",
            SecretType::GenericApiKey => "API Key",
            SecretType::GenericHighEntropy => "High-Entropy Secret",
            SecretType::Custom(_) => unreachable!(),
        },
    };
    println!("  Type:     {type_name}");

    // Location
    let loc = &finding.location;
    let path_str = display_path(&loc.path);
    if let Some(line) = loc.line {
        println!("  Location: {path_str}:{line}");
    } else {
        println!("  Location: {path_str}");
    }

    // Redacted value
    println!("  Value:    {}", finding.value.redacted());

    // Confidence
    println!("  Confidence: {:.0}%", finding.confidence * 100.0);

    // Explanation
    println!();
    println!("  {}", secret_type_explanation(&finding.secret_type));

    // Remediation
    println!();
    println!("  Remediation: {}", finding.remediation);
}

/// Print a severity count summary.
fn print_summary(findings: &[Finding]) {
    let (crit, high, med, low, info) = severity_counts(findings);
    println!();
    println!("  Scan Summary");
    println!("  {}", "\u{2500}".repeat(30));
    println!("  Total findings: {}", findings.len());
    if crit > 0 {
        println!("  \x1b[1;31mCritical: {crit}\x1b[0m");
    }
    if high > 0 {
        println!("  \x1b[1;33mHigh:     {high}\x1b[0m");
    }
    if med > 0 {
        println!("  \x1b[33mMedium:   {med}\x1b[0m");
    }
    if low > 0 {
        println!("  \x1b[2mLow:      {low}\x1b[0m");
    }
    if info > 0 {
        println!("  \x1b[2mInfo:     {info}\x1b[0m");
    }
    println!();
}

/// Build the default report directory path.
fn report_dir() -> PathBuf {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/share"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    data_home.join("sks/reports")
}

/// Build the report file path with today's date.
pub fn report_path() -> PathBuf {
    let date = chrono::Local::now().format("%Y-%m-%d");
    report_dir().join(format!("sks-report-{date}.html"))
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
                    let kind = io_err.kind();
                    if kind == std::io::ErrorKind::Other || kind == std::io::ErrorKind::Interrupted
                    {
                        // dialoguer signals Ctrl+C as ErrorKind::Other;
                        // console may signal it as Interrupted.
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

    // --- Screen 3: Scan execution ---

    fn screen_scan(&mut self) -> Result<(), SksError> {
        println!();
        println!("  Scanning {} target(s)...", self.state.targets.len());
        for target in &self.state.targets {
            println!("    \u{2022} {}", target.label());
        }
        println!();

        // Load and configure config.
        let mut config = crate::config::SksConfig::load()?;
        config.scan.clipboard = self.state.has_clipboard();
        config.scan.browser = self.state.has_browser();
        config.scan.enabled_sources = Some(targets_to_source_types(&self.state.targets));

        // Set up spinner.
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {wide_msg} [{elapsed_precise}]")
                .expect("valid spinner template"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        // Run scan.
        let result = crate::cli::execute_scan(&mut config, false, &|msg| {
            pb.set_message(msg.to_string());
        })?;

        // Finish spinner.
        let count = result.findings.len();
        let files = result.scan_metadata.files_scanned;
        pb.finish_with_message(format!(
            "Done \u{2014} scanned {files} file(s), found {count} potential secret(s)"
        ));
        println!();

        self.state.scan_result = Some(result);
        Ok(())
    }

    // --- Screen 4: Results review ---

    fn screen_review(&self) -> Result<(), SksError> {
        let result = match &self.state.scan_result {
            Some(r) => r,
            None => return Ok(()),
        };

        if result.findings.is_empty() {
            println!();
            println!("  No secrets found. Your machine looks clean!");
            println!();
            return Ok(());
        }

        let total = result.findings.len();
        println!();
        println!(
            "  Found {total} potential secret(s). \
             Press Enter for next, 's' for summary, 'q' to quit."
        );

        let term = Term::stdout();

        for (i, finding) in result.findings.iter().enumerate() {
            print_finding(finding, i, total);
            println!();

            if i + 1 < total {
                print!("  [Enter=next, s=summary, q=quit] ");
                let _ = std::io::Write::flush(&mut std::io::stdout());

                match term.read_key() {
                    Ok(Key::Char('s') | Key::Char('S')) => {
                        println!();
                        break;
                    }
                    Ok(Key::Char('q') | Key::Char('Q')) => {
                        println!();
                        return Ok(());
                    }
                    Ok(Key::Escape) => {
                        println!();
                        return Ok(());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        println!();
                        return Ok(());
                    }
                    _ => {
                        // Enter or any other key → next finding
                        println!();
                    }
                }
            }
        }

        print_summary(&result.findings);
        Ok(())
    }

    // --- Screen 5: Report generation ---

    fn screen_report(&mut self) -> Result<(), SksError> {
        let result = match &self.state.scan_result {
            Some(r) => r,
            None => return Ok(()),
        };

        // Skip if no findings.
        if result.findings.is_empty() {
            return Ok(());
        }

        let save = match Confirm::with_theme(&self.theme)
            .with_prompt("Save an HTML report?")
            .default(true)
            .interact_opt()
            .map_err(dialoguer_err)?
        {
            Some(v) => v,
            None => return Ok(()), // Ctrl+C
        };

        if !save {
            return Ok(());
        }

        let path = report_path();

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                // Set restrictive permissions on the reports directory.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o700);
                    std::fs::set_permissions(parent, perms)?;
                }
            }
        }

        // Generate and write HTML report with secrets redacted.
        let report_config = crate::config::ReportConfig {
            format: crate::config::ReportFormat::Html,
            verbosity: crate::config::Verbosity::Normal,
            redact: true,
            output_path: Some(path.clone()),
        };

        let reporter = crate::reporting::html::HtmlReporter;
        crate::models::Reporter::report(&reporter, result, &report_config)?;

        println!();
        println!("  Report saved to {}", display_path(&path));
        println!();

        self.state.report_path = Some(path);
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

    // --- targets_to_source_types ---

    #[test]
    fn targets_to_source_types_maps_all_variants() {
        let all = ScanTarget::all();
        let sources = targets_to_source_types(&all);
        assert_eq!(sources.len(), 8);
        assert!(sources.contains(&SourceType::ShellHistory));
        assert!(sources.contains(&SourceType::Dotfile));
        assert!(sources.contains(&SourceType::EnvFile));
        assert!(sources.contains(&SourceType::CloudConfig));
        assert!(sources.contains(&SourceType::ApplicationConfig));
        assert!(sources.contains(&SourceType::SshKey));
        assert!(sources.contains(&SourceType::Clipboard));
        assert!(sources.contains(&SourceType::BrowserStorage));
    }

    #[test]
    fn targets_to_source_types_empty_input() {
        assert!(targets_to_source_types(&[]).is_empty());
    }

    #[test]
    fn targets_to_source_types_single() {
        let sources = targets_to_source_types(&[ScanTarget::ShellHistory]);
        assert_eq!(sources, vec![SourceType::ShellHistory]);
    }

    // --- secret_type_explanation ---

    #[test]
    fn secret_type_explanation_nonempty_for_all() {
        let types = vec![
            SecretType::AwsAccessKey,
            SecretType::AwsSecretKey,
            SecretType::GitHubPat,
            SecretType::GitHubOAuth,
            SecretType::StripeKey,
            SecretType::SlackToken,
            SecretType::PrivateKey,
            SecretType::Jwt,
            SecretType::DatabaseUrl,
            SecretType::GenericApiKey,
            SecretType::GenericHighEntropy,
            SecretType::Custom("test-rule".to_string()),
        ];
        for st in types {
            let explanation = secret_type_explanation(&st);
            assert!(!explanation.is_empty(), "Empty explanation for {:?}", st);
        }
    }

    // --- severity_badge ---

    #[test]
    fn severity_badge_nonempty_for_all() {
        let levels = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];
        for level in &levels {
            assert!(
                !severity_badge(level).is_empty(),
                "Empty badge for {:?}",
                level
            );
        }
    }

    #[test]
    fn severity_badge_contains_level_name() {
        assert!(severity_badge(&Severity::Critical).contains("CRITICAL"));
        assert!(severity_badge(&Severity::High).contains("HIGH"));
        assert!(severity_badge(&Severity::Medium).contains("MEDIUM"));
        assert!(severity_badge(&Severity::Low).contains("LOW"));
        assert!(severity_badge(&Severity::Info).contains("INFO"));
    }

    // --- severity_counts ---

    #[test]
    fn severity_counts_empty() {
        assert_eq!(severity_counts(&[]), (0, 0, 0, 0, 0));
    }

    #[test]
    fn severity_counts_mixed() {
        use crate::models::*;
        let findings = vec![
            Finding::new(
                SecretType::AwsAccessKey,
                0.95,
                SecretValue::new("AKIAIOSFODNN7EXAMPLE".to_string()),
                SourceLocation {
                    path: PathBuf::from("/test"),
                    line: Some(1),
                    column: None,
                    context_before: String::new(),
                    context_after: String::new(),
                    source_type: SourceType::EnvFile,
                },
                "test".to_string(),
                "fix".to_string(),
                None,
            ),
            Finding::new(
                SecretType::GenericApiKey,
                0.55,
                SecretValue::new("test-api-key-value".to_string()),
                SourceLocation {
                    path: PathBuf::from("/test2"),
                    line: Some(2),
                    column: None,
                    context_before: String::new(),
                    context_after: String::new(),
                    source_type: SourceType::Dotfile,
                },
                "test".to_string(),
                "fix".to_string(),
                None,
            ),
            Finding::new(
                SecretType::GenericHighEntropy,
                0.35,
                SecretValue::new("low-conf".to_string()),
                SourceLocation {
                    path: PathBuf::from("/test3"),
                    line: Some(3),
                    column: None,
                    context_before: String::new(),
                    context_after: String::new(),
                    source_type: SourceType::ShellHistory,
                },
                "test".to_string(),
                "fix".to_string(),
                None,
            ),
        ];
        let (crit, high, med, low, info) = severity_counts(&findings);
        assert_eq!(crit, 1); // 0.95 → Critical
        assert_eq!(high, 0);
        assert_eq!(med, 1); // 0.55 → Medium
        assert_eq!(low, 1); // 0.35 → Low
        assert_eq!(info, 0);
    }

    // --- display_path ---

    #[test]
    fn display_path_collapses_home() {
        if let Ok(home) = std::env::var("HOME") {
            let full = PathBuf::from(&home).join("test/file.txt");
            assert_eq!(display_path(&full), "~/test/file.txt");
        }
    }

    #[test]
    fn display_path_non_home_unchanged() {
        let path = PathBuf::from("/tmp/test.txt");
        assert_eq!(display_path(&path), "/tmp/test.txt");
    }

    // --- report_path ---

    #[test]
    fn report_path_format() {
        let path = report_path();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            name.starts_with("sks-report-"),
            "Expected sks-report- prefix, got: {name}"
        );
        assert!(
            name.ends_with(".html"),
            "Expected .html suffix, got: {name}"
        );
        // Should contain a date like 2026-03-11
        assert!(
            name.len() >= "sks-report-YYYY-MM-DD.html".len(),
            "Report name too short: {name}"
        );
    }

    #[test]
    fn report_path_is_under_sks_reports() {
        let path = report_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("sks/reports"),
            "Expected sks/reports in path: {path_str}"
        );
    }
}
