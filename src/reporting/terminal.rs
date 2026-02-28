//! ANSI-colored terminal reporter.
//!
//! Findings are grouped by severity (Critical first). Colors are disabled
//! when stdout is not a TTY or the `NO_COLOR` environment variable is set.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::{ReportConfig, Verbosity};
use crate::models::{Finding, Reporter, ScanResult, Severity};
use crate::SksError;

// ---------------------------------------------------------------------------
// ANSI escape codes
// ---------------------------------------------------------------------------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when ANSI color output should be used.
fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    io::stdout().is_terminal()
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn severity_header(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn severity_color(s: &Severity, color: bool) -> (&'static str, &'static str) {
    if !color {
        return ("", "");
    }
    match s {
        Severity::Critical => ("\x1b[31m\x1b[1m", "\x1b[0m"), // red+bold
        Severity::High => ("\x1b[33m\x1b[1m", "\x1b[0m"),     // yellow+bold
        Severity::Medium => ("\x1b[33m", "\x1b[0m"),          // yellow
        Severity::Low | Severity::Info => ("\x1b[2m\x1b[90m", "\x1b[0m"), // dim+gray
    }
}

fn secret_type_label(st: &crate::models::SecretType) -> &str {
    use crate::models::SecretType::*;
    match st {
        AwsAccessKey => "aws-access-key-id",
        AwsSecretKey => "aws-secret-access-key",
        GitHubPat => "github-pat",
        GitHubOAuth => "github-oauth",
        StripeKey => "stripe-key",
        SlackToken => "slack-token",
        PrivateKey => "private-key-pem",
        Jwt => "jwt",
        DatabaseUrl => "database-url",
        GenericApiKey => "generic-api-key",
        GenericHighEntropy => "generic-high-entropy",
        Custom(name) => name.as_str(),
    }
}

fn source_type_label(st: &crate::models::SourceType) -> &'static str {
    use crate::models::SourceType::*;
    match st {
        ShellHistory => "shell history",
        Dotfile => "dotfile",
        EnvFile => ".env file",
        CloudConfig => "cloud config",
        SshKey => "ssh key",
        ApplicationConfig => "app config",
        Clipboard => "clipboard",
        BrowserStorage => "browser storage",
    }
}

/// Shortens a path for display: replaces $HOME prefix with `~`.
fn display_path(path: &Path) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let s = path.to_string_lossy();
    if !home.is_empty() {
        if let Some(rest) = s.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    s.into_owned()
}

/// Counts findings by severity.
fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }
    (critical, high, medium, low, info)
}

/// Groups findings by severity in display order (Critical first).
fn group_by_severity(findings: &[Finding]) -> Vec<(Severity, Vec<&Finding>)> {
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let mut groups = Vec::new();
    for sev in order {
        let items: Vec<&Finding> = findings.iter().filter(|f| f.severity == sev).collect();
        if !items.is_empty() {
            groups.push((sev, items));
        }
    }
    groups
}

/// Returns `true` if findings at this severity should be shown at the given
/// verbosity level.
fn should_show(severity: &Severity, verbosity: &Verbosity) -> bool {
    match verbosity {
        Verbosity::Quiet => false,
        Verbosity::Normal => {
            matches!(
                severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        }
        Verbosity::Verbose => true,
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Formats the entire terminal report into a `String`.
pub(crate) fn format_terminal(result: &ScanResult, config: &ReportConfig) -> String {
    let color = use_color() && config.output_path.is_none();
    let mut out = String::new();

    // Header
    let version = &result.scan_metadata.sks_version;
    if color {
        writeln!(out, "\n{BOLD}── Simple Key Sentry v{version} ──{RESET}").unwrap();
    } else {
        writeln!(out, "\n── Simple Key Sentry v{version} ──").unwrap();
    }

    // Scan info
    let elapsed = result
        .scan_metadata
        .completed_at
        .signed_duration_since(result.scan_metadata.started_at);
    let secs = elapsed.num_milliseconds() as f64 / 1000.0;
    let sources: Vec<&str> = result
        .scan_metadata
        .targets_scanned
        .iter()
        .map(source_type_label)
        .collect();
    writeln!(out, "\nScanning: {}", sources.join(", ")).unwrap();
    if result.scan_metadata.files_cached > 0 {
        writeln!(
            out,
            "Files scanned: {} ({} cached)  |  Time: {:.1}s",
            result.scan_metadata.files_scanned, result.scan_metadata.files_cached, secs
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "Files scanned: {}  |  Time: {:.1}s",
            result.scan_metadata.files_scanned, secs
        )
        .unwrap();
    }

    let (crit, high, med, low, info) = severity_counts(&result.findings);

    // Findings
    if config.verbosity != Verbosity::Quiet {
        let groups = group_by_severity(&result.findings);
        for (ref severity, ref items) in &groups {
            if !should_show(severity, &config.verbosity) {
                continue;
            }
            let (c_on, c_off) = severity_color(severity, color);
            writeln!(
                out,
                "\n{c_on}── {} ({} finding{}) ──{c_off}",
                severity_header(severity),
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            )
            .unwrap();

            for finding in items {
                format_finding(&mut out, finding, config, color);
            }
        }
    }

    // Summary
    if color {
        write!(out, "\n{BOLD}──{RESET}\n").unwrap();
    } else {
        write!(out, "\n──\n").unwrap();
    }
    write!(out, "Summary: {crit} critical, {high} high, {med} medium",).unwrap();

    match config.verbosity {
        Verbosity::Quiet => {
            writeln!(out).unwrap();
        }
        Verbosity::Normal => {
            let hidden = low + info;
            if hidden > 0 {
                writeln!(out, "  |  Run with --verbose for {hidden} more (low/info)").unwrap();
            } else {
                writeln!(out).unwrap();
            }
        }
        Verbosity::Verbose => {
            writeln!(out, ", {low} low, {info} info").unwrap();
        }
    }

    out
}

fn format_finding(out: &mut String, f: &Finding, config: &ReportConfig, color: bool) {
    let (c_on, c_off) = severity_color(&f.severity, color);
    let label = severity_label(&f.severity);
    let path = display_path(&f.location.path);
    let line_suffix = f.location.line.map(|l| format!(":{l}")).unwrap_or_default();

    writeln!(
        out,
        "\n  {c_on}[{label}]{c_off} {} in {path}{line_suffix}",
        f.description
    )
    .unwrap();

    // Type + confidence
    let type_label = secret_type_label(&f.secret_type);
    writeln!(
        out,
        "         Type: {type_label}  |  Confidence: {:.0}%",
        f.confidence * 100.0
    )
    .unwrap();

    // Value (redacted or raw)
    let value_display = if config.redact {
        f.value.redacted()
    } else {
        f.value.raw().to_string()
    };
    if color {
        writeln!(out, "         {DIM}> {value_display}{RESET}").unwrap();
    } else {
        writeln!(out, "         > {value_display}").unwrap();
    }

    // Remediation
    writeln!(out, "         Fix: {}", f.remediation).unwrap();
}

// ---------------------------------------------------------------------------
// TerminalReporter
// ---------------------------------------------------------------------------

/// Human-friendly terminal output with ANSI colors and severity grouping.
pub struct TerminalReporter;

impl Reporter for TerminalReporter {
    fn format_name(&self) -> &str {
        "terminal"
    }

    fn report(&self, result: &ScanResult, config: &ReportConfig) -> Result<(), SksError> {
        let output = format_terminal(result, config);

        if let Some(path) = &config.output_path {
            write_to_file(path, output.as_bytes())?;
        } else {
            print!("{output}");
        }

        Ok(())
    }
}

/// Writes bytes to a file with restrictive permissions (0600 on Unix).
fn write_to_file(path: &Path, data: &[u8]) -> Result<(), SksError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    #[cfg(unix)]
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path);

    #[cfg(not(unix))]
    let file = File::create(path);

    let mut file = file?;
    file.write_all(data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReportFormat;
    use crate::models::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn make_finding(
        severity_confidence: f64,
        secret_type: SecretType,
        value: &str,
        description: &str,
        remediation: &str,
    ) -> Finding {
        Finding::new(
            secret_type,
            severity_confidence,
            SecretValue::new(value.to_string()),
            SourceLocation {
                path: PathBuf::from("/home/user/.bash_history"),
                line: Some(42),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::ShellHistory,
            },
            description.to_string(),
            remediation.to_string(),
            Some("aws-access-key-id".to_string()),
        )
    }

    fn make_scan_result(findings: Vec<Finding>) -> ScanResult {
        let now = Utc::now();
        ScanResult {
            findings,
            scan_metadata: ScanMetadata {
                started_at: now,
                completed_at: now,
                files_scanned: 3,
                files_cached: 0,
                bytes_scanned: 1024,
                targets_scanned: vec![SourceType::ShellHistory, SourceType::Dotfile],
                sks_version: "0.1.0".to_string(),
            },
        }
    }

    fn default_report_config() -> ReportConfig {
        ReportConfig {
            format: ReportFormat::Terminal,
            verbosity: Verbosity::Normal,
            redact: true,
            output_path: None,
        }
    }

    #[test]
    fn terminal_empty_findings_shows_summary() {
        let result = make_scan_result(vec![]);
        let config = default_report_config();
        let output = format_terminal(&result, &config);
        assert!(output.contains("Simple Key Sentry v0.1.0"));
        assert!(output.contains("Summary: 0 critical, 0 high, 0 medium"));
    }

    #[test]
    fn terminal_groups_by_severity() {
        let findings = vec![
            make_finding(
                0.75,
                SecretType::AwsAccessKey,
                "AKIAIOSFODNN7EXAMPLE",
                "AWS Key",
                "Rotate",
            ),
            make_finding(
                0.95,
                SecretType::PrivateKey,
                "-----BEGIN RSA PRIVATE KEY-----",
                "Private Key",
                "Regenerate",
            ),
        ];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        let crit_pos = output.find("CRITICAL").unwrap();
        let high_pos = output.find("HIGH").unwrap();
        assert!(crit_pos < high_pos, "CRITICAL should appear before HIGH");
    }

    #[test]
    fn terminal_redacts_values_by_default() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
            "Rotate this key",
        )];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        assert!(output.contains("AKIA****MPLE"));
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn terminal_shows_raw_when_no_redact() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
            "Rotate this key",
        )];
        let result = make_scan_result(findings);
        let mut config = default_report_config();
        config.redact = false;
        let output = format_terminal(&result, &config);

        assert!(output.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn terminal_quiet_shows_only_summary() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
            "Rotate this key",
        )];
        let result = make_scan_result(findings);
        let mut config = default_report_config();
        config.verbosity = Verbosity::Quiet;
        let output = format_terminal(&result, &config);

        assert!(output.contains("Summary:"));
        assert!(!output.contains("[CRIT]"));
    }

    #[test]
    fn terminal_normal_hides_low_info() {
        let findings = vec![
            make_finding(
                0.95,
                SecretType::AwsAccessKey,
                "AKIAIOSFODNN7EXAMPLE",
                "Critical find",
                "Fix",
            ),
            make_finding(
                0.20,
                SecretType::GenericApiKey,
                "some_low_value1234",
                "Low find",
                "Fix",
            ),
        ];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        assert!(output.contains("[CRIT]"));
        assert!(!output.contains("[INFO]"));
        assert!(output.contains("Run with --verbose for 1 more"));
    }

    #[test]
    fn terminal_verbose_shows_all() {
        let findings = vec![
            make_finding(
                0.95,
                SecretType::AwsAccessKey,
                "AKIAIOSFODNN7EXAMPLE",
                "Crit",
                "Fix",
            ),
            make_finding(
                0.20,
                SecretType::GenericApiKey,
                "some_info_value12345",
                "Info find",
                "Fix",
            ),
        ];
        let result = make_scan_result(findings);
        let mut config = default_report_config();
        config.verbosity = Verbosity::Verbose;
        let output = format_terminal(&result, &config);

        assert!(output.contains("[CRIT]"));
        assert!(output.contains("[INFO]"));
    }

    #[test]
    fn terminal_shows_path_and_line() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
            "Rotate",
        )];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        assert!(output.contains(":42"));
    }

    #[test]
    fn terminal_shows_remediation() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
            "Rotate this key in the AWS IAM console.",
        )];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        assert!(output.contains("Fix: Rotate this key in the AWS IAM console."));
    }

    #[test]
    fn terminal_severity_counts_correct() {
        let findings = vec![
            make_finding(0.95, SecretType::AwsAccessKey, "val1_long_enough", "d", "r"),
            make_finding(0.95, SecretType::AwsAccessKey, "val2_long_enough", "d", "r"),
            make_finding(0.75, SecretType::AwsSecretKey, "val3_long_enough", "d", "r"),
            make_finding(
                0.55,
                SecretType::GenericApiKey,
                "val4_long_enough",
                "d",
                "r",
            ),
        ];
        let result = make_scan_result(findings);
        let config = default_report_config();
        let output = format_terminal(&result, &config);

        assert!(output.contains("Summary: 2 critical, 1 high, 1 medium"));
    }

    #[test]
    fn terminal_writes_to_file() {
        let dir = std::env::temp_dir().join("sks_test_terminal_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("report.txt");

        let result = make_scan_result(vec![]);
        let mut config = default_report_config();
        config.output_path = Some(out_path.clone());

        TerminalReporter.report(&result, &config).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("Simple Key Sentry"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&out_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn severity_label_coverage() {
        assert_eq!(severity_label(&Severity::Critical), "CRIT");
        assert_eq!(severity_label(&Severity::High), "HIGH");
        assert_eq!(severity_label(&Severity::Medium), "MED");
        assert_eq!(severity_label(&Severity::Low), "LOW");
        assert_eq!(severity_label(&Severity::Info), "INFO");
    }

    #[test]
    fn should_show_quiet_hides_everything() {
        for sev in &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert!(!should_show(sev, &Verbosity::Quiet));
        }
    }

    #[test]
    fn should_show_normal_shows_medium_and_above() {
        assert!(should_show(&Severity::Critical, &Verbosity::Normal));
        assert!(should_show(&Severity::High, &Verbosity::Normal));
        assert!(should_show(&Severity::Medium, &Verbosity::Normal));
        assert!(!should_show(&Severity::Low, &Verbosity::Normal));
        assert!(!should_show(&Severity::Info, &Verbosity::Normal));
    }

    #[test]
    fn should_show_verbose_shows_all() {
        for sev in &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            assert!(should_show(sev, &Verbosity::Verbose));
        }
    }
}
