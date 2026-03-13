//! CLI argument parsing and scan orchestration.
//!
//! This module is the entry point for the `sks` binary. It parses command-line
//! arguments via `clap`, loads the layered configuration, initialises
//! collectors and the detection engine, runs the scan pipeline, and invokes
//! the appropriate reporter.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | No findings above threshold |
//! | 1    | Findings found above threshold |
//! | 2    | Scan error (config parse failure, etc.) |

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use chrono::Utc;
use clap::{Parser, Subcommand};

use crate::cache::{self, CacheEntry, ScanCache};
use crate::collectors::app_config::AppConfigCollector;
use crate::collectors::browser::BrowserCollector;
use crate::collectors::clipboard::ClipboardCollector;
use crate::collectors::cloud_cli::CloudCliCollector;
use crate::collectors::filesystem::{DotfileCollector, EnvFileCollector};
use crate::collectors::shell_history::{
    BashHistoryCollector, FishHistoryCollector, ZshHistoryCollector,
};
use crate::collectors::ssh::SshCollector;
use crate::config::{CliOverrides, ReportFormat, SksConfig};
use crate::detection::patterns::all_patterns;
use crate::detection::{CompiledPattern, DetectionEngine};
use crate::models::{
    Collector, ContentItem, Finding, Reporter, ScanMetadata, ScanResult, SourceType,
};
use crate::reporting::html::HtmlReporter;
use crate::reporting::json::JsonReporter;
use crate::reporting::sarif::SarifReporter;
use crate::reporting::terminal::TerminalReporter;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// No findings above the configured threshold.
const EXIT_CLEAN: i32 = 0;
/// At least one finding above the configured threshold.
const EXIT_FINDINGS: i32 = 1;
/// Fatal error during scanning (config parse error, etc.).
const EXIT_ERROR: i32 = 2;

// ---------------------------------------------------------------------------
// Clap argument definitions
// ---------------------------------------------------------------------------

/// Simple Key Sentry - Find leaked secrets on your machine
#[derive(Parser)]
#[command(
    name = "sks",
    version,
    about = "Simple Key Sentry - Find leaked secrets on your machine",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Scan flags applied when no subcommand is given (bare `sks` = `sks scan`).
    #[command(flatten)]
    scan_args: ScanArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Scan for secrets in local files and history
    Scan(ScanArgs),
    /// Re-render a saved JSON scan report in another format
    Report(ReportArgs),
    /// Manage detection rules
    Rules(RulesArgs),
    /// Create a default config file
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Parser, Clone)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand, Clone)]
enum RulesCommand {
    /// List all built-in and custom detection rules
    List {
        /// Show regex patterns and remediation advice
        #[arg(short, long)]
        verbose: bool,
    },
    /// Test a regex pattern against stdin
    Test {
        /// The regex pattern to test
        #[arg(value_name = "REGEX")]
        regex: String,
    },
}

#[derive(Parser, Clone)]
struct ScanArgs {
    /// Scan a specific file or directory
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Output format [terminal|json|html|sarif]
    #[arg(short, long, value_name = "FORMAT")]
    format: Option<String>,

    /// Show low/info findings
    #[arg(short, long)]
    verbose: bool,

    /// Show only summary
    #[arg(short, long)]
    quiet: bool,

    /// Write report to file
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Show full secret values (dangerous!)
    #[arg(long)]
    no_redact: bool,

    /// Minimum confidence 0-100 [default: 30]
    #[arg(long, value_name = "N")]
    min_confidence: Option<u8>,

    /// Disable entropy analysis
    #[arg(long)]
    no_entropy: bool,

    /// Disable incremental scanning cache (force full scan)
    #[arg(long)]
    no_cache: bool,

    /// Scan clipboard contents (opt-in, privacy-sensitive)
    #[arg(long)]
    clipboard: bool,

    /// Scan browser localStorage (opt-in, privacy-sensitive)
    #[arg(long)]
    browser: bool,

    /// Path to custom rules TOML file
    #[arg(long, value_name = "PATH")]
    rules_path: Option<PathBuf>,

    /// Comma-separated sources to scan
    /// [shell,dotfile,env,cloud,ssh,app,clipboard,browser]
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    sources: Option<Vec<String>>,
}

#[derive(Parser, Clone)]
struct ReportArgs {
    /// Path to a JSON scan report file
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Output format [terminal|html|json|sarif]
    #[arg(short, long, value_name = "FORMAT")]
    format: Option<String>,

    /// Write report to file
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Show full secret values (dangerous!)
    #[arg(long)]
    no_redact: bool,

    /// Show low/info findings
    #[arg(short, long)]
    verbose: bool,

    /// Show only summary
    #[arg(short, long)]
    quiet: bool,
}

impl ScanArgs {
    /// Returns true if all fields are at their default values (no flags given).
    fn is_default(&self) -> bool {
        self.path.is_none()
            && self.format.is_none()
            && !self.verbose
            && !self.quiet
            && self.output.is_none()
            && !self.no_redact
            && self.min_confidence.is_none()
            && !self.no_entropy
            && !self.no_cache
            && !self.clipboard
            && !self.browser
            && self.rules_path.is_none()
            && self.sources.is_none()
    }

    /// Convert parsed CLI arguments into a `CliOverrides` struct.
    fn to_overrides(&self) -> Result<CliOverrides, String> {
        let format = match &self.format {
            Some(f) => {
                let fmt = match f.to_lowercase().as_str() {
                    "terminal" => ReportFormat::Terminal,
                    "json" => ReportFormat::Json,
                    "html" => ReportFormat::Html,
                    "sarif" => ReportFormat::Sarif,
                    other => {
                        return Err(format!(
                            "Unknown format '{other}': expected terminal, json, html, or sarif"
                        ))
                    }
                };
                Some(fmt)
            }
            None => None,
        };

        let min_confidence = self.min_confidence.map(|n| {
            let clamped = n.min(100);
            f64::from(clamped) / 100.0
        });

        let enabled_sources = match &self.sources {
            Some(names) => {
                let mut types = Vec::new();
                for name in names {
                    types.push(parse_cli_source(name)?);
                }
                Some(types)
            }
            None => None,
        };

        Ok(CliOverrides {
            format,
            verbose: self.verbose,
            quiet: self.quiet,
            redact: if self.no_redact { Some(false) } else { None },
            output: self.output.clone(),
            min_confidence,
            no_entropy: self.no_entropy,
            no_cache: self.no_cache,
            clipboard: if self.clipboard { Some(true) } else { None },
            browser: if self.browser { Some(true) } else { None },
            rules_path: self
                .rules_path
                .as_ref()
                .map(|p| crate::config::tilde_expand(&p.to_string_lossy())),
            enabled_sources,
        })
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse CLI arguments and run the appropriate command. Returns an exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init { force }) => run_init(force),
        Some(Command::Scan(args)) => run_scan(args),
        Some(Command::Report(args)) => run_report(args),
        Some(Command::Rules(args)) => run_rules(args),
        None => {
            if cli.scan_args.is_default() && crate::interactive::InteractiveSession::is_terminal() {
                run_interactive()
            } else {
                run_scan(cli.scan_args)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Init command
// ---------------------------------------------------------------------------

fn run_init(force: bool) -> i32 {
    match crate::config::write_default_config(force) {
        Ok(path) => {
            println!("Config written to {}", path.display());
            EXIT_CLEAN
        }
        Err(e) => {
            eprintln!("sks error: {e}");
            EXIT_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive mode
// ---------------------------------------------------------------------------

fn run_interactive() -> i32 {
    let mut session = crate::interactive::InteractiveSession::new();
    session.run()
}

// ---------------------------------------------------------------------------
// Report command
// ---------------------------------------------------------------------------

fn run_report(args: ReportArgs) -> i32 {
    // 1. Read the JSON file.
    let json_content = match std::fs::read_to_string(&args.path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sks error: cannot read {}: {e}", args.path.display());
            return EXIT_ERROR;
        }
    };

    // 2. Parse JSON into ScanResult.
    let result = match crate::reporting::json::parse_json_report(&json_content) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sks error: {e}");
            return EXIT_ERROR;
        }
    };

    // 3. Build report config from flags.
    let format = match &args.format {
        Some(f) => match f.to_lowercase().as_str() {
            "terminal" => ReportFormat::Terminal,
            "json" => ReportFormat::Json,
            "html" => ReportFormat::Html,
            "sarif" => ReportFormat::Sarif,
            other => {
                eprintln!(
                    "sks error: Unknown format '{other}': expected terminal, json, html, or sarif"
                );
                return EXIT_ERROR;
            }
        },
        None => ReportFormat::Terminal,
    };

    let verbosity = if args.quiet {
        crate::config::Verbosity::Quiet
    } else if args.verbose {
        crate::config::Verbosity::Verbose
    } else {
        crate::config::Verbosity::Normal
    };

    let report_config = crate::config::ReportConfig {
        format: format.clone(),
        verbosity,
        redact: !args.no_redact,
        output_path: args.output,
    };

    if format == ReportFormat::Sarif && !report_config.redact {
        eprintln!(
            "sks warn: SARIF format always redacts secrets; \
             --no-redact is ignored for SARIF output"
        );
    }

    // 4. Invoke reporter.
    let reporter: Box<dyn crate::models::Reporter> = match format {
        ReportFormat::Terminal => Box::new(TerminalReporter),
        ReportFormat::Json => Box::new(JsonReporter),
        ReportFormat::Html => Box::new(HtmlReporter),
        ReportFormat::Sarif => Box::new(SarifReporter),
    };

    if let Err(e) = reporter.report(&result, &report_config) {
        eprintln!("sks error: {e}");
        return EXIT_ERROR;
    }

    if result.findings.is_empty() {
        EXIT_CLEAN
    } else {
        EXIT_FINDINGS
    }
}

// ---------------------------------------------------------------------------
// Scan orchestration
// ---------------------------------------------------------------------------

fn run_scan(args: ScanArgs) -> i32 {
    // 1. Convert CLI args to overrides.
    let overrides = match args.to_overrides() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sks error: {e}");
            return EXIT_ERROR;
        }
    };

    // 2. Load config (fatal on error).
    let mut config = match SksConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sks error: {e}");
            return EXIT_ERROR;
        }
    };

    // 3. Apply CLI overrides (highest priority).
    let no_cache = overrides.no_cache;
    config.apply_overrides(&overrides);

    if config.report.format == ReportFormat::Sarif && !config.report.redact {
        eprintln!(
            "sks warn: SARIF format always redacts secrets; \
             --no-redact is ignored for SARIF output"
        );
    }

    // If a specific PATH was given, add it to extra_paths.
    if let Some(path) = &args.path {
        config.scan.extra_paths.push(path.clone());
    }

    // 4. Capture bools before borrowing config mutably.
    let quiet = config.report.verbosity == crate::config::Verbosity::Quiet;
    let to_file = config.report.output_path.is_some();
    let on_progress = move |msg: &str| {
        if quiet || to_file {
            return;
        }
        eprint!("\r\x1b[2K{msg}");
        let _ = std::io::stderr().flush();
    };

    // 5. Run the scan pipeline.
    let result = match execute_scan(&mut config, no_cache, &on_progress) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sks error: {e}");
            return EXIT_ERROR;
        }
    };

    // Clear the progress line.
    clear_progress(&config);

    // 6. Report.
    let has_findings = !result.findings.is_empty();
    let reporter: Box<dyn Reporter> = match config.report.format {
        ReportFormat::Terminal => Box::new(TerminalReporter),
        ReportFormat::Json => Box::new(JsonReporter),
        ReportFormat::Html => Box::new(HtmlReporter),
        ReportFormat::Sarif => Box::new(SarifReporter),
    };

    if let Err(e) = reporter.report(&result, &config.report) {
        eprintln!("sks error: {e}");
        return EXIT_ERROR;
    }

    if has_findings {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

// ---------------------------------------------------------------------------
// Reusable scan pipeline (shared by run_scan and interactive mode)
// ---------------------------------------------------------------------------

/// Execute the scan pipeline: collectors → detection → filtering.
///
/// This is the core scan logic extracted from `run_scan()` so that interactive
/// mode can reuse it. The `on_progress` closure receives status messages
/// (e.g. "Scanning Shell History...") for UI display.
pub fn execute_scan(
    config: &mut SksConfig,
    no_cache: bool,
    on_progress: &dyn Fn(&str),
) -> Result<ScanResult, crate::SksError> {
    // Load .sentryignore rules.
    config.scan.ignore_rules = crate::ignore::IgnoreRules::load();

    // Load incremental scanning cache.
    let cache_file = cache::cache_path();
    let mut scan_cache = if no_cache {
        ScanCache::new()
    } else {
        ScanCache::load(&cache_file)
    };

    // Initialize collectors — check is_available() on each, then filter
    // by enabled_sources if set.
    let mut collectors: Vec<Box<dyn Collector>> = available_collectors();
    if let Some(ref sources) = config.scan.enabled_sources {
        collectors.retain(|c| sources.contains(&c.source_type()));
    }

    let mut targets_scanned: Vec<SourceType> = Vec::new();
    for c in &collectors {
        targets_scanned.push(c.source_type());
    }
    targets_scanned.dedup_by(|a, b| std::mem::discriminant(a) == std::mem::discriminant(b));

    // Initialize detection engine.
    let mut all_rules = all_patterns();
    let custom_result = match &config.rules_path {
        Some(path) => crate::detection::custom_rules::load_custom_rules_from(path),
        None => crate::detection::custom_rules::load_custom_rules(),
    };
    match custom_result {
        Ok(custom) => {
            if !custom.is_empty() {
                on_progress(&format!("Loaded {} custom rule(s)", custom.len()));
                all_rules.extend(custom);
            }
        }
        Err(e) => eprintln!("sks warn: {e}"),
    }

    let compiled: Vec<CompiledPattern> = all_rules
        .into_iter()
        .filter_map(|rule| match CompiledPattern::compile(rule) {
            Ok(cp) => Some(cp),
            Err(e) => {
                eprintln!("sks warn: skipping pattern: {e}");
                None
            }
        })
        .collect();

    let engine = if config.detection.entropy_enabled {
        DetectionEngine::with_defaults(compiled)
    } else {
        DetectionEngine::new(compiled)
    };

    let started_at = Utc::now();

    // Run collectors — collector errors are non-fatal.
    // Items from cached (unchanged) files are filtered out.
    let mut all_items: Vec<ContentItem> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_cached: usize = 0;

    for collector in &collectors {
        on_progress(&format!("Scanning {}...", collector.name()));
        match collector.collect(&config.scan) {
            Ok(items) => {
                if !items.is_empty() {
                    let mut unique_paths: Vec<PathBuf> =
                        items.iter().map(|i| i.path.clone()).collect();
                    unique_paths.sort();
                    unique_paths.dedup();
                    let total_paths = unique_paths.len();

                    let stale_paths: std::collections::HashSet<PathBuf> = unique_paths
                        .into_iter()
                        .filter(|p| scan_cache.is_stale(p))
                        .collect();

                    let cached_count = total_paths - stale_paths.len();
                    files_scanned += total_paths;
                    files_cached += cached_count;

                    let stale_items: Vec<ContentItem> = items
                        .into_iter()
                        .filter(|item| stale_paths.contains(&item.path))
                        .collect();
                    all_items.extend(stale_items);
                }
            }
            Err(e) => {
                eprintln!("sks warn: {} collector error: {e}", collector.name());
            }
        }
    }

    let bytes_scanned: u64 = all_items.iter().map(|i| i.line.len() as u64).sum();

    // Collect direct findings (e.g., SSH permission checks).
    let mut direct_findings: Vec<Finding> = Vec::new();
    for collector in &collectors {
        match collector.direct_findings(&config.scan) {
            Ok(df) => direct_findings.extend(df),
            Err(e) => {
                eprintln!("sks warn: {} direct findings error: {e}", collector.name());
            }
        }
    }

    // Run detection.
    on_progress("Analyzing...");
    let mut findings: Vec<Finding> = engine.analyze_batch(&all_items);

    // Merge direct findings so they go through the same filter/sort.
    findings.extend(direct_findings);

    // Filter suppressed fingerprints from .sentryignore.
    let pre_suppress = findings.len();
    findings.retain(|f| !config.scan.ignore_rules.is_fingerprint_excluded(&f.id));
    let findings_suppressed = pre_suppress - findings.len();

    // Filter by min_confidence and sort.
    findings.retain(|f| f.confidence >= config.detection.min_confidence);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.path.cmp(&b.location.path))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });

    // Update the incremental scanning cache.
    if !no_cache {
        let mut findings_per_path: HashMap<&PathBuf, usize> = HashMap::new();
        for f in &findings {
            *findings_per_path.entry(&f.location.path).or_insert(0) += 1;
        }

        for item in &all_items {
            if crate::collectors::clipboard::is_clipboard_path(&item.path) {
                continue;
            }
            if crate::collectors::browser::is_browser_path(&item.path) {
                continue;
            }
            if !scan_cache.entries.contains_key(&item.path) {
                if let Ok(meta) = std::fs::metadata(&item.path) {
                    let count = findings_per_path.get(&item.path).copied().unwrap_or(0);
                    scan_cache.update(item.path.clone(), CacheEntry::from_metadata(&meta, count));
                }
            }
        }

        scan_cache.prune_missing();
        if let Err(e) = scan_cache.save(&cache_file) {
            eprintln!("sks warn: failed to save cache: {e}");
        }
    }

    let completed_at = Utc::now();

    // Build ScanResult.
    Ok(ScanResult {
        findings,
        scan_metadata: ScanMetadata {
            started_at,
            completed_at,
            files_scanned,
            files_cached,
            findings_suppressed,
            bytes_scanned,
            targets_scanned,
            sks_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    })
}

// ---------------------------------------------------------------------------
// Rules command
// ---------------------------------------------------------------------------

fn run_rules(args: RulesArgs) -> i32 {
    match args.command {
        RulesCommand::List { verbose } => run_rules_list(verbose),
        RulesCommand::Test { regex } => run_rules_test(&regex),
    }
}

fn run_rules_list(verbose: bool) -> i32 {
    let builtins = all_patterns();
    println!("Built-in rules ({}):", builtins.len());
    for rule in &builtins {
        print_rule(rule, verbose);
    }

    match crate::detection::custom_rules::load_custom_rules() {
        Ok(custom) if custom.is_empty() => {
            println!(
                "\nNo custom rules found. Add rules to {}",
                crate::detection::custom_rules::rules_file_path().display()
            );
        }
        Ok(custom) => {
            println!("\nCustom rules ({}):", custom.len());
            for rule in &custom {
                print_rule(rule, verbose);
            }
        }
        Err(e) => {
            eprintln!("sks warn: {e}");
        }
    }

    EXIT_CLEAN
}

fn print_rule(rule: &crate::detection::PatternRule, verbose: bool) {
    println!(
        "  {:<30} {:<40} confidence: {:.0}%",
        rule.name,
        rule.description,
        rule.base_confidence * 100.0
    );
    if verbose {
        println!("    regex: {}", rule.regex);
        println!("    remediation: {}", rule.remediation);
    }
}

fn run_rules_test(pattern: &str) -> i32 {
    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sks error: invalid regex: {e}");
            return EXIT_ERROR;
        }
    };

    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut match_count: usize = 0;

    for (line_num, line_result) in stdin.lock().lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sks error: reading stdin: {e}");
                return EXIT_ERROR;
            }
        };

        for m in re.find_iter(&line) {
            println!("{}:{}:{} {}", line_num + 1, m.start(), m.end(), &line);
            match_count += 1;
        }
    }

    println!("\n{} match(es) found.", match_count);

    if match_count > 0 {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_cli_source(s: &str) -> Result<SourceType, String> {
    match s.to_lowercase().as_str() {
        "shell" => Ok(SourceType::ShellHistory),
        "dotfile" => Ok(SourceType::Dotfile),
        "env" => Ok(SourceType::EnvFile),
        "cloud" => Ok(SourceType::CloudConfig),
        "ssh" => Ok(SourceType::SshKey),
        "app" => Ok(SourceType::ApplicationConfig),
        "clipboard" => Ok(SourceType::Clipboard),
        "browser" => Ok(SourceType::BrowserStorage),
        other => Err(format!(
            "Unknown source '{other}': expected one of \
             shell, dotfile, env, cloud, ssh, app, clipboard, browser"
        )),
    }
}

/// Returns all collectors that are available on this system.
fn available_collectors() -> Vec<Box<dyn Collector>> {
    let candidates: Vec<Box<dyn Collector>> = vec![
        Box::new(DotfileCollector),
        Box::new(EnvFileCollector),
        Box::new(CloudCliCollector),
        Box::new(AppConfigCollector),
        Box::new(SshCollector),
        Box::new(BashHistoryCollector),
        Box::new(ZshHistoryCollector),
        Box::new(FishHistoryCollector),
        Box::new(ClipboardCollector),
        Box::new(BrowserCollector),
    ];
    candidates
        .into_iter()
        .filter(|c| c.is_available())
        .collect()
}

/// Clears the progress line on stderr.
fn clear_progress(config: &SksConfig) {
    use crate::config::Verbosity;
    if config.report.verbosity == Verbosity::Quiet {
        return;
    }
    if config.report.output_path.is_some() {
        return;
    }
    eprint!("\r\x1b[2K");
    let _ = std::io::stderr().flush();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_args_default_produces_no_overrides() {
        let args = default_scan_args();
        let overrides = args.to_overrides().unwrap();
        assert!(overrides.format.is_none());
        assert!(!overrides.verbose);
        assert!(!overrides.quiet);
        assert!(overrides.redact.is_none());
        assert!(overrides.output.is_none());
        assert!(overrides.min_confidence.is_none());
        assert!(!overrides.no_entropy);
        assert!(!overrides.no_cache);
    }

    #[test]
    fn scan_args_is_default_when_no_flags() {
        let args = default_scan_args();
        assert!(args.is_default());
    }

    #[test]
    fn scan_args_is_not_default_with_path() {
        let args = ScanArgs {
            path: Some(PathBuf::from("/tmp")),
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_is_not_default_with_verbose() {
        let args = ScanArgs {
            verbose: true,
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_is_not_default_with_clipboard() {
        let args = ScanArgs {
            clipboard: true,
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_is_not_default_with_browser() {
        let args = ScanArgs {
            browser: true,
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_format_json() {
        let args = ScanArgs {
            format: Some("json".to_string()),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.format, Some(ReportFormat::Json));
    }

    #[test]
    fn scan_args_format_terminal_case_insensitive() {
        let args = ScanArgs {
            format: Some("TERMINAL".to_string()),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.format, Some(ReportFormat::Terminal));
    }

    #[test]
    fn scan_args_format_html() {
        let args = ScanArgs {
            format: Some("html".to_string()),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.format, Some(ReportFormat::Html));
    }

    #[test]
    fn scan_args_format_invalid_returns_error() {
        let args = ScanArgs {
            format: Some("xml".to_string()),
            ..default_scan_args()
        };
        assert!(args.to_overrides().is_err());
    }

    #[test]
    fn scan_args_verbose_flag() {
        let args = ScanArgs {
            verbose: true,
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert!(overrides.verbose);
    }

    #[test]
    fn scan_args_quiet_flag() {
        let args = ScanArgs {
            quiet: true,
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert!(overrides.quiet);
    }

    #[test]
    fn scan_args_no_redact_sets_redact_false() {
        let args = ScanArgs {
            no_redact: true,
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.redact, Some(false));
    }

    #[test]
    fn scan_args_min_confidence_conversion() {
        let args = ScanArgs {
            min_confidence: Some(70),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        let conf = overrides.min_confidence.unwrap();
        assert!((conf - 0.70).abs() < f64::EPSILON);
    }

    #[test]
    fn scan_args_min_confidence_clamped_at_100() {
        // u8 max is 255, but we clamp to 100
        let args = ScanArgs {
            min_confidence: Some(200),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        let conf = overrides.min_confidence.unwrap();
        assert!((conf - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scan_args_no_entropy_flag() {
        let args = ScanArgs {
            no_entropy: true,
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert!(overrides.no_entropy);
    }

    #[test]
    fn scan_args_output_path() {
        let args = ScanArgs {
            output: Some(PathBuf::from("/tmp/report.json")),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.output, Some(PathBuf::from("/tmp/report.json")));
    }

    #[test]
    fn scan_args_no_cache_flag() {
        let args = ScanArgs {
            no_cache: true,
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert!(overrides.no_cache);
    }

    #[test]
    fn scan_args_default_no_cache_is_false() {
        let args = default_scan_args();
        let overrides = args.to_overrides().unwrap();
        assert!(!overrides.no_cache);
    }

    #[test]
    fn exit_codes_are_distinct() {
        assert_ne!(EXIT_CLEAN, EXIT_FINDINGS);
        assert_ne!(EXIT_CLEAN, EXIT_ERROR);
        assert_ne!(EXIT_FINDINGS, EXIT_ERROR);
    }

    fn default_scan_args() -> ScanArgs {
        ScanArgs {
            path: None,
            format: None,
            verbose: false,
            quiet: false,
            output: None,
            no_redact: false,
            min_confidence: None,
            no_entropy: false,
            no_cache: false,
            clipboard: false,
            browser: false,
            rules_path: None,
            sources: None,
        }
    }

    #[test]
    fn report_reads_json_and_rerenders() {
        use crate::models::*;
        use crate::reporting::json::format_json;

        let now = chrono::Utc::now();
        let finding = Finding::new(
            SecretType::AwsAccessKey,
            0.95,
            SecretValue::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            SourceLocation {
                path: PathBuf::from("/home/user/.env"),
                line: Some(5),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::EnvFile,
            },
            "AWS key".to_string(),
            "Rotate".to_string(),
            Some("aws-access-key-id".to_string()),
        );
        let result = ScanResult {
            findings: vec![finding],
            scan_metadata: ScanMetadata {
                started_at: now,
                completed_at: now,
                files_scanned: 10,
                files_cached: 2,
                findings_suppressed: 0,
                bytes_scanned: 4096,
                targets_scanned: vec![SourceType::EnvFile],
                sks_version: "0.1.0".to_string(),
            },
        };

        let config = crate::config::ReportConfig {
            format: ReportFormat::Json,
            verbosity: crate::config::Verbosity::Normal,
            redact: false,
            output_path: None,
        };

        // Write JSON to a temp file.
        let dir = std::env::temp_dir().join("sks_test_report_cmd");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let json_path = dir.join("scan.json");
        let json_str = format_json(&result, &config).unwrap();
        std::fs::write(&json_path, &json_str).unwrap();

        // Use run_report to re-render as JSON to a file.
        let out_path = dir.join("out.json");
        let args = ReportArgs {
            path: json_path,
            format: Some("json".to_string()),
            output: Some(out_path.clone()),
            no_redact: true,
            verbose: false,
            quiet: false,
        };
        let code = run_report(args);
        assert_eq!(code, EXIT_FINDINGS);

        let output = std::fs::read_to_string(&out_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["scan"]["files_scanned"], 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_missing_file_returns_error() {
        let args = ReportArgs {
            path: PathBuf::from("/tmp/nonexistent_sks_report.json"),
            format: None,
            output: None,
            no_redact: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(run_report(args), EXIT_ERROR);
    }

    #[test]
    fn report_invalid_json_returns_error() {
        let dir = std::env::temp_dir().join("sks_test_report_invalid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, "not valid json").unwrap();

        let args = ReportArgs {
            path,
            format: None,
            output: None,
            no_redact: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(run_report(args), EXIT_ERROR);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_invalid_format_returns_error() {
        let dir = std::env::temp_dir().join("sks_test_report_badfmt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.json");
        std::fs::write(&path, "{}").unwrap();

        let args = ReportArgs {
            path,
            format: Some("xml".to_string()),
            output: None,
            no_redact: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(run_report(args), EXIT_ERROR);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_no_findings_returns_clean() {
        use crate::models::*;
        use crate::reporting::json::format_json;

        let now = chrono::Utc::now();
        let result = ScanResult {
            findings: vec![],
            scan_metadata: ScanMetadata {
                started_at: now,
                completed_at: now,
                files_scanned: 5,
                files_cached: 0,
                findings_suppressed: 0,
                bytes_scanned: 1024,
                targets_scanned: vec![],
                sks_version: "0.1.0".to_string(),
            },
        };
        let config = crate::config::ReportConfig {
            format: ReportFormat::Json,
            verbosity: crate::config::Verbosity::Normal,
            redact: true,
            output_path: None,
        };

        let dir = std::env::temp_dir().join("sks_test_report_clean");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clean.json");
        std::fs::write(&path, format_json(&result, &config).unwrap()).unwrap();

        let out_path = dir.join("out.json");
        let args = ReportArgs {
            path,
            format: Some("json".to_string()),
            output: Some(out_path),
            no_redact: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(run_report(args), EXIT_CLEAN);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn execute_scan_returns_valid_result() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut config = SksConfig::default();
        let called = AtomicBool::new(false);
        let result = execute_scan(&mut config, true, &|_msg| {
            called.store(true, Ordering::SeqCst);
        });
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.scan_metadata.sks_version.is_empty());
        assert!(
            called.load(Ordering::SeqCst),
            "progress callback should be invoked"
        );
    }

    #[test]
    fn execute_scan_progress_callback_invoked() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut config = SksConfig::default();
        let count = AtomicUsize::new(0);
        let _ = execute_scan(&mut config, true, &|_msg| {
            count.fetch_add(1, Ordering::SeqCst);
        });
        assert!(
            count.load(Ordering::SeqCst) > 0,
            "progress callback should be called at least once"
        );
    }

    #[test]
    fn execute_scan_enabled_sources_filters_collectors() {
        let mut config = SksConfig::default();
        // Only enable env files — should find no shell history targets.
        config.scan.enabled_sources = Some(vec![SourceType::EnvFile]);
        let result = execute_scan(&mut config, true, &|_| {}).unwrap();
        // The only target scanned should be EnvFile (if the collector is available).
        for st in &result.scan_metadata.targets_scanned {
            assert_eq!(
                *st,
                SourceType::EnvFile,
                "Only EnvFile should be in targets_scanned"
            );
        }
    }

    #[test]
    fn parse_cli_source_valid_values() {
        assert_eq!(parse_cli_source("shell").unwrap(), SourceType::ShellHistory);
        assert_eq!(parse_cli_source("dotfile").unwrap(), SourceType::Dotfile);
        assert_eq!(parse_cli_source("env").unwrap(), SourceType::EnvFile);
        assert_eq!(parse_cli_source("cloud").unwrap(), SourceType::CloudConfig);
        assert_eq!(parse_cli_source("ssh").unwrap(), SourceType::SshKey);
        assert_eq!(
            parse_cli_source("app").unwrap(),
            SourceType::ApplicationConfig
        );
        assert_eq!(
            parse_cli_source("clipboard").unwrap(),
            SourceType::Clipboard
        );
        assert_eq!(
            parse_cli_source("browser").unwrap(),
            SourceType::BrowserStorage
        );
    }

    #[test]
    fn parse_cli_source_case_insensitive() {
        assert_eq!(parse_cli_source("SHELL").unwrap(), SourceType::ShellHistory);
        assert_eq!(parse_cli_source("Shell").unwrap(), SourceType::ShellHistory);
    }

    #[test]
    fn parse_cli_source_invalid_returns_error() {
        let result = parse_cli_source("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown source"));
    }

    #[test]
    fn scan_args_sources_single() {
        let args = ScanArgs {
            sources: Some(vec!["shell".to_string()]),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        let sources = overrides.enabled_sources.unwrap();
        assert_eq!(sources, vec![SourceType::ShellHistory]);
    }

    #[test]
    fn scan_args_sources_multiple() {
        let args = ScanArgs {
            sources: Some(vec!["shell".to_string(), "env".to_string()]),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        let sources = overrides.enabled_sources.unwrap();
        assert_eq!(sources, vec![SourceType::ShellHistory, SourceType::EnvFile]);
    }

    #[test]
    fn scan_args_sources_invalid_returns_error() {
        let args = ScanArgs {
            sources: Some(vec!["shell".to_string(), "bogus".to_string()]),
            ..default_scan_args()
        };
        assert!(args.to_overrides().is_err());
    }

    #[test]
    fn scan_args_rules_path_passthrough() {
        let args = ScanArgs {
            rules_path: Some(PathBuf::from("/tmp/rules.toml")),
            ..default_scan_args()
        };
        let overrides = args.to_overrides().unwrap();
        assert_eq!(overrides.rules_path, Some(PathBuf::from("/tmp/rules.toml")));
    }

    #[test]
    fn scan_args_is_default_with_sources_is_false() {
        let args = ScanArgs {
            sources: Some(vec!["shell".to_string()]),
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_is_default_with_rules_path_is_false() {
        let args = ScanArgs {
            rules_path: Some(PathBuf::from("/tmp/rules.toml")),
            ..default_scan_args()
        };
        assert!(!args.is_default());
    }

    #[test]
    fn scan_args_is_default_still_true() {
        let args = default_scan_args();
        assert!(args.is_default());
    }
}
