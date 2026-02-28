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
    /// Create a default config file
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Parser, Clone)]
struct ScanArgs {
    /// Scan a specific file or directory
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,

    /// Output format [terminal|json|html]
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
}

impl ScanArgs {
    /// Convert parsed CLI arguments into a `CliOverrides` struct.
    fn to_overrides(&self) -> Result<CliOverrides, String> {
        let format = match &self.format {
            Some(f) => {
                let fmt = match f.to_lowercase().as_str() {
                    "terminal" => ReportFormat::Terminal,
                    "json" => ReportFormat::Json,
                    "html" => ReportFormat::Html,
                    other => {
                        return Err(format!(
                            "Unknown format '{other}': expected terminal, json, or html"
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

        Ok(CliOverrides {
            format,
            verbose: self.verbose,
            quiet: self.quiet,
            redact: if self.no_redact { Some(false) } else { None },
            output: self.output.clone(),
            min_confidence,
            no_entropy: self.no_entropy,
            no_cache: self.no_cache,
            clipboard: None,
            browser: None,
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
        None => run_scan(cli.scan_args),
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

    // If a specific PATH was given, add it to extra_paths.
    if let Some(path) = &args.path {
        config.scan.extra_paths.push(path.clone());
    }

    // 3b. Load incremental scanning cache.
    let cache_file = cache::cache_path();
    let mut scan_cache = if no_cache {
        ScanCache::new()
    } else {
        ScanCache::load(&cache_file)
    };

    // 4. Initialize collectors — check is_available() on each.
    let collectors: Vec<Box<dyn Collector>> = available_collectors();
    let mut targets_scanned: Vec<SourceType> = Vec::new();
    for c in &collectors {
        targets_scanned.push(c.source_type());
    }
    targets_scanned.dedup_by(|a, b| std::mem::discriminant(a) == std::mem::discriminant(b));

    // 5. Initialize detection engine.
    let compiled: Vec<CompiledPattern> = all_patterns()
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

    // 6. Run collectors — collector errors are non-fatal.
    //    Items from cached (unchanged) files are filtered out.
    let mut all_items: Vec<ContentItem> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_cached: usize = 0;

    for collector in &collectors {
        progress(&format!("Scanning {}...", collector.name()), &config);
        match collector.collect(&config.scan) {
            Ok(items) => {
                if !items.is_empty() {
                    // Collect unique paths from this collector.
                    let mut unique_paths: Vec<PathBuf> =
                        items.iter().map(|i| i.path.clone()).collect();
                    unique_paths.sort();
                    unique_paths.dedup();
                    let total_paths = unique_paths.len();

                    // Determine which paths are stale (need re-scanning).
                    let stale_paths: std::collections::HashSet<PathBuf> = unique_paths
                        .into_iter()
                        .filter(|p| scan_cache.is_stale(p))
                        .collect();

                    let cached_count = total_paths - stale_paths.len();
                    files_scanned += total_paths;
                    files_cached += cached_count;

                    // Only keep items from stale files.
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

    // 6b. Collect direct findings (e.g., SSH permission checks).
    let mut direct_findings: Vec<Finding> = Vec::new();
    for collector in &collectors {
        match collector.direct_findings(&config.scan) {
            Ok(df) => direct_findings.extend(df),
            Err(e) => {
                eprintln!("sks warn: {} direct findings error: {e}", collector.name());
            }
        }
    }

    // 7. Run detection.
    progress("Analyzing...", &config);
    let mut findings: Vec<Finding> = engine.analyze_batch(&all_items);

    // Merge direct findings so they go through the same filter/sort.
    findings.extend(direct_findings);

    // 8. Filter by min_confidence and sort.
    findings.retain(|f| f.confidence >= config.detection.min_confidence);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.location.path.cmp(&b.location.path))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });

    // 8b. Update the incremental scanning cache.
    if !no_cache {
        // Count findings per path from the filtered findings list.
        let mut findings_per_path: HashMap<&PathBuf, usize> = HashMap::new();
        for f in &findings {
            *findings_per_path.entry(&f.location.path).or_insert(0) += 1;
        }

        // Update cache entries for all re-scanned files.
        for item in &all_items {
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

    // Clear the progress line.
    clear_progress(&config);

    // 9. Build ScanResult.
    let has_findings = !findings.is_empty();
    let result = ScanResult {
        findings,
        scan_metadata: ScanMetadata {
            started_at,
            completed_at,
            files_scanned,
            files_cached,
            bytes_scanned,
            targets_scanned,
            sks_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    // 10. Report.
    let reporter: Box<dyn Reporter> = match config.report.format {
        ReportFormat::Terminal => Box::new(TerminalReporter),
        ReportFormat::Json => Box::new(JsonReporter),
        ReportFormat::Html => Box::new(HtmlReporter),
        _ => {
            eprintln!(
                "sks error: format '{:?}' is not yet supported; using terminal",
                config.report.format
            );
            Box::new(TerminalReporter)
        }
    };

    if let Err(e) = reporter.report(&result, &config.report) {
        eprintln!("sks error: {e}");
        return EXIT_ERROR;
    }

    // Exit code.
    if has_findings {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    ];
    candidates
        .into_iter()
        .filter(|c| c.is_available())
        .collect()
}

/// Writes a progress message to stderr with a carriage return (overwrites
/// the current line). Only shown when not in quiet mode and output is not
/// to a file.
fn progress(msg: &str, config: &SksConfig) {
    use crate::config::Verbosity;
    if config.report.verbosity == Verbosity::Quiet {
        return;
    }
    if config.report.output_path.is_some() {
        return;
    }
    eprint!("\r\x1b[2K{msg}");
    let _ = std::io::stderr().flush();
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
        let args = ScanArgs {
            path: None,
            format: None,
            verbose: false,
            quiet: false,
            output: None,
            no_redact: false,
            min_confidence: None,
            no_entropy: false,
            no_cache: false,
        };
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
        }
    }
}
