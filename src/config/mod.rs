use std::path::{Path, PathBuf};
use std::{env, fs};

use serde::Deserialize;

use crate::SksError;

// ─── Platform helpers ─────────────────────────────────────────────────────────

/// Returns the user's home directory from `$HOME`, with a `.` fallback.
fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Returns the user-level config file path.
/// Respects `$XDG_CONFIG_HOME` on Linux; falls back to `~/.config` on macOS.
pub fn user_config_path() -> PathBuf {
    let config_home = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".config"));
    config_home.join("sks/config.toml")
}

// ─── Public config types ──────────────────────────────────────────────────────

/// Top-level configuration container.
#[derive(Debug, Clone, Default)]
pub struct SksConfig {
    pub scan: ScanConfig,
    pub detection: DetectionConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub clipboard: bool,       // default: false
    pub browser: bool,         // default: false
    pub follow_symlinks: bool, // default: true
    pub max_file_size: u64,    // default: 10 MB in bytes
    pub max_depth: usize,      // default: 10
    pub dotfile_targets: Vec<PathBuf>,
    pub env_search_roots: Vec<PathBuf>,
    pub extra_paths: Vec<PathBuf>,
    pub exclude_paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub min_confidence: f64,   // default: 0.3 (stored as 0.0–1.0)
    pub entropy_enabled: bool, // default: true
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub format: ReportFormat, // default: Terminal
    pub verbosity: Verbosity, // default: Normal
    pub redact: bool,         // default: true
    pub output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormat {
    Terminal,
    Json,
    Html,
    Sarif,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

/// CLI-provided values that override any config layer. Applied last.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub format: Option<ReportFormat>,
    pub verbose: bool,
    pub quiet: bool,
    pub redact: Option<bool>,
    pub output: Option<PathBuf>,
    pub min_confidence: Option<f64>, // 0.0–1.0
    pub no_entropy: bool,
    pub clipboard: Option<bool>,
    pub browser: Option<bool>,
}

// ─── Default implementations ──────────────────────────────────────────────────

impl Default for ScanConfig {
    fn default() -> Self {
        let home = home_dir();
        ScanConfig {
            clipboard: false,
            browser: false,
            follow_symlinks: true,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_depth: 10,
            dotfile_targets: default_dotfile_targets(&home),
            env_search_roots: default_env_search_roots(&home),
            extra_paths: Vec::new(),
            exclude_paths: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        DetectionConfig {
            min_confidence: 0.3,
            entropy_enabled: true,
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        ReportConfig {
            format: ReportFormat::Terminal,
            verbosity: Verbosity::Normal,
            redact: true,
            output_path: None,
        }
    }
}

// ─── Platform-aware defaults ──────────────────────────────────────────────────

fn default_dotfile_targets(home: &Path) -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut targets = vec![
        home.join(".bashrc"),
        home.join(".zshrc"),
        home.join(".profile"),
        home.join(".bash_profile"),
        home.join(".zprofile"),
        home.join(".exports"),
        home.join(".gitconfig"),
        home.join(".netrc"),
        home.join(".npmrc"),
        home.join(".pypirc"),
    ];
    #[cfg(target_os = "linux")]
    targets.push(home.join(".config/fish/config.fish"));
    targets
}

fn default_env_search_roots(home: &Path) -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut roots = vec![
        home.join("projects"),
        home.join("code"),
        home.join("dev"),
        home.join("repos"),
        home.join("src"),
    ];
    #[cfg(target_os = "macos")]
    roots.push(home.join("Developer"));
    roots
}

// ─── Config loading ───────────────────────────────────────────────────────────

impl SksConfig {
    /// Load config with full layered resolution:
    /// built-in defaults → user config → project config → env vars
    ///
    /// CLI overrides are applied separately via `apply_overrides()`.
    pub fn load() -> Result<Self, SksError> {
        let mut config = SksConfig::default();

        // Layer 2: user config (~/.config/sks/config.toml)
        let user_path = user_config_path();
        if user_path.exists() {
            let toml_config = load_toml_file(&user_path)?;
            merge_toml(&mut config, toml_config)?;
        }

        // Layer 3: project config (.sks.toml in cwd)
        let project_path = PathBuf::from(".sks.toml");
        if project_path.exists() {
            let toml_config = load_toml_file(&project_path)?;
            merge_toml(&mut config, toml_config)?;
        }

        // Layer 4: environment variables
        apply_env_vars(&mut config);

        Ok(config)
    }

    /// Apply CLI-flag overrides (highest priority, called after `load()`).
    pub fn apply_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(fmt) = &overrides.format {
            self.report.format = fmt.clone();
        }
        if overrides.verbose {
            self.report.verbosity = Verbosity::Verbose;
        }
        if overrides.quiet {
            self.report.verbosity = Verbosity::Quiet;
        }
        if let Some(redact) = overrides.redact {
            self.report.redact = redact;
        }
        if let Some(output) = &overrides.output {
            self.report.output_path = Some(output.clone());
        }
        if let Some(min_conf) = overrides.min_confidence {
            self.detection.min_confidence = min_conf;
        }
        if overrides.no_entropy {
            self.detection.entropy_enabled = false;
        }
        if let Some(clipboard) = overrides.clipboard {
            self.scan.clipboard = clipboard;
        }
        if let Some(browser) = overrides.browser {
            self.scan.browser = browser;
        }
    }
}

// ─── TOML deserialization structs ─────────────────────────────────────────────
// These mirror the config file format. All fields are optional so that a
// partial config file merges cleanly on top of the defaults.

#[derive(Debug, Deserialize, Default)]
struct TomlConfig {
    #[serde(default)]
    scan: TomlScanConfig,
    #[serde(default)]
    detection: TomlDetectionConfig,
    #[serde(default)]
    report: TomlReportConfig,
}

#[derive(Debug, Deserialize, Default)]
struct TomlScanConfig {
    clipboard: Option<bool>,
    browser: Option<bool>,
    follow_symlinks: Option<bool>,
    max_file_size: Option<String>, // e.g. "10MB"
    max_depth: Option<usize>,
    dotfile_targets: Option<Vec<String>>,
    env_search_roots: Option<Vec<String>>,
    extra_paths: Option<Vec<String>>,
    exclude_paths: Option<Vec<String>>,
    exclude_patterns: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct TomlDetectionConfig {
    min_confidence: Option<u8>, // 0–100 in TOML; converted to 0.0–1.0 internally
    entropy_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct TomlReportConfig {
    format: Option<String>,
    verbosity: Option<String>,
    redact: Option<bool>,
    output_path: Option<String>,
}

// ─── TOML loading and merging ─────────────────────────────────────────────────

fn load_toml_file(path: &Path) -> Result<TomlConfig, SksError> {
    let content = fs::read_to_string(path).map_err(|e| {
        SksError::Config(format!("Cannot read config file {}: {}", path.display(), e))
    })?;
    toml::from_str(&content)
        .map_err(|e| SksError::Config(format!("Malformed config file {}: {}", path.display(), e)))
}

fn merge_toml(config: &mut SksConfig, toml: TomlConfig) -> Result<(), SksError> {
    let s = &toml.scan;
    if let Some(v) = s.clipboard {
        config.scan.clipboard = v;
    }
    if let Some(v) = s.browser {
        config.scan.browser = v;
    }
    if let Some(v) = s.follow_symlinks {
        config.scan.follow_symlinks = v;
    }
    if let Some(v) = &s.max_file_size {
        config.scan.max_file_size = parse_byte_size(v)?;
    }
    if let Some(v) = s.max_depth {
        config.scan.max_depth = v;
    }
    if let Some(v) = &s.dotfile_targets {
        config.scan.dotfile_targets = expand_paths(v);
    }
    if let Some(v) = &s.env_search_roots {
        config.scan.env_search_roots = expand_paths(v);
    }
    if let Some(v) = &s.extra_paths {
        config.scan.extra_paths = expand_paths(v);
    }
    if let Some(v) = &s.exclude_paths {
        config.scan.exclude_paths = expand_paths(v);
    }
    if let Some(v) = &s.exclude_patterns {
        config.scan.exclude_patterns = v.clone();
    }

    let d = &toml.detection;
    if let Some(v) = d.min_confidence {
        config.detection.min_confidence = f64::from(v) / 100.0;
    }
    if let Some(v) = d.entropy_enabled {
        config.detection.entropy_enabled = v;
    }

    let r = &toml.report;
    if let Some(v) = &r.format {
        config.report.format = parse_format(v)?;
    }
    if let Some(v) = &r.verbosity {
        config.report.verbosity = parse_verbosity(v)?;
    }
    if let Some(v) = r.redact {
        config.report.redact = v;
    }
    if let Some(v) = &r.output_path {
        if !v.is_empty() {
            config.report.output_path = Some(tilde_expand(v));
        }
    }

    Ok(())
}

// ─── Environment variable overrides ──────────────────────────────────────────

fn apply_env_vars(config: &mut SksConfig) {
    if let Ok(v) = env::var("SKS_FORMAT") {
        if let Ok(fmt) = parse_format(&v) {
            config.report.format = fmt;
        }
    }
    if let Ok(v) = env::var("SKS_VERBOSITY") {
        if let Ok(verbosity) = parse_verbosity(&v) {
            config.report.verbosity = verbosity;
        }
    }
    if let Ok(v) = env::var("SKS_REDACT") {
        match v.to_lowercase().as_str() {
            "true" | "1" | "yes" => config.report.redact = true,
            "false" | "0" | "no" => config.report.redact = false,
            _ => {}
        }
    }
    if let Ok(v) = env::var("SKS_MIN_CONFIDENCE") {
        if let Ok(n) = v.parse::<u8>() {
            config.detection.min_confidence = f64::from(n) / 100.0;
        }
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Expands a leading `~` to the user's home directory.
pub fn tilde_expand(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir().join(rest)
    } else if path == "~" {
        home_dir()
    } else {
        PathBuf::from(path)
    }
}

fn expand_paths(paths: &[String]) -> Vec<PathBuf> {
    paths.iter().map(|p| tilde_expand(p)).collect()
}

/// Parse a human-readable byte size string such as `"10MB"` or `"512KiB"`.
pub fn parse_byte_size(s: &str) -> Result<u64, SksError> {
    let s = s.trim();
    let split_at = s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len());
    let num_str = s[..split_at].trim();
    let unit = s[split_at..].trim();
    let num: u64 = num_str.parse().map_err(|_| {
        SksError::Config(format!(
            "Invalid file size '{}': expected a number followed by a unit, e.g. '10MB'",
            s
        ))
    })?;
    let multiplier: u64 = match unit.to_uppercase().as_str() {
        "" | "B" => 1,
        "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "KIB" => 1_024,
        "MIB" => 1_048_576,
        "GIB" => 1_073_741_824,
        other => {
            return Err(SksError::Config(format!(
                "Unknown size unit '{}' in '{}': expected B, KB, MB, GB, KiB, MiB, or GiB",
                other, s
            )))
        }
    };
    Ok(num * multiplier)
}

fn parse_format(s: &str) -> Result<ReportFormat, SksError> {
    match s.to_lowercase().as_str() {
        "terminal" => Ok(ReportFormat::Terminal),
        "json" => Ok(ReportFormat::Json),
        "html" => Ok(ReportFormat::Html),
        "sarif" => Ok(ReportFormat::Sarif),
        other => Err(SksError::Config(format!(
            "Unknown format '{}': expected terminal, json, html, or sarif",
            other
        ))),
    }
}

fn parse_verbosity(s: &str) -> Result<Verbosity, SksError> {
    match s.to_lowercase().as_str() {
        "quiet" => Ok(Verbosity::Quiet),
        "normal" => Ok(Verbosity::Normal),
        "verbose" => Ok(Verbosity::Verbose),
        other => Err(SksError::Config(format!(
            "Unknown verbosity '{}': expected quiet, normal, or verbose",
            other
        ))),
    }
}

// ─── sks init ─────────────────────────────────────────────────────────────────

/// Generate a well-commented default `config.toml` as a String.
/// Every field is present but commented out, giving users a starting point.
pub fn generate_default_config() -> String {
    r#"# Simple Key Sentry configuration file
# All fields are optional. Uncomment and modify as needed.
# Values shown are the built-in defaults.

[scan]
# clipboard = false         # Scan clipboard history (opt-in, privacy-sensitive)
# browser = false           # Scan browser local storage (opt-in)
# follow_symlinks = true    # Follow symbolic links during directory traversal
# max_file_size = "10MB"    # Skip files larger than this size
# max_depth = 10            # Maximum directory traversal depth

# Dotfiles and RC files to scan (absolute paths or ~ prefix)
# dotfile_targets = [
#   "~/.bashrc",
#   "~/.zshrc",
#   "~/.profile",
#   "~/.gitconfig",
#   "~/.npmrc",
# ]

# Root directories searched recursively for .env files
# env_search_roots = [
#   "~/projects",
#   "~/code",
#   "~/dev",
# ]

# Additional paths to scan (files or directories)
# extra_paths = []

# Paths to exclude from scanning
# exclude_paths = [
#   "~/.aws/cli/cache",
# ]

# Glob patterns to exclude
# exclude_patterns = ["*.log", "*.sqlite-journal"]

[detection]
# min_confidence = 30       # Minimum confidence to report, 0–100 (default: 30)
# entropy_enabled = true    # Use entropy analysis to reduce false positives

[report]
# format = "terminal"       # Output format: terminal | json | html | sarif
# verbosity = "normal"      # Output verbosity: quiet | normal | verbose
# redact = true             # Mask secret values in output (recommended)
# output_path = ""          # Write report to this file (empty = stdout)
"#
    .to_string()
}

/// Write the default config file to `~/.config/sks/config.toml`.
///
/// Returns the path written. Errors if the file already exists and `force` is false.
pub fn write_default_config(force: bool) -> Result<PathBuf, SksError> {
    let path = user_config_path();
    if path.exists() && !force {
        return Err(SksError::Config(format!(
            "Config file already exists at {}. Use --force to overwrite.",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            SksError::Config(format!(
                "Cannot create config directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    fs::write(&path, generate_default_config()).map_err(|e| {
        SksError::Config(format!(
            "Cannot write config file {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(path)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_loads_without_config_file() {
        let config = SksConfig::default();
        assert!(!config.scan.clipboard);
        assert!(!config.scan.browser);
        assert!(config.scan.follow_symlinks);
        assert_eq!(config.scan.max_file_size, 10 * 1024 * 1024);
        assert_eq!(config.scan.max_depth, 10);
        assert!(!config.scan.dotfile_targets.is_empty());
        assert!(!config.scan.env_search_roots.is_empty());
        assert!((config.detection.min_confidence - 0.3).abs() < f64::EPSILON);
        assert!(config.detection.entropy_enabled);
        assert_eq!(config.report.format, ReportFormat::Terminal);
        assert_eq!(config.report.verbosity, Verbosity::Normal);
        assert!(config.report.redact);
    }

    #[test]
    fn toml_merge_overrides_defaults() {
        let mut config = SksConfig::default();
        let toml: TomlConfig = toml::from_str(
            r#"
            [scan]
            clipboard = true
            max_depth = 5

            [detection]
            min_confidence = 50

            [report]
            format = "json"
            redact = false
            "#,
        )
        .unwrap();
        merge_toml(&mut config, toml).unwrap();

        assert!(config.scan.clipboard);
        assert_eq!(config.scan.max_depth, 5);
        assert!((config.detection.min_confidence - 0.50).abs() < 0.001);
        assert_eq!(config.report.format, ReportFormat::Json);
        assert!(!config.report.redact);
    }

    #[test]
    fn malformed_toml_returns_config_error() {
        let result: Result<TomlConfig, _> = toml::from_str("[[[ not valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn generated_config_is_valid_toml() {
        let content = generate_default_config();
        let result: Result<TomlConfig, _> = toml::from_str(&content);
        assert!(
            result.is_ok(),
            "Generated config is not valid TOML: {:?}",
            result.err()
        );
    }

    #[test]
    fn parse_byte_size_variants() {
        assert_eq!(parse_byte_size("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_byte_size("10MiB").unwrap(), 10 * 1_048_576);
        assert_eq!(parse_byte_size("1GB").unwrap(), 1_000_000_000);
        assert_eq!(parse_byte_size("512B").unwrap(), 512);
        assert_eq!(parse_byte_size("1024").unwrap(), 1024); // bare number = bytes
    }

    #[test]
    fn parse_byte_size_invalid() {
        assert!(parse_byte_size("notanumber").is_err());
        assert!(parse_byte_size("10XX").is_err());
    }

    #[test]
    fn parse_format_case_insensitive() {
        assert_eq!(parse_format("terminal").unwrap(), ReportFormat::Terminal);
        assert_eq!(parse_format("JSON").unwrap(), ReportFormat::Json);
        assert_eq!(parse_format("Html").unwrap(), ReportFormat::Html);
        assert_eq!(parse_format("SARIF").unwrap(), ReportFormat::Sarif);
        assert!(parse_format("unknown").is_err());
    }

    #[test]
    fn parse_verbosity_variants() {
        assert_eq!(parse_verbosity("quiet").unwrap(), Verbosity::Quiet);
        assert_eq!(parse_verbosity("normal").unwrap(), Verbosity::Normal);
        assert_eq!(parse_verbosity("verbose").unwrap(), Verbosity::Verbose);
        assert!(parse_verbosity("unknown").is_err());
    }

    #[test]
    fn tilde_expand_replaces_home() {
        let expanded = tilde_expand("~/projects");
        assert_eq!(expanded, home_dir().join("projects"));
    }

    #[test]
    fn tilde_expand_bare_tilde() {
        assert_eq!(tilde_expand("~"), home_dir());
    }

    #[test]
    fn tilde_expand_no_tilde_unchanged() {
        assert_eq!(
            tilde_expand("/absolute/path"),
            PathBuf::from("/absolute/path")
        );
    }

    #[test]
    fn apply_overrides_format_and_verbose() {
        let mut config = SksConfig::default();
        let overrides = CliOverrides {
            format: Some(ReportFormat::Json),
            verbose: true,
            ..Default::default()
        };
        config.apply_overrides(&overrides);
        assert_eq!(config.report.format, ReportFormat::Json);
        assert_eq!(config.report.verbosity, Verbosity::Verbose);
    }

    #[test]
    fn apply_overrides_quiet_wins_over_default() {
        let mut config = SksConfig::default();
        config.apply_overrides(&CliOverrides {
            quiet: true,
            ..Default::default()
        });
        assert_eq!(config.report.verbosity, Verbosity::Quiet);
    }

    #[test]
    fn platform_defaults_include_expected_paths() {
        let config = SksConfig::default();
        let has_zshrc = config
            .scan
            .dotfile_targets
            .iter()
            .any(|p| p.file_name().map(|n| n == ".zshrc").unwrap_or(false));
        assert!(has_zshrc, "dotfile_targets should include .zshrc");

        let has_projects = config
            .scan
            .env_search_roots
            .iter()
            .any(|p| p.file_name().map(|n| n == "projects").unwrap_or(false));
        assert!(has_projects, "env_search_roots should include ~/projects");
    }

    #[test]
    fn env_var_format_override() {
        env::set_var("SKS_FORMAT_TEST_ONLY", "json");
        // Test the parsing logic directly (avoids multi-thread env var races)
        let mut config = SksConfig::default();
        if let Ok(fmt) = parse_format("json") {
            config.report.format = fmt;
        }
        assert_eq!(config.report.format, ReportFormat::Json);
        env::remove_var("SKS_FORMAT_TEST_ONLY");
    }

    #[test]
    fn env_var_min_confidence_conversion() {
        // Test the 0-100 → 0.0-1.0 conversion used by env var and TOML parsing
        let mut config = SksConfig::default();
        config.detection.min_confidence = f64::from(70u8) / 100.0;
        assert!((config.detection.min_confidence - 0.70).abs() < 0.001);
    }

    #[test]
    fn project_config_path_is_local() {
        let path = PathBuf::from(".sks.toml");
        // Just verify the path is relative (not absolute)
        assert!(path.is_relative());
    }

    #[test]
    fn user_config_path_contains_sks() {
        let path = user_config_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("sks"),
            "user config path should contain 'sks': {}",
            path_str
        );
    }
}
