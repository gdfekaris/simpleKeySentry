// Block 3 will replace this file with full layered config loading.
// These structs are defined here now so that the Collector and Reporter
// traits in models can reference them without a circular dependency.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub clipboard: bool,       // default: false
    pub browser: bool,         // default: false
    pub follow_symlinks: bool, // default: true
    pub max_file_size: u64,    // default: 10 MB
    pub max_depth: usize,      // default: 10
    pub dotfile_targets: Vec<PathBuf>,
    pub env_search_roots: Vec<PathBuf>,
    pub extra_paths: Vec<PathBuf>,
    pub exclude_paths: Vec<PathBuf>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub min_confidence: f64,   // default: 0.3
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
