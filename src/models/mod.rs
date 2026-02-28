use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SksError;

// ---------------------------------------------------------------------------
// SecretType
// ---------------------------------------------------------------------------

/// Enumeration of credential categories recognised by the detection engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GitHubPat,
    GitHubOAuth,
    StripeKey,
    SlackToken,
    PrivateKey,
    Jwt,
    DatabaseUrl,
    GenericApiKey,
    GenericHighEntropy,
    /// User-defined rule (populated in later phases via custom TOML rules).
    Custom(String),
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Severity level derived from a finding's confidence score.
///
/// Variants are ordered from lowest to highest so that derived `Ord` works
/// correctly: `Severity::Critical > Severity::Info`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,     // 0–29%
    Low,      // 30–49%
    Medium,   // 50–69%
    High,     // 70–89%
    Critical, // 90–100%
}

impl From<f64> for Severity {
    /// Maps a confidence score in `[0.0, 1.0]` to a `Severity` level.
    fn from(confidence: f64) -> Self {
        if confidence >= 0.90 {
            Severity::Critical
        } else if confidence >= 0.70 {
            Severity::High
        } else if confidence >= 0.50 {
            Severity::Medium
        } else if confidence >= 0.30 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

// ---------------------------------------------------------------------------
// SourceType
// ---------------------------------------------------------------------------

/// Identifies which scan source produced a given item or finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceType {
    ShellHistory,
    Dotfile,
    EnvFile,
    CloudConfig,
    SshKey,
    ApplicationConfig,
    Clipboard,
    BrowserStorage,
}

// ---------------------------------------------------------------------------
// SecretValue
// ---------------------------------------------------------------------------

/// Raw secret value. Zeroized on drop.
///
/// Does **not** implement `Display` or expose a `Debug` that reveals the value,
/// to prevent accidental logging. Use `.redacted()` for safe output and
/// `.raw()` as an explicit opt-in to the plaintext value.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: String) -> Self {
        SecretValue(value)
    }

    /// Returns a redacted representation safe for display:
    /// - Values ≥ 12 chars: `first4****last4`
    /// - Values < 12 chars: fully masked with `*`
    pub fn redacted(&self) -> String {
        let s = &self.0;
        let len = s.len();
        if len >= 12 {
            format!("{}****{}", &s[..4], &s[len - 4..])
        } else {
            "*".repeat(len)
        }
    }

    /// Returns the raw plaintext value. Explicit opt-in required.
    pub fn raw(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue({})", self.redacted())
    }
}

// ---------------------------------------------------------------------------
// SourceLocation
// ---------------------------------------------------------------------------

/// Where a finding originated.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub line: Option<usize>,    // 1-indexed
    pub column: Option<usize>,  // 1-indexed
    pub context_before: String, // 1–2 lines before (for display)
    pub context_after: String,  // 1–2 lines after
    pub source_type: SourceType,
}

// ---------------------------------------------------------------------------
// ContentItem
// ---------------------------------------------------------------------------

/// A single line of content produced by a collector.
///
/// Collectors produce `ContentItem` values; the detection engine processes
/// them into `Finding` values. This separation keeps collectors simple and
/// makes the detection engine independently testable.
#[derive(Debug, Clone)]
pub struct ContentItem {
    pub path: PathBuf,
    pub line_number: usize, // 1-indexed
    pub line: String,
    pub context_before: Vec<String>, // up to 2 preceding lines
    pub context_after: Vec<String>,  // up to 2 following lines
    pub source_type: SourceType,
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single detected secret. The core output type of the entire tool.
#[derive(Debug)]
pub struct Finding {
    /// Deterministic fingerprint: `sha256:<hex>` of path + line + pattern name.
    /// Stable across runs for the same finding, enabling .sentryignore suppression.
    pub id: String,
    pub secret_type: SecretType,
    pub severity: Severity,
    pub confidence: f64, // 0.0 – 1.0
    pub value: SecretValue,
    pub location: SourceLocation,
    pub description: String, // e.g. "AWS Access Key found in shell history"
    pub remediation: String, // e.g. "Rotate this key in the AWS IAM console"
    pub matched_pattern: Option<String>, // name of the regex pattern that matched
}

impl Finding {
    pub fn new(
        secret_type: SecretType,
        confidence: f64,
        value: SecretValue,
        location: SourceLocation,
        description: String,
        remediation: String,
        matched_pattern: Option<String>,
    ) -> Self {
        let severity = Severity::from(confidence);
        let id = fingerprint(&location.path, location.line, matched_pattern.as_deref());
        Finding {
            id,
            secret_type,
            severity,
            confidence,
            value,
            location,
            description,
            remediation,
            matched_pattern,
        }
    }
}

/// Computes a deterministic SHA-256 fingerprint for a finding.
///
/// Input: `path:line:pattern_name`  — each component separated by `:`.
/// Output: `sha256:<lowercase hex>`
pub fn fingerprint(path: &Path, line: Option<usize>, pattern: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b":");
    hasher.update(line.unwrap_or(0).to_string().as_bytes());
    hasher.update(b":");
    hasher.update(pattern.unwrap_or("").as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex_encode(result.as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// ScanResult + ScanMetadata
// ---------------------------------------------------------------------------

/// Aggregated output from a complete scan.
#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub scan_metadata: ScanMetadata,
}

#[derive(Debug)]
pub struct ScanMetadata {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub targets_scanned: Vec<SourceType>,
    pub sks_version: String,
}

// ---------------------------------------------------------------------------
// Collector trait
// ---------------------------------------------------------------------------

/// Every scan source implements this trait.
///
/// Collectors discover and extract content; detection is a separate stage.
/// Collectors return `ContentItem` values — they never produce `Finding` values.
pub trait Collector {
    /// Human-readable name shown in progress output ("Shell History", etc.).
    fn name(&self) -> &str;

    /// The source type this collector handles.
    fn source_type(&self) -> SourceType;

    /// Returns `true` if this collector can run on the current system
    /// (e.g., the history file exists, the required binary is present).
    fn is_available(&self) -> bool;

    /// Discover and yield all content items to be scanned.
    fn collect(&self, config: &crate::config::ScanConfig) -> Result<Vec<ContentItem>, SksError>;

    /// Return pre-built findings that bypass the detection engine.
    /// Only the SSH collector overrides this (permission checks, encryption status).
    fn direct_findings(
        &self,
        _config: &crate::config::ScanConfig,
    ) -> Result<Vec<Finding>, SksError> {
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Reporter trait
// ---------------------------------------------------------------------------

/// The pluggable interface for output formats.
pub trait Reporter {
    fn format_name(&self) -> &str;
    fn report(
        &self,
        result: &ScanResult,
        config: &crate::config::ReportConfig,
    ) -> Result<(), SksError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SecretValue::redacted() ---

    #[test]
    fn redacted_long_value() {
        // 20 chars >= 12: show first 4 + last 4
        let s = SecretValue::new("AKIAIOSFODNN7EXAMPLE".to_string());
        assert_eq!(s.redacted(), "AKIA****MPLE");
    }

    #[test]
    fn redacted_short_value() {
        // 5 chars < 12: fully masked
        let s = SecretValue::new("short".to_string());
        assert_eq!(s.redacted(), "*****");
    }

    #[test]
    fn redacted_exactly_12_chars() {
        // boundary: exactly 12 chars should show first 4 + last 4
        let s = SecretValue::new("123456789012".to_string());
        assert_eq!(s.redacted(), "1234****9012");
    }

    #[test]
    fn redacted_11_chars_fully_masked() {
        // one below boundary: 11 chars fully masked
        let s = SecretValue::new("12345678901".to_string());
        assert_eq!(s.redacted(), "***********");
    }

    #[test]
    fn raw_returns_plaintext() {
        let s = SecretValue::new("my-secret".to_string());
        assert_eq!(s.raw(), "my-secret");
    }

    // --- SecretValue zeroize ---

    #[test]
    fn secret_value_zeroize_clears_value() {
        let mut s = SecretValue::new("super_secret_value".to_string());
        Zeroize::zeroize(&mut s);
        assert!(s.raw().is_empty());
    }

    // --- Severity::from() boundaries ---

    #[test]
    fn severity_from_confidence_boundaries() {
        assert_eq!(Severity::from(0.00), Severity::Info);
        assert_eq!(Severity::from(0.29), Severity::Info);
        assert_eq!(Severity::from(0.30), Severity::Low);
        assert_eq!(Severity::from(0.49), Severity::Low);
        assert_eq!(Severity::from(0.50), Severity::Medium);
        assert_eq!(Severity::from(0.69), Severity::Medium);
        assert_eq!(Severity::from(0.70), Severity::High);
        assert_eq!(Severity::from(0.89), Severity::High);
        assert_eq!(Severity::from(0.90), Severity::Critical);
        assert_eq!(Severity::from(1.00), Severity::Critical);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    // --- Finding fingerprint ---

    #[test]
    fn fingerprint_is_deterministic() {
        let path = Path::new("/home/user/.bash_history");
        let id1 = fingerprint(path, Some(42), Some("aws-access-key"));
        let id2 = fingerprint(path, Some(42), Some("aws-access-key"));
        assert_eq!(id1, id2);
    }

    #[test]
    fn fingerprint_has_sha256_prefix() {
        let id = fingerprint(Path::new("/tmp/test"), Some(1), Some("pattern"));
        assert!(id.starts_with("sha256:"));
    }

    #[test]
    fn fingerprint_varies_by_line() {
        let path = Path::new("/home/user/.bash_history");
        let id1 = fingerprint(path, Some(42), Some("aws-access-key"));
        let id2 = fingerprint(path, Some(43), Some("aws-access-key"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn fingerprint_varies_by_pattern() {
        let path = Path::new("/home/user/.bash_history");
        let id1 = fingerprint(path, Some(42), Some("aws-access-key"));
        let id2 = fingerprint(path, Some(42), Some("github-pat"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn fingerprint_varies_by_path() {
        let id1 = fingerprint(Path::new("/home/a/.env"), Some(1), Some("pattern"));
        let id2 = fingerprint(Path::new("/home/b/.env"), Some(1), Some("pattern"));
        assert_ne!(id1, id2);
    }
}
