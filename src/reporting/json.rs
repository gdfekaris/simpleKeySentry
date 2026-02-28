//! Machine-readable JSON reporter.
//!
//! Emits a single JSON object with `version`, `scan` metadata, `summary`
//! counts, and a `findings` array. All findings are included regardless of
//! verbosity. Secrets are redacted by default (respects `config.redact`).

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::config::ReportConfig;
use crate::models::{
    Finding, Reporter, ScanMetadata, ScanResult, SecretType, SecretValue, Severity, SourceLocation,
    SourceType,
};
use crate::SksError;

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn secret_type_str(st: &crate::models::SecretType) -> String {
    use crate::models::SecretType::*;
    match st {
        AwsAccessKey => "aws-access-key-id".into(),
        AwsSecretKey => "aws-secret-access-key".into(),
        GitHubPat => "github-pat".into(),
        GitHubOAuth => "github-oauth".into(),
        StripeKey => "stripe-key".into(),
        SlackToken => "slack-token".into(),
        PrivateKey => "private-key-pem".into(),
        Jwt => "jwt".into(),
        DatabaseUrl => "database-url".into(),
        GenericApiKey => "generic-api-key".into(),
        GenericHighEntropy => "generic-high-entropy".into(),
        Custom(name) => name.clone(),
    }
}

fn source_type_str(st: &crate::models::SourceType) -> &'static str {
    use crate::models::SourceType::*;
    match st {
        ShellHistory => "shell_history",
        Dotfile => "dotfile",
        EnvFile => "env_file",
        CloudConfig => "cloud_config",
        SshKey => "ssh_key",
        ApplicationConfig => "app_config",
        Clipboard => "clipboard",
        BrowserStorage => "browser_storage",
    }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Formats the scan result as a pretty-printed JSON string.
pub(crate) fn format_json(result: &ScanResult, config: &ReportConfig) -> Result<String, SksError> {
    let meta = &result.scan_metadata;

    let findings_json: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| finding_to_json_value(f, config.redact))
        .collect();

    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;
    for f in &result.findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let targets: Vec<&str> = meta.targets_scanned.iter().map(source_type_str).collect();

    let report = serde_json::json!({
        "version": meta.sks_version,
        "scan": {
            "started_at": meta.started_at.to_rfc3339(),
            "completed_at": meta.completed_at.to_rfc3339(),
            "files_scanned": meta.files_scanned,
            "files_cached": meta.files_cached,
            "bytes_scanned": meta.bytes_scanned,
            "targets_scanned": targets,
        },
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "findings": findings_json,
    });

    serde_json::to_string_pretty(&report).map_err(|e| SksError::Report(e.to_string()))
}

fn finding_to_json_value(f: &Finding, redact: bool) -> serde_json::Value {
    let value = if redact {
        f.value.redacted()
    } else {
        f.value.raw().to_string()
    };

    serde_json::json!({
        "id": f.id,
        "secret_type": secret_type_str(&f.secret_type),
        "severity": severity_str(&f.severity),
        "confidence": f.confidence,
        "value": value,
        "location": {
            "path": f.location.path.to_string_lossy(),
            "line": f.location.line,
            "source_type": source_type_str(&f.location.source_type),
        },
        "description": f.description,
        "remediation": f.remediation,
    })
}

// ---------------------------------------------------------------------------
// JSON → ScanResult deserialization (for `sks report`)
// ---------------------------------------------------------------------------

fn parse_secret_type(s: &str) -> SecretType {
    match s {
        "aws-access-key-id" => SecretType::AwsAccessKey,
        "aws-secret-access-key" => SecretType::AwsSecretKey,
        "github-pat" => SecretType::GitHubPat,
        "github-oauth" => SecretType::GitHubOAuth,
        "stripe-key" => SecretType::StripeKey,
        "slack-token" => SecretType::SlackToken,
        "private-key-pem" => SecretType::PrivateKey,
        "jwt" => SecretType::Jwt,
        "database-url" => SecretType::DatabaseUrl,
        "generic-api-key" => SecretType::GenericApiKey,
        "generic-high-entropy" => SecretType::GenericHighEntropy,
        other => SecretType::Custom(other.to_string()),
    }
}

fn parse_source_type(s: &str) -> Result<SourceType, SksError> {
    match s {
        "shell_history" => Ok(SourceType::ShellHistory),
        "dotfile" => Ok(SourceType::Dotfile),
        "env_file" => Ok(SourceType::EnvFile),
        "cloud_config" => Ok(SourceType::CloudConfig),
        "ssh_key" => Ok(SourceType::SshKey),
        "app_config" => Ok(SourceType::ApplicationConfig),
        "clipboard" => Ok(SourceType::Clipboard),
        "browser_storage" => Ok(SourceType::BrowserStorage),
        other => Err(SksError::Report(format!("Unknown source type: {other}"))),
    }
}

fn json_str(val: &serde_json::Value, key: &str) -> Result<String, SksError> {
    val.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SksError::Report(format!("Missing or invalid field: {key}")))
}

fn json_f64(val: &serde_json::Value, key: &str) -> Result<f64, SksError> {
    val.get(key)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| SksError::Report(format!("Missing or invalid field: {key}")))
}

fn json_u64(val: &serde_json::Value, key: &str) -> Result<u64, SksError> {
    val.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| SksError::Report(format!("Missing or invalid field: {key}")))
}

fn parse_finding(val: &serde_json::Value) -> Result<Finding, SksError> {
    let id = json_str(val, "id")?;
    let secret_type = parse_secret_type(&json_str(val, "secret_type")?);
    let confidence = json_f64(val, "confidence")?;
    let severity = Severity::from(confidence);
    let value = SecretValue::new(json_str(val, "value")?);
    let description = json_str(val, "description")?;
    let remediation = json_str(val, "remediation")?;

    let loc = val
        .get("location")
        .ok_or_else(|| SksError::Report("Missing field: location".into()))?;
    let path = PathBuf::from(json_str(loc, "path")?);
    let line = loc.get("line").and_then(|v| v.as_u64()).map(|n| n as usize);
    let source_type = parse_source_type(&json_str(loc, "source_type")?)?;

    Ok(Finding {
        id,
        secret_type,
        severity,
        confidence,
        value,
        location: SourceLocation {
            path,
            line,
            column: None,
            context_before: String::new(),
            context_after: String::new(),
            source_type,
        },
        description,
        remediation,
        matched_pattern: None,
    })
}

/// Parses a JSON scan report back into a `ScanResult`.
///
/// Used by the `sks report` command to re-render a previously saved JSON report
/// in a different format (e.g., terminal or HTML).
pub fn parse_json_report(input: &str) -> Result<ScanResult, SksError> {
    let root: serde_json::Value =
        serde_json::from_str(input).map_err(|e| SksError::Report(format!("Invalid JSON: {e}")))?;

    let version = json_str(&root, "version")?;

    let scan = root
        .get("scan")
        .ok_or_else(|| SksError::Report("Missing field: scan".into()))?;

    let started_at = chrono::DateTime::parse_from_rfc3339(&json_str(scan, "started_at")?)
        .map_err(|e| SksError::Report(format!("Invalid started_at: {e}")))?
        .with_timezone(&chrono::Utc);

    let completed_at = chrono::DateTime::parse_from_rfc3339(&json_str(scan, "completed_at")?)
        .map_err(|e| SksError::Report(format!("Invalid completed_at: {e}")))?
        .with_timezone(&chrono::Utc);

    let files_scanned = json_u64(scan, "files_scanned")? as usize;
    let files_cached = scan
        .get("files_cached")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let bytes_scanned = json_u64(scan, "bytes_scanned")?;

    let targets_scanned: Vec<SourceType> = scan
        .get("targets_scanned")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| parse_source_type(s).ok())
                .collect()
        })
        .unwrap_or_default();

    let findings: Vec<Finding> = root
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| parse_finding(v).ok()).collect())
        .unwrap_or_default();

    Ok(ScanResult {
        findings,
        scan_metadata: ScanMetadata {
            started_at,
            completed_at,
            files_scanned,
            files_cached,
            bytes_scanned,
            targets_scanned,
            sks_version: version,
        },
    })
}

// ---------------------------------------------------------------------------
// JsonReporter
// ---------------------------------------------------------------------------

/// Machine-readable JSON reporter for scripting and CI integration.
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn format_name(&self) -> &str {
        "json"
    }

    fn report(&self, result: &ScanResult, config: &ReportConfig) -> Result<(), SksError> {
        let json = format_json(result, config)?;

        if let Some(path) = &config.output_path {
            write_to_file(path, json.as_bytes())?;
        } else {
            println!("{json}");
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
    let file = std::fs::File::create(path);

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
    use crate::config::{ReportFormat, Verbosity};
    use crate::models::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn make_finding(
        confidence: f64,
        secret_type: SecretType,
        value: &str,
        description: &str,
    ) -> Finding {
        Finding::new(
            secret_type,
            confidence,
            SecretValue::new(value.to_string()),
            SourceLocation {
                path: PathBuf::from("/home/user/.bash_history"),
                line: Some(1547),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::ShellHistory,
            },
            description.to_string(),
            "Rotate this key".to_string(),
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
                files_scanned: 47,
                files_cached: 0,
                bytes_scanned: 1048576,
                targets_scanned: vec![SourceType::ShellHistory],
                sks_version: "0.1.0".to_string(),
            },
        }
    }

    fn default_config() -> ReportConfig {
        ReportConfig {
            format: ReportFormat::Json,
            verbosity: Verbosity::Normal,
            redact: true,
            output_path: None,
        }
    }

    #[test]
    fn json_output_is_valid_json() {
        let result = make_scan_result(vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )]);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn json_has_required_top_level_keys() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(parsed.get("version").is_some());
        assert!(parsed.get("scan").is_some());
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("findings").is_some());
    }

    #[test]
    fn json_version_matches() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["version"], "0.1.0");
    }

    #[test]
    fn json_scan_metadata_present() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let scan = &parsed["scan"];
        assert!(scan["started_at"].is_string());
        assert!(scan["completed_at"].is_string());
        assert_eq!(scan["files_scanned"], 47);
        assert_eq!(scan["bytes_scanned"], 1048576);
    }

    #[test]
    fn json_summary_counts_correct() {
        let findings = vec![
            make_finding(0.95, SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE", "d"),
            make_finding(0.95, SecretType::PrivateKey, "-----BEGIN RSA-----", "d"),
            make_finding(
                0.75,
                SecretType::DatabaseUrl,
                "postgres://user:pass@h/d",
                "d",
            ),
            make_finding(0.55, SecretType::GenericApiKey, "some_medium_val123", "d"),
        ];
        let result = make_scan_result(findings);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["summary"]["critical"], 2);
        assert_eq!(parsed["summary"]["high"], 1);
        assert_eq!(parsed["summary"]["medium"], 1);
        assert_eq!(parsed["summary"]["low"], 0);
        assert_eq!(parsed["summary"]["info"], 0);
    }

    #[test]
    fn json_redacts_values_by_default() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let value = parsed["findings"][0]["value"].as_str().unwrap();
        assert_eq!(value, "AKIA****MPLE");
    }

    #[test]
    fn json_shows_raw_when_no_redact() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.redact = false;
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let value = parsed["findings"][0]["value"].as_str().unwrap();
        assert_eq!(value, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn json_includes_all_findings_regardless_of_verbosity() {
        let findings = vec![
            make_finding(
                0.95,
                SecretType::AwsAccessKey,
                "AKIAIOSFODNN7EXAMPLE",
                "Crit",
            ),
            make_finding(
                0.20,
                SecretType::GenericApiKey,
                "low_value_here1234",
                "Info",
            ),
        ];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.verbosity = Verbosity::Quiet;
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_finding_has_required_fields() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let f = &parsed["findings"][0];
        assert!(f["id"].is_string());
        assert_eq!(f["secret_type"], "aws-access-key-id");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["confidence"], 0.95);
        assert!(f["value"].is_string());
        assert!(f["location"]["path"].is_string());
        assert_eq!(f["location"]["line"], 1547);
        assert_eq!(f["location"]["source_type"], "shell_history");
        assert!(f["description"].is_string());
        assert!(f["remediation"].is_string());
    }

    #[test]
    fn json_empty_findings_has_empty_array() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json_str = format_json(&result, &config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_writes_to_file() {
        let dir = std::env::temp_dir().join("sks_test_json_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("report.json");

        let result = make_scan_result(vec![]);
        let mut config = default_config();
        config.output_path = Some(out_path.clone());

        JsonReporter.report(&result, &config).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["version"], "0.1.0");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&out_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- parse_json_report (deserialization) tests ---

    #[test]
    fn parse_round_trip_no_redact() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key found",
        )];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.redact = false;
        let json = format_json(&result, &config).unwrap();

        let parsed = parse_json_report(&json).unwrap();
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].value.raw(), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(parsed.findings[0].confidence, 0.95);
        assert_eq!(parsed.findings[0].severity, Severity::Critical);
        assert_eq!(parsed.findings[0].description, "AWS Access Key found");
        assert_eq!(parsed.findings[0].remediation, "Rotate this key");
        assert_eq!(
            parsed.findings[0].location.path,
            PathBuf::from("/home/user/.bash_history")
        );
        assert_eq!(parsed.findings[0].location.line, Some(1547));
        assert_eq!(
            parsed.findings[0].location.source_type,
            SourceType::ShellHistory
        );
    }

    #[test]
    fn parse_round_trip_metadata() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json = format_json(&result, &config).unwrap();

        let parsed = parse_json_report(&json).unwrap();
        assert_eq!(parsed.scan_metadata.files_scanned, 47);
        assert_eq!(parsed.scan_metadata.files_cached, 0);
        assert_eq!(parsed.scan_metadata.bytes_scanned, 1048576);
        assert_eq!(parsed.scan_metadata.sks_version, "0.1.0");
        assert_eq!(
            parsed.scan_metadata.targets_scanned,
            vec![SourceType::ShellHistory]
        );
    }

    #[test]
    fn parse_round_trip_empty_findings() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let json = format_json(&result, &config).unwrap();

        let parsed = parse_json_report(&json).unwrap();
        assert!(parsed.findings.is_empty());
    }

    #[test]
    fn parse_round_trip_multiple_findings() {
        let findings = vec![
            make_finding(0.95, SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE", "d"),
            make_finding(
                0.75,
                SecretType::DatabaseUrl,
                "postgres://u:p@h/db1234",
                "d",
            ),
        ];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.redact = false;
        let json = format_json(&result, &config).unwrap();

        let parsed = parse_json_report(&json).unwrap();
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].secret_type, SecretType::AwsAccessKey);
        assert_eq!(parsed.findings[1].secret_type, SecretType::DatabaseUrl);
    }

    #[test]
    fn parse_all_secret_types_round_trip() {
        let types = vec![
            (SecretType::AwsAccessKey, "aws-access-key-id"),
            (SecretType::AwsSecretKey, "aws-secret-access-key"),
            (SecretType::GitHubPat, "github-pat"),
            (SecretType::GitHubOAuth, "github-oauth"),
            (SecretType::StripeKey, "stripe-key"),
            (SecretType::SlackToken, "slack-token"),
            (SecretType::PrivateKey, "private-key-pem"),
            (SecretType::Jwt, "jwt"),
            (SecretType::DatabaseUrl, "database-url"),
            (SecretType::GenericApiKey, "generic-api-key"),
            (SecretType::GenericHighEntropy, "generic-high-entropy"),
        ];
        for (st, name) in types {
            assert_eq!(parse_secret_type(name), st, "Failed for {name}");
        }
    }

    #[test]
    fn parse_custom_secret_type() {
        assert_eq!(
            parse_secret_type("my-custom-rule"),
            SecretType::Custom("my-custom-rule".to_string())
        );
    }

    #[test]
    fn parse_all_source_types() {
        let types = vec![
            ("shell_history", SourceType::ShellHistory),
            ("dotfile", SourceType::Dotfile),
            ("env_file", SourceType::EnvFile),
            ("cloud_config", SourceType::CloudConfig),
            ("ssh_key", SourceType::SshKey),
            ("app_config", SourceType::ApplicationConfig),
            ("clipboard", SourceType::Clipboard),
            ("browser_storage", SourceType::BrowserStorage),
        ];
        for (name, expected) in types {
            assert_eq!(
                parse_source_type(name).unwrap(),
                expected,
                "Failed for {name}"
            );
        }
    }

    #[test]
    fn parse_unknown_source_type_errors() {
        assert!(parse_source_type("unknown_source").is_err());
    }

    #[test]
    fn parse_invalid_json_errors() {
        assert!(parse_json_report("not json at all").is_err());
    }

    #[test]
    fn parse_missing_version_errors() {
        let json = r#"{"scan":{},"summary":{},"findings":[]}"#;
        assert!(parse_json_report(json).is_err());
    }

    #[test]
    fn parse_missing_scan_errors() {
        let json = r#"{"version":"0.1.0","summary":{},"findings":[]}"#;
        assert!(parse_json_report(json).is_err());
    }
}
