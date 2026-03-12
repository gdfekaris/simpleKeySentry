//! SARIF v2.1.0 reporter.
//!
//! Produces a Static Analysis Results Interchange Format (SARIF) JSON file
//! compatible with VS Code (SARIF Viewer extension), GitHub code scanning,
//! and other SARIF-consuming tools. Secrets are always redacted — there is
//! no `--no-redact` for SARIF output since these files may be committed to
//! repositories or shared in CI systems.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::ReportConfig;
use crate::detection::patterns::all_patterns;
use crate::models::{Finding, Reporter, ScanResult, Severity};
use crate::SksError;

/// SARIF v2.1.0 JSON schema URI (embedded as a constant, never fetched).
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

const SARIF_VERSION: &str = "2.1.0";

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Map sks severity to SARIF result level.
fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Build the `tool.driver.rules[]` array from the built-in pattern library.
fn build_rules_array() -> Vec<serde_json::Value> {
    all_patterns()
        .into_iter()
        .map(|rule| {
            serde_json::json!({
                "id": rule.name,
                "name": rule.name,
                "shortDescription": { "text": rule.description },
                "helpUri": rule.remediation,
                "defaultConfiguration": {
                    "level": sarif_level(&Severity::from(rule.base_confidence))
                }
            })
        })
        .collect()
}

/// Convert a single `Finding` to a SARIF `result` object.
/// Secrets are always redacted in SARIF output.
fn finding_to_sarif_result(f: &Finding) -> serde_json::Value {
    let mut location = serde_json::json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": f.location.path.to_string_lossy()
            }
        }
    });

    // Add region (line/column) if available
    if let Some(line) = f.location.line {
        let mut region = serde_json::json!({ "startLine": line });
        if let Some(col) = f.location.column {
            region["startColumn"] = serde_json::json!(col);
        }
        location["physicalLocation"]["region"] = region;
    }

    let mut result = serde_json::json!({
        "message": { "text": f.description },
        "level": sarif_level(&f.severity),
        "locations": [location],
        "fingerprints": { "sks/v1": f.id },
        "properties": {
            "confidence": f.confidence,
            "redactedValue": f.value.redacted()
        }
    });

    // Link to the rule that matched
    if let Some(ref pattern) = f.matched_pattern {
        result["ruleId"] = serde_json::json!(pattern);
    }

    // Remediation as a fix suggestion
    if !f.remediation.is_empty() {
        result["fixes"] = serde_json::json!([{
            "description": { "text": f.remediation }
        }]);
    }

    result
}

/// Format the scan result as a SARIF v2.1.0 JSON string.
pub(crate) fn format_sarif(result: &ScanResult) -> Result<String, SksError> {
    let meta = &result.scan_metadata;

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(finding_to_sarif_result)
        .collect();

    let sarif = serde_json::json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sks",
                    "semanticVersion": meta.sks_version,
                    "informationUri": "https://github.com/gdfekaris/simpleKeySentry",
                    "rules": build_rules_array()
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).map_err(|e| SksError::Report(e.to_string()))
}

// ---------------------------------------------------------------------------
// SarifReporter
// ---------------------------------------------------------------------------

/// SARIF v2.1.0 reporter for IDE integration and CI systems.
pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn format_name(&self) -> &str {
        "sarif"
    }

    fn report(&self, result: &ScanResult, config: &ReportConfig) -> Result<(), SksError> {
        let json = format_sarif(result)?;

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
    let file = fs::File::create(path);

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
    use crate::models::*;

    fn test_finding(pattern: &str, confidence: f64) -> Finding {
        Finding::new(
            SecretType::GenericApiKey,
            confidence,
            SecretValue::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            SourceLocation {
                path: std::path::PathBuf::from("/home/user/.env"),
                line: Some(42),
                column: Some(10),
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::EnvFile,
            },
            "Generic API key found".to_string(),
            "Rotate this key immediately".to_string(),
            Some(pattern.to_string()),
        )
    }

    fn test_scan_result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            findings,
            scan_metadata: ScanMetadata {
                started_at: chrono::Utc::now(),
                completed_at: chrono::Utc::now(),
                files_scanned: 10,
                files_cached: 0,
                findings_suppressed: 0,
                bytes_scanned: 5000,
                targets_scanned: vec![SourceType::EnvFile],
                sks_version: "0.2.0".to_string(),
            },
        }
    }

    // --- SARIF structure ---

    #[test]
    fn sarif_has_schema_and_version() {
        let result = test_scan_result(vec![]);
        let json_str = format_sarif(&result).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(sarif["$schema"], SARIF_SCHEMA);
        assert_eq!(sarif["version"], SARIF_VERSION);
    }

    #[test]
    fn sarif_has_runs_array() {
        let result = test_scan_result(vec![]);
        let json_str = format_sarif(&result).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(sarif["runs"].is_array());
        assert_eq!(sarif["runs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_tool_driver_has_name_and_version() {
        let result = test_scan_result(vec![]);
        let json_str = format_sarif(&result).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "sks");
        assert_eq!(driver["semanticVersion"], "0.2.0");
    }

    #[test]
    fn sarif_driver_rules_match_pattern_count() {
        let result = test_scan_result(vec![]);
        let json_str = format_sarif(&result).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), all_patterns().len());
    }

    // --- Finding conversion ---

    #[test]
    fn sarif_result_has_rule_id() {
        let f = test_finding("generic-api-key", 0.75);
        let result = finding_to_sarif_result(&f);
        assert_eq!(result["ruleId"], "generic-api-key");
    }

    #[test]
    fn sarif_result_has_location() {
        let f = test_finding("generic-api-key", 0.75);
        let result = finding_to_sarif_result(&f);

        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "/home/user/.env");
        assert_eq!(loc["region"]["startLine"], 42);
        assert_eq!(loc["region"]["startColumn"], 10);
    }

    #[test]
    fn sarif_result_has_fix() {
        let f = test_finding("generic-api-key", 0.75);
        let result = finding_to_sarif_result(&f);

        let fix = &result["fixes"][0]["description"]["text"];
        assert_eq!(fix, "Rotate this key immediately");
    }

    #[test]
    fn sarif_result_has_fingerprint() {
        let f = test_finding("generic-api-key", 0.75);
        let result = finding_to_sarif_result(&f);

        let fp = result["fingerprints"]["sks/v1"].as_str().unwrap();
        assert!(fp.starts_with("sha256:"));
    }

    // --- Severity mapping ---

    #[test]
    fn severity_critical_maps_to_error() {
        assert_eq!(sarif_level(&Severity::Critical), "error");
    }

    #[test]
    fn severity_high_maps_to_error() {
        assert_eq!(sarif_level(&Severity::High), "error");
    }

    #[test]
    fn severity_medium_maps_to_warning() {
        assert_eq!(sarif_level(&Severity::Medium), "warning");
    }

    #[test]
    fn severity_low_maps_to_note() {
        assert_eq!(sarif_level(&Severity::Low), "note");
    }

    #[test]
    fn severity_info_maps_to_note() {
        assert_eq!(sarif_level(&Severity::Info), "note");
    }

    // --- Secret redaction ---

    #[test]
    fn secrets_always_redacted_in_sarif() {
        let f = test_finding("generic-api-key", 0.95);
        let result = finding_to_sarif_result(&f);

        let redacted = result["properties"]["redactedValue"].as_str().unwrap();
        assert_eq!(redacted, "AKIA****MPLE");
        // Raw secret must NOT appear anywhere in the serialized output
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    // --- Full round-trip ---

    #[test]
    fn format_sarif_produces_valid_json() {
        let findings = vec![
            test_finding("generic-api-key", 0.95),
            test_finding("aws-access-key-id", 0.80),
        ];
        let result = test_scan_result(findings);
        let json_str = format_sarif(&result).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
    }

    // --- File output ---

    #[test]
    fn sarif_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.sarif");

        let result = test_scan_result(vec![test_finding("generic-api-key", 0.9)]);
        let reporter = SarifReporter;
        let config = ReportConfig {
            format: crate::config::ReportFormat::Sarif,
            verbosity: crate::config::Verbosity::Normal,
            redact: true,
            output_path: Some(path.clone()),
        };

        reporter.report(&result, &config).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let sarif: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(sarif["version"], SARIF_VERSION);
    }
}
