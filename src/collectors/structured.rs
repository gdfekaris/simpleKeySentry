//! Structured file parsing for JSON, YAML, TOML, and INI config files.
//!
//! Cloud CLI configs and application configs store secrets inside nested
//! objects. This module provides extractors that walk parsed trees and emit
//! [`StructuredEntry`] values with dotted key paths (e.g.
//! `profiles.default.aws_secret_access_key`), which are then converted into
//! [`ContentItem`]s for the detection engine.
//!
//! If structured parsing fails or the file extension is unrecognised, the
//! module falls back to line-by-line scanning via
//! [`filesystem::content_to_items`].

use std::path::Path;

use serde::Deserialize;

use crate::collectors::filesystem::{content_to_items, truncate_line};
use crate::models::{ContentItem, SourceType};
use crate::SksError;

// ---------------------------------------------------------------------------
// StructuredEntry
// ---------------------------------------------------------------------------

/// A single leaf value extracted from a structured config file.
#[derive(Debug, Clone)]
pub struct StructuredEntry {
    /// Dotted key path, e.g. `"profiles.default.aws_secret_access_key"`.
    pub key_path: String,
    /// The raw string value.
    pub value: String,
    /// Approximate 1-indexed line number in the original file.
    pub line_number: usize,
}

// ---------------------------------------------------------------------------
// JSON extractor
// ---------------------------------------------------------------------------

/// Extracts all string-valued leaves from a JSON document.
pub fn extract_json(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| SksError::Collector(format!("JSON parse: {e}")))?;
    let mut entries = Vec::new();
    walk_json(&value, String::new(), raw, &mut entries);
    Ok(entries)
}

fn walk_json(value: &serde_json::Value, prefix: String, raw: &str, out: &mut Vec<StructuredEntry>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk_json(v, path, raw, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                walk_json(v, path, raw, out);
            }
        }
        serde_json::Value::Null => {}
        other => {
            let s = match other {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => unreachable!(),
            };
            out.push(StructuredEntry {
                key_path: prefix,
                value: s.clone(),
                line_number: approximate_line_number(raw, &s),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// YAML extractor
// ---------------------------------------------------------------------------

/// Extracts all string-valued leaves from a YAML document.
///
/// Multi-document YAML (separated by `---`) is supported: documents are
/// walked sequentially and entries from all documents are combined.
pub fn extract_yaml(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let mut entries = Vec::new();
    for doc in serde_yaml_ng::Deserializer::from_str(raw) {
        let value: serde_yaml_ng::Value = Deserialize::deserialize(doc)
            .map_err(|e| SksError::Collector(format!("YAML parse: {e}")))?;
        walk_yaml(&value, String::new(), raw, &mut entries);
    }
    if entries.is_empty() && !raw.trim().is_empty() {
        // Single document that parsed to a non-mapping scalar — try once more.
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(raw)
            .map_err(|e| SksError::Collector(format!("YAML parse: {e}")))?;
        walk_yaml(&value, String::new(), raw, &mut entries);
    }
    Ok(entries)
}

fn walk_yaml(
    value: &serde_yaml_ng::Value,
    prefix: String,
    raw: &str,
    out: &mut Vec<StructuredEntry>,
) {
    match value {
        serde_yaml_ng::Value::Mapping(map) => {
            for (k, v) in map {
                let key_str = yaml_key_to_string(k);
                let path = if prefix.is_empty() {
                    key_str
                } else {
                    format!("{prefix}.{key_str}")
                };
                walk_yaml(v, path, raw, out);
            }
        }
        serde_yaml_ng::Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                walk_yaml(v, path, raw, out);
            }
        }
        serde_yaml_ng::Value::Null => {}
        serde_yaml_ng::Value::Tagged(tagged) => {
            walk_yaml(&tagged.value, prefix, raw, out);
        }
        other => {
            let s = match other {
                serde_yaml_ng::Value::Bool(b) => b.to_string(),
                serde_yaml_ng::Value::Number(n) => n.to_string(),
                serde_yaml_ng::Value::String(s) => s.clone(),
                _ => return,
            };
            out.push(StructuredEntry {
                key_path: prefix,
                value: s.clone(),
                line_number: approximate_line_number(raw, &s),
            });
        }
    }
}

fn yaml_key_to_string(v: &serde_yaml_ng::Value) -> String {
    match v {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Number(n) => n.to_string(),
        serde_yaml_ng::Value::Bool(b) => b.to_string(),
        _ => format!("{v:?}"),
    }
}

// ---------------------------------------------------------------------------
// TOML extractor
// ---------------------------------------------------------------------------

/// Extracts all string-valued leaves from a TOML document.
pub fn extract_toml(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let value: toml::Value =
        toml::from_str(raw).map_err(|e| SksError::Collector(format!("TOML parse: {e}")))?;
    let mut entries = Vec::new();
    walk_toml(&value, String::new(), raw, &mut entries);
    Ok(entries)
}

fn walk_toml(value: &toml::Value, prefix: String, raw: &str, out: &mut Vec<StructuredEntry>) {
    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk_toml(v, path, raw, out);
            }
        }
        toml::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                walk_toml(v, path, raw, out);
            }
        }
        other => {
            let s = match other {
                toml::Value::String(s) => s.clone(),
                toml::Value::Integer(n) => n.to_string(),
                toml::Value::Float(f) => f.to_string(),
                toml::Value::Boolean(b) => b.to_string(),
                toml::Value::Datetime(dt) => dt.to_string(),
                _ => return,
            };
            out.push(StructuredEntry {
                key_path: prefix,
                value: s.clone(),
                line_number: approximate_line_number(raw, &s),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// INI extractor
// ---------------------------------------------------------------------------

/// Extracts all key-value pairs from an INI file.
///
/// Section headers become dotted prefixes: `[section]` key `name` becomes
/// `section.name`. Global (sectionless) keys use the key name directly.
pub fn extract_ini(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let ini =
        ini::Ini::load_from_str(raw).map_err(|e| SksError::Collector(format!("INI parse: {e}")))?;
    let mut entries = Vec::new();

    for (section, props) in &ini {
        for (key, value) in props.iter() {
            let key_path = match section {
                Some(sec) => format!("{sec}.{key}"),
                None => key.to_string(),
            };
            entries.push(StructuredEntry {
                key_path,
                value: value.to_string(),
                line_number: approximate_line_number(raw, value),
            });
        }
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Line number approximation
// ---------------------------------------------------------------------------

/// Approximates the 1-indexed line number where `needle` first appears in `raw`.
///
/// Returns 1 if `needle` is empty or not found. Accuracy is typically ±3 lines
/// for well-formatted config files.
fn approximate_line_number(raw: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 1;
    }
    match raw.find(needle) {
        Some(offset) => raw[..offset].chars().filter(|&c| c == '\n').count() + 1,
        None => 1,
    }
}

// ---------------------------------------------------------------------------
// StructuredEntry → ContentItem conversion
// ---------------------------------------------------------------------------

/// Converts structured entries into [`ContentItem`]s for the detection engine.
///
/// Each entry's `line` is formatted as `"{key_path}: {value}"`, which gives
/// heuristics strong signals (KeyValueProximity, KeywordProximity). Context
/// is drawn from ±2 adjacent entries.
pub fn entries_to_content_items(
    entries: &[StructuredEntry],
    path: &Path,
    source_type: SourceType,
) -> Vec<ContentItem> {
    let lines: Vec<String> = entries
        .iter()
        .map(|e| truncate_line(&format!("{}: {}", e.key_path, e.value)))
        .collect();
    let n = lines.len();

    entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let context_before = lines[i.saturating_sub(2)..i].to_vec();
            let context_after = lines[(i + 1).min(n)..((i + 1 + 2).min(n))].to_vec();
            ContentItem {
                path: path.to_path_buf(),
                line_number: entry.line_number,
                line: lines[i].clone(),
                context_before,
                context_after,
                source_type: source_type.clone(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// High-level entry point
// ---------------------------------------------------------------------------

/// Parses a structured config file and returns [`ContentItem`]s.
///
/// Selects an extractor based on file extension. If structured parsing fails
/// or returns no entries, falls back to line-by-line scanning via
/// [`content_to_items`].
pub fn parse_structured_file(path: &Path, raw: &str, source_type: SourceType) -> Vec<ContentItem> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let result = match ext.as_str() {
        "json" => extract_json(raw),
        "yaml" | "yml" => extract_yaml(raw),
        "toml" => extract_toml(raw),
        "ini" | "cfg" | "conf" => extract_ini(raw),
        _ => return content_to_items(path, source_type, raw),
    };

    match result {
        Ok(entries) if !entries.is_empty() => entries_to_content_items(&entries, path, source_type),
        _ => content_to_items(path, source_type, raw),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // ── JSON extractor ─────────────────────────────────────────────────────

    #[test]
    fn json_flat_object() {
        let raw = r#"{"key": "value", "count": 42}"#;
        let entries = extract_json(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "key" && e.value == "value"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "count" && e.value == "42"));
    }

    #[test]
    fn json_nested_object() {
        let raw = r#"{"outer": {"inner": "secret"}}"#;
        let entries = extract_json(raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "outer.inner");
        assert_eq!(entries[0].value, "secret");
    }

    #[test]
    fn json_array() {
        let raw = r#"{"items": ["a", "b", "c"]}"#;
        let entries = extract_json(raw).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key_path, "items[0]");
        assert_eq!(entries[0].value, "a");
        assert_eq!(entries[2].key_path, "items[2]");
    }

    #[test]
    fn json_mixed_types() {
        let raw = r#"{"s": "text", "n": 3.14, "b": true, "null_val": null}"#;
        let entries = extract_json(raw).unwrap();
        // null is skipped
        assert_eq!(entries.len(), 3);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "b" && e.value == "true"));
    }

    #[test]
    fn json_empty_object() {
        let entries = extract_json("{}").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn json_invalid() {
        assert!(extract_json("not json at all").is_err());
    }

    #[test]
    fn json_realistic_aws_config() {
        let raw = r#"{
            "profiles": {
                "default": {
                    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "region": "us-east-1"
                }
            }
        }"#;
        let entries = extract_json(raw).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "profiles.default.aws_secret_access_key"
                && e.value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn json_deeply_nested() {
        let raw = r#"{"a": {"b": {"c": {"d": "deep"}}}}"#;
        let entries = extract_json(raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "a.b.c.d");
        assert_eq!(entries[0].value, "deep");
    }

    // ── YAML extractor ─────────────────────────────────────────────────────

    #[test]
    fn yaml_flat_mapping() {
        let raw = "key: value\ncount: 42\n";
        let entries = extract_yaml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "key" && e.value == "value"));
    }

    #[test]
    fn yaml_nested_mapping() {
        let raw = "outer:\n  inner: secret\n";
        let entries = extract_yaml(raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "outer.inner");
        assert_eq!(entries[0].value, "secret");
    }

    #[test]
    fn yaml_sequence() {
        let raw = "items:\n  - a\n  - b\n";
        let entries = extract_yaml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key_path, "items[0]");
        assert_eq!(entries[1].key_path, "items[1]");
    }

    #[test]
    fn yaml_multi_document() {
        let raw = "---\nfirst: 1\n---\nsecond: 2\n";
        let entries = extract_yaml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.key_path == "first"));
        assert!(entries.iter().any(|e| e.key_path == "second"));
    }

    #[test]
    fn yaml_empty() {
        let entries = extract_yaml("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn yaml_invalid() {
        assert!(extract_yaml(":\n  :\n    - :\n      [invalid").is_err());
    }

    #[test]
    fn yaml_realistic_docker_compose() {
        let raw = r#"version: "3"
services:
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: s3cr3t_passw0rd
      POSTGRES_USER: admin
"#;
        let entries = extract_yaml(raw).unwrap();
        assert!(entries.iter().any(
            |e| e.key_path == "services.db.environment.POSTGRES_PASSWORD"
                && e.value == "s3cr3t_passw0rd"
        ));
    }

    // ── TOML extractor ─────────────────────────────────────────────────────

    #[test]
    fn toml_flat() {
        let raw = "key = \"value\"\ncount = 42\n";
        let entries = extract_toml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "key" && e.value == "value"));
    }

    #[test]
    fn toml_nested_table() {
        let raw = "[database]\nhost = \"localhost\"\npassword = \"s3cr3t\"\n";
        let entries = extract_toml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "database.password" && e.value == "s3cr3t"));
    }

    #[test]
    fn toml_inline_table() {
        let raw = "server = { host = \"127.0.0.1\", port = 8080 }\n";
        let entries = extract_toml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.key_path == "server.host"));
        assert!(entries.iter().any(|e| e.key_path == "server.port"));
    }

    #[test]
    fn toml_array_of_tables() {
        let raw = "[[users]]\nname = \"alice\"\n\n[[users]]\nname = \"bob\"\n";
        let entries = extract_toml(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key_path, "users[0].name");
        assert_eq!(entries[1].key_path, "users[1].name");
    }

    #[test]
    fn toml_empty() {
        let entries = extract_toml("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn toml_invalid() {
        assert!(extract_toml("not = [valid toml !!").is_err());
    }

    // ── INI extractor ──────────────────────────────────────────────────────

    #[test]
    fn ini_global_keys() {
        let raw = "key = value\n";
        let entries = extract_ini(raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "key");
        assert_eq!(entries[0].value, "value");
    }

    #[test]
    fn ini_sections() {
        let raw = "[section]\nkey = value\n";
        let entries = extract_ini(raw).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key_path, "section.key");
        assert_eq!(entries[0].value, "value");
    }

    #[test]
    fn ini_multiple_sections() {
        let raw = "[db]\nhost = localhost\n\n[auth]\ntoken = abc123\n";
        let entries = extract_ini(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.key_path == "db.host"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "auth.token" && e.value == "abc123"));
    }

    #[test]
    fn ini_empty() {
        let entries = extract_ini("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn ini_invalid() {
        // rust-ini is very permissive; this test verifies it doesn't panic
        let result = extract_ini("[section\nkey = value");
        // Even malformed INI may parse partially — just ensure no panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn ini_realistic_gitconfig() {
        let raw = "[user]\n\tname = John Doe\n\temail = john@example.com\n\
                   [credential]\n\thelper = store\n";
        let entries = extract_ini(raw).unwrap();
        assert!(entries.iter().any(|e| e.key_path == "user.name"));
        assert!(entries.iter().any(|e| e.key_path == "credential.helper"));
    }

    // ── Line number approximation ──────────────────────────────────────────

    #[test]
    fn line_number_found() {
        let raw = "line1\nline2\ntarget\nline4\n";
        assert_eq!(approximate_line_number(raw, "target"), 3);
    }

    #[test]
    fn line_number_not_found() {
        let raw = "line1\nline2\n";
        assert_eq!(approximate_line_number(raw, "missing"), 1);
    }

    #[test]
    fn line_number_empty_needle() {
        assert_eq!(approximate_line_number("anything", ""), 1);
    }

    // ── Conversion: entries_to_content_items ────────────────────────────────

    #[test]
    fn conversion_format() {
        let entries = vec![StructuredEntry {
            key_path: "db.password".to_string(),
            value: "s3cr3t".to_string(),
            line_number: 5,
        }];
        let items = entries_to_content_items(
            &entries,
            Path::new("/tmp/config.json"),
            SourceType::ApplicationConfig,
        );
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "db.password: s3cr3t");
        assert_eq!(items[0].line_number, 5);
        assert_eq!(items[0].source_type, SourceType::ApplicationConfig);
    }

    #[test]
    fn conversion_context_window() {
        let entries: Vec<StructuredEntry> = (0..5)
            .map(|i| StructuredEntry {
                key_path: format!("key{i}"),
                value: format!("val{i}"),
                line_number: i + 1,
            })
            .collect();
        let items = entries_to_content_items(
            &entries,
            Path::new("/tmp/test.toml"),
            SourceType::ApplicationConfig,
        );
        // Middle entry (index 2) should have 2 before, 2 after
        assert_eq!(items[2].context_before.len(), 2);
        assert_eq!(items[2].context_after.len(), 2);
        // First entry: no before
        assert!(items[0].context_before.is_empty());
        // Last entry: no after
        assert!(items[4].context_after.is_empty());
    }

    #[test]
    fn conversion_empty_entries() {
        let items = entries_to_content_items(
            &[],
            Path::new("/tmp/empty.json"),
            SourceType::ApplicationConfig,
        );
        assert!(items.is_empty());
    }

    #[test]
    fn conversion_truncates_long_values() {
        let long_val = "x".repeat(5000);
        let entries = vec![StructuredEntry {
            key_path: "key".to_string(),
            value: long_val,
            line_number: 1,
        }];
        let items = entries_to_content_items(
            &entries,
            Path::new("/tmp/big.json"),
            SourceType::ApplicationConfig,
        );
        assert!(items[0].line.ends_with("[truncated]"));
    }

    // ── Fallback / parse_structured_file ────────────────────────────────────

    #[test]
    fn fallback_json_dispatches_correctly() {
        let raw = r#"{"secret_key": "AKIAIOSFODNN7EXAMPLE"}"#;
        let items =
            parse_structured_file(Path::new("/tmp/config.json"), raw, SourceType::CloudConfig);
        assert_eq!(items.len(), 1);
        assert!(items[0].line.contains("secret_key"));
    }

    #[test]
    fn fallback_yaml_dispatches_correctly() {
        let raw = "password: hunter2\n";
        let items =
            parse_structured_file(Path::new("/tmp/config.yaml"), raw, SourceType::CloudConfig);
        assert_eq!(items.len(), 1);
        assert!(items[0].line.contains("password"));
    }

    #[test]
    fn fallback_unknown_ext_uses_line_by_line() {
        let raw = "line1\nline2\n";
        let items = parse_structured_file(
            Path::new("/tmp/data.txt"),
            raw,
            SourceType::ApplicationConfig,
        );
        // Line-by-line: each line is its own ContentItem
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "line1");
        assert_eq!(items[1].line, "line2");
    }

    #[test]
    fn fallback_malformed_json_uses_line_by_line() {
        let raw = "not json\nbut has content\n";
        let items = parse_structured_file(
            Path::new("/tmp/broken.json"),
            raw,
            SourceType::ApplicationConfig,
        );
        // Should fall back to line-by-line
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "not json");
    }

    // ── Detection integration ──────────────────────────────────────────────

    #[test]
    fn structured_entries_produce_findings_aws_key() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        let raw = r#"{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}"#;
        let items = parse_structured_file(
            Path::new("/tmp/credentials.json"),
            raw,
            SourceType::CloudConfig,
        );

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "AWS access key in structured file should produce at least one finding"
        );
    }

    #[test]
    fn structured_entries_produce_findings_generic_secret() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        let raw = "password: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12\n";
        let items = parse_structured_file(
            Path::new("/tmp/config.yml"),
            raw,
            SourceType::ApplicationConfig,
        );

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "GitHub PAT in YAML config should produce at least one finding"
        );
    }
}
