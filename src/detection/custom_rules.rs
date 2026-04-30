//! Custom rule definitions loaded from `rules.toml`.
//!
//! Users can define their own detection patterns in `~/.config/sks/rules.toml`
//! (or `$XDG_CONFIG_HOME/sks/rules.toml`). Rules are validated at load time and
//! merged with the built-in patterns before the detection engine is compiled.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detection::PatternRule;
use crate::models::SecretType;
use crate::SksError;

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TomlRulesFile {
    #[serde(default)]
    rules: Vec<TomlRule>,
}

#[derive(Debug, Deserialize)]
struct TomlRule {
    name: String,
    description: String,
    regex: String,
    /// Base confidence in [0.0, 1.0] (matches PatternRule, NOT 0–100).
    base_confidence: f64,
    remediation: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the default path for user-defined rules:
/// `$XDG_CONFIG_HOME/sks/rules.toml` (default `~/.config/sks/rules.toml`).
pub fn rules_file_path() -> PathBuf {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".config")
        });
    config_home.join("sks").join("rules.toml")
}

/// Load custom rules from the default path.
/// Missing file → `Ok(vec![])` silently.
/// Malformed TOML → `Err(SksError::Config(...))`.
pub fn load_custom_rules() -> Result<Vec<PatternRule>, SksError> {
    load_custom_rules_from(&rules_file_path())
}

/// Load custom rules from a given path.
/// Missing file → `Ok(vec![])`.
pub fn load_custom_rules_from(path: &Path) -> Result<Vec<PatternRule>, SksError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => {
            return Err(SksError::Config(format!(
                "cannot read {}: {e}",
                path.display()
            )))
        }
    };
    parse_custom_rules(&content)
}

/// Parse and validate custom rules from a TOML string.
pub fn parse_custom_rules(toml_content: &str) -> Result<Vec<PatternRule>, SksError> {
    let file: TomlRulesFile = toml::from_str(toml_content)
        .map_err(|e| SksError::Config(format!("failed to parse rules TOML: {e}")))?;

    let builtin_names: HashSet<String> = crate::detection::patterns::all_patterns()
        .into_iter()
        .map(|p| p.name)
        .collect();

    let mut seen_names: HashSet<String> = HashSet::new();
    let mut rules = Vec::new();

    for tr in file.rules {
        // Empty name → skip
        if tr.name.trim().is_empty() {
            eprintln!("sks warn: custom rule with empty name skipped");
            continue;
        }

        // Built-in collision → skip
        if builtin_names.contains(&tr.name) {
            eprintln!(
                "sks warn: custom rule '{}' conflicts with built-in pattern, skipped",
                tr.name
            );
            continue;
        }

        // Duplicate custom name → skip
        if seen_names.contains(&tr.name) {
            eprintln!("sks warn: duplicate custom rule '{}' skipped", tr.name);
            continue;
        }

        // Regex validation → skip on failure
        if let Err(e) = regex::Regex::new(&tr.regex) {
            eprintln!("sks warn: custom rule '{}' has invalid regex: {e}", tr.name);
            continue;
        }

        let confidence = tr.base_confidence.clamp(0.0, 1.0);

        seen_names.insert(tr.name.clone());
        rules.push(PatternRule {
            secret_type: SecretType::Custom(tr.name.clone()),
            name: tr.name,
            description: tr.description,
            regex: tr.regex,
            base_confidence: confidence,
            remediation: tr.remediation,
            validator: None,
        });
    }

    Ok(rules)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::detection::{CompiledPattern, DetectionEngine};
    use crate::models::{ContentItem, SecretType, SourceType};

    // 1
    #[test]
    fn parse_valid_rules() {
        let toml = r#"
[[rules]]
name = "acme-token"
description = "ACME Corp Token"
regex = "ACME_[A-Za-z0-9]{32}"
base_confidence = 0.85
remediation = "Rotate in ACME dashboard"

[[rules]]
name = "internal-key"
description = "Internal API key"
regex = "INT_KEY_[0-9]{16}"
base_confidence = 0.70
remediation = "Regenerate via admin panel"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "acme-token");
        assert_eq!(rules[0].description, "ACME Corp Token");
        assert_eq!(rules[0].regex, "ACME_[A-Za-z0-9]{32}");
        assert!((rules[0].base_confidence - 0.85).abs() < f64::EPSILON);
        assert_eq!(rules[0].remediation, "Rotate in ACME dashboard");
        assert_eq!(rules[1].name, "internal-key");
    }

    // 2
    #[test]
    fn parse_empty_file() {
        assert!(parse_custom_rules("").unwrap().is_empty());
        assert!(parse_custom_rules("rules = []").unwrap().is_empty());
    }

    // 3
    #[test]
    fn parse_missing_field_errors() {
        let toml = r#"
[[rules]]
description = "Missing name"
regex = "foo"
base_confidence = 0.5
remediation = "bar"
"#;
        assert!(parse_custom_rules(toml).is_err());
    }

    // 4
    #[test]
    fn parse_invalid_toml_errors() {
        assert!(parse_custom_rules("this is not valid toml {{{{").is_err());
    }

    // 5
    #[test]
    fn parse_no_rules_key() {
        let toml = r#"
[metadata]
author = "test"
"#;
        assert!(parse_custom_rules(toml).unwrap().is_empty());
    }

    // 6
    #[test]
    fn confidence_clamped() {
        let toml = r#"
[[rules]]
name = "over"
description = "Over confident"
regex = "OVER_[A-Z]{4}"
base_confidence = 1.5
remediation = "n/a"

[[rules]]
name = "under"
description = "Under confident"
regex = "UNDER_[A-Z]{4}"
base_confidence = -0.1
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(rules.len(), 2);
        assert!((rules[0].base_confidence - 1.0).abs() < f64::EPSILON);
        assert!((rules[1].base_confidence - 0.0).abs() < f64::EPSILON);
    }

    // 7
    #[test]
    fn uses_custom_secret_type() {
        let toml = r#"
[[rules]]
name = "my-rule"
description = "My Rule"
regex = "MY_[A-Z]{4}"
base_confidence = 0.5
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(
            rules[0].secret_type,
            SecretType::Custom("my-rule".to_string())
        );
    }

    // 8
    #[test]
    fn invalid_regex_skipped() {
        let toml = r#"
[[rules]]
name = "bad-regex"
description = "Bad"
regex = "[unclosed"
base_confidence = 0.5
remediation = "n/a"

[[rules]]
name = "good-regex"
description = "Good"
regex = "GOOD_[A-Z]{4}"
base_confidence = 0.5
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "good-regex");
    }

    // 9
    #[test]
    fn empty_name_rejected() {
        let toml = r#"
[[rules]]
name = ""
description = "Empty"
regex = "FOO"
base_confidence = 0.5
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert!(rules.is_empty());
    }

    // 10
    #[test]
    fn builtin_name_collision_skipped() {
        let toml = r#"
[[rules]]
name = "aws-access-key-id"
description = "Collision"
regex = "COLL_[A-Z]{4}"
base_confidence = 0.5
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert!(rules.is_empty());
    }

    // 11
    #[test]
    fn duplicate_custom_name_skipped() {
        let toml = r#"
[[rules]]
name = "dup-rule"
description = "First"
regex = "DUP1_[A-Z]{4}"
base_confidence = 0.5
remediation = "n/a"

[[rules]]
name = "dup-rule"
description = "Second"
regex = "DUP2_[A-Z]{4}"
base_confidence = 0.5
remediation = "n/a"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].description, "First");
    }

    // 12
    #[test]
    fn load_nonexistent_file_returns_empty() {
        let result = load_custom_rules_from(Path::new("/tmp/sks_nonexistent_rules_file.toml"));
        assert!(result.unwrap().is_empty());
    }

    // 13
    #[test]
    fn load_from_real_file() {
        let dir = std::env::temp_dir().join("sks_test_custom_rules_load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        std::fs::write(
            &path,
            r#"
[[rules]]
name = "file-rule"
description = "From file"
regex = "FILE_[A-Z]{8}"
base_confidence = 0.75
remediation = "fix it"
"#,
        )
        .unwrap();

        let rules = load_custom_rules_from(&path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "file-rule");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // 14
    #[test]
    fn rules_file_path_correct() {
        let path = rules_file_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("sks") && path_str.ends_with("rules.toml"),
            "unexpected path: {path_str}"
        );
    }

    // 15
    #[test]
    fn custom_rule_produces_finding() {
        let toml = r#"
[[rules]]
name = "test-custom"
description = "Test custom"
regex = "(CUSTOM_[A-Z]{8})"
base_confidence = 0.90
remediation = "rotate"
"#;
        let rules = parse_custom_rules(toml).unwrap();
        let compiled: Vec<CompiledPattern> = rules
            .into_iter()
            .map(|r| CompiledPattern::compile(r).unwrap())
            .collect();
        let engine = DetectionEngine::new(compiled);

        let item = ContentItem {
            path: PathBuf::from("/test/.env"),
            line_number: 1,
            line: "KEY=CUSTOM_ABCDEFGH".to_string(),
            context_before: vec![],
            context_after: vec![],
            source_type: SourceType::EnvFile,
        };

        let findings = engine.analyze(&item);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].secret_type,
            SecretType::Custom("test-custom".to_string())
        );
        assert_eq!(findings[0].value.raw(), "CUSTOM_ABCDEFGH");
    }

    // 16
    #[test]
    fn custom_and_builtin_merged() {
        use crate::detection::patterns::all_patterns;

        let custom_toml = r#"
[[rules]]
name = "corp-token"
description = "Corp token"
regex = "(CORP_[A-Z0-9]{20})"
base_confidence = 0.85
remediation = "rotate"
"#;
        let mut all_rules = all_patterns();
        let custom = parse_custom_rules(custom_toml).unwrap();
        all_rules.extend(custom);

        let compiled: Vec<CompiledPattern> = all_rules
            .into_iter()
            .filter_map(|r| CompiledPattern::compile(r).ok())
            .collect();
        let engine = DetectionEngine::new(compiled);

        // Built-in: AWS key
        let item_aws = ContentItem {
            path: PathBuf::from("/test/.env"),
            line_number: 1,
            line: "AWS_KEY=AKIAIOSFODNN7EXAMPLE".to_string(),
            context_before: vec![],
            context_after: vec![],
            source_type: SourceType::EnvFile,
        };
        let aws_findings = engine.analyze(&item_aws);
        assert!(
            aws_findings
                .iter()
                .any(|f| f.matched_pattern.as_deref() == Some("aws-access-key-id")),
            "built-in AWS pattern should still match"
        );

        // Custom: corp token
        let item_corp = ContentItem {
            path: PathBuf::from("/test/.env"),
            line_number: 2,
            line: "TOKEN=CORP_ABCDEFGHIJ0123456789".to_string(),
            context_before: vec![],
            context_after: vec![],
            source_type: SourceType::EnvFile,
        };
        let corp_findings = engine.analyze(&item_corp);
        assert!(
            corp_findings
                .iter()
                .any(|f| f.matched_pattern.as_deref() == Some("corp-token")),
            "custom corp-token pattern should match"
        );
    }

    // 17
    #[test]
    fn rules_test_invalid_regex_returns_error() {
        // Verify that Regex::new fails for an invalid pattern (used by run_rules_test)
        assert!(regex::Regex::new("[invalid").is_err());
    }

    // 18
    #[test]
    fn rules_list_shows_builtin_count() {
        let patterns = crate::detection::patterns::all_patterns();
        assert_eq!(patterns.len(), 44, "expected 44 built-in patterns");
    }
}
