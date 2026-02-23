use regex::{Regex, RegexSet};

use crate::models::{ContentItem, Finding, SecretType, SecretValue, SourceLocation};
use crate::SksError;

// ---------------------------------------------------------------------------
// PatternRule
// ---------------------------------------------------------------------------

/// A pattern definition: regex, metadata, and a base confidence score.
///
/// Patterns are data — the engine compiles them at startup and applies them
/// uniformly, so adding a new pattern never requires changing engine logic.
#[derive(Debug, Clone)]
pub struct PatternRule {
    pub name: String,
    pub description: String,
    /// Raw regex string. Must compile with the `regex` crate.
    pub regex: String,
    pub secret_type: SecretType,
    /// Starting confidence score before pipeline adjustments. Range [0.0, 1.0].
    pub base_confidence: f64,
    pub remediation: String,
}

// ---------------------------------------------------------------------------
// CompiledPattern
// ---------------------------------------------------------------------------

/// A `PatternRule` with its regex pre-compiled for repeated use.
pub struct CompiledPattern {
    pub rule: PatternRule,
    pub regex: Regex,
}

impl CompiledPattern {
    /// Compile a `PatternRule` into a `CompiledPattern`.
    ///
    /// Returns an error if the regex string is invalid.
    pub fn compile(rule: PatternRule) -> Result<Self, SksError> {
        let regex = Regex::new(&rule.regex)
            .map_err(|e| SksError::Detection(format!("Invalid regex '{}': {}", rule.name, e)))?;
        Ok(CompiledPattern { rule, regex })
    }
}

// ---------------------------------------------------------------------------
// Hooks for Block 6
// ---------------------------------------------------------------------------

/// Adjusts confidence based on the entropy of the matched value.
///
/// The no-op implementation is used until Block 6 wires in the real analyzer.
pub trait EntropyAnalyzer {
    fn confidence_delta(&self, value: &str) -> f64;
}

/// A single heuristic that adjusts confidence based on content context.
///
/// Examples (Block 6): key-value proximity (+0.20), placeholder pattern (−0.30).
pub trait Heuristic {
    fn name(&self) -> &str;
    fn confidence_delta(&self, item: &ContentItem, value: &str) -> f64;
}

struct NoopEntropyAnalyzer;

impl EntropyAnalyzer for NoopEntropyAnalyzer {
    fn confidence_delta(&self, _value: &str) -> f64 {
        0.0
    }
}

// ---------------------------------------------------------------------------
// DetectionEngine
// ---------------------------------------------------------------------------

/// Matches compiled patterns against content items and produces findings.
///
/// Design:
/// - A `RegexSet` performs a fast first pass: lines with no matches are skipped
///   entirely before any capture-group extraction is attempted.
/// - The confidence pipeline runs for every match: base score → entropy
///   adjustment → heuristic adjustments → clamp to [0.0, 1.0].
/// - Entropy and heuristic slots are no-ops until Block 6 plugs in the real
///   implementations.
pub struct DetectionEngine {
    patterns: Vec<CompiledPattern>,
    /// Pre-built from pattern regexes for fast multi-pattern first-pass.
    regex_set: RegexSet,
    entropy_analyzer: Box<dyn EntropyAnalyzer>,
    heuristics: Vec<Box<dyn Heuristic>>,
}

impl DetectionEngine {
    /// Construct the engine from a list of compiled patterns.
    ///
    /// An empty pattern list is valid; `analyze` will always return `[]`.
    pub fn new(patterns: Vec<CompiledPattern>) -> Self {
        let regexes: Vec<&str> = patterns.iter().map(|p| p.rule.regex.as_str()).collect();
        // Individual patterns were validated by CompiledPattern::compile, so
        // RegexSet construction from the same strings must not fail.
        let regex_set =
            RegexSet::new(&regexes).expect("RegexSet build failed after individual compilation");
        DetectionEngine {
            patterns,
            regex_set,
            entropy_analyzer: Box::new(NoopEntropyAnalyzer),
            heuristics: Vec::new(),
        }
    }

    /// Analyze a single content item and return all findings.
    pub fn analyze(&self, item: &ContentItem) -> Vec<Finding> {
        // Fast first pass: skip lines that match no pattern at all.
        let matches = self.regex_set.matches(&item.line);
        if !matches.matched_any() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for idx in matches.iter() {
            let compiled = &self.patterns[idx];

            if let Some(captures) = compiled.regex.captures(&item.line) {
                // Prefer capture group 1 (the isolated secret value).
                // Fall back to the full match if there are no groups.
                let matched_str = captures
                    .get(1)
                    .or_else(|| captures.get(0))
                    .map(|m| m.as_str())
                    .unwrap_or("");

                if matched_str.is_empty() {
                    continue;
                }

                let confidence = self.compute_confidence(&compiled.rule, matched_str, item);

                let location = SourceLocation {
                    path: item.path.clone(),
                    line: Some(item.line_number),
                    column: None,
                    context_before: item.context_before.join("\n"),
                    context_after: item.context_after.join("\n"),
                    source_type: item.source_type.clone(),
                };

                let description = format!(
                    "{} found in {}",
                    compiled.rule.description,
                    item.path.display()
                );

                findings.push(Finding::new(
                    compiled.rule.secret_type.clone(),
                    confidence,
                    SecretValue::new(matched_str.to_string()),
                    location,
                    description,
                    compiled.rule.remediation.clone(),
                    Some(compiled.rule.name.clone()),
                ));
            }
        }

        findings
    }

    /// Analyze a batch of content items and return all findings.
    pub fn analyze_batch(&self, items: &[ContentItem]) -> Vec<Finding> {
        items.iter().flat_map(|item| self.analyze(item)).collect()
    }

    /// Runs the confidence pipeline for a single match.
    ///
    /// 1. Base score from the pattern.
    /// 2. Entropy adjustment (no-op until Block 6).
    /// 3. Heuristic adjustments (no-op until Block 6).
    /// 4. Clamp result to [0.0, 1.0].
    fn compute_confidence(&self, rule: &PatternRule, value: &str, item: &ContentItem) -> f64 {
        let mut score = rule.base_confidence;
        score += self.entropy_analyzer.confidence_delta(value);
        for h in &self.heuristics {
            score += h.confidence_delta(item, value);
        }
        score.clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::models::{SecretType, SourceType};

    fn make_item(line: &str) -> ContentItem {
        ContentItem {
            path: PathBuf::from("/test/.env"),
            line_number: 1,
            line: line.to_string(),
            context_before: Vec::new(),
            context_after: Vec::new(),
            source_type: SourceType::EnvFile,
        }
    }

    fn test_rule() -> PatternRule {
        PatternRule {
            name: "test-secret".to_string(),
            description: "Test secret".to_string(),
            regex: r"(TEST_SECRET_[A-Z0-9]{8,})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.90,
            remediation: "Remove the test secret.".to_string(),
        }
    }

    fn engine_with_test_pattern() -> DetectionEngine {
        let compiled = CompiledPattern::compile(test_rule()).unwrap();
        DetectionEngine::new(vec![compiled])
    }

    // --- Construction ---

    #[test]
    fn empty_engine_accepts_empty_pattern_list() {
        let engine = DetectionEngine::new(vec![]);
        let item = make_item("TEST_SECRET_ABCDEFGH");
        assert!(engine.analyze(&item).is_empty());
    }

    // --- Non-matching lines ---

    #[test]
    fn non_matching_line_returns_empty_vec() {
        let engine = engine_with_test_pattern();
        let item = make_item("export PATH=/usr/local/bin:$PATH");
        assert!(engine.analyze(&item).is_empty());
    }

    // --- Basic matching ---

    #[test]
    fn matching_line_returns_one_finding() {
        let engine = engine_with_test_pattern();
        let item = make_item("SECRET=TEST_SECRET_ABCDEFGH");
        let findings = engine.analyze(&item);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn finding_carries_matched_pattern_name() {
        let engine = engine_with_test_pattern();
        let item = make_item("SECRET=TEST_SECRET_ABCDEFGH");
        let findings = engine.analyze(&item);
        assert_eq!(findings[0].matched_pattern.as_deref(), Some("test-secret"));
    }

    #[test]
    fn finding_value_is_capture_group_one() {
        let engine = engine_with_test_pattern();
        let item = make_item("KEY=TEST_SECRET_ABCDEFGH");
        let findings = engine.analyze(&item);
        assert_eq!(findings[0].value.raw(), "TEST_SECRET_ABCDEFGH");
    }

    // --- Confidence pipeline ---

    #[test]
    fn confidence_equals_base_score_when_no_adjustments() {
        let engine = engine_with_test_pattern();
        let item = make_item("KEY=TEST_SECRET_ABCDEFGH");
        let findings = engine.analyze(&item);
        assert!((findings[0].confidence - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_clamped_to_one_when_base_exceeds_one() {
        let rule = PatternRule {
            name: "over-confident".to_string(),
            description: "Test".to_string(),
            regex: r"(OVERCONF_[A-Z]{4})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 1.5,
            remediation: "N/A".to_string(),
        };
        let engine = DetectionEngine::new(vec![CompiledPattern::compile(rule).unwrap()]);
        let findings = engine.analyze(&make_item("OVERCONF_ABCD"));
        assert_eq!(findings[0].confidence, 1.0);
    }

    #[test]
    fn confidence_clamped_to_zero_when_base_below_zero() {
        let rule = PatternRule {
            name: "zero-conf".to_string(),
            description: "Test".to_string(),
            regex: r"(ZEROCONF_[A-Z]{4})".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: -0.5,
            remediation: "N/A".to_string(),
        };
        let engine = DetectionEngine::new(vec![CompiledPattern::compile(rule).unwrap()]);
        let findings = engine.analyze(&make_item("ZEROCONF_ABCD"));
        assert_eq!(findings[0].confidence, 0.0);
    }

    // --- Determinism ---

    #[test]
    fn finding_id_is_deterministic_across_calls() {
        let engine = engine_with_test_pattern();
        let item = make_item("KEY=TEST_SECRET_ABCDEFGH");
        let id1 = engine.analyze(&item)[0].id.clone();
        let id2 = engine.analyze(&item)[0].id.clone();
        assert_eq!(id1, id2);
    }

    // --- Batch ---

    #[test]
    fn analyze_batch_aggregates_findings_across_items() {
        let engine = engine_with_test_pattern();
        let items = vec![
            make_item("A=TEST_SECRET_AAAAAAAA"),
            make_item("no match here"),
            make_item("B=TEST_SECRET_BBBBBBBB"),
        ];
        assert_eq!(engine.analyze_batch(&items).len(), 2);
    }

    // --- Error handling ---

    #[test]
    fn invalid_regex_compile_returns_error() {
        let rule = PatternRule {
            name: "bad-pattern".to_string(),
            description: "Bad regex".to_string(),
            regex: r"[unclosed bracket".to_string(),
            secret_type: SecretType::GenericApiKey,
            base_confidence: 0.5,
            remediation: "N/A".to_string(),
        };
        assert!(CompiledPattern::compile(rule).is_err());
    }
}
