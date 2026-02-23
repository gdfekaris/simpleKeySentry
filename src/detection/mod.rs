pub mod entropy;
pub mod heuristics;
pub mod patterns;

use std::path::Path;

use regex::{Regex, RegexSet};

use crate::models::{ContentItem, Finding, SecretType, SecretValue, SourceLocation, SourceType};
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
// EntropyAnalyzer trait
// ---------------------------------------------------------------------------

/// Adjusts confidence based on the entropy of the matched value.
pub trait EntropyAnalyzer {
    fn confidence_delta(&self, value: &str) -> f64;
}

struct NoopEntropyAnalyzer;

impl EntropyAnalyzer for NoopEntropyAnalyzer {
    fn confidence_delta(&self, _value: &str) -> f64 {
        0.0
    }
}

// ---------------------------------------------------------------------------
// HeuristicContext
// ---------------------------------------------------------------------------

/// All contextual information available to a heuristic when it evaluates a match.
pub struct HeuristicContext<'a> {
    /// The raw matched value (capture group 1, or the full match as fallback).
    pub matched_text: &'a str,
    /// The complete source line containing the match.
    pub full_line: &'a str,
    /// Up to 3 lines that precede the matched line.
    pub lines_before: &'a [String],
    /// Up to 3 lines that follow the matched line.
    pub lines_after: &'a [String],
    /// Path to the source file.
    pub file_path: &'a Path,
    /// Source type of the collector that produced this item.
    pub source_type: SourceType,
}

// ---------------------------------------------------------------------------
// Heuristic trait
// ---------------------------------------------------------------------------

/// A single heuristic that adjusts confidence based on content context.
///
/// Each heuristic returns a delta in `[−0.30, +0.20]`.  Implementing `Send +
/// Sync` allows the engine to be used from multiple threads (e.g., with rayon
/// in a later block).
pub trait Heuristic: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, context: &HeuristicContext) -> f64;
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
/// - Use [`DetectionEngine::new`] for a bare engine (no entropy / heuristics) or
///   [`DetectionEngine::with_defaults`] to wire in the full pipeline.
pub struct DetectionEngine {
    patterns: Vec<CompiledPattern>,
    /// Pre-built from pattern regexes for fast multi-pattern first-pass.
    regex_set: RegexSet,
    entropy_analyzer: Box<dyn EntropyAnalyzer>,
    heuristics: Vec<Box<dyn Heuristic>>,
}

impl DetectionEngine {
    /// Construct a bare engine from a list of compiled patterns.
    ///
    /// The entropy analyzer is a no-op and no heuristics are applied; only
    /// the base confidence score from each matching pattern is used. This is
    /// suitable for unit-testing pattern logic in isolation.
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

    /// Construct an engine pre-loaded with the full confidence pipeline:
    /// [`entropy::ShannonEntropyAnalyzer`] and all built-in heuristics from
    /// [`heuristics::all_heuristics`].
    ///
    /// This is the recommended constructor for production use.
    pub fn with_defaults(patterns: Vec<CompiledPattern>) -> Self {
        let mut engine = Self::new(patterns);
        engine.entropy_analyzer = Box::new(entropy::ShannonEntropyAnalyzer);
        engine.heuristics = heuristics::all_heuristics();
        engine
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
    /// 2. Entropy adjustment.
    /// 3. Heuristic adjustments.
    /// 4. Clamp result to [0.0, 1.0].
    fn compute_confidence(&self, rule: &PatternRule, value: &str, item: &ContentItem) -> f64 {
        let mut score = rule.base_confidence;
        score += self.entropy_analyzer.confidence_delta(value);

        let ctx = HeuristicContext {
            matched_text: value,
            full_line: &item.line,
            lines_before: &item.context_before,
            lines_after: &item.context_after,
            file_path: &item.path,
            source_type: item.source_type.clone(),
        };

        for h in &self.heuristics {
            score += h.evaluate(&ctx);
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

    use crate::models::{SecretType, Severity, SourceType};

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

    fn make_item_at(line: &str, path: &str) -> ContentItem {
        ContentItem {
            path: PathBuf::from(path),
            line_number: 1,
            line: line.to_string(),
            context_before: Vec::new(),
            context_after: Vec::new(),
            source_type: SourceType::Dotfile,
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

    // --- Confidence pipeline (bare engine — no entropy or heuristics) ---

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

    // --- Full confidence pipeline (with_defaults) ---

    /// Acceptance test from the Block 6 spec:
    ///
    /// `export AKIAIOSFODNN7EXAMPLE` → base 0.95 + AssignmentContext +0.10
    /// − PlaceholderDetection −0.30 = **0.75** (High, not Critical).
    ///
    /// The matched value "AKIAIOSFODNN7EXAMPLE" has entropy ≈ 3.69 which is
    /// below the alphanumeric threshold (4.0), so the entropy delta is 0.0.
    /// No other heuristics fire for this bare `export` line without a `=`.
    #[test]
    fn pipeline_test_placeholder_key_scores_high() {
        use crate::detection::patterns::all_patterns;

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);

        let item = make_item_at("export AKIAIOSFODNN7EXAMPLE", "/tmp/deploy.sh");
        let findings = engine.analyze(&item);

        let f = findings
            .iter()
            .find(|f| f.matched_pattern.as_deref() == Some("aws-access-key-id"))
            .expect("aws-access-key-id finding not produced");

        assert!(
            (f.confidence - 0.75).abs() < 1e-10,
            "expected 0.75, got {}",
            f.confidence
        );
        assert_eq!(f.severity, Severity::High);
    }

    /// A genuinely high-entropy AWS key in the same context should score
    /// Critical (1.0 after clamping):
    /// base 0.95 + entropy +0.10 + AssignmentContext +0.10 = 1.15 → clamped to 1.0.
    ///
    /// "AKIAQZXCWSREDFVTGBYH": A appears twice, remaining 18 chars are unique.
    /// H ≈ 4.22 > ALPHANUM_THRESHOLD 4.0 → entropy delta = +0.10.
    #[test]
    fn pipeline_test_real_looking_key_scores_critical() {
        use crate::detection::patterns::all_patterns;

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);

        let item = make_item_at("export AKIAQZXCWSREDFVTGBYH", "/tmp/deploy.sh");
        let findings = engine.analyze(&item);

        let f = findings
            .iter()
            .find(|f| f.matched_pattern.as_deref() == Some("aws-access-key-id"))
            .expect("aws-access-key-id finding not produced");

        assert_eq!(f.confidence, 1.0);
        assert_eq!(f.severity, Severity::Critical);
    }
}
