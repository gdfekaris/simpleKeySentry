//! Contextual heuristics for the confidence pipeline.
//!
//! Each heuristic receives a [`HeuristicContext`] containing the matched value
//! and its surrounding context, then returns a confidence adjustment in the
//! range `[−0.30, +0.20]`. Positive values signal stronger evidence of a real
//! secret; negative values flag likely false positives.
//!
//! The full set is exposed via [`all_heuristics`].

use std::sync::OnceLock;

use regex::Regex;

use super::{Heuristic, HeuristicContext};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn build_regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("hard-coded heuristic regex must compile")
}

// ---------------------------------------------------------------------------
// 1. KeyValueProximity (+0.20)
// ---------------------------------------------------------------------------

/// Fires when the matched value appears as the right-hand side of an explicit
/// key–value assignment on the same line: shell/dotenv (`KEY=value`),
/// JSON (`"key": "value"`), or YAML (`key: value`).
pub struct KeyValueProximity;

impl Heuristic for KeyValueProximity {
    fn name(&self) -> &str {
        "KeyValueProximity"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(
                r#"(?i)(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S|"[^"]+"\s*:\s*(?:"[^"]*"|\S)|[A-Za-z_][A-Za-z0-9_-]*\s*:\s*\S)"#,
            )
        });
        if re.is_match(ctx.full_line) {
            0.20
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// 2. KeywordProximity (+0.15)
// ---------------------------------------------------------------------------

/// Fires when a high-signal keyword (`secret`, `token`, `password`, `api_key`,
/// `auth`, `credential`) appears on the matched line or within the 3-line
/// context window (before or after).
pub struct KeywordProximity;

impl Heuristic for KeywordProximity {
    fn name(&self) -> &str {
        "KeywordProximity"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(
                r"(?i)\b(secret|token|password|api[_-]?key|auth(?:en(?:tication)?|orization)?|credential)",
            )
        });

        if re.is_match(ctx.full_line) {
            return 0.15;
        }
        // Check up to 3 context lines on each side.
        for line in ctx
            .lines_before
            .iter()
            .chain(ctx.lines_after.iter())
            .take(3)
        {
            if re.is_match(line) {
                return 0.15;
            }
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// 3. FilePathSignal (+0.10)
// ---------------------------------------------------------------------------

/// Fires when the source file's basename is a well-known secrets-bearing name:
/// `.env`, `.env.*`, `credentials`, `secrets`, `.netrc`, `config.json`, etc.
pub struct FilePathSignal;

impl Heuristic for FilePathSignal {
    fn name(&self) -> &str {
        "FilePathSignal"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(
                r"(?i)^(?:\.env(?:\..+)?|credentials?(?:\.toml)?|secrets?|\.netrc|config\.json|settings\.(?:py|ya?ml)|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf|terraform\.tfvars|vault\.ya?ml)$",
            )
        });

        if let Some(name) = ctx.file_path.file_name().and_then(|n| n.to_str()) {
            if re.is_match(name) {
                return 0.10;
            }
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// 4. AssignmentContext (+0.10)
// ---------------------------------------------------------------------------

/// Fires when the line contains an explicit variable assignment:
/// - `export VAR` or `export VAR=VALUE` (shell export)
/// - `set VAR=VALUE` (Windows/PowerShell set)
/// - `VAR=VALUE` (bare POSIX assignment)
pub struct AssignmentContext;

impl Heuristic for AssignmentContext {
    fn name(&self) -> &str {
        "AssignmentContext"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(r"(?i)(?:\bexport\b|\bset\b[^=\n]*=|^\s*[A-Za-z_][A-Za-z0-9_]*\s*=)")
        });
        if re.is_match(ctx.full_line) {
            0.10
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// 5. CommentContext (−0.10)
// ---------------------------------------------------------------------------

/// Fires when the line appears to be a comment (`#`, `//`, `/*`).
/// Secrets inside comments are usually documentation examples, not live values.
pub struct CommentContext;

impl Heuristic for CommentContext {
    fn name(&self) -> &str {
        "CommentContext"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        let t = ctx.full_line.trim_start();
        if t.starts_with('#') || t.starts_with("//") || t.starts_with("/*") {
            -0.10
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// 6. PlaceholderDetection (−0.30)
// ---------------------------------------------------------------------------

/// Fires when the matched text contains a well-known placeholder marker:
/// `example`, `test`, `dummy`, `changeme`, `YOUR_`, `xxxx`, `<…>`, `TODO`,
/// `placeholder`.
pub struct PlaceholderDetection;

impl Heuristic for PlaceholderDetection {
    fn name(&self) -> &str {
        "PlaceholderDetection"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(r"(?i)example|test|dummy|changeme|your_|xxxx|<[^>]*>|TODO|placeholder")
        });
        if re.is_match(ctx.matched_text) {
            -0.30
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// 7. VersionHashPattern (−0.20)
// ---------------------------------------------------------------------------

/// Fires when the matched text looks like a version string (`v1.2.3`), a
/// 40-character git SHA (lowercase hex), or carries a hash algorithm prefix
/// (`sha256:`, `sha1:`, `md5:`).
pub struct VersionHashPattern;

impl Heuristic for VersionHashPattern {
    fn name(&self) -> &str {
        "VersionHashPattern"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            build_regex(r"(?i)(?:^v?\d+\.\d+\.\d+|^[0-9a-f]{40}$|(?:sha256|sha1|md5):[0-9a-f]+)")
        });
        if re.is_match(ctx.matched_text) {
            -0.20
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// 8. UrlPathSegment (−0.15)
// ---------------------------------------------------------------------------

/// Fires when the matched text appears inside a URL path (preceded or followed
/// by `/`), suggesting it is a resource identifier rather than a secret value.
pub struct UrlPathSegment;

impl Heuristic for UrlPathSegment {
    fn name(&self) -> &str {
        "UrlPathSegment"
    }

    fn evaluate(&self, ctx: &HeuristicContext) -> f64 {
        let line = ctx.full_line;
        let text = ctx.matched_text;
        if let Some(pos) = line.find(text) {
            let before_slash = pos > 0 && line.as_bytes()[pos - 1] == b'/';
            let after_slash =
                pos + text.len() < line.len() && line.as_bytes()[pos + text.len()] == b'/';
            if before_slash || after_slash {
                return -0.15;
            }
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// Public constructor
// ---------------------------------------------------------------------------

/// Returns all built-in heuristics in their recommended application order.
pub fn all_heuristics() -> Vec<Box<dyn Heuristic>> {
    vec![
        Box::new(KeyValueProximity),
        Box::new(KeywordProximity),
        Box::new(FilePathSignal),
        Box::new(AssignmentContext),
        Box::new(CommentContext),
        Box::new(PlaceholderDetection),
        Box::new(VersionHashPattern),
        Box::new(UrlPathSegment),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SourceType;
    use std::path::{Path, PathBuf};

    fn env_path() -> PathBuf {
        PathBuf::from("/project/.env")
    }
    fn script_path() -> PathBuf {
        PathBuf::from("/project/src/deploy.sh")
    }

    fn ctx<'a>(
        matched: &'a str,
        line: &'a str,
        before: &'a [String],
        after: &'a [String],
        path: &'a Path,
    ) -> HeuristicContext<'a> {
        HeuristicContext {
            matched_text: matched,
            full_line: line,
            lines_before: before,
            lines_after: after,
            file_path: path,
            source_type: SourceType::Dotfile,
        }
    }

    // ── KeyValueProximity ────────────────────────────────────────────────────

    #[test]
    fn kvp_fires_on_dotenv_assignment() {
        let h = KeyValueProximity;
        assert_eq!(
            h.evaluate(&ctx(
                "sk_live_abc",
                "API_KEY=sk_live_abc",
                &[],
                &[],
                &env_path()
            )),
            0.20
        );
    }

    #[test]
    fn kvp_fires_on_json_key_value() {
        let h = KeyValueProximity;
        assert_eq!(
            h.evaluate(&ctx(
                "tok123",
                r#"{"api_key": "tok123"}"#,
                &[],
                &[],
                &script_path()
            )),
            0.20
        );
    }

    #[test]
    fn kvp_does_not_fire_on_bare_token() {
        let h = KeyValueProximity;
        // No key=value structure — just the value on its own.
        assert_eq!(
            h.evaluate(&ctx("sk_live_abc", "sk_live_abc", &[], &[], &script_path())),
            0.0
        );
    }

    // ── KeywordProximity ─────────────────────────────────────────────────────

    #[test]
    fn kwp_fires_when_keyword_on_same_line() {
        let h = KeywordProximity;
        assert_eq!(
            h.evaluate(&ctx(
                "abc123",
                "secret_key = abc123",
                &[],
                &[],
                &script_path()
            )),
            0.15
        );
    }

    #[test]
    fn kwp_fires_when_keyword_in_context_window() {
        let h = KeywordProximity;
        let before = vec!["# API token below".to_string()];
        assert_eq!(
            h.evaluate(&ctx("abc123", "abc123", &before, &[], &script_path())),
            0.15
        );
    }

    #[test]
    fn kwp_does_not_fire_on_unrelated_line() {
        let h = KeywordProximity;
        assert_eq!(
            h.evaluate(&ctx("abc123", "value = abc123", &[], &[], &script_path())),
            0.0
        );
    }

    // ── FilePathSignal ───────────────────────────────────────────────────────

    #[test]
    fn fps_fires_on_dotenv_file() {
        let h = FilePathSignal;
        assert_eq!(
            h.evaluate(&ctx("val", "KEY=val", &[], &[], &env_path())),
            0.10
        );
    }

    #[test]
    fn fps_fires_on_dotenv_production() {
        let h = FilePathSignal;
        let path = PathBuf::from("/project/.env.production");
        assert_eq!(h.evaluate(&ctx("val", "KEY=val", &[], &[], &path)), 0.10);
    }

    #[test]
    fn fps_does_not_fire_on_source_file() {
        let h = FilePathSignal;
        assert_eq!(
            h.evaluate(&ctx("val", "let x = val;", &[], &[], &script_path())),
            0.0
        );
    }

    #[test]
    fn fps_fires_on_pgpass() {
        let h = FilePathSignal;
        let path = PathBuf::from("/home/user/.pgpass");
        assert_eq!(h.evaluate(&ctx("val", "KEY=val", &[], &[], &path)), 0.10);
    }

    #[test]
    fn fps_fires_on_my_cnf() {
        let h = FilePathSignal;
        let path = PathBuf::from("/home/user/.my.cnf");
        assert_eq!(h.evaluate(&ctx("val", "KEY=val", &[], &[], &path)), 0.10);
    }

    #[test]
    fn fps_fires_on_credentials_toml() {
        let h = FilePathSignal;
        let path = PathBuf::from("/home/user/.cargo/credentials.toml");
        assert_eq!(h.evaluate(&ctx("val", "KEY=val", &[], &[], &path)), 0.10);
    }

    // ── AssignmentContext ────────────────────────────────────────────────────

    #[test]
    fn ac_fires_on_export_keyword() {
        let h = AssignmentContext;
        assert_eq!(
            h.evaluate(&ctx(
                "AKIAIOSFODNN7EXAMPLE",
                "export AKIAIOSFODNN7EXAMPLE",
                &[],
                &[],
                &script_path()
            )),
            0.10
        );
    }

    #[test]
    fn ac_fires_on_export_with_equals() {
        let h = AssignmentContext;
        assert_eq!(
            h.evaluate(&ctx(
                "val",
                "export SECRET_KEY=val",
                &[],
                &[],
                &script_path()
            )),
            0.10
        );
    }

    #[test]
    fn ac_fires_on_bare_assignment() {
        let h = AssignmentContext;
        assert_eq!(
            h.evaluate(&ctx("val", "SECRET_KEY=val", &[], &[], &script_path())),
            0.10
        );
    }

    #[test]
    fn ac_does_not_fire_on_equality_comparison() {
        let h = AssignmentContext;
        // "if key == val:" — starts with "if", not a bare assignment
        assert_eq!(
            h.evaluate(&ctx("val", "if key == val:", &[], &[], &script_path())),
            0.0
        );
    }

    // ── CommentContext ───────────────────────────────────────────────────────

    #[test]
    fn cc_fires_on_hash_comment() {
        let h = CommentContext;
        assert_eq!(
            h.evaluate(&ctx("val", "# SECRET=val", &[], &[], &script_path())),
            -0.10
        );
    }

    #[test]
    fn cc_fires_on_double_slash_comment() {
        let h = CommentContext;
        assert_eq!(
            h.evaluate(&ctx("val", "// api_key = val", &[], &[], &script_path())),
            -0.10
        );
    }

    #[test]
    fn cc_does_not_fire_on_code_line() {
        let h = CommentContext;
        assert_eq!(
            h.evaluate(&ctx("val", "let x = val;", &[], &[], &script_path())),
            0.0
        );
    }

    // ── PlaceholderDetection ─────────────────────────────────────────────────

    #[test]
    fn pd_fires_on_example_suffix() {
        let h = PlaceholderDetection;
        assert_eq!(
            h.evaluate(&ctx(
                "AKIAIOSFODNN7EXAMPLE",
                "KEY=AKIAIOSFODNN7EXAMPLE",
                &[],
                &[],
                &script_path()
            )),
            -0.30
        );
    }

    #[test]
    fn pd_fires_on_your_prefix() {
        let h = PlaceholderDetection;
        assert_eq!(
            h.evaluate(&ctx(
                "YOUR_API_KEY_HERE",
                "KEY=YOUR_API_KEY_HERE",
                &[],
                &[],
                &script_path()
            )),
            -0.30
        );
    }

    #[test]
    fn pd_does_not_fire_on_real_looking_key() {
        let h = PlaceholderDetection;
        assert_eq!(
            h.evaluate(&ctx(
                "sk_live_aB3dEfGhIjKlMnOpQrSt",
                "STRIPE_KEY=sk_live_aB3dEfGhIjKlMnOpQrSt",
                &[],
                &[],
                &script_path()
            )),
            0.0
        );
    }

    // ── VersionHashPattern ───────────────────────────────────────────────────

    #[test]
    fn vhp_fires_on_semver() {
        let h = VersionHashPattern;
        assert_eq!(
            h.evaluate(&ctx("v1.2.3", "version=v1.2.3", &[], &[], &script_path())),
            -0.20
        );
    }

    #[test]
    fn vhp_fires_on_40_char_git_sha() {
        let h = VersionHashPattern;
        let sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert_eq!(sha.len(), 40);
        let line = format!("commit = {sha}");
        let path = script_path();
        assert_eq!(h.evaluate(&ctx(sha, &line, &[], &[], &path)), -0.20);
    }

    #[test]
    fn vhp_does_not_fire_on_api_key() {
        let h = VersionHashPattern;
        assert_eq!(
            h.evaluate(&ctx(
                "sk_live_abc123defXYZ456",
                "STRIPE=sk_live_abc123defXYZ456",
                &[],
                &[],
                &script_path()
            )),
            0.0
        );
    }

    // ── UrlPathSegment ───────────────────────────────────────────────────────

    #[test]
    fn ups_fires_when_value_followed_by_slash() {
        let h = UrlPathSegment;
        assert_eq!(
            h.evaluate(&ctx(
                "abc123def456",
                "https://example.com/abc123def456/resource",
                &[],
                &[],
                &script_path()
            )),
            -0.15
        );
    }

    #[test]
    fn ups_fires_when_value_preceded_by_slash() {
        let h = UrlPathSegment;
        assert_eq!(
            h.evaluate(&ctx(
                "abc123def456",
                "path = /abc123def456",
                &[],
                &[],
                &script_path()
            )),
            -0.15
        );
    }

    #[test]
    fn ups_does_not_fire_for_bare_assignment() {
        let h = UrlPathSegment;
        assert_eq!(
            h.evaluate(&ctx(
                "abc123def456",
                "token=abc123def456",
                &[],
                &[],
                &script_path()
            )),
            0.0
        );
    }

    // ── all_heuristics ───────────────────────────────────────────────────────

    #[test]
    fn all_heuristics_returns_eight_entries() {
        assert_eq!(all_heuristics().len(), 8);
    }

    #[test]
    fn all_heuristics_names_are_unique() {
        let hs = all_heuristics();
        let names: Vec<&str> = hs.iter().map(|h| h.name()).collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len());
    }
}
