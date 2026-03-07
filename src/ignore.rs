//! `.sentryignore` suppression system.
//!
//! Two-stage suppression loaded from `~/.config/sks/.sentryignore` (user-level)
//! and `.sentryignore` (project-level):
//!
//! - **Stage 1 — Path exclusion (pre-collection):** Gitignore-style glob
//!   patterns. Collectors skip matched files entirely.
//! - **Stage 2 — Fingerprint exclusion (post-detection):** `fingerprint:sha256:<hex>`
//!   lines filter out specific findings after detection, before reporting.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs};

use globset::{Glob, GlobSet, GlobSetBuilder};

// ---------------------------------------------------------------------------
// File locations
// ---------------------------------------------------------------------------

/// Returns the user-level `.sentryignore` path.
/// Respects `$XDG_CONFIG_HOME`; defaults to `~/.config/sks/.sentryignore`.
fn user_ignore_path() -> PathBuf {
    let config_home = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".config"));
    config_home.join("sks/.sentryignore")
}

/// Returns the project-level `.sentryignore` path (CWD).
fn project_ignore_path() -> PathBuf {
    PathBuf::from(".sentryignore")
}

fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Expands a leading `~` or `~/` to the user's home directory.
fn expand_tilde(s: &str) -> String {
    if s == "~" {
        home_dir().to_string_lossy().into_owned()
    } else if let Some(rest) = s.strip_prefix("~/") {
        format!("{}/{rest}", home_dir().display())
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// IgnoreRules
// ---------------------------------------------------------------------------

/// Compiled suppression rules from `.sentryignore` files.
#[derive(Clone)]
pub struct IgnoreRules {
    globs: Arc<GlobSet>,
    fingerprints: HashSet<String>,
    path_pattern_count: usize,
}

impl std::fmt::Debug for IgnoreRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IgnoreRules")
            .field("path_patterns", &self.path_pattern_count)
            .field("fingerprints", &self.fingerprints.len())
            .finish()
    }
}

impl IgnoreRules {
    /// Returns no-op rules (no patterns, no fingerprints).
    pub fn empty() -> Self {
        IgnoreRules {
            globs: Arc::new(GlobSet::empty()),
            fingerprints: HashSet::new(),
            path_pattern_count: 0,
        }
    }

    /// Loads user + project `.sentryignore` files, merges, never errors.
    /// Missing files are silently ignored.
    pub fn load() -> Self {
        let mut glob_patterns = Vec::new();
        let mut fingerprints = HashSet::new();

        // Load user-level file.
        let user_path = user_ignore_path();
        if user_path.exists() {
            parse_file(&user_path, &mut glob_patterns, &mut fingerprints);
        }

        // Load project-level file.
        let project_path = project_ignore_path();
        if project_path.exists() {
            parse_file(&project_path, &mut glob_patterns, &mut fingerprints);
        }

        // Compile glob patterns.
        let mut builder = GlobSetBuilder::new();
        let mut valid_count = 0;
        for pattern in &glob_patterns {
            match Glob::new(pattern) {
                Ok(g) => {
                    builder.add(g);
                    valid_count += 1;
                }
                Err(e) => {
                    eprintln!("sks warn: invalid glob pattern '{pattern}': {e}");
                }
            }
        }

        let glob_set = match builder.build() {
            Ok(gs) => gs,
            Err(e) => {
                eprintln!("sks warn: failed to compile ignore globs: {e}");
                GlobSet::empty()
            }
        };

        IgnoreRules {
            globs: Arc::new(glob_set),
            fingerprints,
            path_pattern_count: valid_count,
        }
    }

    /// Constructs from raw lines (for testing).
    #[cfg(test)]
    fn from_lines(lines: &[&str]) -> Self {
        let mut glob_patterns = Vec::new();
        let mut fingerprints = HashSet::new();

        for line in lines {
            parse_line(line, &mut glob_patterns, &mut fingerprints);
        }

        let mut builder = GlobSetBuilder::new();
        let mut valid_count = 0;
        for pattern in &glob_patterns {
            match Glob::new(pattern) {
                Ok(g) => {
                    builder.add(g);
                    valid_count += 1;
                }
                Err(e) => {
                    eprintln!("sks warn: invalid glob pattern '{pattern}': {e}");
                }
            }
        }

        let glob_set = builder.build().unwrap_or_else(|_| GlobSet::empty());

        IgnoreRules {
            globs: Arc::new(glob_set),
            fingerprints,
            path_pattern_count: valid_count,
        }
    }

    /// Returns `true` if the path matches any glob pattern.
    pub fn is_path_excluded(&self, path: &Path) -> bool {
        self.globs.is_match(path)
    }

    /// Returns `true` if the finding ID matches a fingerprint line.
    pub fn is_fingerprint_excluded(&self, id: &str) -> bool {
        self.fingerprints.contains(id)
    }

    /// Number of compiled path glob patterns.
    pub fn path_pattern_count(&self) -> usize {
        self.path_pattern_count
    }

    /// Number of fingerprint exclusions.
    pub fn fingerprint_count(&self) -> usize {
        self.fingerprints.len()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Reads a `.sentryignore` file and appends patterns/fingerprints to the
/// provided collections.
fn parse_file(path: &Path, glob_patterns: &mut Vec<String>, fingerprints: &mut HashSet<String>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sks warn: cannot read '{}': {e}", path.display());
            return;
        }
    };

    for line in content.lines() {
        parse_line(line, glob_patterns, fingerprints);
    }
}

/// Parses a single `.sentryignore` line.
fn parse_line(line: &str, glob_patterns: &mut Vec<String>, fingerprints: &mut HashSet<String>) {
    let trimmed = line.trim();

    // Skip blank lines and comments.
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }

    // Fingerprint line: `fingerprint:sha256:<hex>`
    if let Some(rest) = trimmed.strip_prefix("fingerprint:") {
        let fp = rest.trim().to_string();
        if !fp.is_empty() {
            fingerprints.insert(fp);
        }
        return;
    }

    // Everything else is a glob pattern.
    let mut pattern = expand_tilde(trimmed);

    // Trailing `/` → append `**` for recursive directory matching.
    if pattern.ends_with('/') {
        pattern.push_str("**");
    }

    glob_patterns.push(pattern);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn tmp(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sks_test_ignore_{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    // ── Unit tests ──────────────────────────────────────────────────────────

    #[test]
    fn empty_rules_exclude_nothing() {
        let rules = IgnoreRules::empty();
        assert!(!rules.is_path_excluded(Path::new("/home/user/.bashrc")));
        assert!(!rules.is_fingerprint_excluded("sha256:abc123"));
        assert_eq!(rules.path_pattern_count(), 0);
        assert_eq!(rules.fingerprint_count(), 0);
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let rules =
            IgnoreRules::from_lines(&["# This is a comment", "", "  ", "# Another comment"]);
        assert_eq!(rules.path_pattern_count(), 0);
        assert_eq!(rules.fingerprint_count(), 0);
    }

    #[test]
    fn parse_fingerprint_lines() {
        let rules = IgnoreRules::from_lines(&[
            "fingerprint:sha256:abc123def456",
            "fingerprint:sha256:789012345678",
        ]);
        assert_eq!(rules.fingerprint_count(), 2);
        assert!(rules.is_fingerprint_excluded("sha256:abc123def456"));
        assert!(rules.is_fingerprint_excluded("sha256:789012345678"));
        assert!(!rules.is_fingerprint_excluded("sha256:unknown"));
    }

    #[test]
    fn parse_glob_patterns() {
        let rules = IgnoreRules::from_lines(&["/tmp/test/*.env", "**/node_modules/**"]);
        assert_eq!(rules.path_pattern_count(), 2);
        assert_eq!(rules.fingerprint_count(), 0);
    }

    #[test]
    fn malformed_glob_warns_continues() {
        // `[invalid` is a malformed glob (unclosed bracket).
        let rules = IgnoreRules::from_lines(&["[invalid", "/tmp/valid/*.env"]);
        // The valid pattern should still be loaded.
        assert_eq!(rules.path_pattern_count(), 1);
        assert!(rules.is_path_excluded(Path::new("/tmp/valid/test.env")));
    }

    #[test]
    fn tilde_expansion_in_globs() {
        let home = home_dir();
        let rules = IgnoreRules::from_lines(&["~/.cache/**"]);
        assert_eq!(rules.path_pattern_count(), 1);
        let test_path = home.join(".cache/some/file.txt");
        assert!(
            rules.is_path_excluded(&test_path),
            "tilde-expanded glob should match: {}",
            test_path.display()
        );
    }

    #[test]
    fn path_excluded_exact_file() {
        let rules = IgnoreRules::from_lines(&["/tmp/secret.env"]);
        assert!(rules.is_path_excluded(Path::new("/tmp/secret.env")));
        assert!(!rules.is_path_excluded(Path::new("/tmp/other.env")));
    }

    #[test]
    fn path_excluded_directory_trailing_slash() {
        let home = home_dir();
        let rules = IgnoreRules::from_lines(&["~/.cache/"]);
        let inside = home.join(".cache/subdir/file.txt");
        assert!(
            rules.is_path_excluded(&inside),
            "trailing slash glob should match files underneath"
        );
    }

    #[test]
    fn path_excluded_double_star() {
        let rules = IgnoreRules::from_lines(&["**/node_modules/**"]);
        assert!(rules.is_path_excluded(Path::new("/home/user/project/node_modules/pkg/index.js")));
        assert!(rules.is_path_excluded(Path::new("/other/node_modules/file.env")));
        assert!(!rules.is_path_excluded(Path::new("/home/user/project/src/index.js")));
    }

    #[test]
    fn path_excluded_question_mark() {
        let rules = IgnoreRules::from_lines(&["/tmp/test?.env"]);
        assert!(rules.is_path_excluded(Path::new("/tmp/test1.env")));
        assert!(rules.is_path_excluded(Path::new("/tmp/testA.env")));
        assert!(!rules.is_path_excluded(Path::new("/tmp/test12.env")));
    }

    #[test]
    fn path_not_excluded_no_match() {
        let rules = IgnoreRules::from_lines(&["/tmp/excluded/**"]);
        assert!(!rules.is_path_excluded(Path::new("/home/user/.bashrc")));
        assert!(!rules.is_path_excluded(Path::new("/tmp/included/file.txt")));
    }

    #[test]
    fn fingerprint_excluded_match() {
        let rules = IgnoreRules::from_lines(&[
            "fingerprint:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]);
        assert!(rules.is_fingerprint_excluded(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn fingerprint_excluded_no_match() {
        let rules = IgnoreRules::from_lines(&["fingerprint:sha256:abc123"]);
        assert!(!rules.is_fingerprint_excluded("sha256:def456"));
        assert!(!rules.is_fingerprint_excluded("abc123"));
    }

    #[test]
    fn load_missing_files_returns_empty() {
        // Point HOME and CWD to dirs with no .sentryignore.
        let dir = tmp("load_missing");
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("xdg"));
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let rules = IgnoreRules::load();
        std::env::set_current_dir(&original_dir).unwrap();
        assert_eq!(rules.path_pattern_count(), 0);
        assert_eq!(rules.fingerprint_count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_merges_user_and_project() {
        let dir = tmp("load_merge");

        // User-level file.
        let user_dir = dir.join("xdg/sks");
        write_file(
            &user_dir.join(".sentryignore"),
            "/tmp/user-excluded/**\nfingerprint:sha256:user111\n",
        );

        // Project-level file (in CWD).
        let project_dir = dir.join("project");
        fs::create_dir_all(&project_dir).unwrap();
        write_file(
            &project_dir.join(".sentryignore"),
            "/tmp/project-excluded/**\nfingerprint:sha256:proj222\n",
        );

        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join("xdg"));

        // Change to project dir to pick up project .sentryignore.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&project_dir).unwrap();

        let rules = IgnoreRules::load();

        // Restore CWD.
        std::env::set_current_dir(&original_dir).unwrap();

        assert_eq!(rules.path_pattern_count(), 2);
        assert_eq!(rules.fingerprint_count(), 2);
        assert!(rules.is_path_excluded(Path::new("/tmp/user-excluded/file.txt")));
        assert!(rules.is_path_excluded(Path::new("/tmp/project-excluded/file.txt")));
        assert!(rules.is_fingerprint_excluded("sha256:user111"));
        assert!(rules.is_fingerprint_excluded("sha256:proj222"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_filtering_in_findings() {
        use crate::models::*;

        let rules = IgnoreRules::from_lines(&["fingerprint:sha256:abc123"]);

        let f1 = Finding {
            id: "sha256:abc123".to_string(),
            secret_type: SecretType::GenericApiKey,
            severity: Severity::High,
            confidence: 0.8,
            value: SecretValue::new("secret1".to_string()),
            location: SourceLocation {
                path: PathBuf::from("/test"),
                line: Some(1),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::Dotfile,
            },
            description: "test".to_string(),
            remediation: "fix".to_string(),
            matched_pattern: None,
        };

        let f2 = Finding {
            id: "sha256:def456".to_string(),
            secret_type: SecretType::GenericApiKey,
            severity: Severity::Medium,
            confidence: 0.6,
            value: SecretValue::new("secret2".to_string()),
            location: SourceLocation {
                path: PathBuf::from("/test2"),
                line: Some(2),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::Dotfile,
            },
            description: "test2".to_string(),
            remediation: "fix2".to_string(),
            matched_pattern: None,
        };

        let mut findings = vec![f1, f2];
        findings.retain(|f| !rules.is_fingerprint_excluded(&f.id));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "sha256:def456");
    }

    #[test]
    fn suppressed_count_accurate() {
        use crate::models::*;

        let rules = IgnoreRules::from_lines(&["fingerprint:sha256:aaa", "fingerprint:sha256:bbb"]);

        let make = |id: &str| Finding {
            id: id.to_string(),
            secret_type: SecretType::GenericApiKey,
            severity: Severity::Medium,
            confidence: 0.6,
            value: SecretValue::new("val".to_string()),
            location: SourceLocation {
                path: PathBuf::from("/test"),
                line: Some(1),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::Dotfile,
            },
            description: "d".to_string(),
            remediation: "r".to_string(),
            matched_pattern: None,
        };

        let mut findings = vec![make("sha256:aaa"), make("sha256:bbb"), make("sha256:ccc")];
        let pre_suppress = findings.len();
        findings.retain(|f| !rules.is_fingerprint_excluded(&f.id));
        let suppressed = pre_suppress - findings.len();

        assert_eq!(suppressed, 2);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn dotfile_collector_respects_ignore() {
        let dir = tmp("dotfile_ignore");
        let dotfile = dir.join(".bashrc");
        write_file(&dotfile, "export SECRET=leaked\n");

        let rules = IgnoreRules::from_lines(&[&format!("{}/.bashrc", dir.display())]);
        assert!(rules.is_path_excluded(&dotfile));
    }

    #[test]
    fn env_collector_respects_ignore() {
        let dir = tmp("env_ignore");
        let env_file = dir.join("project/.env");
        write_file(&env_file, "SECRET=leaked\n");

        let rules = IgnoreRules::from_lines(&[&format!("{}/project/", dir.display())]);
        assert!(rules.is_path_excluded(&env_file));
    }

    #[test]
    fn shell_history_respects_ignore() {
        let home = home_dir();
        let rules = IgnoreRules::from_lines(&["~/.bash_history"]);
        let path = home.join(".bash_history");
        assert!(
            rules.is_path_excluded(&path),
            "should exclude tilde-expanded path: {}",
            path.display()
        );
    }
}
