//! Filesystem collectors: dotfiles at fixed paths and `.env` file discovery.
//!
//! # Sub-collectors
//!
//! - [`DotfileCollector`] — reads a fixed list of well-known paths from
//!   `config.scan.dotfile_targets` (e.g. `~/.bashrc`, `~/.zshrc`).
//! - [`EnvFileCollector`] — recursively walks `config.scan.env_search_roots`
//!   and yields every file whose basename matches a `.env*` pattern.
//!
//! Both produce [`ContentItem`] values with a ±2-line context window and
//! delegate detection entirely to the engine — they never filter content.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Lines longer than this are truncated to prevent memory issues from minified
/// files or binary blobs accidentally named `.env`.
const MAX_LINE_BYTES: usize = 4096;

/// Number of bytes inspected at the start of a file for binary detection.
const BINARY_CHECK_BYTES: usize = 512;

/// Lines of context captured before and after each matched line.
const CONTEXT_LINES: usize = 2;

/// Directory basenames that are never recursed into during `EnvFileCollector`
/// traversal.
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "vendor",
    "venv",
    "__pycache__",
    "target",
    "build",
    "dist",
];

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Expands a leading `~` or `~/` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" {
        home_dir()
    } else if let Some(rest) = s.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        path.to_path_buf()
    }
}

/// Returns `true` if the first [`BINARY_CHECK_BYTES`] of the file contain a
/// null byte — the standard heuristic for detecting binary files.
fn is_binary(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; BINARY_CHECK_BYTES];
    let n = file.read(&mut buf).unwrap_or(0);
    buf[..n].contains(&0u8)
}

/// Reads a file as UTF-8, falling back to Latin-1 (ISO 8859-1) on failure.
///
/// Latin-1 maps every byte value `0x00–0xFF` directly to the corresponding
/// Unicode code point, so it can decode any byte sequence without error.
fn read_content(path: &Path) -> Result<String, SksError> {
    let bytes = fs::read(path)?;
    match String::from_utf8(bytes.clone()) {
        Ok(s) => Ok(s),
        Err(_) => {
            eprintln!(
                "sks warn: '{}' is not valid UTF-8; reading as Latin-1",
                path.display()
            );
            Ok(bytes.iter().map(|&b| b as char).collect())
        }
    }
}

/// Truncates `s` to at most [`MAX_LINE_BYTES`] bytes (at a char boundary),
/// appending `"  [truncated]"` so readers know the line is incomplete.
fn truncate_line(s: &str) -> String {
    if s.len() <= MAX_LINE_BYTES {
        return s.to_string();
    }
    let mut end = MAX_LINE_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}  [truncated]", &s[..end])
}

/// Converts file text into [`ContentItem`]s with a ±2-line context window.
fn content_to_items(path: &Path, source_type: SourceType, text: &str) -> Vec<ContentItem> {
    let lines: Vec<String> = text.lines().map(truncate_line).collect();
    let n = lines.len();
    lines
        .iter()
        .enumerate()
        .map(|(i, line)| ContentItem {
            path: path.to_path_buf(),
            line_number: i + 1,
            line: line.clone(),
            context_before: lines[i.saturating_sub(CONTEXT_LINES)..i].to_vec(),
            context_after: lines[(i + 1).min(n)..((i + 1 + CONTEXT_LINES).min(n))].to_vec(),
            source_type: source_type.clone(),
        })
        .collect()
}

/// Core file-reading logic shared by both collectors.
///
/// Returns:
/// - `Ok(Some(items))` — file was read successfully.
/// - `Ok(None)` — file should be silently skipped (missing, binary, oversized,
///   permission denied, or unreadable).
/// - `Err(_)` — unexpected I/O error that should propagate.
fn try_read_file(
    path: &Path,
    source_type: SourceType,
    max_file_size: u64,
) -> Result<Option<Vec<ContentItem>>, SksError> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Missing files are skipped silently (not an error).
            return Ok(None);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "sks warn: permission denied reading '{}'; skipping",
                path.display()
            );
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };

    if !meta.is_file() {
        return Ok(None);
    }

    if meta.len() > max_file_size {
        eprintln!(
            "sks warn: '{}' ({} bytes) exceeds max_file_size; skipping",
            path.display(),
            meta.len()
        );
        return Ok(None);
    }

    if is_binary(path) {
        return Ok(None);
    }

    match read_content(path) {
        Ok(text) => Ok(Some(content_to_items(path, source_type, &text))),
        Err(e) => {
            eprintln!(
                "sks warn: could not read '{}': {}; skipping",
                path.display(),
                e
            );
            Ok(None)
        }
    }
}

/// Returns `true` if the file basename matches a recognised `.env` pattern:
/// - exactly `.env`
/// - `.env.<something>` (any suffix)
/// - `<something>.env` (any prefix, e.g. `app.env`)
pub(crate) fn is_env_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name == ".env" || name.starts_with(".env.") || (name.ends_with(".env") && name.len() > 4)
}

// ---------------------------------------------------------------------------
// DotfileCollector
// ---------------------------------------------------------------------------

/// Scans a fixed list of dotfile paths from `config.scan.dotfile_targets`.
///
/// - Tilde expansion is applied to every path.
/// - Missing files are skipped silently (not an error).
/// - Permission-denied files produce a warning on stderr and are skipped.
/// - Files larger than `config.scan.max_file_size` are skipped with a warning.
pub struct DotfileCollector;

impl Collector for DotfileCollector {
    fn name(&self) -> &str {
        "Dotfiles"
    }

    fn source_type(&self) -> SourceType {
        SourceType::Dotfile
    }

    fn is_available(&self) -> bool {
        true
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let mut items = Vec::new();
        for raw in &config.dotfile_targets {
            let path = expand_tilde(raw);
            if let Some(found) = try_read_file(&path, SourceType::Dotfile, config.max_file_size)? {
                items.extend(found);
            }
        }
        Ok(items)
    }
}

// ---------------------------------------------------------------------------
// EnvFileCollector
// ---------------------------------------------------------------------------

/// Recursively discovers `.env*` files under `config.scan.env_search_roots`.
///
/// Directory exclusions applied in order:
/// 1. Hardcoded names: `node_modules`, `.git`, `vendor`, `venv`,
///    `__pycache__`, `target`, `build`, `dist`.
/// 2. `config.scan.exclude_paths` — path-prefix exclusion.
/// 3. `config.scan.exclude_patterns` — regex exclusion against the full path.
///
/// Symlink following and max depth are taken from `ScanConfig`.
pub struct EnvFileCollector;

impl Collector for EnvFileCollector {
    fn name(&self) -> &str {
        "Env Files"
    }

    fn source_type(&self) -> SourceType {
        SourceType::EnvFile
    }

    fn is_available(&self) -> bool {
        true
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let mut items = Vec::new();

        // Compile exclude patterns once, before the root loop.
        let exclude_regexes: Vec<regex::Regex> = config
            .exclude_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        for root in &config.env_search_roots {
            let root = expand_tilde(root);
            if !root.exists() {
                continue;
            }

            let walker = WalkDir::new(&root)
                .max_depth(config.max_depth)
                .follow_links(config.follow_symlinks)
                .into_iter()
                .filter_entry(|e| {
                    // Always enter the root itself.
                    if e.depth() == 0 {
                        return true;
                    }
                    let path = e.path();
                    // Prune hardcoded excluded directory names.
                    if e.file_type().is_dir() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            if EXCLUDED_DIRS.contains(&name) {
                                return false;
                            }
                        }
                    }
                    // Prune user-configured excluded paths.
                    if config.exclude_paths.iter().any(|ex| path.starts_with(ex)) {
                        return false;
                    }
                    true
                });

            for entry in walker {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("sks warn: walk error: {e}");
                        continue;
                    }
                };

                if entry.file_type().is_dir() {
                    continue;
                }

                let path = entry.path();

                // Apply regex exclude patterns against the full path string.
                let path_str = path.to_string_lossy();
                if exclude_regexes.iter().any(|re| re.is_match(&path_str)) {
                    continue;
                }

                if !is_env_filename(path) {
                    continue;
                }

                if let Some(found) = try_read_file(path, SourceType::EnvFile, config.max_file_size)?
                {
                    items.extend(found);
                }
            }
        }

        Ok(items)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Creates a fresh, empty temp directory for one test, removing any
    /// leftover directory from a previous run first.
    fn tmp(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sks_test_fs_{suffix}"));
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

    fn scan_config_for(dotfile_targets: Vec<PathBuf>, env_roots: Vec<PathBuf>) -> ScanConfig {
        ScanConfig {
            clipboard: false,
            browser: false,
            follow_symlinks: false,
            max_file_size: 1024 * 1024,
            max_depth: 10,
            dotfile_targets,
            env_search_roots: env_roots,
            extra_paths: vec![],
            exclude_paths: vec![],
            exclude_patterns: vec![],
        }
    }

    // ── Unit tests: pure helpers ──────────────────────────────────────────────

    #[test]
    fn expand_tilde_no_tilde_is_unchanged() {
        let p = PathBuf::from("/absolute/path");
        assert_eq!(expand_tilde(&p), p);
    }

    #[test]
    fn expand_tilde_replaces_tilde_slash() {
        let home = home_dir();
        let result = expand_tilde(Path::new("~/foo/bar"));
        assert_eq!(result, home.join("foo/bar"));
    }

    #[test]
    fn expand_tilde_bare_tilde() {
        assert_eq!(expand_tilde(Path::new("~")), home_dir());
    }

    #[test]
    fn truncate_line_short_string_unchanged() {
        let s = "hello world";
        assert_eq!(truncate_line(s), s);
    }

    #[test]
    fn truncate_line_long_string_is_truncated() {
        let s = "a".repeat(MAX_LINE_BYTES + 100);
        let result = truncate_line(&s);
        assert!(result.len() <= MAX_LINE_BYTES + "[truncated]".len() + 2);
        assert!(result.ends_with("[truncated]"));
    }

    #[test]
    fn is_env_filename_exact_dotenv() {
        assert!(is_env_filename(Path::new(".env")));
        assert!(is_env_filename(Path::new("/project/.env")));
    }

    #[test]
    fn is_env_filename_dotenv_with_suffix() {
        assert!(is_env_filename(Path::new(".env.local")));
        assert!(is_env_filename(Path::new(".env.production")));
        assert!(is_env_filename(Path::new(".env.staging")));
        assert!(is_env_filename(Path::new(".env.test")));
    }

    #[test]
    fn is_env_filename_dotenv_prefix() {
        // "app.env" should match: ends with ".env" and len > 4
        assert!(is_env_filename(Path::new("app.env")));
    }

    #[test]
    fn is_env_filename_non_env_files_rejected() {
        assert!(!is_env_filename(Path::new("main.rs")));
        assert!(!is_env_filename(Path::new(".bashrc")));
        assert!(!is_env_filename(Path::new("env.txt")));
        // ".env" is exactly 4 chars; "env" (without dot) should not match
        assert!(!is_env_filename(Path::new("env")));
    }

    #[test]
    fn content_to_items_line_count_matches() {
        let text = "line1\nline2\nline3\n";
        let items = content_to_items(Path::new("/tmp/x"), SourceType::EnvFile, text);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].line_number, 1);
        assert_eq!(items[2].line_number, 3);
    }

    #[test]
    fn content_to_items_context_window_first_line() {
        let text = "A\nB\nC\nD\nE\n";
        let items = content_to_items(Path::new("/tmp/x"), SourceType::EnvFile, text);
        // First line: no before-context, 2-line after-context.
        assert!(items[0].context_before.is_empty());
        assert_eq!(items[0].context_after, vec!["B", "C"]);
    }

    #[test]
    fn content_to_items_context_window_middle_line() {
        let text = "A\nB\nC\nD\nE\n";
        let items = content_to_items(Path::new("/tmp/x"), SourceType::EnvFile, text);
        // Third line (C, index 2): 2 before, 2 after.
        assert_eq!(items[2].context_before, vec!["A", "B"]);
        assert_eq!(items[2].context_after, vec!["D", "E"]);
    }

    #[test]
    fn content_to_items_context_window_last_line() {
        let text = "A\nB\nC\nD\nE\n";
        let items = content_to_items(Path::new("/tmp/x"), SourceType::EnvFile, text);
        // Last line: 2-line before-context, no after-context.
        assert_eq!(items[4].context_before, vec!["C", "D"]);
        assert!(items[4].context_after.is_empty());
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[test]
    fn dotfile_collector_reads_configured_path() {
        let dir = tmp("dotfile_reads");
        let dotfile = dir.join(".bashrc");
        write_file(&dotfile, "export PATH=/usr/bin\nexport SECRET=hello\n");

        let config = scan_config_for(vec![dotfile.clone()], vec![]);
        let items = DotfileCollector.collect(&config).unwrap();

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "export PATH=/usr/bin");
        assert_eq!(items[1].line, "export SECRET=hello");
        assert_eq!(items[0].source_type, SourceType::Dotfile);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotfile_collector_silently_skips_missing_file() {
        let config = scan_config_for(vec![PathBuf::from("/no/such/file/.bashrc")], vec![]);
        let items = DotfileCollector.collect(&config).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn dotfile_collector_respects_file_size_limit() {
        let dir = tmp("dotfile_size");
        let big = dir.join("big.env");
        // Write 5 bytes of content but set max_file_size to 4.
        write_file(&big, "hello");

        let mut config = scan_config_for(vec![big], vec![]);
        config.max_file_size = 4;
        let items = DotfileCollector.collect(&config).unwrap();
        assert!(items.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotfile_collector_skips_binary_file() {
        let dir = tmp("dotfile_binary");
        let bin = dir.join("binary_file");
        // Write content with a null byte.
        let mut f = File::create(&bin).unwrap();
        f.write_all(b"valid text\x00binary garbage").unwrap();

        let config = scan_config_for(vec![bin], vec![]);
        let items = DotfileCollector.collect(&config).unwrap();
        assert!(items.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_discovers_dotenv_files() {
        let dir = tmp("env_discover");
        write_file(&dir.join(".env"), "DB_URL=postgres://user:pass@host/db\n");
        write_file(&dir.join("subdir/.env.local"), "SECRET=abc123\n");

        let config = scan_config_for(vec![], vec![dir.clone()]);
        let mut items = EnvFileCollector.collect(&config).unwrap();
        items.sort_by(|a, b| a.path.cmp(&b.path));

        // Should find both files.
        let paths: Vec<_> = items.iter().map(|i| i.path.clone()).collect();
        let unique_paths: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(unique_paths.len(), 2);
        assert_eq!(items[0].source_type, SourceType::EnvFile);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_does_not_traverse_excluded_dirs() {
        let dir = tmp("env_excluded");
        // Place a .env inside node_modules — should be skipped.
        write_file(&dir.join("node_modules/.env"), "SHOULD_NOT_FIND=1\n");
        // Place a .env at the root — should be found.
        write_file(&dir.join(".env"), "SHOULD_FIND=1\n");

        let config = scan_config_for(vec![], vec![dir.clone()]);
        let items = EnvFileCollector.collect(&config).unwrap();

        assert_eq!(items.len(), 1, "should find exactly 1 item (root .env)");
        assert_eq!(items[0].line, "SHOULD_FIND=1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_skips_non_env_files() {
        let dir = tmp("env_non_env");
        write_file(&dir.join("README.md"), "# project\n");
        write_file(&dir.join("main.rs"), "fn main() {}\n");
        write_file(&dir.join(".env"), "KEY=value\n");

        let config = scan_config_for(vec![], vec![dir.clone()]);
        let items = EnvFileCollector.collect(&config).unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "KEY=value");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_respects_exclude_paths() {
        let dir = tmp("env_excl_paths");
        let secret_dir = dir.join("secrets");
        write_file(&secret_dir.join(".env"), "EXCLUDE_ME=1\n");
        write_file(&dir.join(".env"), "INCLUDE_ME=1\n");

        let mut config = scan_config_for(vec![], vec![dir.clone()]);
        config.exclude_paths = vec![secret_dir];

        let items = EnvFileCollector.collect(&config).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "INCLUDE_ME=1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_respects_exclude_patterns() {
        let dir = tmp("env_excl_patterns");
        write_file(&dir.join(".env.test"), "TEST_KEY=val\n");
        write_file(&dir.join(".env"), "REAL_KEY=val\n");

        let mut config = scan_config_for(vec![], vec![dir.clone()]);
        // Exclude any path containing ".env.test"
        config.exclude_patterns = vec![r"\.env\.test$".to_string()];

        let items = EnvFileCollector.collect(&config).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "REAL_KEY=val");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_file_collector_skips_binary_files() {
        let dir = tmp("env_binary");
        // Write a file named .env but with binary content.
        let bin = dir.join(".env");
        let mut f = File::create(&bin).unwrap();
        f.write_all(b"KEY=\x00binary\xff").unwrap();
        // Also a clean file.
        write_file(&dir.join(".env.local"), "CLEAN=yes\n");

        let config = scan_config_for(vec![], vec![dir.clone()]);
        let items = EnvFileCollector.collect(&config).unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "CLEAN=yes");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Integration test: populate a temp tree with dotfiles and .env files
    /// containing known secrets; verify they are all discovered and yielded.
    #[test]
    fn integration_dotfiles_and_env_files_all_discovered() {
        let dir = tmp("integration");

        // Dotfile with a secret.
        let bashrc = dir.join(".bashrc");
        write_file(&bashrc, "export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n");

        // .env in a project subdirectory.
        let project_env = dir.join("myproject/.env");
        write_file(
            &project_env,
            "DATABASE_URL=postgres://user:s3cr3t@host/db\n",
        );

        // .env.production two levels deep.
        let prod_env = dir.join("myproject/config/.env.production");
        write_file(&prod_env, "STRIPE_KEY=sk_live_abc123xyz456def789ghi\n");

        // A file that should NOT be found.
        write_file(&dir.join("myproject/README.md"), "# nothing secret here\n");

        let config = scan_config_for(vec![bashrc], vec![dir.join("myproject")]);

        let dotfile_items = DotfileCollector.collect(&config).unwrap();
        let env_items = EnvFileCollector.collect(&config).unwrap();

        assert_eq!(dotfile_items.len(), 1);
        assert!(dotfile_items[0].line.contains("AKIAIOSFODNN7EXAMPLE"));

        // Should find both .env files (2 lines total).
        assert_eq!(env_items.len(), 2);
        let lines: Vec<&str> = env_items.iter().map(|i| i.line.as_str()).collect();
        assert!(lines
            .iter()
            .any(|l| l.contains("DATABASE_URL") || l.contains("STRIPE_KEY")));

        let _ = fs::remove_dir_all(&dir);
    }
}
