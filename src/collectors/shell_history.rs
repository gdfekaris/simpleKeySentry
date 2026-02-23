//! Shell history collectors: Bash, Zsh, and Fish.
//!
//! # Sub-collectors
//!
//! - [`BashHistoryCollector`] — reads `~/.bash_history` (one command per line,
//!   optional `#timestamp` lines when `HISTTIMEFORMAT` is set).
//! - [`ZshHistoryCollector`] — reads `~/.zsh_history` (strips `: epoch:elapsed;`
//!   timestamp prefix, rejoins multi-line commands split with trailing `\`).
//! - [`FishHistoryCollector`] — reads `~/.local/share/fish/fish_history`
//!   (YAML-like format, extracts `- cmd:` lines with multi-line continuations).
//!
//! All three produce [`ContentItem`] values with a ±2-command context window and
//! delegate detection entirely to the engine — they never filter content.

use std::fs;
use std::path::{Path, PathBuf};

use crate::collectors::filesystem::{expand_tilde, is_binary, read_content, truncate_line};
use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

/// Lines of context captured before and after each command.
const CONTEXT_COMMANDS: usize = 2;

// ---------------------------------------------------------------------------
// Shared helper: build ContentItems from parsed commands
// ---------------------------------------------------------------------------

/// Converts parsed `(original_line_number, command_text)` pairs into
/// [`ContentItem`]s with a ±2-command context window.
///
/// Context comes from neighbouring *commands* (not raw file lines), so that
/// timestamp lines, metadata, and continuation markers are excluded.
fn commands_to_items(path: &Path, commands: &[(usize, String)]) -> Vec<ContentItem> {
    let n = commands.len();
    commands
        .iter()
        .enumerate()
        .map(|(i, (line_number, cmd))| {
            let line = truncate_line(cmd);

            let context_before: Vec<String> = commands[i.saturating_sub(CONTEXT_COMMANDS)..i]
                .iter()
                .map(|(_, c)| truncate_line(c))
                .collect();

            let context_after: Vec<String> = commands
                [(i + 1).min(n)..((i + 1 + CONTEXT_COMMANDS).min(n))]
                .iter()
                .map(|(_, c)| truncate_line(c))
                .collect();

            ContentItem {
                path: path.to_path_buf(),
                line_number: *line_number,
                line,
                context_before,
                context_after,
                source_type: SourceType::ShellHistory,
            }
        })
        .collect()
}

/// Reads a history file with the same safety checks as the filesystem
/// collectors: missing/permission-denied files are silently skipped,
/// binary files are skipped, and oversized files are skipped with a warning.
///
/// Returns `Ok(Some(text))` on success, `Ok(None)` when the file should be
/// skipped, or `Err` on unexpected I/O errors.
fn try_read_history(path: &Path, max_file_size: u64) -> Result<Option<String>, SksError> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
        Ok(text) => Ok(Some(text)),
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

// ---------------------------------------------------------------------------
// Bash history parser
// ---------------------------------------------------------------------------

/// Parses bash history text into `(line_number, command)` pairs.
///
/// Bash history is one command per line. When `HISTTIMEFORMAT` is set, lines
/// starting with `#` followed by digits are timestamp markers and are skipped.
fn parse_bash_history(text: &str) -> Vec<(usize, String)> {
    let mut commands = Vec::new();
    let mut has_timestamps = false;

    // Detect whether timestamps are present: look for lines matching `#\d+`.
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('#') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                has_timestamps = true;
                break;
            }
        }
    }

    for (i, line) in text.lines().enumerate() {
        let line_number = i + 1; // 1-indexed

        if has_timestamps {
            if let Some(rest) = line.strip_prefix('#') {
                if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                    continue; // skip timestamp line
                }
            }
        }

        if !line.is_empty() {
            commands.push((line_number, line.to_string()));
        }
    }

    commands
}

// ---------------------------------------------------------------------------
// Zsh history parser
// ---------------------------------------------------------------------------

/// Parses zsh history text into `(starting_line_number, joined_command)` pairs.
///
/// Handles two zsh-specific features:
/// 1. Timestamp prefix: `: 1234567890:0;command` — the command is everything
///    after the first `;`.
/// 2. Multi-line continuation: a trailing `\` means the command continues on
///    the next line. The `\` is removed and lines are joined with `\n`.
fn parse_zsh_history(text: &str) -> Vec<(usize, String)> {
    let mut commands = Vec::new();
    let mut continuation: Option<(usize, String)> = None;

    for (i, raw_line) in text.lines().enumerate() {
        let line_number = i + 1;

        // Strip timestamp prefix: `: <digits>:<digits>;`
        let line = strip_zsh_timestamp(raw_line);

        if let Some((start, ref mut acc)) = continuation {
            // We're accumulating a multi-line command.
            if let Some(stripped) = line.strip_suffix('\\') {
                acc.push('\n');
                acc.push_str(stripped);
            } else {
                acc.push('\n');
                acc.push_str(line);
                let finished = (start, acc.clone());
                commands.push(finished);
                continuation = None;
            }
        } else if let Some(stripped) = line.strip_suffix('\\') {
            // Start of a multi-line command.
            continuation = Some((line_number, stripped.to_string()));
        } else if !line.is_empty() {
            commands.push((line_number, line.to_string()));
        }
    }

    // If the file ends mid-continuation, emit what we have.
    if let Some((start, acc)) = continuation {
        if !acc.is_empty() {
            commands.push((start, acc));
        }
    }

    commands
}

/// Strips the zsh extended-history timestamp prefix if present.
///
/// Format: `: <epoch>:<elapsed>;` — returns everything after the `;`.
/// If no prefix is found, returns the original line.
fn strip_zsh_timestamp(line: &str) -> &str {
    if !line.starts_with(": ") {
        return line;
    }
    // Find the semicolon that ends the timestamp portion.
    if let Some(semi_pos) = line.find(';') {
        // Validate that characters between ": " and ";" look like "digits:digits"
        let middle = &line[2..semi_pos];
        if let Some(colon_pos) = middle.find(':') {
            let epoch = &middle[..colon_pos];
            let elapsed = &middle[colon_pos + 1..];
            if !epoch.is_empty()
                && epoch.chars().all(|c| c.is_ascii_digit())
                && !elapsed.is_empty()
                && elapsed.chars().all(|c| c.is_ascii_digit())
            {
                return &line[semi_pos + 1..];
            }
        }
    }
    line
}

// ---------------------------------------------------------------------------
// Fish history parser
// ---------------------------------------------------------------------------

/// Parses fish history text into `(starting_line_number, command)` pairs.
///
/// Fish history is YAML-like:
/// ```text
/// - cmd: some command
///   when: 1234567890
///   paths:
///     - /some/path
/// - cmd: another command
/// ```
///
/// Only `- cmd: ` lines are extracted. Continuation lines (indented, not
/// starting with `- ` or known metadata keys like `  when:` / `  paths:`)
/// are appended to the current command.
fn parse_fish_history(text: &str) -> Vec<(usize, String)> {
    let mut commands: Vec<(usize, String)> = Vec::new();
    let mut current_cmd: Option<(usize, String)> = None;
    let mut in_metadata = false;

    for (i, line) in text.lines().enumerate() {
        let line_number = i + 1;

        if let Some(rest) = line.strip_prefix("- cmd: ") {
            // Finalize previous command.
            if let Some(cmd) = current_cmd.take() {
                commands.push(cmd);
            }
            current_cmd = Some((line_number, rest.to_string()));
            in_metadata = false;
        } else if line.starts_with("  when:") || line.starts_with("  paths:") {
            // Known metadata — skip, but mark that we're in metadata section.
            in_metadata = true;
        } else if line.starts_with("    - ") {
            // Sub-items under `paths:` — skip.
            continue;
        } else if line.starts_with("- ") {
            // Some other top-level entry — finalize current command.
            if let Some(cmd) = current_cmd.take() {
                commands.push(cmd);
            }
            in_metadata = false;
        } else if !in_metadata && line.starts_with("  ") && current_cmd.is_some() {
            // Continuation of a multi-line command (indented, not metadata).
            if let Some((_, ref mut cmd)) = current_cmd {
                cmd.push('\n');
                cmd.push_str(line.trim_start());
            }
        }
    }

    // Finalize last command.
    if let Some(cmd) = current_cmd.take() {
        commands.push(cmd);
    }

    commands
}

// ---------------------------------------------------------------------------
// BashHistoryCollector
// ---------------------------------------------------------------------------

/// Scans `~/.bash_history` for leaked credentials.
pub struct BashHistoryCollector;

impl BashHistoryCollector {
    fn history_path() -> PathBuf {
        expand_tilde(Path::new("~/.bash_history"))
    }
}

impl Collector for BashHistoryCollector {
    fn name(&self) -> &str {
        "Bash History"
    }

    fn source_type(&self) -> SourceType {
        SourceType::ShellHistory
    }

    fn is_available(&self) -> bool {
        Self::history_path().exists()
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let path = Self::history_path();
        let text = match try_read_history(&path, config.max_file_size)? {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let commands = parse_bash_history(&text);
        Ok(commands_to_items(&path, &commands))
    }
}

// ---------------------------------------------------------------------------
// ZshHistoryCollector
// ---------------------------------------------------------------------------

/// Scans `~/.zsh_history` for leaked credentials.
pub struct ZshHistoryCollector;

impl ZshHistoryCollector {
    fn history_path() -> PathBuf {
        expand_tilde(Path::new("~/.zsh_history"))
    }
}

impl Collector for ZshHistoryCollector {
    fn name(&self) -> &str {
        "Zsh History"
    }

    fn source_type(&self) -> SourceType {
        SourceType::ShellHistory
    }

    fn is_available(&self) -> bool {
        Self::history_path().exists()
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let path = Self::history_path();
        let text = match try_read_history(&path, config.max_file_size)? {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let commands = parse_zsh_history(&text);
        Ok(commands_to_items(&path, &commands))
    }
}

// ---------------------------------------------------------------------------
// FishHistoryCollector
// ---------------------------------------------------------------------------

/// Scans `~/.local/share/fish/fish_history` for leaked credentials.
pub struct FishHistoryCollector;

impl FishHistoryCollector {
    fn history_path() -> PathBuf {
        expand_tilde(Path::new("~/.local/share/fish/fish_history"))
    }
}

impl Collector for FishHistoryCollector {
    fn name(&self) -> &str {
        "Fish History"
    }

    fn source_type(&self) -> SourceType {
        SourceType::ShellHistory
    }

    fn is_available(&self) -> bool {
        Self::history_path().exists()
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let path = Self::history_path();
        let text = match try_read_history(&path, config.max_file_size)? {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let commands = parse_fish_history(&text);
        Ok(commands_to_items(&path, &commands))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn tmp(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sks_test_sh_{suffix}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    fn scan_config() -> ScanConfig {
        ScanConfig {
            clipboard: false,
            browser: false,
            follow_symlinks: false,
            max_file_size: 1024 * 1024,
            max_depth: 10,
            dotfile_targets: vec![],
            env_search_roots: vec![],
            extra_paths: vec![],
            exclude_paths: vec![],
            exclude_patterns: vec![],
        }
    }

    // ── Bash parser unit tests ──────────────────────────────────────────────

    #[test]
    fn parse_bash_simple() {
        let text = "ls -la\ncd /tmp\necho hello\n";
        let cmds = parse_bash_history(text);
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0], (1, "ls -la".to_string()));
        assert_eq!(cmds[1], (2, "cd /tmp".to_string()));
        assert_eq!(cmds[2], (3, "echo hello".to_string()));
    }

    #[test]
    fn parse_bash_with_timestamps() {
        let text = "#1700000000\nls -la\n#1700000001\ncurl -H 'Authorization: Bearer tok'\n";
        let cmds = parse_bash_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], (2, "ls -la".to_string()));
        assert_eq!(
            cmds[1],
            (4, "curl -H 'Authorization: Bearer tok'".to_string())
        );
    }

    #[test]
    fn parse_bash_empty() {
        let cmds = parse_bash_history("");
        assert!(cmds.is_empty());
    }

    #[test]
    fn parse_bash_comment_not_timestamp() {
        // Lines starting with # that aren't pure digits should be kept as commands.
        let text = "#1700000000\nls\n# this is a comment\n";
        let cmds = parse_bash_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], (2, "ls".to_string()));
        assert_eq!(cmds[1], (3, "# this is a comment".to_string()));
    }

    // ── Zsh parser unit tests ───────────────────────────────────────────────

    #[test]
    fn parse_zsh_with_timestamps() {
        let text = ": 1700000000:0;ls -la\n: 1700000001:0;cd /tmp\n";
        let cmds = parse_zsh_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], (1, "ls -la".to_string()));
        assert_eq!(cmds[1], (2, "cd /tmp".to_string()));
    }

    #[test]
    fn parse_zsh_no_timestamps() {
        let text = "ls -la\ncd /tmp\n";
        let cmds = parse_zsh_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], (1, "ls -la".to_string()));
        assert_eq!(cmds[1], (2, "cd /tmp".to_string()));
    }

    #[test]
    fn parse_zsh_multiline_continuation() {
        let text = ": 1700000000:0;echo hello \\\n: 1700000001:0;world\n";
        let cmds = parse_zsh_history(text);
        // The first line ends with \, so it joins with the next.
        // After stripping timestamp from line 1: "echo hello \"
        // After stripping timestamp from line 2: "world"
        // But wait — zsh continuation applies to the raw lines, not timestamp-stripped.
        // Actually, zsh history records multi-line commands with the timestamp
        // only on the first line. Continuation lines are NOT prefixed.
        // Let me reconsider — the test needs to match actual zsh format.
        // In practice, multi-line zsh history looks like:
        // `: 1234:0;echo \`
        // `world`
        // (no timestamp on continuation lines)
        // This test uses timestamps on both lines, but that's fine — the parser
        // strips timestamps from each line independently, then handles continuation.
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].0, 1);
        assert!(cmds[0].1.contains("echo hello "));
        assert!(cmds[0].1.contains("world"));
    }

    #[test]
    fn parse_zsh_multiline_no_timestamps() {
        let text = "echo hello \\\nworld\n";
        let cmds = parse_zsh_history(text);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0], (1, "echo hello \nworld".to_string()));
    }

    #[test]
    fn parse_zsh_empty() {
        let cmds = parse_zsh_history("");
        assert!(cmds.is_empty());
    }

    // ── Fish parser unit tests ──────────────────────────────────────────────

    #[test]
    fn parse_fish_simple() {
        let text = "- cmd: ls -la\n  when: 1700000000\n- cmd: cd /tmp\n  when: 1700000001\n";
        let cmds = parse_fish_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], (1, "ls -la".to_string()));
        assert_eq!(cmds[1], (3, "cd /tmp".to_string()));
    }

    #[test]
    fn parse_fish_skips_metadata() {
        let text = concat!(
            "- cmd: echo hello\n",
            "  when: 1700000000\n",
            "  paths:\n",
            "    - /some/path\n",
            "- cmd: echo world\n",
        );
        let cmds = parse_fish_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].1, "echo hello");
        assert_eq!(cmds[1].1, "echo world");
    }

    #[test]
    fn parse_fish_multiline() {
        let text = concat!(
            "- cmd: echo hello\n",
            "  world\n",
            "  when: 1700000000\n",
            "- cmd: ls\n",
        );
        let cmds = parse_fish_history(text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].1, "echo hello\nworld");
        assert_eq!(cmds[1].1, "ls");
    }

    #[test]
    fn parse_fish_empty() {
        let cmds = parse_fish_history("");
        assert!(cmds.is_empty());
    }

    // ── commands_to_items unit tests ────────────────────────────────────────

    #[test]
    fn context_window_correct() {
        let commands: Vec<(usize, String)> = vec![
            (1, "cmd1".into()),
            (2, "cmd2".into()),
            (3, "cmd3".into()),
            (4, "cmd4".into()),
            (5, "cmd5".into()),
        ];
        let items = commands_to_items(Path::new("/tmp/history"), &commands);
        assert_eq!(items.len(), 5);

        // First item: no before, 2 after
        assert!(items[0].context_before.is_empty());
        assert_eq!(items[0].context_after, vec!["cmd2", "cmd3"]);

        // Middle item (cmd3): 2 before, 2 after
        assert_eq!(items[2].context_before, vec!["cmd1", "cmd2"]);
        assert_eq!(items[2].context_after, vec!["cmd4", "cmd5"]);

        // Last item: 2 before, no after
        assert_eq!(items[4].context_before, vec!["cmd3", "cmd4"]);
        assert!(items[4].context_after.is_empty());
    }

    #[test]
    fn context_window_single_command() {
        let commands = vec![(1, "only_cmd".into())];
        let items = commands_to_items(Path::new("/tmp/history"), &commands);
        assert_eq!(items.len(), 1);
        assert!(items[0].context_before.is_empty());
        assert!(items[0].context_after.is_empty());
    }

    #[test]
    fn commands_to_items_preserves_line_numbers() {
        // Line numbers from the original file, not sequential indices.
        let commands = vec![
            (2, "cmd_at_line_2".into()),
            (4, "cmd_at_line_4".into()),
            (6, "cmd_at_line_6".into()),
        ];
        let items = commands_to_items(Path::new("/tmp/history"), &commands);
        assert_eq!(items[0].line_number, 2);
        assert_eq!(items[1].line_number, 4);
        assert_eq!(items[2].line_number, 6);
    }

    #[test]
    fn commands_to_items_source_type_is_shell_history() {
        let commands = vec![(1, "ls".into())];
        let items = commands_to_items(Path::new("/tmp/history"), &commands);
        assert_eq!(items[0].source_type, SourceType::ShellHistory);
    }

    // ── Collector trait tests ───────────────────────────────────────────────

    #[test]
    fn bash_is_available_false_when_missing() {
        // Override HOME to a dir that has no .bash_history
        let dir = tmp("bash_avail");
        std::env::set_var("HOME", &dir);
        let collector = BashHistoryCollector;
        assert!(!collector.is_available());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bash_collects_commands() {
        let dir = tmp("bash_collect");
        let history = dir.join(".bash_history");
        write_file(
            &history,
            "ls -la\ncurl -H 'Authorization: Bearer secret123'\ncd /tmp\n",
        );
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = BashHistoryCollector.collect(&config).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].line, "ls -la");
        assert_eq!(items[1].line, "curl -H 'Authorization: Bearer secret123'");
        assert_eq!(items[2].line, "cd /tmp");
        assert_eq!(items[0].source_type, SourceType::ShellHistory);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zsh_collects_and_strips_timestamps() {
        let dir = tmp("zsh_collect");
        let history = dir.join(".zsh_history");
        write_file(
            &history,
            ": 1700000000:0;ls -la\n: 1700000001:0;export API_KEY=secret\n",
        );
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = ZshHistoryCollector.collect(&config).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "ls -la");
        assert_eq!(items[1].line, "export API_KEY=secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fish_collects_commands() {
        let dir = tmp("fish_collect");
        let fish_dir = dir.join(".local/share/fish");
        let history = fish_dir.join("fish_history");
        write_file(
            &history,
            concat!(
                "- cmd: ls -la\n",
                "  when: 1700000000\n",
                "- cmd: export TOKEN=abc123\n",
                "  when: 1700000001\n",
            ),
        );
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = FishHistoryCollector.collect(&config).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "ls -la");
        assert_eq!(items[1].line, "export TOKEN=abc123");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_history_yields_empty_vec() {
        let dir = tmp("empty_hist");
        let history = dir.join(".bash_history");
        write_file(&history, "");
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = BashHistoryCollector.collect(&config).unwrap();
        assert!(items.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_file_skipped() {
        let dir = tmp("binary_hist");
        let history = dir.join(".bash_history");
        // Write binary content (null bytes).
        let mut f = std::fs::File::create(&history).unwrap();
        f.write_all(b"ls\x00binary\xffgarbage").unwrap();
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = BashHistoryCollector.collect(&config).unwrap();
        assert!(items.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_history_yields_empty_vec() {
        let dir = tmp("missing_hist");
        std::env::set_var("HOME", &dir);

        let config = scan_config();
        let items = BashHistoryCollector.collect(&config).unwrap();
        assert!(items.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── strip_zsh_timestamp edge cases ──────────────────────────────────────

    #[test]
    fn strip_zsh_timestamp_valid() {
        assert_eq!(strip_zsh_timestamp(": 1700000000:0;ls -la"), "ls -la");
    }

    #[test]
    fn strip_zsh_timestamp_no_prefix() {
        assert_eq!(strip_zsh_timestamp("plain command"), "plain command");
    }

    #[test]
    fn strip_zsh_timestamp_invalid_format() {
        // Not a valid timestamp — should return as-is.
        assert_eq!(strip_zsh_timestamp(": abc:def;cmd"), ": abc:def;cmd");
    }
}
