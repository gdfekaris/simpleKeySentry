//! Clipboard collector.
//!
//! Opt-in collector that scans clipboard contents for leaked secrets.
//! Gated by `config.scan.clipboard` (must be `true`). Two scan sources:
//!
//! - **Current pasteboard** — invokes `pbpaste` (macOS) or `xclip`/`xsel`
//!   (Linux) via subprocess and scans the output.
//! - **Clipboard manager databases** — reads stored entries from Clipy (macOS),
//!   CopyQ (Linux), and GPaste (Linux).
//!
//! # Privacy safeguards
//!
//! - Clipboard content is **never written to disk**: not in the scan cache,
//!   not in any log file, and not in unredacted report output.
//! - Subprocess output is captured as a `String`, converted to
//!   [`ContentItem`] values, and the original data is dropped. The detection
//!   engine wraps matched portions in [`SecretValue`] (zeroized on drop).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

/// Synthetic path used for clipboard content items. This path is never a
/// real file, so the incremental cache will naturally skip it.
const CLIPBOARD_PATH: &str = "<clipboard>";

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

/// Returns the first available pasteboard command on this system, or `None`.
fn pasteboard_command() -> Option<(&'static str, &'static [&'static str])> {
    if cfg!(target_os = "macos") {
        if command_exists("pbpaste") {
            return Some(("pbpaste", &[]));
        }
    } else {
        // Linux: prefer xclip, fall back to xsel.
        if command_exists("xclip") {
            return Some(("xclip", &["-selection", "clipboard", "-o"]));
        }
        if command_exists("xsel") {
            return Some(("xsel", &["--clipboard", "--output"]));
        }
    }
    None
}

/// Returns `true` if the given command is on `$PATH`.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Pasteboard reading
// ---------------------------------------------------------------------------

/// Runs the pasteboard command and returns the clipboard text.
/// Returns `Ok(None)` if the clipboard is empty or the command fails.
fn read_pasteboard() -> Result<Option<String>, SksError> {
    let (cmd, args) = match pasteboard_command() {
        Some(c) => c,
        None => return Ok(None),
    };

    let output = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(SksError::Io)?;

    if !output.status.success() {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(text))
}

/// Converts clipboard text into [`ContentItem`] values (one per line).
fn clipboard_text_to_items(text: &str) -> Vec<ContentItem> {
    let path = PathBuf::from(CLIPBOARD_PATH);
    let lines: Vec<&str> = text.lines().collect();
    let n = lines.len();

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let context_before: Vec<String> = lines[i.saturating_sub(2)..i]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let context_after: Vec<String> = lines[(i + 1).min(n)..((i + 3).min(n))]
                .iter()
                .map(|s| s.to_string())
                .collect();

            ContentItem {
                path: path.clone(),
                line_number: i + 1,
                line: line.to_string(),
                context_before,
                context_after,
                source_type: SourceType::Clipboard,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// ClipboardCollector
// ---------------------------------------------------------------------------

/// Scans the system clipboard for leaked secrets.
///
/// Gated by `config.scan.clipboard` — does nothing unless explicitly enabled.
pub struct ClipboardCollector;

impl Collector for ClipboardCollector {
    fn name(&self) -> &str {
        "Clipboard"
    }

    fn source_type(&self) -> SourceType {
        SourceType::Clipboard
    }

    fn is_available(&self) -> bool {
        // Available if at least one clipboard source exists.
        pasteboard_command().is_some() || !clipboard_manager_paths().is_empty()
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        if !config.clipboard {
            return Ok(Vec::new());
        }

        let mut items = Vec::new();

        // Current pasteboard.
        match read_pasteboard() {
            Ok(Some(text)) => {
                items.extend(clipboard_text_to_items(&text));
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("sks warn: clipboard read failed: {e}");
            }
        }

        // Clipboard manager databases.
        for db_path in clipboard_manager_paths() {
            let db_name = db_path.to_string_lossy();
            let entries = if db_name.contains("copyq") {
                read_copyq_db(&db_path)
            } else if db_name.contains("gpaste") {
                read_gpaste_history(&db_path)
            } else if db_name.contains("clipy") || db_name.contains("Clipy") {
                read_clipy_db(&db_path)
            } else {
                continue;
            };

            if !entries.is_empty() {
                let label = if db_name.contains("copyq") {
                    "copyq"
                } else if db_name.contains("gpaste") {
                    "gpaste"
                } else {
                    "clipy"
                };
                items.extend(entries_to_items(&entries, label));
            }
        }

        Ok(items)
    }
}

/// Returns `true` if the given path is a synthetic clipboard path.
/// Used by the cache to skip clipboard entries.
pub fn is_clipboard_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("<clipboard")
}

// ---------------------------------------------------------------------------
// Clipboard manager helpers
// ---------------------------------------------------------------------------

fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Returns known clipboard manager database paths that exist on this system.
fn clipboard_manager_paths() -> Vec<PathBuf> {
    let home = home_dir();
    let candidates: Vec<PathBuf> = if cfg!(target_os = "macos") {
        vec![
            // Clipy (macOS)
            home.join("Library/Application Support/com.clipy-app.Clipy/default.realm"),
        ]
    } else {
        vec![
            // CopyQ (Linux)
            home.join(".local/share/copyq/copyq.db"),
            // GPaste history (Linux) — plain text, one entry per file
            home.join(".local/share/gpaste/history"),
        ]
    };
    candidates.into_iter().filter(|p| p.exists()).collect()
}

// ---------------------------------------------------------------------------
// CopyQ reader (SQLite)
// ---------------------------------------------------------------------------

/// Reads all text entries from a CopyQ SQLite database.
///
/// CopyQ stores clipboard items in a table. The schema varies by version;
/// common layouts use `copyq(tab TEXT, item_data BLOB)` where `item_data`
/// contains the entry content. We attempt a simple query and fall back
/// gracefully on schema mismatches.
fn read_copyq_db(path: &Path) -> Vec<String> {
    let conn = match rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sks warn: cannot open CopyQ database: {e}");
            return Vec::new();
        }
    };

    // CopyQ stores items in a `copyq` table with `item_data` blob.
    // The blob starts with a Qt serialization header; for plain-text items
    // the text is embedded directly. We try reading as UTF-8 and skip
    // entries that are binary.
    let mut entries = Vec::new();

    // Try common schema variants.
    let query = "SELECT item_data FROM copyq ORDER BY rowid DESC";
    let mut stmt = match conn.prepare(query) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([], |row| {
        let data: Vec<u8> = row.get(0)?;
        Ok(data)
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    for data in rows.flatten() {
        if let Ok(text) = String::from_utf8(data.clone()) {
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() {
                entries.push(trimmed);
            }
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// GPaste reader (plain text history)
// ---------------------------------------------------------------------------

/// Reads GPaste history entries from the history directory.
///
/// GPaste stores its history in XML files under `~/.local/share/gpaste/`.
/// Each history file is an XML document. We also check for a simpler
/// plain-text format used by some versions.
fn read_gpaste_history(history_dir: &Path) -> Vec<String> {
    let mut entries = Vec::new();

    // GPaste history is stored as XML files in the history directory.
    // Look for all XML files and extract text content.
    let dir = if history_dir.is_file() {
        // We were given the history file path; use its parent.
        match history_dir.parent() {
            Some(p) => p,
            None => return entries,
        }
    } else {
        history_dir
    };

    let read_dir = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return entries,
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        // Read file and extract text content.
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // GPaste XML format: extract text between <value> and </value> tags.
        // The tags may appear anywhere on a line (possibly wrapped in other tags).
        let is_xml = content.trim_start().starts_with('<');
        if is_xml {
            for line in content.lines() {
                if let Some(start) = line.find("<value>") {
                    let after_tag = &line[start + 7..];
                    if let Some(end) = after_tag.find("</value>") {
                        let value = &after_tag[..end];
                        let decoded = value
                            .replace("&amp;", "&")
                            .replace("&lt;", "<")
                            .replace("&gt;", ">");
                        if !decoded.trim().is_empty() {
                            entries.push(decoded);
                        }
                    }
                }
            }
        } else {
            // Plain-text format (one entry per line).
            for line in content.lines() {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    entries.push(trimmed);
                }
            }
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Clipy reader (macOS Realm database — best-effort)
// ---------------------------------------------------------------------------

/// Attempts to read Clipy clipboard entries.
///
/// Clipy uses a Realm database which requires a dedicated parser. Since
/// adding a Realm dependency would be heavy, we check if there's a SQLite
/// export or fall back to skipping with a debug message.
fn read_clipy_db(path: &Path) -> Vec<String> {
    // Clipy uses Realm (not SQLite). A full Realm parser is out of scope.
    // If the file exists we note it but can't read it without a Realm crate.
    if path.exists() {
        eprintln!(
            "sks warn: Clipy database found at {} but Realm format not yet supported",
            path.display()
        );
    }
    Vec::new()
}

/// Converts clipboard manager entries into [`ContentItem`] values.
fn entries_to_items(entries: &[String], source_label: &str) -> Vec<ContentItem> {
    let path = PathBuf::from(format!("<clipboard:{source_label}>"));
    let mut items = Vec::new();

    for (entry_idx, entry) in entries.iter().enumerate() {
        let lines: Vec<&str> = entry.lines().collect();
        let n = lines.len();

        for (i, line) in lines.iter().enumerate() {
            let context_before: Vec<String> = lines[i.saturating_sub(2)..i]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let context_after: Vec<String> = lines[(i + 1).min(n)..((i + 3).min(n))]
                .iter()
                .map(|s| s.to_string())
                .collect();

            items.push(ContentItem {
                path: path.clone(),
                line_number: entry_idx + 1,
                line: line.to_string(),
                context_before,
                context_after,
                source_type: SourceType::Clipboard,
            });
        }
    }

    items
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;

    // ── clipboard_text_to_items ────────────────────────────────────────────

    #[test]
    fn single_line_clipboard() {
        let items = clipboard_text_to_items("export API_KEY=secret123");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].line, "export API_KEY=secret123");
        assert_eq!(items[0].line_number, 1);
        assert_eq!(items[0].path, PathBuf::from(CLIPBOARD_PATH));
        assert_eq!(items[0].source_type, SourceType::Clipboard);
        assert!(items[0].context_before.is_empty());
        assert!(items[0].context_after.is_empty());
    }

    #[test]
    fn multiline_clipboard() {
        let text = "line1\nline2\nline3\nline4\nline5";
        let items = clipboard_text_to_items(text);
        assert_eq!(items.len(), 5);

        // First item: no before, 2 after.
        assert!(items[0].context_before.is_empty());
        assert_eq!(items[0].context_after, vec!["line2", "line3"]);

        // Middle item (line3): 2 before, 2 after.
        assert_eq!(items[2].context_before, vec!["line1", "line2"]);
        assert_eq!(items[2].context_after, vec!["line4", "line5"]);

        // Last item: 2 before, no after.
        assert_eq!(items[4].context_before, vec!["line3", "line4"]);
        assert!(items[4].context_after.is_empty());
    }

    #[test]
    fn empty_clipboard_text() {
        let items = clipboard_text_to_items("");
        // Empty string produces one empty-line item; the detection engine
        // will simply not match anything on it.
        assert!(items.len() <= 1);
    }

    #[test]
    fn all_items_have_clipboard_source_type() {
        let items = clipboard_text_to_items("a\nb\nc");
        for item in &items {
            assert_eq!(item.source_type, SourceType::Clipboard);
        }
    }

    #[test]
    fn all_items_use_synthetic_path() {
        let items = clipboard_text_to_items("secret\ntoken");
        for item in &items {
            assert_eq!(item.path, PathBuf::from(CLIPBOARD_PATH));
        }
    }

    // ── is_clipboard_path ──────────────────────────────────────────────────

    #[test]
    fn synthetic_path_detected() {
        assert!(is_clipboard_path(Path::new(CLIPBOARD_PATH)));
    }

    #[test]
    fn real_path_not_clipboard() {
        assert!(!is_clipboard_path(Path::new("/home/user/.env")));
        assert!(!is_clipboard_path(Path::new("clipboard")));
    }

    // ── Collector trait ────────────────────────────────────────────────────

    #[test]
    fn disabled_by_default() {
        let config = ScanConfig::default();
        assert!(!config.clipboard);
        let items = ClipboardCollector.collect(&config).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn command_exists_false_for_nonsense() {
        assert!(!command_exists("sks_nonexistent_binary_xyz"));
    }

    // ── Detection integration ──────────────────────────────────────────────

    #[test]
    fn clipboard_items_produce_findings() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        let items = clipboard_text_to_items("AWS_KEY=AKIAIOSFODNN7EXAMPLE");
        let compiled: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .filter_map(|r| CompiledPattern::compile(r).ok())
            .collect();
        let engine = DetectionEngine::new(compiled);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "clipboard item with AWS key should produce a finding"
        );
        assert_eq!(findings[0].location.source_type, SourceType::Clipboard);
    }

    // ── Pasteboard subprocess ──────────────────────────────────────────────

    #[test]
    fn pasteboard_command_returns_some_on_linux_with_xclip() {
        // This test is conditional: only meaningful if xclip is installed.
        if command_exists("xclip") {
            let cmd = pasteboard_command();
            assert!(cmd.is_some());
            let (name, _) = cmd.unwrap();
            assert!(name == "xclip" || name == "xsel");
        }
    }

    // ── Clipboard manager paths ────────────────────────────────────────────

    #[test]
    fn clipboard_manager_synthetic_paths_detected() {
        assert!(is_clipboard_path(Path::new("<clipboard>")));
        assert!(is_clipboard_path(Path::new("<clipboard:copyq>")));
        assert!(is_clipboard_path(Path::new("<clipboard:gpaste>")));
        assert!(is_clipboard_path(Path::new("<clipboard:clipy>")));
        assert!(!is_clipboard_path(Path::new("/home/user/.env")));
    }

    // ── entries_to_items ───────────────────────────────────────────────────

    #[test]
    fn entries_to_items_basic() {
        let entries = vec![
            "export SECRET=abc123".to_string(),
            "just normal text".to_string(),
        ];
        let items = entries_to_items(&entries, "test");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].line, "export SECRET=abc123");
        assert_eq!(items[1].line, "just normal text");
        assert_eq!(items[0].source_type, SourceType::Clipboard);
        assert_eq!(items[0].path, PathBuf::from("<clipboard:test>"));
    }

    #[test]
    fn entries_to_items_multiline_entry() {
        let entries = vec!["line1\nline2\nline3".to_string()];
        let items = entries_to_items(&entries, "test");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].line, "line1");
        assert_eq!(items[1].line, "line2");
        assert_eq!(items[2].line, "line3");
    }

    #[test]
    fn entries_to_items_empty() {
        let entries: Vec<String> = vec![];
        let items = entries_to_items(&entries, "test");
        assert!(items.is_empty());
    }

    // ── CopyQ reader ──────────────────────────────────────────────────────

    #[test]
    fn copyq_nonexistent_db_returns_empty() {
        let entries = read_copyq_db(Path::new("/tmp/sks_nonexistent_copyq.db"));
        assert!(entries.is_empty());
    }

    #[test]
    fn copyq_reads_from_sqlite() {
        let dir = std::env::temp_dir().join("sks_test_copyq");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("copyq.db");

        // Create a minimal CopyQ-like SQLite database.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE copyq (item_data BLOB);
             INSERT INTO copyq VALUES (X'6578706f727420544f4b454e3d736563726574');",
            // hex for "export TOKEN=secret"
        )
        .unwrap();
        drop(conn);

        let entries = read_copyq_db(&db_path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "export TOKEN=secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copyq_skips_binary_entries() {
        let dir = std::env::temp_dir().join("sks_test_copyq_bin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("copyq.db");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE copyq (item_data BLOB);
             INSERT INTO copyq VALUES (X'89504e470d0a1a0a');", // PNG magic bytes
        )
        .unwrap();
        drop(conn);

        let entries = read_copyq_db(&db_path);
        assert!(entries.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copyq_wrong_schema_returns_empty() {
        let dir = std::env::temp_dir().join("sks_test_copyq_schema");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("copyq.db");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE other (id INTEGER);")
            .unwrap();
        drop(conn);

        let entries = read_copyq_db(&db_path);
        assert!(entries.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── GPaste reader ─────────────────────────────────────────────────────

    #[test]
    fn gpaste_nonexistent_dir_returns_empty() {
        let entries = read_gpaste_history(Path::new("/tmp/sks_nonexistent_gpaste"));
        assert!(entries.is_empty());
    }

    #[test]
    fn gpaste_reads_xml_values() {
        let dir = std::env::temp_dir().join("sks_test_gpaste");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let xml = concat!(
            "<history>\n",
            "  <item><value>export API_KEY=secret123</value></item>\n",
            "  <item><value>normal text</value></item>\n",
            "</history>\n",
        );
        std::fs::write(dir.join("history.xml"), xml).unwrap();

        let entries = read_gpaste_history(&dir);
        assert!(entries.len() >= 2);
        assert!(entries.iter().any(|e| e.contains("API_KEY=secret123")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gpaste_decodes_xml_entities() {
        let dir = std::env::temp_dir().join("sks_test_gpaste_xml");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let xml = "<history>\n<item><value>a &amp; b &lt; c</value></item>\n</history>\n";
        std::fs::write(dir.join("hist.xml"), xml).unwrap();

        let entries = read_gpaste_history(&dir);
        assert!(entries.iter().any(|e| e == "a & b < c"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Cache exclusion integration ────────────────────────────────────────

    #[test]
    fn clipboard_items_not_cached() {
        use crate::cache::ScanCache;

        let items = clipboard_text_to_items("SECRET=leaked");
        let cache = ScanCache::new();

        // Clipboard items should have a synthetic path that metadata() fails on.
        for item in &items {
            assert!(is_clipboard_path(&item.path));
            assert!(std::fs::metadata(&item.path).is_err());
            assert!(cache.is_stale(&item.path));
        }
    }
}
