//! Browser localStorage collector.
//!
//! Opt-in collector that scans browser localStorage databases for leaked
//! secrets. Gated by `config.scan.browser` (must be `true`). Supports:
//!
//! - **Chrome-family** (Chrome, Chromium, Brave, Edge) — LevelDB via Block 22
//! - **Firefox** — SQLite via Block 23
//!
//! Each `BrowserEntry` is converted to a `ContentItem` with a synthetic path
//! pointing to the browser profile directory. Browser data is never written to
//! the scan cache.

use std::path::{Path, PathBuf};

use crate::browser::firefox::{self, BrowserEntry};
use crate::browser::leveldb::LevelDbReader;
use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

// ---------------------------------------------------------------------------
// Synthetic path prefix for cache exclusion
// ---------------------------------------------------------------------------

const BROWSER_PATH_PREFIX: &str = "<browser";

/// Returns `true` if the given path is a synthetic browser path.
/// Used by the cache to skip browser entries (browser data must never be persisted).
pub fn is_browser_path(path: &Path) -> bool {
    path.to_string_lossy().starts_with(BROWSER_PATH_PREFIX)
}

// ---------------------------------------------------------------------------
// Chrome-family browser profile discovery
// ---------------------------------------------------------------------------

/// A Chrome-family browser with its known profile locations.
struct ChromeBrowser {
    name: &'static str,
    /// (macOS path relative to ~, Linux path relative to ~)
    profile_bases: &'static [(&'static str, &'static str)],
}

const CHROME_BROWSERS: &[ChromeBrowser] = &[
    ChromeBrowser {
        name: "chrome",
        profile_bases: &[(
            "Library/Application Support/Google/Chrome",
            ".config/google-chrome",
        )],
    },
    ChromeBrowser {
        name: "chromium",
        profile_bases: &[("Library/Application Support/Chromium", ".config/chromium")],
    },
    ChromeBrowser {
        name: "brave",
        profile_bases: &[(
            "Library/Application Support/BraveSoftware/Brave-Browser",
            ".config/BraveSoftware/Brave-Browser",
        )],
    },
    ChromeBrowser {
        name: "edge",
        profile_bases: &[(
            "Library/Application Support/Microsoft Edge",
            ".config/microsoft-edge",
        )],
    },
];

/// Find all localStorage LevelDB directories for Chrome-family browsers.
/// Each browser can have multiple profiles (Default, Profile 1, Profile 2, ...).
fn find_chrome_profiles(home: &Path) -> Vec<(String, PathBuf)> {
    let mut profiles = Vec::new();

    for browser in CHROME_BROWSERS {
        for &(mac_rel, linux_rel) in browser.profile_bases {
            let base = if cfg!(target_os = "macos") {
                home.join(mac_rel)
            } else {
                home.join(linux_rel)
            };

            if !base.is_dir() {
                continue;
            }

            // Look for profile directories containing Local Storage/leveldb/
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    // Chrome profiles: "Default", "Profile 1", "Profile 2", etc.
                    if name == "Default" || name.starts_with("Profile ") {
                        let ls_path = path.join("Local Storage").join("leveldb");
                        if ls_path.is_dir() {
                            profiles.push((browser.name.to_string(), ls_path));
                        }
                    }
                }
            }
        }
    }

    profiles
}

// ---------------------------------------------------------------------------
// BrowserEntry → ContentItem conversion
// ---------------------------------------------------------------------------

/// Convert browser entries to `ContentItem` values.
///
/// Each entry becomes a single content item with:
/// - `path`: synthetic `<browser:name:profile>` path
/// - `line`: `origin | key = value` format (so heuristics see the context)
/// - `source_type`: `BrowserStorage`
fn entries_to_items(entries: &[BrowserEntry], browser_label: &str) -> Vec<ContentItem> {
    let path = PathBuf::from(format!("<browser:{browser_label}>"));
    let lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{} | {} = {}", e.origin, e.key, e.value))
        .collect();
    let n = lines.len();

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let ctx_before: Vec<String> = if i >= 2 {
                lines[i - 2..i].to_vec()
            } else {
                lines[..i].to_vec()
            };
            let ctx_after: Vec<String> = if i + 3 <= n {
                lines[i + 1..i + 3].to_vec()
            } else {
                lines[i + 1..].to_vec()
            };

            ContentItem {
                path: path.clone(),
                line_number: i + 1,
                line: line.clone(),
                context_before: ctx_before,
                context_after: ctx_after,
                source_type: SourceType::BrowserStorage,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// BrowserCollector
// ---------------------------------------------------------------------------

/// Scans browser localStorage databases for leaked secrets.
///
/// Gated by `config.scan.browser` — does nothing unless explicitly enabled.
pub struct BrowserCollector;

impl Collector for BrowserCollector {
    fn name(&self) -> &str {
        "Browser localStorage"
    }

    fn source_type(&self) -> SourceType {
        SourceType::BrowserStorage
    }

    fn is_available(&self) -> bool {
        // Available if any browser profile directory exists.
        let home = match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => return false,
        };
        !find_chrome_profiles(&home).is_empty() || !firefox::find_firefox_profiles().is_empty()
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        if !config.browser {
            return Ok(Vec::new());
        }

        let home = match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => return Ok(Vec::new()),
        };

        let mut items = Vec::new();

        // Chrome-family browsers (LevelDB)
        for (browser_name, ls_path) in find_chrome_profiles(&home) {
            match LevelDbReader::open(&ls_path) {
                Ok(reader) => {
                    if reader.is_locked() {
                        eprintln!(
                            "sks warn: {browser_name} localStorage is locked \
                             (browser running?), skipping"
                        );
                        continue;
                    }
                    match reader.read_all() {
                        Ok(kv_pairs) => {
                            let entries: Vec<BrowserEntry> = kv_pairs
                                .into_iter()
                                .map(|(key, value)| BrowserEntry {
                                    origin: key.clone(),
                                    key,
                                    value,
                                })
                                .collect();
                            items.extend(entries_to_items(&entries, &browser_name));
                        }
                        Err(e) => {
                            eprintln!("sks warn: failed to read {browser_name} localStorage: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("sks warn: cannot open {browser_name} localStorage: {e}");
                }
            }
        }

        // Firefox (SQLite)
        for profile_path in firefox::find_firefox_profiles() {
            match firefox::read_firefox_localstorage(&profile_path) {
                Ok(entries) => {
                    items.extend(entries_to_items(&entries, "firefox"));
                }
                Err(e) => {
                    eprintln!(
                        "sks warn: failed to read Firefox profile {}: {e}",
                        profile_path.display()
                    );
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

    // --- is_browser_path ---

    #[test]
    fn browser_path_detected() {
        assert!(is_browser_path(Path::new("<browser:chrome>")));
        assert!(is_browser_path(Path::new("<browser:firefox>")));
        assert!(is_browser_path(Path::new("<browser:brave>")));
        assert!(is_browser_path(Path::new("<browser:edge>")));
    }

    #[test]
    fn non_browser_path_rejected() {
        assert!(!is_browser_path(Path::new("/home/user/.env")));
        assert!(!is_browser_path(Path::new("browser")));
        assert!(!is_browser_path(Path::new("<clipboard>")));
    }

    // --- entries_to_items ---

    #[test]
    fn entries_converted_to_content_items() {
        let entries = vec![
            BrowserEntry {
                origin: "https://example.com".to_string(),
                key: "auth_token".to_string(),
                value: "sk-secret-123".to_string(),
            },
            BrowserEntry {
                origin: "https://api.stripe.com".to_string(),
                key: "api_key".to_string(),
                value: "sk_live_abc".to_string(),
            },
        ];

        let items = entries_to_items(&entries, "chrome");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].path, PathBuf::from("<browser:chrome>"));
        assert!(items[0].line.contains("auth_token"));
        assert!(items[0].line.contains("sk-secret-123"));
        assert_eq!(items[0].line_number, 1);
        assert_eq!(items[0].source_type, SourceType::BrowserStorage);
        assert!(items[0].context_before.is_empty());
        assert_eq!(items[0].context_after.len(), 1);
    }

    #[test]
    fn entries_have_context_window() {
        let entries: Vec<BrowserEntry> = (0..5)
            .map(|i| BrowserEntry {
                origin: format!("https://site{i}.com"),
                key: format!("key{i}"),
                value: format!("val{i}"),
            })
            .collect();

        let items = entries_to_items(&entries, "test");
        // Middle item (index 2) should have 2 before and 2 after
        assert_eq!(items[2].context_before.len(), 2);
        assert_eq!(items[2].context_after.len(), 2);
        // First item: 0 before
        assert!(items[0].context_before.is_empty());
        // Last item: 0 after
        assert!(items[4].context_after.is_empty());
    }

    #[test]
    fn empty_entries_produce_no_items() {
        let items = entries_to_items(&[], "chrome");
        assert!(items.is_empty());
    }

    #[test]
    fn line_format_has_origin_key_value() {
        let entries = vec![BrowserEntry {
            origin: "https://example.com".to_string(),
            key: "session".to_string(),
            value: "abc123".to_string(),
        }];
        let items = entries_to_items(&entries, "firefox");
        assert_eq!(items[0].line, "https://example.com | session = abc123");
    }

    // --- BrowserCollector trait ---

    #[test]
    fn collector_name_and_source_type() {
        let c = BrowserCollector;
        assert_eq!(c.name(), "Browser localStorage");
        assert_eq!(c.source_type(), SourceType::BrowserStorage);
    }

    #[test]
    fn collect_returns_empty_when_disabled() {
        let c = BrowserCollector;
        let config = ScanConfig {
            browser: false,
            ..ScanConfig::default()
        };
        let items = c.collect(&config).unwrap();
        assert!(items.is_empty());
    }

    // --- Chrome profile discovery ---

    #[test]
    fn find_chrome_profiles_in_synthetic_dir() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        // Create a fake Chrome Default profile with Local Storage/leveldb/
        let chrome_base = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Google/Chrome")
        } else {
            home.join(".config/google-chrome")
        };
        let ls_dir = chrome_base.join("Default/Local Storage/leveldb");
        std::fs::create_dir_all(&ls_dir).unwrap();
        // Need a CURRENT file for it to be a valid LevelDB dir
        std::fs::write(ls_dir.join("CURRENT"), "MANIFEST-000001\n").unwrap();

        let profiles = find_chrome_profiles(home);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].0, "chrome");
        assert!(profiles[0].1.ends_with("leveldb"));
    }

    #[test]
    fn find_chrome_profiles_multiple_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        let chrome_base = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Google/Chrome")
        } else {
            home.join(".config/google-chrome")
        };

        for profile in &["Default", "Profile 1", "Profile 2"] {
            let ls_dir = chrome_base.join(profile).join("Local Storage/leveldb");
            std::fs::create_dir_all(&ls_dir).unwrap();
            std::fs::write(ls_dir.join("CURRENT"), "MANIFEST-000001\n").unwrap();
        }

        let profiles = find_chrome_profiles(home);
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn find_chrome_profiles_empty_when_no_browsers() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = find_chrome_profiles(dir.path());
        assert!(profiles.is_empty());
    }

    // --- Integration: LevelDB → ContentItem ---

    #[test]
    fn chrome_leveldb_to_content_items() {
        use crate::browser::leveldb::LevelDbReader;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path();
        std::fs::write(db_path.join("CURRENT"), "MANIFEST-000001\n").unwrap();

        // Build a synthetic SSTable with a key-value pair
        let sst_data = build_test_sstable(&[(b"test_origin\x00token", b"secret_value", 1)]);
        std::fs::write(db_path.join("000001.ldb"), &sst_data).unwrap();

        let reader = LevelDbReader::open(db_path).unwrap();
        let kv_pairs = reader.read_all().unwrap();
        assert!(!kv_pairs.is_empty());

        let entries: Vec<BrowserEntry> = kv_pairs
            .into_iter()
            .map(|(key, value)| BrowserEntry {
                origin: key.clone(),
                key,
                value,
            })
            .collect();
        let items = entries_to_items(&entries, "chrome");
        assert!(!items.is_empty());
        assert_eq!(items[0].source_type, SourceType::BrowserStorage);
    }

    // --- Integration: Firefox SQLite → ContentItem ---

    #[test]
    fn firefox_sqlite_to_content_items() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path();
        let db_path = profile.join("webappsstore.sqlite");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (
                originAttributes TEXT,
                originKey TEXT,
                scope TEXT,
                key TEXT,
                value TEXT
            );
            INSERT INTO webappsstore2 VALUES (
                '', 'moc.elpmaxe.:https:443', '', 'api_key', 'sk_live_secret'
            );",
        )
        .unwrap();
        drop(conn);

        let entries = firefox::read_firefox_localstorage(profile).unwrap();
        assert_eq!(entries.len(), 1);

        let items = entries_to_items(&entries, "firefox");
        assert_eq!(items.len(), 1);
        assert!(items[0].line.contains("https://example.com"));
        assert!(items[0].line.contains("api_key"));
        assert!(items[0].line.contains("sk_live_secret"));
        assert_eq!(items[0].path, PathBuf::from("<browser:firefox>"));
    }

    // --- Test helper: build synthetic SSTable ---

    fn encode_varint(mut val: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if val == 0 {
                break;
            }
        }
        buf
    }

    const TABLE_MAGIC: u64 = 0xdb4775248b80fb57;
    const FOOTER_SIZE: usize = 48;

    fn build_test_sstable(entries: &[(&[u8], &[u8], u64)]) -> Vec<u8> {
        // Build data block
        let mut block = Vec::new();
        let mut last_key: Vec<u8> = Vec::new();

        for (user_key, value, seq) in entries {
            let packed: u64 = (seq << 8) | 1u64; // value type = 1
            let mut ikey = user_key.to_vec();
            ikey.extend_from_slice(&packed.to_le_bytes());

            let shared = last_key
                .iter()
                .zip(ikey.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let unshared = ikey.len() - shared;

            block.extend_from_slice(&encode_varint(shared as u64));
            block.extend_from_slice(&encode_varint(unshared as u64));
            block.extend_from_slice(&encode_varint(value.len() as u64));
            block.extend_from_slice(&ikey[shared..]);
            block.extend_from_slice(value);
            last_key = ikey;
        }
        block.extend_from_slice(&0u32.to_le_bytes()); // restart[0]
        block.extend_from_slice(&1u32.to_le_bytes()); // num_restarts

        let data_block_size = block.len();
        let mut file = Vec::new();
        file.extend_from_slice(&block);
        file.push(0); // no compression
        file.extend_from_slice(&[0; 4]); // CRC

        // Index block
        let last = entries.last().unwrap();
        let packed: u64 = (last.2 << 8) | 1u64;
        let mut sep_key = last.0.to_vec();
        sep_key.extend_from_slice(&packed.to_le_bytes());
        sep_key.push(0xFF);

        let mut handle = encode_varint(0);
        handle.extend_from_slice(&encode_varint(data_block_size as u64));

        let index_offset = file.len();
        let mut idx_block = Vec::new();
        idx_block.extend_from_slice(&encode_varint(0));
        idx_block.extend_from_slice(&encode_varint(sep_key.len() as u64));
        idx_block.extend_from_slice(&encode_varint(handle.len() as u64));
        idx_block.extend_from_slice(&sep_key);
        idx_block.extend_from_slice(&handle);
        idx_block.extend_from_slice(&0u32.to_le_bytes());
        idx_block.extend_from_slice(&1u32.to_le_bytes());

        let index_size = idx_block.len();
        file.extend_from_slice(&idx_block);
        file.push(0);
        file.extend_from_slice(&[0; 4]);

        // Footer
        let mut footer = [0u8; FOOTER_SIZE];
        let idx_off = encode_varint(index_offset as u64);
        let idx_sz = encode_varint(index_size as u64);
        footer[20..20 + idx_off.len()].copy_from_slice(&idx_off);
        footer[20 + idx_off.len()..20 + idx_off.len() + idx_sz.len()].copy_from_slice(&idx_sz);
        footer[40..48].copy_from_slice(&TABLE_MAGIC.to_le_bytes());
        file.extend_from_slice(&footer);
        file
    }
}
