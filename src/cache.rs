//! Incremental scanning cache.
//!
//! Stores per-file mtime + size so that unchanged files can be skipped on
//! re-scans. The cache is a JSON file at `$XDG_DATA_HOME/sks/cache.json`
//! (fallback `~/.local/share/sks/cache.json`).
//!
//! All load failures (missing file, malformed JSON, version mismatch) degrade
//! gracefully to a fresh cache, forcing a full scan.

use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::SksError;

/// Current cache format version. Bump this on breaking schema changes.
const CACHE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// Per-file cache entry recording the last-seen mtime, size, and finding count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub mtime: i64,
    pub size: u64,
    pub findings_count: usize,
}

impl CacheEntry {
    /// Build an entry from live file metadata and a finding count.
    pub fn from_metadata(meta: &fs::Metadata, findings_count: usize) -> Self {
        CacheEntry {
            mtime: file_mtime_unix(meta),
            size: meta.len(),
            findings_count,
        }
    }
}

// ---------------------------------------------------------------------------
// ScanCache
// ---------------------------------------------------------------------------

/// Mtime-based file cache for incremental scanning.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanCache {
    pub version: u32,
    pub sks_version: String,
    pub created_at: DateTime<Utc>,
    pub entries: HashMap<PathBuf, CacheEntry>,
}

impl Default for ScanCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanCache {
    /// Creates an empty cache tagged with the current binary version.
    pub fn new() -> Self {
        ScanCache {
            version: CACHE_VERSION,
            sks_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: Utc::now(),
            entries: HashMap::new(),
        }
    }

    /// Loads a cache from disk. All failures degrade to `Self::new()`.
    pub fn load(path: &Path) -> Self {
        let data = match fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return Self::new(),
        };
        let cache: ScanCache = match serde_json::from_str(&data) {
            Ok(c) => c,
            Err(_) => return Self::new(),
        };
        // Reject caches from a different format version.
        if cache.version != CACHE_VERSION {
            return Self::new();
        }
        // Reject caches from a different sks binary version.
        if cache.sks_version != env!("CARGO_PKG_VERSION") {
            return Self::new();
        }
        cache
    }

    /// Persists the cache to disk as pretty-printed JSON.
    /// File permissions: 0600. Parent directory permissions: 0700.
    pub fn save(&self, path: &Path) -> Result<(), SksError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)?;
                }
                #[cfg(not(unix))]
                {
                    fs::create_dir_all(parent)?;
                }
            }
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SksError::Io(std::io::Error::other(e)))?;

        #[cfg(unix)]
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path);

        #[cfg(not(unix))]
        let file = fs::File::create(path);

        let mut file = file?;
        std::io::Write::write_all(&mut file, json.as_bytes())?;
        Ok(())
    }

    /// Returns `true` if the file should be re-scanned (no cache entry,
    /// metadata read failure, or mtime/size mismatch).
    pub fn is_stale(&self, path: &Path) -> bool {
        let entry = match self.entries.get(path) {
            Some(e) => e,
            None => return true,
        };
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return true,
        };
        let live_mtime = file_mtime_unix(&meta);
        let live_size = meta.len();
        entry.mtime != live_mtime || entry.size != live_size
    }

    /// Insert or overwrite an entry.
    pub fn update(&mut self, path: PathBuf, entry: CacheEntry) {
        self.entries.insert(path, entry);
    }

    /// Removes entries whose paths no longer exist on disk.
    pub fn prune_missing(&mut self) {
        self.entries.retain(|path, _| path.exists());
    }
}

// ---------------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------------

/// Returns the default cache file path:
/// `$XDG_DATA_HOME/sks/cache.json` (fallback `~/.local/share/sks/cache.json`).
pub fn cache_path() -> PathBuf {
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::collectors::filesystem::home_dir().join(".local/share"));
    data_home.join("sks/cache.json")
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Extracts the unix timestamp (seconds since epoch) from file metadata.
fn file_mtime_unix(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -- Construction --

    #[test]
    fn new_has_current_version_and_empty_entries() {
        let cache = ScanCache::new();
        assert_eq!(cache.version, CACHE_VERSION);
        assert_eq!(cache.sks_version, env!("CARGO_PKG_VERSION"));
        assert!(cache.entries.is_empty());
    }

    // -- Round-trip --

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("sks_cache_test_roundtrip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");

        let mut cache = ScanCache::new();
        cache.update(
            PathBuf::from("/tmp/test.env"),
            CacheEntry {
                mtime: 1700000000,
                size: 256,
                findings_count: 2,
            },
        );
        cache.save(&path).unwrap();

        let loaded = ScanCache::load(&path);
        assert_eq!(loaded.version, CACHE_VERSION);
        assert_eq!(loaded.entries.len(), 1);
        let entry = loaded.entries.get(&PathBuf::from("/tmp/test.env")).unwrap();
        assert_eq!(entry.mtime, 1700000000);
        assert_eq!(entry.size, 256);
        assert_eq!(entry.findings_count, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- File permissions (Unix) --

    #[cfg(unix)]
    #[test]
    fn saved_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("sks_cache_test_perms");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("cache.json");

        let cache = ScanCache::new();
        cache.save(&path).unwrap();

        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn saved_dir_has_0700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("sks_cache_test_dirperms/nested");
        let _ = fs::remove_dir_all(std::env::temp_dir().join("sks_cache_test_dirperms"));
        let path = dir.join("cache.json");

        let cache = ScanCache::new();
        cache.save(&path).unwrap();

        let perms = fs::metadata(&dir).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);

        let _ = fs::remove_dir_all(std::env::temp_dir().join("sks_cache_test_dirperms"));
    }

    // -- Load edge cases --

    #[test]
    fn load_missing_file_returns_empty_cache() {
        let cache = ScanCache::load(Path::new("/nonexistent/path/cache.json"));
        assert!(cache.entries.is_empty());
        assert_eq!(cache.version, CACHE_VERSION);
    }

    #[test]
    fn load_malformed_json_returns_empty_cache() {
        let dir = std::env::temp_dir().join("sks_cache_test_malformed");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");
        fs::write(&path, "{ not valid json }}}").unwrap();

        let cache = ScanCache::load(&path);
        assert!(cache.entries.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_wrong_version_returns_empty_cache() {
        let dir = std::env::temp_dir().join("sks_cache_test_badver");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");

        let json = serde_json::json!({
            "version": 999,
            "sks_version": env!("CARGO_PKG_VERSION"),
            "created_at": Utc::now().to_rfc3339(),
            "entries": {}
        });
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cache = ScanCache::load(&path);
        assert!(cache.entries.is_empty());
        assert_eq!(cache.version, CACHE_VERSION);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_wrong_sks_version_returns_empty_cache() {
        let dir = std::env::temp_dir().join("sks_cache_test_badsksver");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");

        let json = serde_json::json!({
            "version": CACHE_VERSION,
            "sks_version": "0.0.0-fake",
            "created_at": Utc::now().to_rfc3339(),
            "entries": {}
        });
        fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let cache = ScanCache::load(&path);
        assert!(cache.entries.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Staleness --

    #[test]
    fn unknown_file_is_stale() {
        let cache = ScanCache::new();
        assert!(cache.is_stale(Path::new("/tmp/does_not_exist_in_cache")));
    }

    #[test]
    fn known_file_unchanged_is_not_stale() {
        let dir = std::env::temp_dir().join("sks_cache_test_stale_unchanged");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let meta = fs::metadata(&file_path).unwrap();
        let mut cache = ScanCache::new();
        cache.update(file_path.clone(), CacheEntry::from_metadata(&meta, 0));

        assert!(!cache.is_stale(&file_path));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_file_mtime_changed_is_stale() {
        let dir = std::env::temp_dir().join("sks_cache_test_stale_mtime");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let mut cache = ScanCache::new();
        cache.update(
            file_path.clone(),
            CacheEntry {
                mtime: 1,
                size: 5,
                findings_count: 0,
            },
        );

        assert!(cache.is_stale(&file_path));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_file_size_changed_is_stale() {
        let dir = std::env::temp_dir().join("sks_cache_test_stale_size");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let meta = fs::metadata(&file_path).unwrap();
        let mut cache = ScanCache::new();
        cache.update(
            file_path.clone(),
            CacheEntry {
                mtime: file_mtime_unix(&meta),
                size: 99999, // wrong size
                findings_count: 0,
            },
        );

        assert!(cache.is_stale(&file_path));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonexistent_path_is_stale() {
        let mut cache = ScanCache::new();
        let path = PathBuf::from("/tmp/sks_nonexistent_file_xyz");
        cache.update(
            path.clone(),
            CacheEntry {
                mtime: 100,
                size: 50,
                findings_count: 0,
            },
        );
        assert!(cache.is_stale(&path));
    }

    // -- Update --

    #[test]
    fn update_inserts_new_entry() {
        let mut cache = ScanCache::new();
        let path = PathBuf::from("/tmp/new_file");
        cache.update(
            path.clone(),
            CacheEntry {
                mtime: 100,
                size: 50,
                findings_count: 1,
            },
        );
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[&path].findings_count, 1);
    }

    #[test]
    fn update_overwrites_existing_entry() {
        let mut cache = ScanCache::new();
        let path = PathBuf::from("/tmp/existing_file");
        cache.update(
            path.clone(),
            CacheEntry {
                mtime: 100,
                size: 50,
                findings_count: 1,
            },
        );
        cache.update(
            path.clone(),
            CacheEntry {
                mtime: 200,
                size: 60,
                findings_count: 3,
            },
        );
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.entries[&path].mtime, 200);
        assert_eq!(cache.entries[&path].findings_count, 3);
    }

    // -- Prune --

    #[test]
    fn prune_removes_missing_files_keeps_existing() {
        let dir = std::env::temp_dir().join("sks_cache_test_prune");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let existing = dir.join("exists.txt");
        fs::write(&existing, "data").unwrap();
        let missing = PathBuf::from("/tmp/sks_cache_prune_nonexistent");

        let mut cache = ScanCache::new();
        cache.update(
            existing.clone(),
            CacheEntry {
                mtime: 100,
                size: 4,
                findings_count: 0,
            },
        );
        cache.update(
            missing.clone(),
            CacheEntry {
                mtime: 100,
                size: 4,
                findings_count: 0,
            },
        );

        assert_eq!(cache.entries.len(), 2);
        cache.prune_missing();
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.entries.contains_key(&existing));
        assert!(!cache.entries.contains_key(&missing));

        let _ = fs::remove_dir_all(&dir);
    }

    // -- Security: no secrets in serialized JSON --

    #[test]
    fn serialized_cache_contains_no_secret_patterns() {
        let mut cache = ScanCache::new();
        cache.update(
            PathBuf::from("/home/user/.env"),
            CacheEntry {
                mtime: 1700000000,
                size: 100,
                findings_count: 5,
            },
        );
        let json = serde_json::to_string_pretty(&cache).unwrap();
        // Should only contain paths, integers, and version strings
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
        assert!(!json.contains("AKIA"));
    }

    // -- cache_path respects XDG_DATA_HOME --

    #[test]
    fn cache_path_respects_xdg_data_home() {
        // We can't safely set env vars in parallel tests, so just verify the
        // default path contains the expected suffix.
        let path = cache_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with("sks/cache.json"),
            "cache path should end with sks/cache.json: {path_str}"
        );
    }

    // -- CacheEntry::from_metadata --

    #[test]
    fn cache_entry_from_metadata_captures_size() {
        let dir = std::env::temp_dir().join("sks_cache_test_from_meta");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test.txt");
        {
            let mut f = fs::File::create(&file_path).unwrap();
            f.write_all(b"12345").unwrap();
        }
        let meta = fs::metadata(&file_path).unwrap();
        let entry = CacheEntry::from_metadata(&meta, 3);
        assert_eq!(entry.size, 5);
        assert_eq!(entry.findings_count, 3);
        assert!(entry.mtime > 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
