//! Firefox localStorage reader.
//!
//! Reads key-value pairs from Firefox's `webappsstore.sqlite` database
//! using read-only SQLite access. Discovers Firefox profiles automatically
//! on Linux and macOS.

use std::path::{Path, PathBuf};

use crate::SksError;

// ---------------------------------------------------------------------------
// BrowserEntry — shared type for Block 22 (LevelDB) and Block 23 (SQLite)
// ---------------------------------------------------------------------------

/// A single localStorage entry extracted from a browser database.
pub struct BrowserEntry {
    /// Human-readable origin URL (e.g., "https://example.com").
    pub origin: String,
    /// The localStorage key name.
    pub key: String,
    /// The localStorage value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Firefox profile discovery
// ---------------------------------------------------------------------------

/// Find all Firefox profile directories on the system.
///
/// Checks standard locations on Linux and macOS. Returns directories
/// matching `*.default*` (covers `*.default`, `*.default-release`,
/// `*.default-esr`, etc.).
pub fn find_firefox_profiles() -> Vec<PathBuf> {
    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return Vec::new(),
    };

    let candidates = [
        // Linux
        home.join(".mozilla/firefox"),
        // macOS
        home.join("Library/Application Support/Firefox/Profiles"),
    ];

    let mut profiles = Vec::new();
    for base in &candidates {
        if !base.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains(".default") {
                    profiles.push(path);
                }
            }
        }
    }
    profiles.sort();
    profiles
}

// ---------------------------------------------------------------------------
// Firefox localStorage reader
// ---------------------------------------------------------------------------

/// Read all localStorage entries from a Firefox profile's `webappsstore.sqlite`.
///
/// Opens the database in read-only mode to avoid conflicts with a running
/// Firefox instance. Returns an empty vec (with a warning) if the database
/// is locked (SQLITE_BUSY) or missing.
pub fn read_firefox_localstorage(profile_path: &Path) -> Result<Vec<BrowserEntry>, SksError> {
    let db_path = profile_path.join("webappsstore.sqlite");
    if !db_path.exists() {
        return Ok(Vec::new());
    }

    let conn = match rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            if is_busy_error(&e) {
                eprintln!(
                    "sks warn: Firefox profile {} is in use. Close Firefox or try again later.",
                    profile_path.display()
                );
                return Ok(Vec::new());
            }
            return Err(SksError::Collector(format!(
                "cannot open {}: {e}",
                db_path.display()
            )));
        }
    };

    // Firefox schema: webappsstore2(originAttributes, originKey, scope, key, value)
    let mut stmt = match conn.prepare("SELECT originKey, key, value FROM webappsstore2") {
        Ok(s) => s,
        Err(e) => {
            if is_busy_error(&e) {
                eprintln!(
                    "sks warn: Firefox profile {} is in use. Close Firefox or try again later.",
                    profile_path.display()
                );
                return Ok(Vec::new());
            }
            // Table might not exist (empty profile, schema change)
            eprintln!(
                "sks warn: cannot read webappsstore2 in {}: {e}",
                db_path.display()
            );
            return Ok(Vec::new());
        }
    };

    let rows = stmt.query_map([], |row| {
        let origin_key: String = row.get(0)?;
        let key: String = row.get(1)?;
        let value: String = row.get(2)?;
        Ok((origin_key, key, value))
    });

    let mut entries = Vec::new();
    match rows {
        Ok(rows) => {
            for row in rows.flatten() {
                let (origin_key, key, value) = row;
                let origin = reverse_origin_key(&origin_key);
                entries.push(BrowserEntry { origin, key, value });
            }
        }
        Err(e) => {
            if is_busy_error(&e) {
                eprintln!(
                    "sks warn: Firefox profile {} is in use. Close Firefox or try again later.",
                    profile_path.display()
                );
            } else {
                eprintln!("sks warn: error reading {}: {e}", db_path.display());
            }
        }
    }

    Ok(entries)
}

/// Check if a rusqlite error is a SQLITE_BUSY / database-locked error.
fn is_busy_error(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy,
                ..
            },
            _
        ) | rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

// ---------------------------------------------------------------------------
// Origin key reversal
// ---------------------------------------------------------------------------

/// Reverse a Firefox `originKey` back to a readable origin URL.
///
/// Firefox stores origin keys with the hostname portion reversed and
/// dot-separated, followed by `:<scheme>:<port>`. Examples:
///   - `moc.elpmaxe.:https:443` → `https://example.com`
///   - `moc.elpmaxe.:http:80`   → `http://example.com`
///   - `gro.allizom.www.:https:443` → `https://www.mozilla.org`
///
/// Default ports (80 for http, 443 for https) are omitted from the output.
pub fn reverse_origin_key(origin_key: &str) -> String {
    // Split on ':' — expected format: reversed_host:scheme:port
    let parts: Vec<&str> = origin_key.split(':').collect();
    if parts.len() < 3 {
        // Unrecognized format — return as-is
        return origin_key.to_string();
    }

    let reversed_host = parts[0];
    let scheme = parts[1];
    let port = parts[2];

    // Reverse the host character-by-character: "moc.elpmaxe." → ".example.com"
    // Then strip the leading dot.
    let host: String = reversed_host.chars().rev().collect();
    let host = host.trim_start_matches('.');

    // Omit default ports
    let is_default_port =
        (scheme == "https" && port == "443") || (scheme == "http" && port == "80");

    if is_default_port || port.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Origin key reversal ---

    #[test]
    fn reverse_https_default_port() {
        assert_eq!(
            reverse_origin_key("moc.elpmaxe.:https:443"),
            "https://example.com"
        );
    }

    #[test]
    fn reverse_http_default_port() {
        assert_eq!(
            reverse_origin_key("moc.elpmaxe.:http:80"),
            "http://example.com"
        );
    }

    #[test]
    fn reverse_custom_port() {
        assert_eq!(
            reverse_origin_key("moc.elpmaxe.:https:8443"),
            "https://example.com:8443"
        );
    }

    #[test]
    fn reverse_subdomain() {
        assert_eq!(
            reverse_origin_key("gro.allizom.www.:https:443"),
            "https://www.mozilla.org"
        );
    }

    #[test]
    fn reverse_deep_subdomain() {
        assert_eq!(
            reverse_origin_key("moc.elpmaxe.ipa.2v.:https:443"),
            "https://v2.api.example.com"
        );
    }

    #[test]
    fn reverse_unrecognized_format() {
        assert_eq!(reverse_origin_key("garbage"), "garbage");
    }

    #[test]
    fn reverse_localhost() {
        assert_eq!(
            reverse_origin_key("tsohlacol.:http:3000"),
            "http://localhost:3000"
        );
    }

    // --- SQLite reader (synthetic database) ---

    #[test]
    fn read_firefox_synthetic_db() {
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
                '', 'moc.elpmaxe.:https:443', '', 'auth_token', 'sk-secret-123'
            );
            INSERT INTO webappsstore2 VALUES (
                '', 'gro.allizom.:https:443', '', 'session', 'abc-def-ghi'
            );",
        )
        .unwrap();
        drop(conn);

        let entries = read_firefox_localstorage(profile).unwrap();
        assert_eq!(entries.len(), 2);

        let token_entry = entries.iter().find(|e| e.key == "auth_token").unwrap();
        assert_eq!(token_entry.origin, "https://example.com");
        assert_eq!(token_entry.value, "sk-secret-123");

        let session_entry = entries.iter().find(|e| e.key == "session").unwrap();
        assert_eq!(session_entry.origin, "https://mozilla.org");
        assert_eq!(session_entry.value, "abc-def-ghi");
    }

    #[test]
    fn read_firefox_missing_db_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let entries = read_firefox_localstorage(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn read_firefox_wrong_schema_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("webappsstore.sqlite");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE other_table (id INTEGER);")
            .unwrap();
        drop(conn);

        let entries = read_firefox_localstorage(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn read_firefox_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("webappsstore.sqlite");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (
                originAttributes TEXT,
                originKey TEXT,
                scope TEXT,
                key TEXT,
                value TEXT
            );",
        )
        .unwrap();
        drop(conn);

        let entries = read_firefox_localstorage(dir.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn read_firefox_db_is_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("webappsstore.sqlite");

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE webappsstore2 (
                originAttributes TEXT,
                originKey TEXT,
                scope TEXT,
                key TEXT,
                value TEXT
            );",
        )
        .unwrap();
        drop(conn);

        // Open via our reader, then verify we can't write
        let read_conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let result = read_conn.execute("INSERT INTO webappsstore2 VALUES ('','','','','')", []);
        assert!(result.is_err());
    }
}
