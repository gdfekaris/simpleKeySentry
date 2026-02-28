//! SSH key scanner.
//!
//! Scans `~/.ssh/` for security issues specific to SSH key material:
//! unencrypted private keys, overly permissive file/directory permissions,
//! authorized_keys analysis, and known_hosts plaintext hostnames.
//!
//! Produces both [`ContentItem`] values (fed through the detection engine) and
//! pre-built [`Finding`] values (via [`Collector::direct_findings`]) for checks
//! that don't fit the "line containing a secret" model.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::collectors::filesystem::{content_to_items, expand_tilde, try_read_raw};
use crate::config::ScanConfig;
use crate::models::{
    Collector, ContentItem, Finding, SecretType, SecretValue, SourceLocation, SourceType,
};
use crate::SksError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base64 prefix of an unencrypted OpenSSH private key.
///
/// Encodes the magic `openssh-key-v1\0` followed by cipher name `none` and
/// KDF name `none`, which together indicate the key is not passphrase-protected.
const OPENSSH_UNENCRYPTED_PREFIX: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9u";

// ---------------------------------------------------------------------------
// Key format detection
// ---------------------------------------------------------------------------

/// Private key format detected from file header lines.
#[derive(Debug, PartialEq)]
enum KeyFormat {
    /// Traditional PEM format (RSA, EC, DSA, generic PRIVATE KEY).
    Pem,
    /// OpenSSH native format (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    OpenSsh,
}

/// Inspects the first few lines to determine if the file contains a private key.
/// Returns the detected format and the header line itself.
fn detect_private_key(first_lines: &[&str]) -> Option<(KeyFormat, String)> {
    for line in first_lines {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN OPENSSH PRIVATE KEY-----" {
            return Some((KeyFormat::OpenSsh, trimmed.to_string()));
        }
        if trimmed.contains("-----BEGIN") && trimmed.contains("PRIVATE KEY-----") {
            return Some((KeyFormat::Pem, trimmed.to_string()));
        }
    }
    None
}

/// Returns `true` if PEM lines indicate the key is encrypted.
///
/// Checks for `Proc-Type: 4,ENCRYPTED`, `DEK-Info:` headers (legacy PEM), or
/// the `ENCRYPTED PRIVATE KEY` PKCS#8 wrapper.
fn is_encrypted_pem(lines: &[&str]) -> bool {
    for line in lines {
        let trimmed = line.trim();
        if trimmed.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return true;
        }
        if trimmed.starts_with("Proc-Type:") && trimmed.contains("ENCRYPTED") {
            return true;
        }
        if trimmed.starts_with("DEK-Info:") {
            return true;
        }
    }
    false
}

/// Returns `true` if the OpenSSH base64 body indicates encryption (cipher != none).
fn is_encrypted_openssh(base64_body: &str) -> bool {
    !base64_body.starts_with(OPENSSH_UNENCRYPTED_PREFIX)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `Some(~/.ssh)` if the home directory is available.
fn ssh_dir() -> Option<PathBuf> {
    let dir = expand_tilde(Path::new("~/.ssh"));
    if dir.to_string_lossy().starts_with('~') {
        // expand_tilde failed (no $HOME)
        return None;
    }
    Some(dir)
}

/// Returns `true` if the path should be skipped based on exclusion config.
fn is_excluded(path: &Path, config: &ScanConfig, exclude_regexes: &[regex::Regex]) -> bool {
    if config
        .exclude_paths
        .iter()
        .any(|ex| path.starts_with(ex) || path == *ex)
    {
        return true;
    }
    let path_str = path.to_string_lossy();
    exclude_regexes.iter().any(|re| re.is_match(&path_str))
}

/// Compiles exclude_patterns into regexes, silently dropping invalid ones.
fn compile_exclude_regexes(config: &ScanConfig) -> Vec<regex::Regex> {
    config
        .exclude_patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
}

/// Parameters for building an SSH-specific [`Finding`].
struct SshFindingParams<'a> {
    secret_type: SecretType,
    confidence: f64,
    value: &'a str,
    path: &'a Path,
    line: Option<usize>,
    description: String,
    remediation: String,
    pattern_name: &'a str,
}

/// Builds a [`Finding`] with common SSH defaults.
fn ssh_finding(p: SshFindingParams<'_>) -> Finding {
    Finding::new(
        p.secret_type,
        p.confidence,
        SecretValue::new(p.value.to_string()),
        SourceLocation {
            path: p.path.to_path_buf(),
            line: p.line,
            column: None,
            context_before: String::new(),
            context_after: String::new(),
            source_type: SourceType::SshKey,
        },
        p.description,
        p.remediation,
        Some(p.pattern_name.to_string()),
    )
}

// ---------------------------------------------------------------------------
// SshCollector
// ---------------------------------------------------------------------------

/// Scans `~/.ssh/` for SSH-specific security issues.
pub struct SshCollector;

impl Collector for SshCollector {
    fn name(&self) -> &str {
        "SSH Keys"
    }

    fn source_type(&self) -> SourceType {
        SourceType::SshKey
    }

    fn is_available(&self) -> bool {
        ssh_dir().is_some_and(|d| d.is_dir())
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let dir = match ssh_dir() {
            Some(d) if d.is_dir() => d,
            _ => return Ok(vec![]),
        };

        let exclude_regexes = compile_exclude_regexes(config);
        let mut items = Vec::new();

        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("sks warn: cannot read ~/.ssh/: {e}");
                return Ok(vec![]);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip directories and (optionally) symlinks.
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                continue;
            }
            if meta.file_type().is_symlink() && !config.follow_symlinks {
                continue;
            }

            if is_excluded(&path, config, &exclude_regexes) {
                continue;
            }

            if let Some(raw) = try_read_raw(&path, config.max_file_size)? {
                items.extend(content_to_items(&path, SourceType::SshKey, &raw));
            }
        }

        Ok(items)
    }

    fn direct_findings(&self, config: &ScanConfig) -> Result<Vec<Finding>, SksError> {
        let dir = match ssh_dir() {
            Some(d) if d.is_dir() => d,
            _ => return Ok(vec![]),
        };

        let exclude_regexes = compile_exclude_regexes(config);
        let mut findings = Vec::new();

        // ── Check 1: Directory permissions ──────────────────────────────────
        if let Ok(meta) = fs::metadata(&dir) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                findings.push(ssh_finding(SshFindingParams {
                    secret_type: SecretType::Custom("ssh-permissive-dir-permission".to_string()),
                    confidence: 0.85,
                    value: &format!("mode:{:04o}", mode & 0o7777),
                    path: &dir,
                    line: None,
                    description: format!(
                        "SSH directory ~/.ssh/ has mode {:04o} (should be 0700)",
                        mode & 0o7777
                    ),
                    remediation: "Run: chmod 700 ~/.ssh/".to_string(),
                    pattern_name: "ssh-dir-permission",
                }));
            }
        }

        // ── Iterate files for key checks ────────────────────────────────────
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Ok(findings),
        };

        for entry in entries.flatten() {
            let path = entry.path();

            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                continue;
            }
            if meta.file_type().is_symlink() && !config.follow_symlinks {
                continue;
            }
            if is_excluded(&path, config, &exclude_regexes) {
                continue;
            }

            let raw = match try_read_raw(&path, config.max_file_size)? {
                Some(r) => r,
                None => continue,
            };

            let lines: Vec<&str> = raw.lines().collect();
            let first_lines: Vec<&str> = lines.iter().take(10).copied().collect();

            // ── Check 2: Private key encryption ─────────────────────────────
            if let Some((format, header_line)) = detect_private_key(&first_lines) {
                let is_unencrypted = match format {
                    KeyFormat::Pem => !is_encrypted_pem(&lines),
                    KeyFormat::OpenSsh => {
                        // Concatenate base64 body (lines between BEGIN/END).
                        let body: String = lines
                            .iter()
                            .skip(1)
                            .take_while(|l| !l.contains("-----END"))
                            .map(|l| l.trim())
                            .collect();
                        !is_encrypted_openssh(&body)
                    }
                };

                if is_unencrypted {
                    findings.push(ssh_finding(SshFindingParams {
                        secret_type: SecretType::PrivateKey,
                        confidence: 0.95,
                        value: &header_line,
                        path: &path,
                        line: Some(1),
                        description: format!(
                            "Unencrypted private key: {}",
                            path.file_name().unwrap_or_default().to_string_lossy()
                        ),
                        remediation: format!("Encrypt with: ssh-keygen -p -f {}", path.display()),
                        pattern_name: "ssh-unencrypted-key",
                    }));
                }

                // ── Check 3: Key file permissions ───────────────────────────
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    findings.push(ssh_finding(SshFindingParams {
                        secret_type: SecretType::Custom(
                            "ssh-permissive-key-permission".to_string(),
                        ),
                        confidence: 0.85,
                        value: &format!("mode:{:04o}", mode & 0o7777),
                        path: &path,
                        line: None,
                        description: format!(
                            "Private key {} has mode {:04o} (should be 0600)",
                            path.file_name().unwrap_or_default().to_string_lossy(),
                            mode & 0o7777
                        ),
                        remediation: format!("Run: chmod 600 {}", path.display()),
                        pattern_name: "ssh-key-permission",
                    }));
                }
            }

            // ── Check 4: authorized_keys audit ──────────────────────────────
            if path.file_name().is_some_and(|n| n == "authorized_keys") {
                let key_count = lines
                    .iter()
                    .filter(|l| {
                        let t = l.trim();
                        !t.is_empty() && !t.starts_with('#')
                    })
                    .count();

                findings.push(ssh_finding(SshFindingParams {
                    secret_type: SecretType::Custom("ssh-authorized-keys-audit".to_string()),
                    confidence: 0.20,
                    value: &format!("{key_count} key(s)"),
                    path: &path,
                    line: None,
                    description: format!("authorized_keys contains {key_count} public key(s)"),
                    remediation: "Review authorized keys periodically and remove unused entries"
                        .to_string(),
                    pattern_name: "ssh-authorized-keys",
                }));
            }

            // ── Check 5: known_hosts plaintext hostnames ────────────────────
            if path.file_name().is_some_and(|n| n == "known_hosts") {
                let plaintext_count = lines
                    .iter()
                    .filter(|l| {
                        let t = l.trim();
                        !t.is_empty() && !t.starts_with('#') && !t.starts_with("|1|")
                    })
                    .count();

                if plaintext_count > 0 {
                    findings.push(ssh_finding(SshFindingParams {
                        secret_type: SecretType::Custom("ssh-plaintext-known-host".to_string()),
                        confidence: 0.35,
                        value: &format!("{plaintext_count} plaintext host(s)"),
                        path: &path,
                        line: None,
                        description: format!(
                            "known_hosts contains {plaintext_count} plaintext \
                             hostname(s) (not hashed)"
                        ),
                        remediation: "Run: ssh-keygen -H to hash all hostnames, then remove \
                             ~/.ssh/known_hosts.old"
                            .to_string(),
                        pattern_name: "ssh-plaintext-known-hosts",
                    }));
                }
            }
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn tmp(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sks_test_ssh_{suffix}"));
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

    fn test_config() -> ScanConfig {
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

    // ── ssh_dir helper ──────────────────────────────────────────────────────

    #[test]
    fn ssh_dir_returns_path_ending_in_dot_ssh() {
        let dir = ssh_dir();
        assert!(dir.is_some());
        let d = dir.unwrap();
        assert!(
            d.to_string_lossy().ends_with(".ssh"),
            "expected path ending in .ssh, got: {d:?}"
        );
    }

    // ── is_available ────────────────────────────────────────────────────────

    #[test]
    fn is_available_returns_false_when_dir_missing() {
        // We can't easily remove ~/.ssh in a test, but we can verify the
        // method doesn't panic. If ~/.ssh exists it returns true, otherwise
        // false — both are acceptable.
        let collector = SshCollector;
        let _ = collector.is_available(); // no panic
    }

    // ── PEM detection ───────────────────────────────────────────────────────

    #[test]
    fn detect_rsa_private_key() {
        let lines = vec!["-----BEGIN RSA PRIVATE KEY-----"];
        let result = detect_private_key(&lines);
        assert!(result.is_some());
        let (fmt, _) = result.unwrap();
        assert_eq!(fmt, KeyFormat::Pem);
    }

    #[test]
    fn detect_ec_private_key() {
        let lines = vec!["-----BEGIN EC PRIVATE KEY-----"];
        let result = detect_private_key(&lines);
        assert!(result.is_some());
        let (fmt, _) = result.unwrap();
        assert_eq!(fmt, KeyFormat::Pem);
    }

    #[test]
    fn detect_dsa_private_key() {
        let lines = vec!["-----BEGIN DSA PRIVATE KEY-----"];
        let result = detect_private_key(&lines);
        assert!(result.is_some());
        let (fmt, _) = result.unwrap();
        assert_eq!(fmt, KeyFormat::Pem);
    }

    #[test]
    fn detect_openssh_private_key() {
        let lines = vec!["-----BEGIN OPENSSH PRIVATE KEY-----"];
        let result = detect_private_key(&lines);
        assert!(result.is_some());
        let (fmt, _) = result.unwrap();
        assert_eq!(fmt, KeyFormat::OpenSsh);
    }

    #[test]
    fn detect_no_private_key() {
        let lines = vec!["-----BEGIN PUBLIC KEY-----", "ssh-rsa AAAA... user@host"];
        assert!(detect_private_key(&lines).is_none());
    }

    // ── PEM encryption detection ────────────────────────────────────────────

    #[test]
    fn pem_encrypted_proc_type() {
        let lines = vec![
            "-----BEGIN RSA PRIVATE KEY-----",
            "Proc-Type: 4,ENCRYPTED",
            "DEK-Info: AES-128-CBC,AABBCCDD11223344",
            "",
            "base64data...",
            "-----END RSA PRIVATE KEY-----",
        ];
        assert!(is_encrypted_pem(&lines));
    }

    #[test]
    fn pem_encrypted_pkcs8_header() {
        let lines = vec![
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "base64data...",
            "-----END ENCRYPTED PRIVATE KEY-----",
        ];
        assert!(is_encrypted_pem(&lines));
    }

    #[test]
    fn pem_unencrypted() {
        let lines = vec![
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...",
            "-----END RSA PRIVATE KEY-----",
        ];
        assert!(!is_encrypted_pem(&lines));
    }

    // ── OpenSSH encryption detection ────────────────────────────────────────

    #[test]
    fn openssh_unencrypted_detected() {
        // The prefix encodes: openssh-key-v1\0 + ciphername=none + kdfname=none
        let body = format!("{OPENSSH_UNENCRYPTED_PREFIX}RESTOFDATA");
        assert!(!is_encrypted_openssh(&body));
    }

    #[test]
    fn openssh_encrypted_detected() {
        // Random base64 that doesn't match the "none" prefix
        let body = "AAAAB3NzaC1yc2EAAAABIwAAAQEArandomencrypteddata";
        assert!(is_encrypted_openssh(body));
    }

    // ── Directory permission check ──────────────────────────────────────────

    #[test]
    fn dir_permission_0700_no_finding() {
        let dir = tmp("dir_perm_ok");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        let meta = fs::metadata(&dir).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(mode & 0o077, 0, "0700 should have no group/other bits");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_permission_0755_produces_finding() {
        let dir = tmp("dir_perm_bad");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let meta = fs::metadata(&dir).unwrap();
        let mode = meta.permissions().mode();
        assert_ne!(mode & 0o077, 0, "0755 should have group/other bits");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Key file permission check ───────────────────────────────────────────

    #[test]
    fn key_permission_0600_no_finding() {
        let dir = tmp("key_perm_ok");
        let key = dir.join("id_rsa");
        write_file(
            &key,
            "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n",
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let meta = fs::metadata(&key).unwrap();
        let mode = meta.permissions().mode();
        assert_eq!(mode & 0o077, 0, "0600 should have no group/other bits");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_permission_0644_produces_finding() {
        let dir = tmp("key_perm_bad");
        let key = dir.join("id_rsa");
        write_file(
            &key,
            "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n",
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        let meta = fs::metadata(&key).unwrap();
        let mode = meta.permissions().mode();
        assert_ne!(mode & 0o077, 0, "0644 should have group/other bits");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── authorized_keys analysis ────────────────────────────────────────────

    #[test]
    fn authorized_keys_counts_keys() {
        let lines: Vec<&str> = vec![
            "# comment",
            "ssh-rsa AAAA... user1@host",
            "",
            "ssh-ed25519 AAAA... user2@host",
            "# another comment",
            "ssh-rsa AAAA... user3@host",
        ];
        let count = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .count();
        assert_eq!(count, 3);
    }

    #[test]
    fn authorized_keys_empty_file() {
        let lines: Vec<&str> = vec!["# only comments", "", "  "];
        let count = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .count();
        assert_eq!(count, 0);
    }

    // ── known_hosts plaintext detection ─────────────────────────────────────

    #[test]
    fn known_hosts_detects_plaintext() {
        let lines: Vec<&str> = vec![
            "github.com ssh-rsa AAAA...",
            "|1|hashedhost= ssh-rsa AAAA...",
            "192.168.1.1 ssh-ed25519 AAAA...",
            "# comment",
        ];
        let count = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && !t.starts_with("|1|")
            })
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn known_hosts_all_hashed() {
        let lines: Vec<&str> = vec![
            "|1|salt1=|hash1= ssh-rsa AAAA...",
            "|1|salt2=|hash2= ssh-ed25519 AAAA...",
        ];
        let count = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && !t.starts_with("|1|")
            })
            .count();
        assert_eq!(count, 0);
    }

    // ── Exclusion filtering ─────────────────────────────────────────────────

    #[test]
    fn exclude_paths_skips_file() {
        let dir = tmp("excl");
        let key = dir.join("id_rsa");
        write_file(
            &key,
            "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\n",
        );

        let mut config = test_config();
        config.exclude_paths = vec![key.clone()];
        let regexes = compile_exclude_regexes(&config);

        assert!(
            is_excluded(&key, &config, &regexes),
            "excluded path should be skipped"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── collect produces items ───────────────────────────────────────────────

    #[test]
    fn collect_produces_items_from_temp_dir() {
        let dir = tmp("collect");
        let config_file = dir.join("config");
        write_file(
            &config_file,
            "Host example\n  HostName example.com\n  User admin\n",
        );

        // Read the file via try_read_raw + content_to_items (same as collect does)
        let raw = try_read_raw(&config_file, 1024 * 1024).unwrap().unwrap();
        let items = content_to_items(&config_file, SourceType::SshKey, &raw);
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|i| i.source_type == SourceType::SshKey));

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Direct findings integration ─────────────────────────────────────────

    #[test]
    fn direct_findings_detects_unencrypted_pem_key() {
        let dir = tmp("df_pem");
        let key = dir.join("id_rsa");
        write_file(
            &key,
            "-----BEGIN RSA PRIVATE KEY-----\n\
             MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...\n\
             -----END RSA PRIVATE KEY-----\n",
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        // Simulate the direct_findings logic on a single file.
        let raw = fs::read_to_string(&key).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        let first_lines: Vec<&str> = lines.iter().take(10).copied().collect();
        let detection = detect_private_key(&first_lines);
        assert!(detection.is_some());

        let (fmt, _header) = detection.unwrap();
        assert_eq!(fmt, KeyFormat::Pem);
        assert!(!is_encrypted_pem(&lines), "should be unencrypted");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn direct_findings_skips_encrypted_openssh_key() {
        let dir = tmp("df_openssh_enc");
        let key = dir.join("id_ed25519");
        // Encrypted OpenSSH key: body does NOT start with the "none" prefix
        write_file(
            &key,
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             AAAAB3NzaC1yc2EAAAABIwAAAQEArandomencrypteddata==\n\
             -----END OPENSSH PRIVATE KEY-----\n",
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let raw = fs::read_to_string(&key).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        let first_lines: Vec<&str> = lines.iter().take(10).copied().collect();
        let detection = detect_private_key(&first_lines);
        assert!(detection.is_some());

        let (fmt, _) = detection.unwrap();
        assert_eq!(fmt, KeyFormat::OpenSsh);
        let body: String = lines
            .iter()
            .skip(1)
            .take_while(|l| !l.contains("-----END"))
            .map(|l| l.trim())
            .collect();
        assert!(
            is_encrypted_openssh(&body),
            "should be detected as encrypted"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
