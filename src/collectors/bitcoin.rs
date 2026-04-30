//! Bitcoin / Lightning self-custody scanner.
//!
//! Reports on-disk artifacts whose mere presence is a critical signal for
//! Bitcoin self-custody: Core Lightning `hsm_secret`, LND `admin.macaroon`,
//! LND `wallet.db`. Possession of an `hsm_secret` or `admin.macaroon` allows
//! immediate, irreversible theft of all funds and full node control.
//!
//! Path-presence only. Files are never read — possession of the file IS the
//! compromise. The collector emits no [`ContentItem`] values; all output
//! flows through [`Collector::direct_findings`].

use std::path::Path;

use crate::collectors::filesystem::home_dir;
use crate::config::ScanConfig;
use crate::models::{
    Collector, ContentItem, Finding, SecretType, SecretValue, SourceLocation, SourceType,
};
use crate::SksError;

// ---------------------------------------------------------------------------
// Monitored paths
// ---------------------------------------------------------------------------

/// A single Lightning artifact whose presence is a finding.
struct MonitoredPath {
    /// Path relative to the user's home directory.
    relative: &'static str,
    /// Confidence to assign to the finding when the file is present. Maps
    /// to severity via [`Severity::from`]: 1.0 → Critical, 0.75 → High.
    base_confidence: f64,
    /// Pattern name carried on the resulting [`Finding`]; surfaced by the
    /// terminal/JSON/SARIF reporters.
    pattern_name: &'static str,
    /// Short description of why this file is sensitive.
    description: &'static str,
    /// Remediation language. Bitcoin-specific — generic "rotate the key"
    /// advice is wrong for self-custody material. Testnet/regtest variants
    /// explicitly note that the finding is not theft-relevant for real funds.
    remediation: &'static str,
}

const MONITORED: &[MonitoredPath] = &[
    // ── Core Lightning master seed (`hsm_secret`) ──────────────────────────
    // 32 bytes of raw seed material. Possession = full custody of every
    // channel and on-chain output the node controls.
    MonitoredPath {
        relative: ".lightning/bitcoin/hsm_secret",
        base_confidence: 1.0,
        pattern_name: "lightning-clightning-hsm-secret",
        description: "Core Lightning master seed (hsm_secret) on mainnet. \
                      Possession allows immediate, irreversible theft of all funds in every \
                      channel and on-chain output controlled by this node.",
        remediation: "Force-close all Lightning channels and recover the on-chain funds. \
                      Generate a new node identity on a clean device. Do NOT restore from \
                      this hsm_secret — treat every channel and address ever derived from \
                      it as compromised forever.",
    },
    MonitoredPath {
        relative: ".lightning/testnet/hsm_secret",
        base_confidence: 1.0,
        pattern_name: "lightning-clightning-hsm-secret",
        description: "Core Lightning master seed (hsm_secret) on TESTNET. Testnet coins have \
                      no monetary value, so this finding is NOT theft-relevant for real funds. \
                      It is reported because a testnet seed should not appear on a production \
                      host that may be backed up or shared.",
        remediation: "This is a TESTNET hsm_secret. No real-money sweep is required. \
                      Remove the file from any host that may be backed up or shared, and \
                      confirm no production wallet was generated under testnet by mistake.",
    },
    MonitoredPath {
        relative: ".lightning/regtest/hsm_secret",
        base_confidence: 1.0,
        pattern_name: "lightning-clightning-hsm-secret",
        description: "Core Lightning master seed (hsm_secret) on REGTEST. Regtest is a \
                      local-only chain with no monetary value, so this finding is NOT \
                      theft-relevant for real funds. It is reported because a regtest seed \
                      should not appear on a production host.",
        remediation: "This is a REGTEST hsm_secret. No real-money sweep is required. \
                      Remove the file from any host that may be backed up or shared, and \
                      confirm no production wallet was generated under regtest by mistake.",
    },
    // ── LND admin macaroon ─────────────────────────────────────────────────
    // Bearer token that grants full RPC authority on an LND node: open/close
    // channels, send funds, sign messages.
    MonitoredPath {
        relative: ".lnd/data/chain/bitcoin/mainnet/admin.macaroon",
        base_confidence: 1.0,
        pattern_name: "lightning-lnd-admin-macaroon",
        description: "LND admin macaroon on mainnet. This bearer token grants full control \
                      over the LND node — opening/closing channels, sending funds, signing \
                      messages — to anyone who possesses the file.",
        remediation: "Rotate the macaroons (`lncli bakemacaroon` flow) and rebuild the \
                      macaroon files. Audit recent channel activity. Treat any host that \
                      had this file copied off it as compromised.",
    },
    MonitoredPath {
        relative: ".lnd/data/chain/bitcoin/testnet/admin.macaroon",
        base_confidence: 1.0,
        pattern_name: "lightning-lnd-admin-macaroon",
        description: "LND admin macaroon on TESTNET. Grants full control over the testnet \
                      node, but testnet coins have no monetary value, so this finding is \
                      NOT theft-relevant for real funds.",
        remediation: "This is a TESTNET admin.macaroon. No real-money sweep is required. \
                      Rotate the testnet macaroons and remove the file from any host that \
                      may be backed up or shared.",
    },
    // ── LND on-disk wallet (encrypted) ─────────────────────────────────────
    // The file is encrypted at rest, but its presence is a strong signal:
    // an attacker who copies it off the host has unlimited time to brute
    // force the password.
    MonitoredPath {
        relative: ".lnd/data/chain/bitcoin/mainnet/wallet.db",
        base_confidence: 0.75,
        pattern_name: "lightning-lnd-wallet-db",
        description: "LND wallet database on mainnet. The file is encrypted at rest, but \
                      its presence is a strong signal: an attacker who copies it off the \
                      host can brute-force the password offline at unlimited speed.",
        remediation: "Verify the LND wallet password is strong (long, random, unique). \
                      If the file may have been copied off this host, migrate funds to a \
                      freshly generated wallet.",
    },
];

// ---------------------------------------------------------------------------
// Collector impl
// ---------------------------------------------------------------------------

/// Path-presence scanner for Bitcoin and Lightning self-custody artifacts.
pub struct BitcoinCollector;

impl Collector for BitcoinCollector {
    fn name(&self) -> &str {
        "Bitcoin / Lightning"
    }

    fn source_type(&self) -> SourceType {
        SourceType::Bitcoin
    }

    fn is_available(&self) -> bool {
        let home = home_dir();
        home.join(".lightning").is_dir() || home.join(".lnd").is_dir()
    }

    fn collect(&self, _config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        // Path-presence model: no per-line content to feed the engine.
        Ok(vec![])
    }

    fn direct_findings(&self, _config: &ScanConfig) -> Result<Vec<Finding>, SksError> {
        Ok(direct_findings_under(&home_dir()))
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (testable without HOME redirection)
// ---------------------------------------------------------------------------

/// Returns one [`Finding`] per monitored artifact present under `home`.
fn direct_findings_under(home: &Path) -> Vec<Finding> {
    MONITORED
        .iter()
        .filter_map(|mp| {
            let path = home.join(mp.relative);
            if path.is_file() {
                Some(make_finding(&path, mp))
            } else {
                None
            }
        })
        .collect()
}

fn make_finding(path: &Path, mp: &MonitoredPath) -> Finding {
    Finding::new(
        SecretType::LightningSecret,
        mp.base_confidence,
        // The path itself is the natural value for a presence finding —
        // the file's contents are not a plaintext secret in the redactable
        // sense, and the path gives the user a copy-pasteable target.
        SecretValue::new(path.display().to_string()),
        SourceLocation {
            path: path.to_path_buf(),
            line: None,
            column: None,
            context_before: String::new(),
            context_after: String::new(),
            source_type: SourceType::Bitcoin,
        },
        mp.description.to_string(),
        mp.remediation.to_string(),
        Some(mp.pattern_name.to_string()),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    use crate::models::Severity;

    /// Build an empty fake-HOME tempdir.
    fn fake_home() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Create a file at `home/relative`, building parent directories as needed.
    fn touch(home: &Path, relative: &str) -> PathBuf {
        let path = home.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create dirs");
        }
        fs::write(&path, b"x").expect("write");
        path
    }

    #[test]
    fn collect_returns_empty_vec() {
        let collector = BitcoinCollector;
        let items = collector.collect(&ScanConfig::default()).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn is_available_does_not_panic() {
        // Cannot reliably remove ~/.lightning or ~/.lnd in a test, so just
        // verify the call doesn't panic. Either outcome is acceptable.
        let _ = BitcoinCollector.is_available();
    }

    #[test]
    fn direct_findings_under_empty_home_is_empty() {
        let home = fake_home();
        let findings = direct_findings_under(home.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn direct_findings_under_emits_critical_for_clightning_hsm_secret() {
        let home = fake_home();
        let path = touch(home.path(), ".lightning/bitcoin/hsm_secret");
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.secret_type, SecretType::LightningSecret);
        assert_eq!(f.location.source_type, SourceType::Bitcoin);
        assert_eq!(
            f.matched_pattern.as_deref(),
            Some("lightning-clightning-hsm-secret")
        );
        assert_eq!(f.value.raw(), path.display().to_string());
    }

    #[test]
    fn direct_findings_under_emits_critical_for_lnd_admin_macaroon() {
        let home = fake_home();
        touch(
            home.path(),
            ".lnd/data/chain/bitcoin/mainnet/admin.macaroon",
        );
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(
            f.matched_pattern.as_deref(),
            Some("lightning-lnd-admin-macaroon")
        );
    }

    #[test]
    fn direct_findings_under_emits_high_for_lnd_wallet_db() {
        let home = fake_home();
        touch(home.path(), ".lnd/data/chain/bitcoin/mainnet/wallet.db");
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(
            f.matched_pattern.as_deref(),
            Some("lightning-lnd-wallet-db")
        );
    }

    #[test]
    fn testnet_finding_carries_testnet_specific_remediation() {
        let home = fake_home();
        touch(home.path(), ".lightning/testnet/hsm_secret");
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        // The remediation must explicitly call out the testnet context — a
        // user who reads "sweep funds to a new wallet" on a testnet finding
        // would either panic for nothing or distrust future findings.
        assert!(
            f.remediation.contains("TESTNET"),
            "expected TESTNET in remediation, got: {}",
            f.remediation
        );
        assert!(f.description.contains("TESTNET"));
    }

    #[test]
    fn regtest_finding_carries_regtest_specific_remediation() {
        let home = fake_home();
        touch(home.path(), ".lightning/regtest/hsm_secret");
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(
            f.remediation.contains("REGTEST"),
            "expected REGTEST in remediation, got: {}",
            f.remediation
        );
        assert!(f.description.contains("REGTEST"));
    }

    #[test]
    fn lnd_testnet_admin_macaroon_carries_testnet_remediation() {
        let home = fake_home();
        touch(
            home.path(),
            ".lnd/data/chain/bitcoin/testnet/admin.macaroon",
        );
        let findings = direct_findings_under(home.path());

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.remediation.contains("TESTNET"));
    }

    #[test]
    fn multiple_present_files_yield_multiple_findings() {
        let home = fake_home();
        touch(home.path(), ".lightning/bitcoin/hsm_secret");
        touch(
            home.path(),
            ".lnd/data/chain/bitcoin/mainnet/admin.macaroon",
        );
        touch(home.path(), ".lnd/data/chain/bitcoin/mainnet/wallet.db");

        let findings = direct_findings_under(home.path());
        assert_eq!(findings.len(), 3);
        let pattern_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.matched_pattern.as_deref())
            .collect();
        assert!(pattern_names.contains(&"lightning-clightning-hsm-secret"));
        assert!(pattern_names.contains(&"lightning-lnd-admin-macaroon"));
        assert!(pattern_names.contains(&"lightning-lnd-wallet-db"));
    }

    #[test]
    fn directory_at_monitored_path_is_not_a_finding() {
        // The check is `is_file()`, so a directory at the same path must
        // not trigger a finding. Defensive: protects against weird
        // local layouts where someone has e.g. an `hsm_secret/` directory.
        let home = fake_home();
        fs::create_dir_all(home.path().join(".lightning/bitcoin/hsm_secret")).unwrap();
        let findings = direct_findings_under(home.path());
        assert!(findings.is_empty());
    }
}
