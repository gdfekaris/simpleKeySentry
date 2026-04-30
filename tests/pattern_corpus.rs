//! Corpus tests for the built-in pattern library.
//!
//! For every pattern in `all_patterns()` this test suite verifies:
//!   - 100 % recall  : every line in `true_positives.txt`  must match.
//!   - 100 % precision: every line in `false_positives.txt` must NOT match.
//!
//! Lines that are blank or start with `#` are treated as comments and skipped.

use simple_key_sentry::detection::patterns::all_patterns;
use simple_key_sentry::detection::CompiledPattern;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/patterns")
}

/// True if `line` would survive the engine's full match → validator gate.
///
/// Mirrors `DetectionEngine::analyze`: a candidate is "matched" only when
/// the regex hits *and* (if present) the rule's validator accepts the
/// captured value. This lets corpus FPs include same-shape strings with
/// broken checksums for validator-gated patterns (e.g. Bitcoin xprv/WIF):
/// they pass the regex but the validator rejects them, so the engine
/// would emit no Finding.
fn matches_with_validator(compiled: &CompiledPattern, line: &str) -> bool {
    let Some(captures) = compiled.regex.captures(line) else {
        return false;
    };
    let value = captures
        .get(1)
        .or_else(|| captures.get(0))
        .map(|m| m.as_str())
        .unwrap_or("");
    if value.is_empty() {
        return false;
    }
    if let Some(validate) = compiled.rule.validator {
        return validate(value);
    }
    true
}

fn run_corpus_test(name: &str) {
    let rule = all_patterns()
        .into_iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("Pattern '{}' not found in all_patterns()", name));

    let compiled = CompiledPattern::compile(rule)
        .unwrap_or_else(|e| panic!("Pattern '{}' failed to compile: {}", name, e));

    let base = corpus_dir().join(name);

    // ── true positives (must match end-to-end: regex + validator) ───────────
    let tp_path = base.join("true_positives.txt");
    let tp_content = std::fs::read_to_string(&tp_path)
        .unwrap_or_else(|_| panic!("Missing true_positives.txt for '{}'", name));

    for line in tp_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            matches_with_validator(&compiled, line),
            "Pattern '{}' should match (true positive): {:?}",
            name,
            line
        );
    }

    // ── false positives (must NOT match end-to-end) ─────────────────────────
    let fp_path = base.join("false_positives.txt");
    let fp_content = std::fs::read_to_string(&fp_path)
        .unwrap_or_else(|_| panic!("Missing false_positives.txt for '{}'", name));

    for line in fp_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            !matches_with_validator(&compiled, line),
            "Pattern '{}' should NOT match (false positive): {:?}",
            name,
            line
        );
    }
}

#[test]
fn corpus_aws_access_key_id() {
    run_corpus_test("aws-access-key-id");
}

#[test]
fn corpus_aws_secret_access_key() {
    run_corpus_test("aws-secret-access-key");
}

#[test]
fn corpus_github_pat() {
    run_corpus_test("github-pat");
}

#[test]
fn corpus_github_oauth() {
    run_corpus_test("github-oauth");
}

#[test]
fn corpus_github_fine_grained_pat() {
    run_corpus_test("github-fine-grained-pat");
}

#[test]
fn corpus_stripe_secret_key() {
    run_corpus_test("stripe-secret-key");
}

#[test]
fn corpus_stripe_test_key() {
    run_corpus_test("stripe-test-key");
}

#[test]
fn corpus_slack_bot_token() {
    run_corpus_test("slack-bot-token");
}

#[test]
fn corpus_slack_user_token() {
    run_corpus_test("slack-user-token");
}

#[test]
fn corpus_private_key_pem() {
    run_corpus_test("private-key-pem");
}

#[test]
fn corpus_jwt() {
    run_corpus_test("jwt");
}

#[test]
fn corpus_database_url() {
    run_corpus_test("database-url");
}

#[test]
fn corpus_generic_connection_string() {
    run_corpus_test("generic-connection-string");
}

#[test]
fn corpus_heroku_api_key() {
    run_corpus_test("heroku-api-key");
}

#[test]
fn corpus_sendgrid_api_key() {
    run_corpus_test("sendgrid-api-key");
}

#[test]
fn corpus_twilio_api_key() {
    run_corpus_test("twilio-api-key");
}

#[test]
fn corpus_npm_token() {
    run_corpus_test("npm-token");
}

#[test]
fn corpus_pypi_token() {
    run_corpus_test("pypi-token");
}

#[test]
fn corpus_generic_bearer_token() {
    run_corpus_test("generic-bearer-token");
}

#[test]
fn corpus_export_secret_assignment() {
    run_corpus_test("export-secret-assignment");
}

// =========================================================================
// Block 15 — Expanded Pattern Library (patterns 21–42)
// =========================================================================

#[test]
fn corpus_gcp_service_account_key() {
    run_corpus_test("gcp-service-account-key");
}

#[test]
fn corpus_gcp_oauth_refresh_token() {
    run_corpus_test("gcp-oauth-refresh-token");
}

#[test]
fn corpus_azure_client_secret() {
    run_corpus_test("azure-client-secret");
}

#[test]
fn corpus_azure_storage_key() {
    run_corpus_test("azure-storage-key");
}

#[test]
fn corpus_azure_sas_token() {
    run_corpus_test("azure-sas-token");
}

#[test]
fn corpus_digitalocean_token() {
    run_corpus_test("digitalocean-token");
}

#[test]
fn corpus_gitlab_pat() {
    run_corpus_test("gitlab-pat");
}

#[test]
fn corpus_gitlab_pipeline_token() {
    run_corpus_test("gitlab-pipeline-token");
}

#[test]
fn corpus_bitbucket_app_password() {
    run_corpus_test("bitbucket-app-password");
}

#[test]
fn corpus_shopify_token() {
    run_corpus_test("shopify-token");
}

#[test]
fn corpus_mailgun_api_key() {
    run_corpus_test("mailgun-api-key");
}

#[test]
fn corpus_datadog_api_key() {
    run_corpus_test("datadog-api-key");
}

#[test]
fn corpus_hashicorp_vault_token() {
    run_corpus_test("hashicorp-vault-token");
}

#[test]
fn corpus_hashicorp_terraform_token() {
    run_corpus_test("hashicorp-terraform-token");
}

#[test]
fn corpus_openai_api_key() {
    run_corpus_test("openai-api-key");
}

#[test]
fn corpus_anthropic_api_key() {
    run_corpus_test("anthropic-api-key");
}

#[test]
fn corpus_docker_auth_base64() {
    run_corpus_test("docker-auth-base64");
}

#[test]
fn corpus_kubernetes_bearer_token() {
    run_corpus_test("kubernetes-bearer-token");
}

#[test]
fn corpus_ssh_unencrypted_key_header() {
    run_corpus_test("ssh-unencrypted-key-header");
}

#[test]
fn corpus_age_secret_key() {
    run_corpus_test("age-secret-key");
}

#[test]
fn corpus_github_app_private_key() {
    run_corpus_test("github-app-private-key");
}

#[test]
fn corpus_basic_auth_url() {
    run_corpus_test("basic-auth-url");
}

// =========================================================================
// Bitcoin MVP — Block B (extended private keys + WIF)
// =========================================================================

#[test]
fn corpus_bitcoin_xprv() {
    run_corpus_test("bitcoin-xprv");
}

#[test]
fn corpus_bitcoin_wif() {
    run_corpus_test("bitcoin-wif");
}

/// Sanity check: all 44 patterns compile successfully from a single RegexSet.
#[test]
fn all_patterns_compile_in_regex_set() {
    use regex::RegexSet;
    let patterns = all_patterns();
    assert_eq!(patterns.len(), 44, "Expected exactly 44 patterns");
    let regexes: Vec<&str> = patterns.iter().map(|p| p.regex.as_str()).collect();
    RegexSet::new(&regexes).expect("One or more patterns failed to compile in RegexSet");
}
