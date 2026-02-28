//! Cloud CLI config collector.
//!
//! Scans well-known credential files written by cloud provider CLIs (AWS,
//! GCP, Azure), container tools (Docker, Kubernetes), and developer tools
//! (GitHub CLI, Hub). Each path is read with the same safety checks as the
//! filesystem collectors and parsed using the structured extractors from
//! [`crate::collectors::structured`].

use std::path::{Path, PathBuf};

use crate::collectors::filesystem::{expand_tilde, try_read_raw};
use crate::collectors::structured::{
    entries_to_content_items, extract_ini, extract_json, extract_yaml, parse_structured_file,
};
use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

// ---------------------------------------------------------------------------
// Cloud target definition
// ---------------------------------------------------------------------------

/// A single cloud config file to scan.
struct CloudTarget {
    path: PathBuf,
    /// Hint used when the file has no recognised extension.
    format_hint: &'static str,
}

/// Returns the hardcoded list of well-known cloud CLI config paths.
fn cloud_config_targets() -> Vec<CloudTarget> {
    let targets: Vec<(&str, &str)> = vec![
        ("~/.aws/credentials", "ini"),
        ("~/.aws/config", "ini"),
        (
            "~/.config/gcloud/application_default_credentials.json",
            "json",
        ),
        ("~/.config/gcloud/properties", "ini"),
        ("~/.azure/accessTokens.json", "json"),
        ("~/.azure/azureProfile.json", "json"),
        ("~/.azure/msal_token_cache.json", "json"),
        ("~/.docker/config.json", "json"),
        ("~/.kube/config", "yaml"),
        ("~/.config/gh/hosts.yml", "yaml"),
        ("~/.config/hub", "yaml"),
    ];

    targets
        .into_iter()
        .map(|(p, hint)| CloudTarget {
            path: expand_tilde(Path::new(p)),
            format_hint: hint,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Format-aware parsing
// ---------------------------------------------------------------------------

/// Parses a cloud config file using structured extractors.
///
/// If the file has a recognised extension (`.json`, `.yaml`, `.yml`, `.ini`,
/// `.toml`), delegates to [`parse_structured_file`]. Otherwise uses
/// `format_hint` to call the correct extractor directly. Falls back to
/// line-by-line scanning on parse failure.
fn parse_cloud_config(
    path: &Path,
    raw: &str,
    format_hint: &str,
    source_type: SourceType,
) -> Vec<ContentItem> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // If the file has a recognised extension, use the standard dispatcher.
    if matches!(
        ext.as_str(),
        "json" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf"
    ) {
        return parse_structured_file(path, raw, source_type);
    }

    // No recognised extension — use the format hint.
    let result = match format_hint {
        "json" => extract_json(raw),
        "yaml" => extract_yaml(raw),
        "ini" => extract_ini(raw),
        _ => {
            return crate::collectors::filesystem::content_to_items(path, source_type, raw);
        }
    };

    match result {
        Ok(entries) if !entries.is_empty() => entries_to_content_items(&entries, path, source_type),
        _ => crate::collectors::filesystem::content_to_items(path, source_type, raw),
    }
}

// ---------------------------------------------------------------------------
// CloudCliCollector
// ---------------------------------------------------------------------------

/// Scans well-known cloud CLI config files for leaked credentials.
///
/// Targets include AWS credentials, GCP application default credentials,
/// Azure tokens, Docker auth, Kubernetes config, and GitHub CLI/Hub configs.
/// Missing files are silently skipped.
pub struct CloudCliCollector;

impl Collector for CloudCliCollector {
    fn name(&self) -> &str {
        "Cloud CLI Configs"
    }

    fn source_type(&self) -> SourceType {
        SourceType::CloudConfig
    }

    fn is_available(&self) -> bool {
        true
    }

    fn collect(&self, config: &ScanConfig) -> Result<Vec<ContentItem>, SksError> {
        let mut items = Vec::new();

        let exclude_regexes: Vec<regex::Regex> = config
            .exclude_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        for target in cloud_config_targets() {
            // Check exclude_paths.
            if config
                .exclude_paths
                .iter()
                .any(|ex| target.path.starts_with(ex) || target.path == *ex)
            {
                continue;
            }

            // Check exclude_patterns.
            let path_str = target.path.to_string_lossy();
            if exclude_regexes.iter().any(|re| re.is_match(&path_str)) {
                continue;
            }

            if let Some(raw) = try_read_raw(&target.path, config.max_file_size)? {
                let parsed = parse_cloud_config(
                    &target.path,
                    &raw,
                    target.format_hint,
                    SourceType::CloudConfig,
                );
                items.extend(parsed);
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
    use std::collections::HashSet;
    use std::fs::{self, File};
    use std::io::Write;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn tmp(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sks_test_cloud_{suffix}"));
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

    // ── Config targets ──────────────────────────────────────────────────────

    #[test]
    fn all_targets_expand_tilde() {
        let targets = cloud_config_targets();
        for t in &targets {
            assert!(
                !t.path.to_string_lossy().starts_with('~'),
                "path should be expanded: {:?}",
                t.path
            );
        }
    }

    #[test]
    fn no_duplicate_paths() {
        let targets = cloud_config_targets();
        let paths: HashSet<_> = targets.iter().map(|t| t.path.clone()).collect();
        assert_eq!(paths.len(), targets.len(), "duplicate paths in target list");
    }

    // ── AWS INI parsing ─────────────────────────────────────────────────────

    #[test]
    fn aws_credentials_parsed_as_ini() {
        let dir = tmp("aws_creds");
        let cred = dir.join("credentials");
        write_file(
            &cred,
            "[default]\n\
             aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n\
             aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        );

        let items = parse_cloud_config(
            &cred,
            &fs::read_to_string(&cred).unwrap(),
            "ini",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("aws_access_key_id")),
            "should contain access key"
        );
        assert!(
            items
                .iter()
                .any(|i| i.line.contains("aws_secret_access_key")),
            "should contain secret key"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn aws_config_with_sso_parsed() {
        let dir = tmp("aws_config");
        let conf = dir.join("config");
        write_file(
            &conf,
            "[profile dev]\n\
             sso_start_url = https://my-sso.awsapps.com/start\n\
             sso_region = us-east-1\n\
             sso_account_id = 123456789012\n\
             sso_role_name = AdminRole\n",
        );

        let items = parse_cloud_config(
            &conf,
            &fs::read_to_string(&conf).unwrap(),
            "ini",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("sso_start_url")),
            "should contain SSO URL"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_skipped_silently() {
        let mut config = test_config();
        config.max_file_size = 1024 * 1024;
        let result = try_read_raw(Path::new("/no/such/cloud/config"), config.max_file_size);
        assert!(result.unwrap().is_none());
    }

    // ── GCP JSON parsing ────────────────────────────────────────────────────

    #[test]
    fn gcp_application_default_credentials_json() {
        let dir = tmp("gcp_adc");
        let adc = dir.join("application_default_credentials.json");
        write_file(
            &adc,
            r#"{
  "client_id": "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com",
  "client_secret": "d-FL95Q19q7MQmFpd7hHD0Ty",
  "refresh_token": "1//0e2bFLbRYfOVnCgYIARAAGA4SNwF-L9IrqI16Xo",
  "type": "authorized_user"
}"#,
        );

        let items = parse_cloud_config(
            &adc,
            &fs::read_to_string(&adc).unwrap(),
            "json",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("client_secret")),
            "should extract client_secret"
        );
        assert!(
            items.iter().any(|i| i.line.contains("refresh_token")),
            "should extract refresh_token"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gcp_properties_extensionless_ini() {
        let dir = tmp("gcp_props");
        let props = dir.join("properties");
        write_file(
            &props,
            "[core]\n\
             project = my-project-123\n\
             account = user@example.com\n",
        );

        let items = parse_cloud_config(
            &props,
            &fs::read_to_string(&props).unwrap(),
            "ini",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("project")),
            "should parse INI properties"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Azure JSON parsing ──────────────────────────────────────────────────

    #[test]
    fn azure_access_tokens_json() {
        let dir = tmp("azure_tokens");
        let tokens = dir.join("accessTokens.json");
        write_file(
            &tokens,
            r#"[{
  "tokenType": "Bearer",
  "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Imk2bEdrM0Z",
  "expiresOn": "2024-01-15 10:30:00"
}]"#,
        );

        let items = parse_cloud_config(
            &tokens,
            &fs::read_to_string(&tokens).unwrap(),
            "json",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("accessToken")),
            "should extract accessToken"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn azure_msal_token_cache() {
        let dir = tmp("azure_msal");
        let msal = dir.join("msal_token_cache.json");
        write_file(
            &msal,
            r#"{
  "AccessToken": {
    "entry1": {
      "secret": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    }
  }
}"#,
        );

        let items = parse_cloud_config(
            &msal,
            &fs::read_to_string(&msal).unwrap(),
            "json",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("secret")),
            "should extract MSAL secret"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Docker JSON parsing ─────────────────────────────────────────────────

    #[test]
    fn docker_config_with_auth() {
        let dir = tmp("docker_auth");
        let docker = dir.join("config.json");
        write_file(
            &docker,
            r#"{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dXNlcm5hbWU6cGFzc3dvcmQ="
    }
  }
}"#,
        );

        let items = parse_cloud_config(
            &docker,
            &fs::read_to_string(&docker).unwrap(),
            "json",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("auth")),
            "should extract auth token"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn docker_config_with_credsstore_no_leaked_secret() {
        let dir = tmp("docker_credsstore");
        let docker = dir.join("config.json");
        write_file(
            &docker,
            r#"{
  "credsStore": "desktop",
  "currentContext": "default"
}"#,
        );

        let items = parse_cloud_config(
            &docker,
            &fs::read_to_string(&docker).unwrap(),
            "json",
            SourceType::CloudConfig,
        );
        // Should still parse but won't contain auth secrets
        assert!(
            !items.iter().any(|i| i.line.contains("auth:")),
            "credsStore config should not contain auth tokens"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Kubernetes YAML ─────────────────────────────────────────────────────

    #[test]
    fn kubernetes_config_with_token() {
        let dir = tmp("kube_config");
        let kube = dir.join("config");
        write_file(
            &kube,
            "apiVersion: v1\n\
             kind: Config\n\
             users:\n\
             - name: admin\n\
               user:\n\
                 token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\n\
                 password: supersecretpassword123\n",
        );

        let items = parse_cloud_config(
            &kube,
            &fs::read_to_string(&kube).unwrap(),
            "yaml",
            SourceType::CloudConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("token")),
            "should extract user token"
        );
        assert!(
            items.iter().any(|i| i.line.contains("password")),
            "should extract user password"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kubernetes_empty_config() {
        let dir = tmp("kube_empty");
        let kube = dir.join("config");
        write_file(&kube, "apiVersion: v1\nkind: Config\nclusters: []\n");

        let items = parse_cloud_config(
            &kube,
            &fs::read_to_string(&kube).unwrap(),
            "yaml",
            SourceType::CloudConfig,
        );
        // Should parse without error, even if mostly empty
        assert!(
            items
                .iter()
                .all(|i| i.source_type == SourceType::CloudConfig),
            "all items should have CloudConfig source"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Exclusion filtering ─────────────────────────────────────────────────

    #[test]
    fn exclude_paths_skips_target() {
        let dir = tmp("excl_path");
        let cred = dir.join("credentials");
        write_file(
            &cred,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        );

        // Build a CloudTarget manually and test with exclude
        let mut config = test_config();
        config.exclude_paths = vec![dir.clone()];

        let targets = vec![CloudTarget {
            path: cred,
            format_hint: "ini",
        }];

        let exclude_regexes: Vec<regex::Regex> = config
            .exclude_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        let mut items = Vec::new();
        for target in targets {
            if config
                .exclude_paths
                .iter()
                .any(|ex| target.path.starts_with(ex) || target.path == *ex)
            {
                continue;
            }
            let path_str = target.path.to_string_lossy();
            if exclude_regexes.iter().any(|re| re.is_match(&path_str)) {
                continue;
            }
            if let Some(raw) = try_read_raw(&target.path, config.max_file_size).unwrap() {
                items.extend(parse_cloud_config(
                    &target.path,
                    &raw,
                    target.format_hint,
                    SourceType::CloudConfig,
                ));
            }
        }

        assert!(items.is_empty(), "excluded path should produce no items");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exclude_patterns_skips_target() {
        let dir = tmp("excl_pattern");
        let cred = dir.join("credentials");
        write_file(
            &cred,
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        );

        let mut config = test_config();
        config.exclude_patterns = vec![r"credentials$".to_string()];

        let targets = vec![CloudTarget {
            path: cred,
            format_hint: "ini",
        }];

        let exclude_regexes: Vec<regex::Regex> = config
            .exclude_patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();

        let mut items = Vec::new();
        for target in targets {
            if config
                .exclude_paths
                .iter()
                .any(|ex| target.path.starts_with(ex) || target.path == *ex)
            {
                continue;
            }
            let path_str = target.path.to_string_lossy();
            if exclude_regexes.iter().any(|re| re.is_match(&path_str)) {
                continue;
            }
            if let Some(raw) = try_read_raw(&target.path, config.max_file_size).unwrap() {
                items.extend(parse_cloud_config(
                    &target.path,
                    &raw,
                    target.format_hint,
                    SourceType::CloudConfig,
                ));
            }
        }

        assert!(items.is_empty(), "excluded pattern should produce no items");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Binary / oversized skip ─────────────────────────────────────────────

    #[test]
    fn binary_file_skipped() {
        let dir = tmp("cloud_binary");
        let bin = dir.join("config.json");
        let mut f = File::create(&bin).unwrap();
        f.write_all(b"{\"key\": \"val\x00ue\"}").unwrap();

        let result = try_read_raw(&bin, 1024 * 1024).unwrap();
        assert!(result.is_none(), "binary file should be skipped");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Detection integration ───────────────────────────────────────────────

    #[test]
    fn aws_creds_produce_findings() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        let raw = "[default]\n\
                   aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n\
                   aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";

        let items = parse_cloud_config(
            Path::new("/home/user/.aws/credentials"),
            raw,
            "ini",
            SourceType::CloudConfig,
        );

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "AWS credentials should produce findings"
        );
    }

    #[test]
    fn gcp_json_produces_findings() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        // Use a JWT-format token that the detection engine recognises.
        let raw = r#"{
  "client_secret": "d-FL95Q19q7MQmFpd7hHD0Ty",
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpv.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
  "type": "authorized_user"
}"#;

        let items = parse_cloud_config(
            Path::new("/home/user/.config/gcloud/application_default_credentials.json"),
            raw,
            "json",
            SourceType::CloudConfig,
        );

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "GCP credentials should produce findings"
        );
    }
}
