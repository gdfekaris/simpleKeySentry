//! Application config collector.
//!
//! Scans well-known developer tool config files that store credentials in
//! structured formats: npm (`~/.npmrc`), pip (`~/.pypirc`), netrc
//! (`~/.netrc`), pgpass (`~/.pgpass`), MySQL (`~/.my.cnf`), Cargo
//! (`~/.cargo/credentials.toml`), and RubyGems (`~/.gem/credentials`).
//!
//! Custom parsers are provided for `.netrc` and `.pgpass` files which use
//! their own formats. All other files are dispatched to the structured
//! extractors from [`crate::collectors::structured`].

use std::path::{Path, PathBuf};

use crate::collectors::filesystem::{expand_tilde, try_read_raw};
use crate::collectors::structured::{
    entries_to_content_items, extract_ini, extract_toml, extract_yaml, parse_structured_file,
    StructuredEntry,
};
use crate::config::ScanConfig;
use crate::models::{Collector, ContentItem, SourceType};
use crate::SksError;

// ---------------------------------------------------------------------------
// App target definition
// ---------------------------------------------------------------------------

/// A single application config file to scan.
struct AppTarget {
    path: PathBuf,
    /// Hint used when the file has no recognised extension.
    format_hint: &'static str,
}

/// Returns the hardcoded list of well-known application config paths.
fn app_config_targets() -> Vec<AppTarget> {
    let targets: Vec<(&str, &str)> = vec![
        ("~/.npmrc", "ini"),
        ("~/.pypirc", "ini"),
        ("~/.netrc", "netrc"),
        ("~/.pgpass", "pgpass"),
        ("~/.my.cnf", "ini"),
        ("~/.cargo/credentials.toml", "toml"),
        ("~/.cargo/credentials", "toml"),
        ("~/.gem/credentials", "yaml"),
    ];

    targets
        .into_iter()
        .map(|(p, hint)| AppTarget {
            path: expand_tilde(Path::new(p)),
            format_hint: hint,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Format-aware parsing
// ---------------------------------------------------------------------------

/// Parses an application config file using structured extractors.
///
/// If the file has a recognised extension (`.json`, `.yaml`, `.yml`, `.toml`,
/// `.ini`, `.cfg`, `.conf`, `.cnf`), delegates to [`parse_structured_file`].
/// Otherwise uses `format_hint` to call the correct extractor directly,
/// including custom parsers for `netrc` and `pgpass` formats. Falls back to
/// line-by-line scanning on parse failure.
fn parse_app_config(
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
        "json" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "cnf"
    ) {
        return parse_structured_file(path, raw, source_type);
    }

    // No recognised extension — use the format hint.
    let result = match format_hint {
        "json" => crate::collectors::structured::extract_json(raw),
        "yaml" => extract_yaml(raw),
        "toml" => extract_toml(raw),
        "ini" => extract_ini(raw),
        "netrc" => parse_netrc(raw),
        "pgpass" => parse_pgpass(raw),
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
// Custom parser: .netrc
// ---------------------------------------------------------------------------

/// Parses a `.netrc` file into [`StructuredEntry`] values.
///
/// Tokenizes the file by whitespace across lines, then walks tokens:
/// - `machine <host>` / `default` — sets current host context
/// - `login <val>` / `password <val>` / `account <val>` — emits entry
/// - Skips `#` comment lines and `macdef` blocks (which end at blank line)
fn parse_netrc(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let mut entries = Vec::new();
    let mut tokens: Vec<(String, usize)> = Vec::new();

    let mut in_macdef = false;
    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();

        // macdef blocks end at the first blank line.
        if in_macdef {
            if trimmed.is_empty() {
                in_macdef = false;
            }
            continue;
        }

        // Skip comment lines.
        if trimmed.starts_with('#') {
            continue;
        }

        // macdef lines start a macro block; skip the line itself too.
        if trimmed.starts_with("macdef") {
            in_macdef = true;
            continue;
        }

        let line_num = line_idx + 1;
        for word in trimmed.split_whitespace() {
            tokens.push((word.to_string(), line_num));
        }
    }

    let mut current_host = String::new();
    let mut i = 0;
    while i < tokens.len() {
        let (ref tok, _line_num) = tokens[i];
        match tok.as_str() {
            "machine" => {
                i += 1;
                if i < tokens.len() {
                    current_host = tokens[i].0.clone();
                }
            }
            "default" => {
                current_host = "default".to_string();
            }
            "login" | "password" | "account" => {
                let key = tok.clone();
                i += 1;
                if i < tokens.len() {
                    let (ref val, val_line) = tokens[i];
                    let host = if current_host.is_empty() {
                        "unknown"
                    } else {
                        &current_host
                    };
                    entries.push(StructuredEntry {
                        key_path: format!("machine.{host}.{key}"),
                        value: val.clone(),
                        line_number: val_line,
                    });
                }
            }
            _ => {}
        }
        i += 1;
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Custom parser: .pgpass
// ---------------------------------------------------------------------------

/// Parses a `.pgpass` file into [`StructuredEntry`] values.
///
/// Each non-comment line has the format:
/// `hostname:port:database:username:password`
///
/// Emits two entries per valid line: `<host>:<port>:<db>.username` and
/// `<host>:<port>:<db>.password`.
fn parse_pgpass(raw: &str) -> Result<Vec<StructuredEntry>, SksError> {
    let mut entries = Vec::new();

    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let line_num = line_idx + 1;
        let fields = split_pgpass_line(trimmed);

        if fields.len() != 5 {
            continue; // malformed line — skip
        }

        let host = &fields[0];
        let port = &fields[1];
        let db = &fields[2];
        let username = &fields[3];
        let password = &fields[4];
        let prefix = format!("{host}:{port}:{db}");

        entries.push(StructuredEntry {
            key_path: format!("{prefix}.username"),
            value: username.clone(),
            line_number: line_num,
        });
        entries.push(StructuredEntry {
            key_path: format!("{prefix}.password"),
            value: password.clone(),
            line_number: line_num,
        });
    }

    Ok(entries)
}

/// Splits a `.pgpass` line by unescaped colons.
///
/// Handles `\:` (escaped colon — kept as literal `:`) and `\\` (escaped
/// backslash — kept as literal `\`).
fn split_pgpass_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    ':' => {
                        current.push(':');
                        chars.next();
                    }
                    '\\' => {
                        current.push('\\');
                        chars.next();
                    }
                    _ => {
                        current.push(ch);
                    }
                }
            } else {
                current.push(ch);
            }
        } else if ch == ':' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    fields.push(current);
    fields
}

// ---------------------------------------------------------------------------
// AppConfigCollector
// ---------------------------------------------------------------------------

/// Scans well-known application config files for leaked credentials.
///
/// Targets include npm, pip, netrc, pgpass, MySQL, Cargo, and RubyGems
/// config files. Missing files are silently skipped.
pub struct AppConfigCollector;

impl Collector for AppConfigCollector {
    fn name(&self) -> &str {
        "Application Configs"
    }

    fn source_type(&self) -> SourceType {
        SourceType::ApplicationConfig
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

        for target in app_config_targets() {
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
                let parsed = parse_app_config(
                    &target.path,
                    &raw,
                    target.format_hint,
                    SourceType::ApplicationConfig,
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
        let dir = std::env::temp_dir().join(format!("sks_test_app_{suffix}"));
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

    // ── Target list ─────────────────────────────────────────────────────────

    #[test]
    fn all_targets_expand_tilde() {
        let targets = app_config_targets();
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
        let targets = app_config_targets();
        let paths: HashSet<_> = targets.iter().map(|t| t.path.clone()).collect();
        assert_eq!(paths.len(), targets.len(), "duplicate paths in target list");
    }

    // ── parse_netrc ─────────────────────────────────────────────────────────

    #[test]
    fn netrc_multiline() {
        let raw = "\
machine api.github.com
login user@example.com
password ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh
";
        let entries = parse_netrc(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|e| e.key_path == "machine.api.github.com.login"
                    && e.value == "user@example.com")
        );
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.api.github.com.password"
                && e.value == "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"));
    }

    #[test]
    fn netrc_single_line() {
        let raw = "machine api.heroku.com login user password s3cr3tP@ss\n";
        let entries = parse_netrc(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.api.heroku.com.login"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.api.heroku.com.password" && e.value == "s3cr3tP@ss"));
    }

    #[test]
    fn netrc_default_entry() {
        let raw = "default login anonymous password user@example.com\n";
        let entries = parse_netrc(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.default.login" && e.value == "anonymous"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.default.password" && e.value == "user@example.com"));
    }

    #[test]
    fn netrc_comments_skipped() {
        let raw = "\
# This is a comment
machine api.github.com
# Another comment
login user
password secret123
";
        let entries = parse_netrc(raw).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn netrc_macdef_skipped() {
        let raw = "\
machine api.github.com
login user
password tok123
macdef init
cd /pub
get file.txt

machine other.host
login admin
password adminpass
";
        let entries = parse_netrc(raw).unwrap();
        // First machine: 2 entries, macdef skipped, second machine: 2 entries
        assert_eq!(entries.len(), 4);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.other.host.password" && e.value == "adminpass"));
    }

    #[test]
    fn netrc_multiple_machines() {
        let raw = "\
machine host1.com login user1 password pass1
machine host2.com login user2 password pass2
";
        let entries = parse_netrc(raw).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.host1.com.password" && e.value == "pass1"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "machine.host2.com.password" && e.value == "pass2"));
    }

    #[test]
    fn netrc_empty() {
        let entries = parse_netrc("").unwrap();
        assert!(entries.is_empty());
    }

    // ── parse_pgpass ────────────────────────────────────────────────────────

    #[test]
    fn pgpass_standard_entry() {
        let raw = "localhost:5432:mydb:admin:s3cr3t\n";
        let entries = parse_pgpass(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "localhost:5432:mydb.username" && e.value == "admin"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "localhost:5432:mydb.password" && e.value == "s3cr3t"));
    }

    #[test]
    fn pgpass_escaped_colon() {
        let raw = "host\\:name:5432:db:user:pass\\:word\n";
        let entries = parse_pgpass(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.key_path == "host:name:5432:db.username" && e.value == "user"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "host:name:5432:db.password" && e.value == "pass:word"));
    }

    #[test]
    fn pgpass_comments_skipped() {
        let raw = "\
# Comment line
localhost:5432:mydb:admin:s3cr3t
# Another comment
";
        let entries = parse_pgpass(raw).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn pgpass_wildcard() {
        let raw = "*:*:*:postgres:supersecret\n";
        let entries = parse_pgpass(raw).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.key_path == "*:*:*.username"));
        assert!(entries
            .iter()
            .any(|e| e.key_path == "*:*:*.password" && e.value == "supersecret"));
    }

    #[test]
    fn pgpass_malformed_line_skipped() {
        let raw = "\
localhost:5432:mydb:admin:s3cr3t
this:is:not:enough
complete:5433:db2:user2:pass2
";
        let entries = parse_pgpass(raw).unwrap();
        // First line + third line = 4 entries, malformed middle line skipped
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn pgpass_empty() {
        let entries = parse_pgpass("").unwrap();
        assert!(entries.is_empty());
    }

    // ── split_pgpass_line ───────────────────────────────────────────────────

    #[test]
    fn split_basic() {
        let fields = split_pgpass_line("a:b:c:d:e");
        assert_eq!(fields, vec!["a", "b", "c", "d", "e"]);
    }

    #[test]
    fn split_escaped_colon_and_backslash() {
        let fields = split_pgpass_line("h\\:ost:5432:db:u\\\\ser:p\\:ass");
        assert_eq!(fields, vec!["h:ost", "5432", "db", "u\\ser", "p:ass"]);
    }

    // ── Format dispatch ─────────────────────────────────────────────────────

    #[test]
    fn npmrc_parsed_as_ini() {
        let dir = tmp("npmrc");
        let npmrc = dir.join(".npmrc");
        write_file(
            &npmrc,
            "//registry.npmjs.org/:_authToken=npm_aB3dEfGhIjKlMnOpQrStUvWxYz0123456789\n",
        );

        let items = parse_app_config(
            &npmrc,
            &fs::read_to_string(&npmrc).unwrap(),
            "ini",
            SourceType::ApplicationConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("_authToken")),
            "should extract npm auth token"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pypirc_parsed_as_ini() {
        let dir = tmp("pypirc");
        let pypirc = dir.join(".pypirc");
        write_file(
            &pypirc,
            "[pypi]\nusername = __token__\npassword = pypi-AgEIcHlwaS5vcmcCJDY\n",
        );

        let items = parse_app_config(
            &pypirc,
            &fs::read_to_string(&pypirc).unwrap(),
            "ini",
            SourceType::ApplicationConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("password")),
            "should extract pypi password"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn my_cnf_parsed_via_extension() {
        let dir = tmp("mycnf");
        let cnf = dir.join(".my.cnf");
        write_file(&cnf, "[client]\nuser = root\npassword = mysql_s3cr3t\n");

        let items = parse_app_config(
            &cnf,
            &fs::read_to_string(&cnf).unwrap(),
            "ini",
            SourceType::ApplicationConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("password")),
            "should extract MySQL password"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cargo_credentials_toml() {
        let dir = tmp("cargo_creds");
        let cred = dir.join("credentials.toml");
        write_file(
            &cred,
            "[registry]\ntoken = \"cio_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345\"\n",
        );

        let items = parse_app_config(
            &cred,
            &fs::read_to_string(&cred).unwrap(),
            "toml",
            SourceType::ApplicationConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("token")),
            "should extract cargo token"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gem_credentials_yaml() {
        let dir = tmp("gem_creds");
        let cred = dir.join("credentials");
        write_file(
            &cred,
            "---\n:rubygems_api_key: rubygems_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123\n",
        );

        let items = parse_app_config(
            &cred,
            &fs::read_to_string(&cred).unwrap(),
            "yaml",
            SourceType::ApplicationConfig,
        );
        assert!(
            items.iter().any(|i| i.line.contains("rubygems_api_key")),
            "should extract rubygems API key"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Exclusion ───────────────────────────────────────────────────────────

    #[test]
    fn exclude_paths_skips_target() {
        let dir = tmp("excl_app");
        let netrc = dir.join(".netrc");
        write_file(&netrc, "machine host.com login user password secret\n");

        let targets = vec![AppTarget {
            path: netrc,
            format_hint: "netrc",
        }];

        let mut config = test_config();
        config.exclude_paths = vec![dir.clone()];

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
                items.extend(parse_app_config(
                    &target.path,
                    &raw,
                    target.format_hint,
                    SourceType::ApplicationConfig,
                ));
            }
        }

        assert!(items.is_empty(), "excluded path should produce no items");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Missing file ────────────────────────────────────────────────────────

    #[test]
    fn missing_file_skipped_silently() {
        let result = try_read_raw(Path::new("/no/such/app/config"), 1024 * 1024);
        assert!(result.unwrap().is_none());
    }

    // ── Detection integration ───────────────────────────────────────────────

    #[test]
    fn npmrc_token_triggers_detection() {
        use crate::detection::patterns::all_patterns;
        use crate::detection::{CompiledPattern, DetectionEngine};

        let raw = "//registry.npmjs.org/:_authToken=npm_aB3dEfGhIjKlMnOpQrStUvWxYz0123456789\n";
        let items = parse_app_config(
            Path::new("/home/user/.npmrc"),
            raw,
            "ini",
            SourceType::ApplicationConfig,
        );

        let patterns: Vec<CompiledPattern> = all_patterns()
            .into_iter()
            .map(|p| CompiledPattern::compile(p).unwrap())
            .collect();
        let engine = DetectionEngine::with_defaults(patterns);
        let findings = engine.analyze_batch(&items);
        assert!(
            !findings.is_empty(),
            "npm auth token should produce at least one finding"
        );
    }
}
