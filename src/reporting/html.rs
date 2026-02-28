//! Self-contained HTML reporter.
//!
//! Produces a single HTML file with embedded CSS and JavaScript. The report
//! is filterable by severity, searchable, and respects the redact flag.
//! All findings are included regardless of verbosity (like JSON).

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::config::ReportConfig;
use crate::models::{Finding, Reporter, ScanResult, Severity};
use crate::SksError;

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn secret_type_str(st: &crate::models::SecretType) -> String {
    use crate::models::SecretType::*;
    match st {
        AwsAccessKey => "aws-access-key-id".into(),
        AwsSecretKey => "aws-secret-access-key".into(),
        GitHubPat => "github-pat".into(),
        GitHubOAuth => "github-oauth".into(),
        StripeKey => "stripe-key".into(),
        SlackToken => "slack-token".into(),
        PrivateKey => "private-key-pem".into(),
        Jwt => "jwt".into(),
        DatabaseUrl => "database-url".into(),
        GenericApiKey => "generic-api-key".into(),
        GenericHighEntropy => "generic-high-entropy".into(),
        Custom(name) => name.clone(),
    }
}

fn source_type_str(st: &crate::models::SourceType) -> &'static str {
    use crate::models::SourceType::*;
    match st {
        ShellHistory => "shell history",
        Dotfile => "dotfile",
        EnvFile => ".env file",
        CloudConfig => "cloud config",
        SshKey => "ssh key",
        ApplicationConfig => "app config",
        Clipboard => "clipboard",
        BrowserStorage => "browser storage",
    }
}

/// HTML-escape a string to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Shortens a path for display: replaces $HOME prefix with `~`.
fn display_path(path: &Path) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let s = path.to_string_lossy();
    if !home.is_empty() {
        if let Some(rest) = s.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    s.into_owned()
}

/// Counts findings by severity.
fn severity_counts(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let (mut c, mut h, mut m, mut l, mut i) = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity {
            Severity::Critical => c += 1,
            Severity::High => h += 1,
            Severity::Medium => m += 1,
            Severity::Low => l += 1,
            Severity::Info => i += 1,
        }
    }
    (c, h, m, l, i)
}

// ---------------------------------------------------------------------------
// HTML generation
// ---------------------------------------------------------------------------

/// Formats the scan result as a self-contained HTML document.
pub(crate) fn format_html(result: &ScanResult, config: &ReportConfig) -> String {
    let meta = &result.scan_metadata;
    let (crit, high, med, low, info) = severity_counts(&result.findings);
    let total = result.findings.len();
    let elapsed = meta.completed_at.signed_duration_since(meta.started_at);
    let secs = elapsed.num_milliseconds() as f64 / 1000.0;

    let mut out = String::with_capacity(8192);

    // DOCTYPE + head
    writeln!(out, "<!DOCTYPE html>").unwrap();
    writeln!(out, "<html lang=\"en\">").unwrap();
    writeln!(out, "<head>").unwrap();
    writeln!(out, "<meta charset=\"UTF-8\">").unwrap();
    writeln!(
        out,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    )
    .unwrap();
    writeln!(out, "<title>Simple Key Sentry Report</title>").unwrap();
    writeln!(out, "<style>{CSS}</style>").unwrap();
    writeln!(out, "</head>").unwrap();
    writeln!(out, "<body>").unwrap();

    // Header
    write!(
        out,
        "<header>\
         <h1>Simple Key Sentry <span class=\"version\">v{}</span></h1>\
         <p class=\"meta\">{} &mdash; {} files scanned",
        html_escape(&meta.sks_version),
        html_escape(&meta.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        meta.files_scanned,
    )
    .unwrap();
    if meta.files_cached > 0 {
        write!(out, " ({} cached)", meta.files_cached).unwrap();
    }
    writeln!(out, " &mdash; {secs:.1}s</p></header>").unwrap();

    // Summary dashboard
    writeln!(out, "<section class=\"summary\">").unwrap();
    write_badge(&mut out, "critical", "Critical", crit);
    write_badge(&mut out, "high", "High", high);
    write_badge(&mut out, "medium", "Medium", med);
    write_badge(&mut out, "low", "Low", low);
    write_badge(&mut out, "info", "Info", info);
    writeln!(
        out,
        "<span class=\"badge total\"><strong>{total}</strong> total</span>"
    )
    .unwrap();
    writeln!(out, "</section>").unwrap();

    // Controls: search + severity filter
    writeln!(out, "<section class=\"controls\">").unwrap();
    writeln!(
        out,
        "<input type=\"text\" id=\"search\" placeholder=\"Search findings\u{2026}\" \
         aria-label=\"Search findings\">"
    )
    .unwrap();
    writeln!(out, "<div class=\"filters\">").unwrap();
    for &(val, label) in &[
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ] {
        writeln!(
            out,
            "<label><input type=\"checkbox\" class=\"sev-filter\" \
             value=\"{val}\" checked> {label}</label>"
        )
        .unwrap();
    }
    writeln!(out, "</div>").unwrap();
    writeln!(out, "</section>").unwrap();

    // Findings
    if total == 0 {
        writeln!(out, "<p class=\"no-findings\">No findings detected.</p>").unwrap();
    } else {
        writeln!(out, "<div id=\"findings\">").unwrap();
        for finding in &result.findings {
            write_finding(&mut out, finding, config.redact);
        }
        writeln!(out, "</div>").unwrap();
    }

    // Footer
    writeln!(
        out,
        "<footer>Generated by Simple Key Sentry v{}</footer>",
        html_escape(&meta.sks_version),
    )
    .unwrap();

    // Embedded JS
    writeln!(out, "<script>{JS}</script>").unwrap();

    writeln!(out, "</body>").unwrap();
    writeln!(out, "</html>").unwrap();
    out
}

fn write_badge(out: &mut String, class: &str, label: &str, count: usize) {
    writeln!(
        out,
        "<span class=\"badge {class}\"><strong>{count}</strong> {label}</span>"
    )
    .unwrap();
}

fn write_finding(out: &mut String, f: &Finding, redact: bool) {
    let sev = severity_str(&f.severity);
    let sev_label = severity_label(&f.severity);
    let path = html_escape(&display_path(&f.location.path));
    let line_suffix = f.location.line.map(|l| format!(":{l}")).unwrap_or_default();
    let secret_type = html_escape(&secret_type_str(&f.secret_type));
    let source = html_escape(source_type_str(&f.location.source_type));
    let description = html_escape(&f.description);
    let remediation = html_escape(&f.remediation);
    let value = if redact {
        html_escape(&f.value.redacted())
    } else {
        html_escape(f.value.raw())
    };

    writeln!(
        out,
        "<div class=\"finding\" data-severity=\"{sev}\">\
         <div class=\"finding-header\">\
         <span class=\"sev-tag {sev}\">{sev_label}</span>\
         <span class=\"description\">{description}</span>\
         <span class=\"location\">{path}{line_suffix}</span>\
         </div>\
         <div class=\"finding-body\">\
         <div class=\"detail\"><span class=\"label\">Type:</span> {secret_type}</div>\
         <div class=\"detail\"><span class=\"label\">Source:</span> {source}</div>\
         <div class=\"detail\"><span class=\"label\">Confidence:</span> {:.0}%</div>\
         <div class=\"detail\"><span class=\"label\">Value:</span> \
         <code class=\"secret\">{value}</code></div>\
         <div class=\"detail\"><span class=\"label\">Fix:</span> {remediation}</div>\
         </div>\
         </div>",
        f.confidence * 100.0
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Embedded CSS
// ---------------------------------------------------------------------------

const CSS: &str = r#"
:root {
  --bg: #fff; --fg: #1a1a2e; --card-bg: #f8f9fa; --border: #dee2e6;
  --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
  --low: #6c757d; --info: #adb5bd;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a2e; --fg: #e8e8e8; --card-bg: #16213e; --border: #333;
    --critical: #ff6b6b; --high: #ffa94d; --medium: #ffd43b;
    --low: #868e96; --info: #495057;
  }
}
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--fg);
  max-width: 960px; margin: 0 auto; padding: 1rem 1.5rem;
  line-height: 1.5;
}
header h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.version { font-weight: normal; opacity: 0.6; font-size: 0.9rem; }
.meta { margin: 0 0 1rem; opacity: 0.7; font-size: 0.85rem; }
.summary { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
.badge {
  padding: 0.3rem 0.7rem; border-radius: 4px; font-size: 0.85rem;
  background: var(--card-bg); border: 1px solid var(--border);
}
.badge.critical { border-left: 3px solid var(--critical); }
.badge.high { border-left: 3px solid var(--high); }
.badge.medium { border-left: 3px solid var(--medium); }
.badge.low { border-left: 3px solid var(--low); }
.badge.info { border-left: 3px solid var(--info); }
.badge.total { font-weight: bold; }
.controls { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center;
  margin-bottom: 1rem; }
#search {
  flex: 1; min-width: 200px; padding: 0.4rem 0.6rem;
  border: 1px solid var(--border); border-radius: 4px;
  background: var(--card-bg); color: var(--fg); font-size: 0.9rem;
}
.filters { display: flex; flex-wrap: wrap; gap: 0.5rem; font-size: 0.85rem; }
.filters label { cursor: pointer; user-select: none; }
.no-findings {
  text-align: center; padding: 2rem; opacity: 0.6; font-size: 1.1rem;
}
.finding {
  background: var(--card-bg); border: 1px solid var(--border);
  border-radius: 6px; margin-bottom: 0.6rem; overflow: hidden;
}
.finding-header {
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem;
  padding: 0.5rem 0.75rem; cursor: pointer;
}
.finding-header:hover { opacity: 0.85; }
.sev-tag {
  padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem;
  font-weight: 600; color: #fff; text-transform: uppercase;
}
.sev-tag.critical { background: var(--critical); }
.sev-tag.high { background: var(--high); }
.sev-tag.medium { background: var(--medium); color: #1a1a2e; }
.sev-tag.low { background: var(--low); }
.sev-tag.info { background: var(--info); color: #1a1a2e; }
.description { flex: 1; font-weight: 500; }
.location { font-family: monospace; font-size: 0.8rem; opacity: 0.7; }
.finding-body {
  padding: 0.5rem 0.75rem 0.75rem; border-top: 1px solid var(--border);
  display: none;
}
.finding.open .finding-body { display: block; }
.detail { font-size: 0.85rem; margin-bottom: 0.25rem; }
.label { font-weight: 600; }
.secret {
  background: var(--border); padding: 0.1rem 0.3rem; border-radius: 3px;
  font-size: 0.8rem; word-break: break-all;
}
footer {
  margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border);
  font-size: 0.75rem; opacity: 0.5; text-align: center;
}
"#;

// ---------------------------------------------------------------------------
// Embedded JS
// ---------------------------------------------------------------------------

const JS: &str = r#"
(function() {
  // Toggle finding details on click
  document.querySelectorAll('.finding-header').forEach(function(h) {
    h.addEventListener('click', function() {
      h.parentElement.classList.toggle('open');
    });
  });

  var search = document.getElementById('search');
  var filters = document.querySelectorAll('.sev-filter');

  function applyFilters() {
    var query = (search ? search.value : '').toLowerCase();
    var checked = {};
    filters.forEach(function(cb) { checked[cb.value] = cb.checked; });
    document.querySelectorAll('.finding').forEach(function(el) {
      var sev = el.getAttribute('data-severity');
      var text = el.textContent.toLowerCase();
      var sevMatch = checked[sev] !== false;
      var searchMatch = !query || text.indexOf(query) !== -1;
      el.style.display = (sevMatch && searchMatch) ? '' : 'none';
    });
  }

  if (search) search.addEventListener('input', applyFilters);
  filters.forEach(function(cb) { cb.addEventListener('change', applyFilters); });
})();
"#;

// ---------------------------------------------------------------------------
// HtmlReporter
// ---------------------------------------------------------------------------

/// Self-contained HTML reporter for sharing and archiving scan results.
pub struct HtmlReporter;

impl Reporter for HtmlReporter {
    fn format_name(&self) -> &str {
        "html"
    }

    fn report(&self, result: &ScanResult, config: &ReportConfig) -> Result<(), SksError> {
        let html = format_html(result, config);

        if let Some(path) = &config.output_path {
            write_to_file(path, html.as_bytes())?;
        } else {
            print!("{html}");
        }

        Ok(())
    }
}

/// Writes bytes to a file with restrictive permissions (0600 on Unix).
fn write_to_file(path: &Path, data: &[u8]) -> Result<(), SksError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

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
    file.write_all(data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ReportFormat, Verbosity};
    use crate::models::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn make_finding(
        confidence: f64,
        secret_type: SecretType,
        value: &str,
        description: &str,
    ) -> Finding {
        Finding::new(
            secret_type,
            confidence,
            SecretValue::new(value.to_string()),
            SourceLocation {
                path: PathBuf::from("/home/user/.bash_history"),
                line: Some(42),
                column: None,
                context_before: String::new(),
                context_after: String::new(),
                source_type: SourceType::ShellHistory,
            },
            description.to_string(),
            "Rotate this key".to_string(),
            Some("aws-access-key-id".to_string()),
        )
    }

    fn make_scan_result(findings: Vec<Finding>) -> ScanResult {
        let now = Utc::now();
        ScanResult {
            findings,
            scan_metadata: ScanMetadata {
                started_at: now,
                completed_at: now,
                files_scanned: 47,
                files_cached: 0,
                bytes_scanned: 1048576,
                targets_scanned: vec![SourceType::ShellHistory],
                sks_version: "0.1.0".to_string(),
            },
        }
    }

    fn default_config() -> ReportConfig {
        ReportConfig {
            format: ReportFormat::Html,
            verbosity: Verbosity::Normal,
            redact: true,
            output_path: None,
        }
    }

    #[test]
    fn html_is_valid_document() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<head>"));
        assert!(html.contains("</head>"));
        assert!(html.contains("<body>"));
        assert!(html.contains("</body>"));
    }

    #[test]
    fn html_contains_title_and_version() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("Simple Key Sentry"));
        assert!(html.contains("v0.1.0"));
    }

    #[test]
    fn html_embeds_css_and_js() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("<style>"));
        assert!(html.contains("</style>"));
        assert!(html.contains("<script>"));
        assert!(html.contains("</script>"));
    }

    #[test]
    fn html_shows_no_findings_message_when_empty() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("No findings detected"));
    }

    #[test]
    fn html_contains_severity_badges() {
        let findings = vec![
            make_finding(0.95, SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE", "d"),
            make_finding(
                0.75,
                SecretType::DatabaseUrl,
                "postgres://u:p@h/db1234",
                "d",
            ),
        ];
        let result = make_scan_result(findings);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("<strong>1</strong> Critical"));
        assert!(html.contains("<strong>1</strong> High"));
        assert!(html.contains("<strong>2</strong> total"));
    }

    #[test]
    fn html_redacts_values_by_default() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("AKIA****MPLE"));
        assert!(!html.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn html_shows_raw_when_no_redact() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.redact = false;
        let html = format_html(&result, &config);
        assert!(html.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn html_includes_all_findings_regardless_of_verbosity() {
        let findings = vec![
            make_finding(0.95, SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE", "C"),
            make_finding(0.20, SecretType::GenericApiKey, "low_value_here1234", "I"),
        ];
        let result = make_scan_result(findings);
        let mut config = default_config();
        config.verbosity = Verbosity::Quiet;
        let html = format_html(&result, &config);
        // Both findings present in HTML (filter checkboxes handle visibility)
        let count = html.matches("class=\"finding\"").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn html_escapes_special_characters() {
        let findings = vec![make_finding(
            0.95,
            SecretType::GenericApiKey,
            "<script>alert(1)</script>",
            "XSS <test> & \"quotes\"",
        )];
        let result = make_scan_result(findings);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("&lt;test&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&quot;quotes&quot;"));
        // The raw script tag must not appear unescaped
        assert!(!html.contains("<script>alert"));
    }

    #[test]
    fn html_finding_has_data_severity_attribute() {
        let findings = vec![make_finding(
            0.95,
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE",
            "AWS Access Key",
        )];
        let result = make_scan_result(findings);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("data-severity=\"critical\""));
    }

    #[test]
    fn html_contains_search_and_filter_controls() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("id=\"search\""));
        assert!(html.contains("class=\"sev-filter\""));
    }

    #[test]
    fn html_shows_scan_metadata() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("47 files scanned"));
    }

    #[test]
    fn html_shows_cached_count_when_nonzero() {
        let now = Utc::now();
        let result = ScanResult {
            findings: vec![],
            scan_metadata: ScanMetadata {
                started_at: now,
                completed_at: now,
                files_scanned: 47,
                files_cached: 10,
                bytes_scanned: 1024,
                targets_scanned: vec![SourceType::ShellHistory],
                sks_version: "0.1.0".to_string(),
            },
        };
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("(10 cached)"));
    }

    #[test]
    fn html_has_dark_mode_support() {
        let result = make_scan_result(vec![]);
        let config = default_config();
        let html = format_html(&result, &config);
        assert!(html.contains("prefers-color-scheme: dark"));
    }

    #[test]
    fn html_writes_to_file() {
        let dir = std::env::temp_dir().join("sks_test_html_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out_path = dir.join("report.html");

        let result = make_scan_result(vec![]);
        let mut config = default_config();
        config.output_path = Some(out_path.clone());

        HtmlReporter.report(&result, &config).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("<!DOCTYPE html>"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&out_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
