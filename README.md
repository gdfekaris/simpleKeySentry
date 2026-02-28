# simpleKeySentry (sks)

## v0.2.0

A privacy-first local secrets scanner. Finds leaked credentials in shell history, dotfiles, cloud CLI configs, SSH keys, and environment files on your own machine — without sending anything off it.

**Zero network calls. Zero telemetry. Everything stays on your machine.**

## What it scans

- **Shell history** — Bash, Zsh, and Fish history files for inline tokens, exported secrets, database connection strings
- **Dotfiles** — `.bashrc`, `.zshrc`, `.profile`, `.bash_profile`, `.gitconfig`, and other shell configs
- **Environment files** — `.env`, `.env.local`, `.env.production`, and variants found recursively under your project directories
- **Cloud CLI configs** — AWS credentials/config, GCP application default credentials, Azure profile, Docker config, Kubernetes kubeconfig, GitHub CLI and Hub configs
- **Application configs** — `.npmrc`, `.pypirc`, `.netrc`, `.pgpass`, `.my.cnf`, Cargo credentials, Gem credentials
- **SSH keys** — unencrypted private keys, permissive file/directory permissions, authorized_keys audit, known_hosts plaintext hostnames

## What it detects

42 built-in patterns covering:

- AWS access keys and secret keys
- GitHub personal access tokens (classic and fine-grained), OAuth tokens, and App private keys
- GCP API keys and service account keys
- Azure storage account keys
- DigitalOcean tokens
- GitLab personal and pipeline tokens
- Bitbucket App passwords
- Stripe secret and test keys
- Slack bot and user tokens
- Shopify access tokens
- OpenAI and Anthropic API keys
- Mailgun, SendGrid, Twilio, and Datadog API keys
- HashiCorp Vault and Terraform tokens
- Heroku, npm, and PyPI API keys
- Private keys (PEM format) and SSH unencrypted key headers
- Age encryption keys
- JWTs and Kubernetes bearer tokens
- Database connection strings with credentials
- Basic-auth URLs
- Docker registry auth tokens
- Generic bearer tokens and high-entropy secrets

Each match is scored with a confidence pipeline that combines regex pattern matching, Shannon entropy analysis, and 8 contextual heuristics to reduce false positives.

## Install

Requires Rust 1.82+.

```bash
# Clone and build
git clone https://github.com/gdfekaris/simpleKeySentry.git
cd simpleKeySentry
cargo build --release

# The binary is at target/release/sks
# Copy it somewhere on your PATH:
cp target/release/sks ~/.local/bin/sks
```

## Quick start

```bash
# Run a scan with default settings
sks

# Same thing, explicitly
sks scan

# Scan a specific directory
sks scan ~/projects/my-app

# Show all findings, including low-confidence ones
sks -v

# JSON output (for scripting or piping to jq)
sks -f json

# HTML report (self-contained, shareable)
sks -f html -o report.html

# Write results to a file (created with 0600 permissions)
sks -o report.json -f json

# Quiet mode — just the summary line
sks -q

# Force a full scan (skip the incremental cache)
sks scan --no-cache

# Re-render a saved JSON report as HTML
sks report report.json --format html -o report.html

# Re-render a saved JSON report in the terminal
sks report report.json
```

## Configuration

Generate a config file with commented defaults:

```bash
sks init
# Creates ~/.config/sks/config.toml (respects $XDG_CONFIG_HOME)
```

You can also place a `.sks.toml` in any project directory for project-specific settings. Configuration layers (each overrides the previous):

1. Built-in defaults
2. User config (`~/.config/sks/config.toml`)
3. Project config (`.sks.toml` in the current directory)
4. Environment variables (`SKS_FORMAT`, `SKS_VERBOSITY`, `SKS_REDACT`, `SKS_MIN_CONFIDENCE`)
5. CLI flags

### Key options

| Flag | Description |
|---|---|
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, or `html` |
| `-v, --verbose` | Show low and info-severity findings |
| `-q, --quiet` | Show only the summary line |
| `-o, --output <PATH>` | Write report to a file |
| `--no-redact` | Show full secret values (use with caution) |
| `--min-confidence <N>` | Minimum confidence threshold, 0-100 (default: 30) |
| `--no-entropy` | Disable entropy analysis |
| `--no-cache` | Disable incremental scanning cache (force full scan) |

## Incremental scanning

After the first scan, sks caches file metadata (mtime and size) so subsequent scans skip unchanged files. This makes re-scans near-instant. The cache is stored at `~/.local/share/sks/cache.json` (respects `$XDG_DATA_HOME`).

Use `--no-cache` to force a full scan.

## Commands

| Command | Description |
|---|---|
| `sks scan [PATH]` | Scan for secrets (default when no command is given) |
| `sks report <PATH>` | Re-render a saved JSON report in another format |
| `sks init [--force]` | Create a default config file |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings above threshold — clean scan |
| 1 | Findings found above threshold |
| 2 | Fatal error (e.g. malformed config file) |

Use these in CI or scripts:

```bash
sks -q && echo "Clean" || echo "Secrets found"
```

## How it works

The pipeline has three stages:

1. **Collectors** read files and produce content items (lines with context)
2. **Detection engine** matches patterns, computes entropy, applies heuristics, and scores each finding
3. **Reporters** format the output for humans (terminal), machines (JSON), or sharing (HTML)

Confidence scoring: `base_confidence + entropy_delta + sum(heuristic_deltas)`, clamped to [0.0, 1.0]. Severity is derived from the final score:

| Confidence | Severity |
|---|---|
| 90-100% | Critical |
| 70-89% | High |
| 50-69% | Medium |
| 30-49% | Low |
| 0-29% | Info |

By default, only Medium and above are shown. Use `-v` to see everything.

## Privacy and security

- **No network access** — enforced at the dependency level via `cargo-deny`. HTTP client crates are banned.
- **Read-only** — collectors never modify the files they scan.
- **Secrets are zeroized** — detected secret values are wiped from memory on drop.
- **Output files are locked down** — any file written by `sks` gets `0600` permissions.
- **Redacted by default** — secret values are masked in output unless you explicitly pass `--no-redact`.

## License

MIT
