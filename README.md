# simpleKeySentry (sks)

## v0.3.0

A privacy-first local secrets scanner. Finds leaked credentials in shell history, dotfiles, cloud CLI configs, SSH keys, and environment files on your own machine — without sending anything off it.

**Zero network calls. Zero telemetry. Everything stays on your machine.**

## What it scans

- **Shell history** — Bash, Zsh, and Fish history files for inline tokens, exported secrets, database connection strings
- **Dotfiles** — `.bashrc`, `.zshrc`, `.profile`, `.bash_profile`, `.gitconfig`, and other shell configs
- **Environment files** — `.env`, `.env.local`, `.env.production`, and variants found recursively under your project directories
- **Cloud CLI configs** — AWS credentials/config, GCP application default credentials, Azure profile, Docker config, Kubernetes kubeconfig, GitHub CLI and Hub configs
- **Application configs** — `.npmrc`, `.pypirc`, `.netrc`, `.pgpass`, `.my.cnf`, Cargo credentials, Gem credentials
- **SSH keys** — unencrypted private keys, permissive file/directory permissions, authorized_keys audit, known_hosts plaintext hostnames
- **Bitcoin / Lightning** — Core Lightning `hsm_secret` and LND `admin.macaroon`/`wallet.db` files (path-presence; mainnet, testnet, regtest)
- **Clipboard** (opt-in) — pasteboard contents and clipboard manager databases (Clipy, CopyQ, GPaste)
- **Browser localStorage** (opt-in) — Chrome, Chromium, Brave, Edge (LevelDB), and Firefox (SQLite)

## What it detects

45 built-in patterns covering:

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
- Bitcoin self-custody material — extended private keys (`xprv`/`yprv`/`zprv`/`tprv`), WIF private keys, and BIP-39 English mnemonic seed phrases (12 or 24 words, checksum-validated)
- Lightning Network secrets (path-presence) — Core Lightning `hsm_secret`, LND `admin.macaroon`, LND `wallet.db` across mainnet/testnet/regtest

Each match is scored with a confidence pipeline that combines regex pattern matching, Shannon entropy analysis, and 8 contextual heuristics to reduce false positives.

You can also define custom detection rules in `~/.config/sks/rules.toml` or point to a custom file with `--rules-path`.

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
# Run a scan (launches interactive mode in a TTY)
sks

# Non-interactive scan
sks scan

# Scan a specific directory
sks scan ~/projects/my-app

# Show all findings, including low-confidence ones
sks -v

# JSON output (for scripting or piping to jq)
sks -f json

# HTML report (self-contained, shareable)
sks -f html -o report.html

# SARIF output (for VS Code, GitHub code scanning, CI)
sks -f sarif -o results.sarif

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

# Scan only specific sources
sks scan --sources shell,env

# Include clipboard and browser (opt-in)
sks scan --clipboard --browser

# Use a custom rules file
sks scan --rules-path ~/my-rules.toml

# List all detection rules (built-in and custom)
sks rules list
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
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, `html`, or `sarif` |
| `-v, --verbose` | Show low and info-severity findings |
| `-q, --quiet` | Show only the summary line |
| `-o, --output <PATH>` | Write report to a file |
| `--no-redact` | Show full secret values (use with caution; ignored for SARIF) |
| `--min-confidence <N>` | Minimum confidence threshold, 0-100 (default: 30) |
| `--no-entropy` | Disable entropy analysis |
| `--no-cache` | Disable incremental scanning cache (force full scan) |
| `--clipboard` | Scan clipboard contents (opt-in) |
| `--browser` | Scan browser localStorage (opt-in) |
| `--sources <LIST>` | Comma-separated sources to scan: `shell,dotfile,env,cloud,ssh,app,bitcoin,clipboard,browser` |
| `--rules-path <PATH>` | Path to a custom rules TOML file |

## Incremental scanning

After the first scan, sks caches file metadata (mtime and size) so subsequent scans skip unchanged files. This makes re-scans near-instant. The cache is stored at `~/.local/share/sks/cache.json` (respects `$XDG_DATA_HOME`).

Use `--no-cache` to force a full scan.

## Commands

| Command | Description |
|---|---|
| `sks` | Launch interactive mode (when run in a TTY with no flags) |
| `sks scan [PATH]` | Scan for secrets |
| `sks report <PATH>` | Re-render a saved JSON report in another format |
| `sks rules list [--verbose]` | List all built-in and custom detection rules |
| `sks rules test <REGEX>` | Test a regex pattern against stdin |
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
3. **Reporters** format the output for humans (terminal), machines (JSON), sharing (HTML), or IDE/CI integration (SARIF)

Confidence scoring: `base_confidence + entropy_delta + sum(heuristic_deltas)`, clamped to [0.0, 1.0]. Severity is derived from the final score:

| Confidence | Severity |
|---|---|
| 90-100% | Critical |
| 70-89% | High |
| 50-69% | Medium |
| 30-49% | Low |
| 0-29% | Info |

By default, only Medium and above are shown. Use `-v` to see everything.

## Suppressing findings

Create a `.sentryignore` file in your project directory to suppress known false positives. Each line is a `sha256:...` fingerprint (shown in scan output) or a glob pattern for path exclusions:

```
# Ignore a specific finding by fingerprint
sha256:abc123...

# Ignore all findings in test fixtures
tests/fixtures/**
```

## Custom rules

Define additional detection patterns in `~/.config/sks/rules.toml`:

```toml
[[rules]]
name = "internal-api-key"
description = "Internal API key pattern"
regex = 'INTERNAL_[A-Z]+_KEY\s*=\s*["\']?([A-Za-z0-9]{32,})'
base_confidence = 0.7
remediation = "Rotate the internal API key and use a secrets manager"
```

Or point to a different file with `--rules-path`. Use `sks rules list` to see all active rules.

## Interactive mode

Running bare `sks` in a terminal launches an interactive guided scan. It walks you through target selection, runs the scan with a progress spinner, lets you review findings one at a time with keyboard navigation, and offers to save an HTML report.

## Privacy and security

- **No network access** — enforced at the dependency level via `cargo-deny`. HTTP client crates are banned.
- **Read-only** — collectors never modify the files they scan.
- **Secrets are zeroized** — detected secret values are wiped from memory on drop.
- **Output files are locked down** — any file written by `sks` gets `0600` permissions.
- **Redacted by default** — secret values are masked in output unless you explicitly pass `--no-redact`.

## License

MIT
