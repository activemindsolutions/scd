# Secure Code by Design

> Automated security scanning for development teams using AI coding tools.

Secure Code by Design (`scd`) is a CLI tool that catches security vulnerabilities before they reach production — running quietly in the background via git hooks and on-demand scans. Built for SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor) who generate code faster than their security awareness can keep up with.

**Not a replacement for penetration testing.** It minimizes the number of vulnerabilities that reach production so that pentests can focus on harder problems.

---

## Features

- **172 security rules** across JavaScript, TypeScript, Python, PHP, ASP.NET, and more
- **Git hooks** – secrets scanning on pre-commit, full OWASP scan on pre-push
- **Zero repo footprint** – no files written to your repository after init
- **HTML, Markdown and JSON reports** with fix guidance for each finding
- **Deep analysis** – optional Claude API integration; sends only the triggering code line + 8 lines of context, never whole files
- **Per-scan storage** – every scan saved individually, never overwritten; regenerate reports from any historical scan
- **Exception management** – reviewed exceptions tracked in config, never as code comments
- **Audit trail** – append-only scan history per repository
- **Infrastructure leakage detection** – hardcoded IPs, internal hostnames, connection strings

---

## Requirements

- Node.js 18 or later
- Git
- npm

**macOS / Linux:** No additional requirements.

**Windows:** Windows 10 (build 1803) or later required. Git for Windows must be installed (not WSL). Windows Terminal or PowerShell recommended — `cmd.exe` has limited ANSI colour support.

---

## Installation

```bash
git clone git@github.com:activemindsolutions/scd.git
cd scd
npm install
npm link
```

### Verify

```bash
scd --version
scd doctor
```

---

## Quick start

```bash
# Register a project and install git hooks
cd /path/to/your/project
scd init

# Run a full security scan
scd scan

# Run with AI deep analysis
scd scan --deep

# Generate an HTML report from the last scan
scd report

# Open the report in your browser
scd report --open          # macOS / Windows
scd report --serve         # Linux / Firefox (starts local HTTP server)
```

---

## Commands

| Command | Description |
|---|---|
| `scd init` | Register repo and install git hooks |
| `scd scan [target]` | Run a full security scan |
| `scd scan --deep` | Scan with Claude API deep analysis |
| `scd scan --include-vendor` | Include vendor/dependency code in scan |
| `scd scan --vendor-only` | Scan only vendor/dependency code (supply chain) |
| `scd scan --deep --deep-delay <ms>` | Add delay between API calls (rate limit prevention) |
| `scd report` | Generate report from last scan (HTML default) |
| `scd report --serve` | Serve report via local HTTP server |
| `scd report --serve --index` | Always show report index page |
| `scd report --scan <id>` | Generate report from a specific saved scan |
| `scd export-findings` | Export all findings from a scan to JSON for external review |
| `scd export-findings --deep-only` | Export only findings that have a deep analysis result |
| `scd export-findings --severity critical` | Filter exported findings by severity |
| `scd export-findings --scan <id>` | Export from a specific saved scan |
| `scd approve` | Create a reviewed exception for a finding |
| `scd resolve` | Mark a finding as resolved |
| `scd audit` | View scan history and audit trail |
| `scd insights` | Analyze behavioral patterns from audit log |
| `scd rules` | List all security rules |
| `scd rules --lang php` | Filter rules by language |
| `scd rules --id INFRA-001` | Show full detail for a rule |
| `scd rules --search "injection"` | Free-text search across rules |
| `scd rules --stats` | Rule counts by severity and language |
| `scd list` | List all repos registered in store |
| `scd store` | Show store info for current repo |
| `scd store --show` | Full metadata for current repo |
| `scd store --scans` | List all saved scans |
| `scd store --verify` | Verify all repos exist on disk |
| `scd store --verify --clean` | Interactive cleanup of missing/stale repos |
| `scd configure --api-key` | Set Claude API key for deep analysis |
| `scd version` | Detailed version info |
| `scd doctor` | Verify installation and configuration |

---

## Rule coverage

| Language / Category | Rules | CRITICAL | HIGH | EXPOSURE |
|---|---|---|---|---|
| JavaScript / TypeScript | 29 | 7 | 10 | 12 |
| Python | 26 | 12 | 10 | 4 |
| PHP | 29 | 13 | 11 | 4 |
| ASP.NET markup | 17 | 3 | 11 | – |
| ASP.NET C# | 26 | 15 | 11 | – |
| Sensitive files | 50 | 14 | 10 | 1 |
| Infrastructure leakage | 21 | – | 3 | 18 |
| **Total** | **172** | **63** | **69** | **30** |

Covers OWASP Top 10 categories including Injection, Broken Access Control, Cryptographic Failures, Security Misconfiguration, and more.

---

## How it works

### Git hooks

`scd init` configures git to use a shared hooks directory (`~/.scd/hooks`):

```
pre-commit  → fast secrets scan (blocks CRITICAL findings)
pre-push    → full OWASP scan  (blocks CRITICAL + HIGH findings)
```

### Global store

All scan data, configs and reports are stored outside your repository:

```
~/.scd/
├── config                    ← API key
└── repos/
    └── {repoId}/
        ├── meta.json         ← repo identity and last scan summary
        ├── config.yml        ← exceptions and rule overrides
        ├── audit.log         ← full scan history (append-only)
        ├── last-scan.json    ← copy of latest scan
        ├── scans/            ← one JSON per scan, never overwritten
        │   ├── 2026-03-17T132421.json
        │   └── 2026-03-17T091500.json
        └── reports/          ← generated HTML/MD/JSON reports
```

### Scan storage

Every scan is saved as an individual file with a timestamp ID (`2026-03-17T132421`). Deep analysis results are stored alongside findings in the same file — running a new scan without `--deep` never loses previous deep data.

```bash
scd store --scans                      # list all saved scans
scd report --scan 2026-03-17T091500    # regenerate report from earlier scan
```

### Deep analysis

`scd scan --deep` sends findings to Claude API for AI-powered analysis. What is sent per finding:

- The filename
- Rule ID, name, severity, line number
- The exact code line that triggered the rule
- 8 lines of surrounding context

**Whole files are never sent.** Set `trust_level: maximum_privacy` in `securityagent.yml` to disable all external API calls entirely.

For large repos, configure a delay to avoid rate limits:

```yaml
# securityagent.yml
deep_delay_ms: 2000   # 2 second pause between files
```

Or override per-run: `scd scan --deep --deep-delay 3000`

### Project configuration

Place `securityagent.yml` in your project root to configure scanning behaviour:

```yaml
trust_level: balanced        # maximum_privacy | balanced | maximum_analysis
deep_delay_ms: 0             # ms delay between --deep API calls
block_on_critical: true
block_on_high: true
```

---

## Exception management

Exceptions for accepted findings are managed in the store config — never as source code comments. Comments like `// scd-ignore` leak information about vulnerabilities to anyone reading the code.

```bash
scd approve --rule FRONT-001 --file src/maps/config.js --line 12
```

Exceptions include a hash of the relevant code line. If the code changes, the exception requires re-approval automatically.

---

## Exporting findings

`scd export-findings` produces a self-contained JSON snapshot of findings from a completed scan — useful for sharing with an external reviewer without giving them access to the codebase.

```bash
# Export all findings (default)
scd export-findings

# Export only findings that have deep analysis results
scd export-findings --deep-only

# Filter by severity or rule
scd export-findings --severity critical
scd export-findings --rule PHP-INJ-001

# Export from a specific scan
scd export-findings --scan 2026-03-17T132421

# Specify output path
scd export-findings --output /tmp/review-findings.json
```

The output file is named `scd-findings-{scanId}.json` in the current directory by default. It includes finding details, per-rule statistics, FP rates, and deep analysis results where available. Findings without deep analysis appear with `deep: null`. Use `--deep-only` to export only findings with deep analysis.

---

## Multi-machine setup

See [INSTALL.md](INSTALL.md) for full instructions including tarball installation and shell configuration.

---

## Project structure

```
bin/
  scd.js               ← CLI entry point (all scd commands)
lib/
  scanner-full.js      ← OWASP scanner
  scanner-secrets.js   ← Fast secrets scanner (pre-commit)
  store.js             ← Global store path management
  store-verify.js      ← Store health checks and cleanup
  scan-cache.js        ← Per-scan storage (scans/ directory)
  rule-registry.js     ← Normalised catalogue of all rules
  deep-analyzer.js     ← Claude API deep analysis
  report-html.js       ← HTML report generator
  report-index.js      ← HTTP server index page
  report-markdown.js   ← Markdown report generator
  report-json.js       ← JSON report generator
  export-findings.js   ← Export findings to JSON for external review
  rules/               ← Rule definitions per language
docs/
  ARCHITECTURE.md      ← Product vision and technical architecture
  CODEBASE.md          ← File-by-file reference
  PROGRESS.md          ← Roadmap and current status
```

---

## Roadmap

- `scd deps` – Dependency scanning with CVE lookup via OSV API
- Multi-user portal (Team and Professional tiers)
- VS Code extension
- `scd uninstall` – clean removal with store data options

---

## About

Built by [Activemind Solutions AB](https://activemind.se) — security consulting and penetration testing.

> Secure Code by Design is a commercial product. See LICENSE for terms.
