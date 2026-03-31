# Secure Code by Design

> Automated security scanning for development teams using AI coding tools.

Secure Code by Design (`scd`) is a CLI tool that catches security vulnerabilities before they reach production — running quietly in the background via git hooks and on-demand scans. Built for SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor) who generate code faster than their security awareness can keep up with.

**Not a replacement for penetration testing.** It minimizes the number of vulnerabilities that reach production so that pentests can focus on harder problems.

---

## Features

- **172 security rules** across JavaScript, TypeScript, Python, PHP, ASP.NET, and more
- **Taint analysis** — tracks user-controlled variables from HTTP input to dangerous sinks
- **Git hooks** – secrets scanning on pre-commit, full OWASP scan on pre-push
- **Zero repo footprint** – no files written to your repository after init
- **Compact terminal output** – summary + top issues + most affected files (use `--verbose` for full detail)
- **HTML, Markdown and JSON reports** with fix guidance for each finding
- **Deep analysis** – optional Claude API integration; sends only the triggering code line + 8 lines of context, never whole files
- **Per-scan storage** – every scan saved with a unique random ID (`s-a3f9b2c1`), never overwritten; regenerate reports from any historical scan
- **Exception management** – reviewed exceptions tracked in config, never as code comments
- **Exception sync** – pull team-lead approvals from scd-server, sync rejected back with reason
- **Audit trail** – append-only scan history per repository

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

# Run with verbose output (full file-grouped + rule-grouped detail)
scd scan --verbose

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

### Scanning

| Command | Description |
|---|---|
| `scd scan [target]` | Run a full security scan (compact output by default) |
| `scd scan --verbose` | Full file-grouped + rule-grouped output |
| `scd scan --deep` | Scan with Claude API deep analysis |
| `scd scan --include-vendor` | Include vendor/dependency code in scan |
| `scd scan --vendor-only` | Scan only vendor/dependency code (supply chain) |
| `scd scan --deep --deep-delay <ms>` | Add delay between API calls (rate limit prevention) |

### Reports

| Command | Description |
|---|---|
| `scd report` | Generate report from last scan (HTML default) |
| `scd report --serve` | Serve report via local HTTP server |
| `scd report --serve --index` | Always show report index page |
| `scd report --scan <id>` | Generate report from a specific saved scan |
| `scd export-findings` | Export all findings from a scan to JSON |
| `scd export-findings --deep-only` | Export only findings that have a deep analysis result |
| `scd export-findings --severity critical` | Filter exported findings by severity |
| `scd export-findings --scan <id>` | Export from a specific saved scan |

### Exception management

| Command | Description |
|---|---|
| `scd approve --rule <id> --file <path> --line <n> --reason <text>` | Create accepted-risk exception (pending team-lead approval) |
| `scd ignore --rule <id> --file <path> --line <n> --reason <text>` | Create general ignore (pending team-lead approval) |
| `scd ignore ... --tag <text>` | Optional free-text tag, e.g. `false_positive`, `out_of_scope` |
| `scd sync` | Pull approved/rejected exceptions from scd-server |
| `scd exceptions` | List all local exceptions |
| `scd exceptions --list rejected` | List only rejected exceptions |
| `scd exceptions --list pending\|approved\|all` | Filter by status |
| `scd resolve --rejected <id>` | Remove a rejected exception and notify server |
| `scd resolve --rule <id> --file <path> --line <n>` | Mark an EXPOSURE finding as handled |

### History & navigation

| Command | Description |
|---|---|
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

### Setup & configuration

| Command | Description |
|---|---|
| `scd init` | Register repo and install git hooks |
| `scd configure --api-key` | Set Claude API key for deep analysis |
| `scd configure --central-url <url>` | Set scd-server URL for team sync |
| `scd version` | Detailed version info |
| `scd doctor` | Verify installation and configuration |

---

## Rule coverage

| Language / Category | Rules | CRITICAL | HIGH | EXPOSURE |
|---|---|---|---|---|
| JavaScript / TypeScript | 32 | 7 | 13 | 12 |
| Python | 31 | 12 | 15 | 4 |
| PHP | 29 | 13 | 11 | 4 |
| ASP.NET markup | 17 | 3 | 11 | – |
| ASP.NET C# | 26 | 15 | 11 | – |
| Sensitive files | 50 | 14 | 10 | 1 |
| Infrastructure leakage | 21 | – | 3 | 18 |
| **Total** | **180** | **63** | **77** | **30** |

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
├── config                    ← API key, central URL, token
└── repos/
    └── {repoId}/
        ├── meta.json         ← repo identity, last scan, sync timestamps
        ├── config.yml        ← exceptions and rule overrides
        ├── audit.log         ← full scan history (append-only)
        ├── last-scan.json    ← copy of latest scan
        ├── scans/            ← one JSON per scan, never overwritten
        └── reports/          ← generated HTML/MD/JSON reports
```

### Scan storage

Every scan is saved with a unique random ID (`s-a3f9b2c1`). This ID is timezone-neutral and is also used as `session_id` on the server for full traceability.

```bash
scd store --scans                  # list all saved scans
scd report --scan s-a3f9b2c1       # regenerate report from a specific scan
```

Deep analysis results are stored alongside findings — running a new scan without `--deep` never loses previous deep data.

### Scan output modes

Default (compact) — designed to fit in a terminal without scrolling:

```
┌─ Summary ──────────────────────────────────────────────────┐
│  🔴 78 CRITICAL   🟠 126 HIGH   🟡 26 MEDIUM               │
│  Manual scan  ·  232 findings total  · 141 taint-tracked    │
└────────────────────────────────────────────────────────────┘

Top issues:
   🔴  76  PHP-INJ-002    SQL Injection – direct variable interpolation
   🟠 115  PHP-ERR-001    Information Disclosure – SQL query on error
   ...

Most affected files:
   🔴  11  WS_setProjectDetails.php  (Lines: 33, 51, 54, 62, …)
   ...

  Full details:  scd report --open   or   scd report --serve
  All findings:  scd scan --verbose   or   scd export-findings
```

Use `scd scan --verbose` for full per-file and per-rule detail.

### Taint analysis

The scanner tracks user-controlled variables (HTTP input, CLI args) through your code to identify two-step injection patterns:

```
↳ $id assigned from $_GET['id'] on line 30
```

Supports PHP, Python, and JavaScript/TypeScript. Set `scan_mode: fast` in config.yml to skip taint analysis on very large codebases.

### Deep analysis

`scd scan --deep` sends findings to Claude API for AI-powered analysis. What is sent per finding:

- The filename
- Rule ID, name, severity, line number
- The exact code line that triggered the rule
- 8 lines of surrounding context

**Whole files are never sent.** Set `trust_level: maximum_privacy` in `securityagent.yml` to disable all external API calls entirely.

### Exception management

Exceptions for accepted findings are managed in the store config — never as source code comments.

```bash
# Accept a risk (requires team-lead approval via scd-server)
scd approve --rule PHP-INJ-002 --file src/db.php --line 45 \
  --reason "Parameterized internally, validated input only"

# Mark as general ignore with optional tag
scd ignore --rule FRONT-005 --file dist/app.js --line 1 \
  --reason "Source maps intentionally included in staging" \
  --tag false_positive

# Pull approvals/rejections from team server
scd sync

# List exceptions and their status
scd exceptions --list all

# Remove a rejected exception after fixing the issue
scd resolve --rejected exc-mn7k96ml
```

Exceptions include a hash of the relevant code line. If the code changes, the exception requires re-approval automatically.

After `scd sync`, the next scan shows pending status inline:

```
ℹ  2 exception(s) pending approval – synced recently – run scd sync
⚠  1 rejected exception(s) — fix required:
   PHP-INJ-002  WS_addUser.php:10  [exc-mn7k96ml]
```

### Project configuration

Place `securityagent.yml` in your project root to configure scanning behaviour:

```yaml
trust_level: balanced        # maximum_privacy | balanced | maximum_analysis
deep_delay_ms: 0             # ms delay between --deep API calls
block_on_critical: true
block_on_high: true
scan_mode: full              # full (with taint analysis) | fast (regex only)
```

---

## Exporting findings

`scd export-findings` produces a self-contained JSON snapshot useful for sharing with an external reviewer:

```bash
scd export-findings                          # all findings
scd export-findings --deep-only              # only findings with deep analysis
scd export-findings --severity critical      # filter by severity
scd export-findings --rule PHP-INJ-001       # filter by rule
scd export-findings --scan s-a3f9b2c1        # from specific scan
scd export-findings --output /tmp/review.json
```

---

## Multi-machine setup

See [INSTALL.md](INSTALL.md) for full instructions including tarball installation and shell configuration.

---

## Project structure

```
bin/
  scd.js                  ← CLI entry point (all scd commands)
lib/
  scanner-full.js         ← OWASP scanner with taint analysis
  scanner-secrets.js      ← Fast secrets scanner (pre-commit)
  taint-register.js       ← Single-file taint tracking engine
  store.js                ← Global store path management
  store-verify.js         ← Store health checks and cleanup
  scan-cache.js           ← Per-scan storage (scans/ directory)
  rule-registry.js        ← Normalised catalogue of all rules
  config.js               ← Config loading, isExcepted(), getRuleAction()
  exception-manager.js    ← Exception/ignore create, sync, resolve
  deep-analyzer.js        ← Claude API deep analysis
  output-terminal.js      ← Compact + verbose terminal output
  report-html.js          ← HTML report generator
  report-markdown.js      ← Markdown report generator
  report-json.js          ← JSON report generator
  export-findings.js      ← Export findings to JSON
  rules/                  ← Rule definitions per language
docs/
  ARCHITECTURE.md         ← Product vision and technical architecture
  CODEBASE.md             ← File-by-file reference
  PROGRESS.md             ← Roadmap and current status
```

---

## Roadmap

- `scd deps` – Dependency scanning with CVE lookup via OSV API
- Python + JS taint analysis (PHP complete)
- `pkg` binary distribution — no Node.js required at customer site
- VS Code extension
- `scd uninstall` – clean removal with store data options

---

## About

Built by [Activemind Solutions AB](https://activemind.se) — security consulting and penetration testing.

> Secure Code by Design is a commercial product. See LICENSE for terms.
