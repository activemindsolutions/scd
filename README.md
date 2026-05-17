# Secure Code by Design

> Automated security scanning for development teams using AI coding tools.

Secure Code by Design (`scd`) is a CLI tool that catches security vulnerabilities before they reach production — running quietly in the background via git hooks and on-demand scans. Built for SMB companies using traditional coding and AI coding tools (Claude Code, GitHub Copilot, Cursor) which generates code faster than their security awareness can keep up with.

**Not a replacement for penetration testing.** scd helps you find and fix common vulnerability patterns before they reach production, so that professional security assessments can focus on harder, context-specific problems. It does not replace a penetration test, threat model, or security audit.

---

## Features

- **182 security rules** across JavaScript, TypeScript, Python, PHP, ASP.NET, and more
- **Taint analysis** — tracks user-controlled variables from HTTP input to dangerous sinks
- **Git hooks** – secrets scanning on pre-commit, full OWASP scan on pre-push
- **Zero repo footprint** – no files written or modified to your repository
- **Compact terminal output** – summary + top issues + most affected files (use `--verbose` for full detail)
- **HTML, Markdown and JSON reports** with fix guidance for each finding
- **Deep analysis** – optional AI-powered analysis via scd-server; requires the Deep Analysis Pack (Premium)
- **Per-scan storage** – every scan saved with a unique random ID (`s-a3f9b2c1`), never overwritten; regenerate reports from any historical scan
- **Finding IDs** – every finding gets a stable ID (`f-a1b2c3d4e5e5`) shown in scan output, reports and export — use directly with `scd accept` and `scd ignore`
- **Exception management** – reviewed exceptions tracked in config, never as code comments
- **Exception sync** – pull team-lead approvals from scd-server, sync rejected back with reason
- **Audit trail** – append-only scan history per repository
- **`.gitignore` respected** – files git ignores are excluded from scans by default; use `--include-ignored` to override
- **Scan scope management** – explicitly exclude files, directories, or rules with documented reasons via `scope.yml`; every exclusion is tracked in scan output and audit log
- **Pipeline-friendly** – works as a subprocess or in CI/CD without a TTY; use `--log-to` to control logging behaviour in automated contexts

## Team & Premium

scd-server extends the CLI with team collaboration features. When you're ready to move beyond local scanning:

- **Team dashboard** — aggregated findings, trend analysis, and knowledge gap tracking across your whole team
- **Exception approval flow** — developers request exceptions, team leads approve or reject with a reason
- **CRA Compliance Report** — ready-made documentation for EU Cyber Resilience Act conformity assessments
- **Findings history** — every scan from every developer in one place, searchable and filterable
- **Deep Analysis Pack** — AI-powered analysis of CRITICAL and HIGH findings; confirms real vulnerabilities, identifies false positives, and suggests concrete fixes. Your code never leaves your infrastructure.

scd-server runs in your own infrastructure. No code, no findings, and no scan data ever leaves your network.

See [securecodebydesign.com](https://securecodebydesign.com) for plans and pricing.

---

## Requirements

- Node.js 22 or later
- Git (required for hook installation)
- npm (included with Node.js)

**macOS / Linux:** No additional requirements.

**Windows:** Windows 10 (build 1803) or later required. Git for Windows must be installed (not WSL). Windows Terminal or PowerShell recommended — `cmd.exe` has limited ANSI colour support.

> On Windows, the store directory is `%USERPROFILE%\\.scd\\` (e.g. `C:\\Users\\YourName\\.scd\\`). All `~/.scd` references in this documentation refer to this path on Windows.

---

## Installation

```bash
npm install -g @activemind/scd
scd --version
```

See [INSTALL.md](INSTALL.md) for platform-specific Node.js setup, advanced options, and
[installation troubleshooting](INSTALL.md#troubleshooting).

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

# Generate an HTML report from the last scan
scd report

# Open the report in your browser
scd report open            # macOS / Windows
scd report serve           # Linux / Firefox (starts local HTTP server)
```

---

## Commands

### Scanning

| Command | Description |
|---|---|
| `scd scan [target]` | Run a full security scan — vendor and `.gitignore`d files excluded by default |
| `scd scan --verbose` | Full file-grouped + rule-grouped output |
| `scd scan --deep` | Deep analysis via scd-server *(Premium)* |
| `scd scan --include-vendor` | Include vendor/dependency code in scan |
| `scd scan --vendor-only` | Scan only vendor/dependency code (supply chain) |
| `scd scan --include-ignored` | Scan files excluded by `.gitignore` (default: respect `.gitignore`) |
| `scd scan --exclude <pattern>` | Exclude a file or directory for this scan only (repeatable, not saved) |
| `scd scan --exclude-rule <id>` | Exclude a rule for this scan only (repeatable, not saved) |
| `scd scan --log-to <mode>` | Logging mode for non-interactive use: `none`, `current`, `target` (see below) |
| `scd scan --no-sync` | Skip pushing this scan to scd-server (audit log kept locally) *(Premium)* |
| `scd scan --no-audit` | Skip audit logging entirely for this scan |

#### `--exclude` and `--exclude-rule` — one-off scan exclusions

Exclude files or rules for a single scan without modifying `scope.yml`. Useful for quick ad-hoc filtering or testing rule changes.

```bash
scd scan --exclude "tests/fixtures/" --exclude-rule INFRA-002
```

One-off exclusions are shown in scan output, stored in the scan JSON, and never written to disk. For permanent exclusions, use `scd repo scope`.

#### `--log-to` — non-interactive and pipeline use

When `scd scan` is used as a subprocess or in a CI/CD pipeline without a TTY, it automatically detects the missing terminal and scans without logging — no prompt, no hanging. A single informational line is written to stderr.

Use `--log-to` when you need explicit control over logging in non-interactive contexts:

| Value | Behaviour |
|---|---|
| `none` | Scan without logging, no prompt (same as auto-detect default) |
| `current` | Log results to the current working directory's repo, no prompt |
| `target` | Log results to the target repository's repo, no prompt |

```bash
# Automated pipeline — no TTY, no prompt, output file always written
scd scan ./repo --format json --output results.json

# Cron job — scan and log results to current repo
scd scan . --log-to current

# Explicit no-logging
scd scan . --log-to none
```

Normal interactive behaviour (with a TTY and no `--log-to`) is completely unchanged.

### Reports

| Command | Description |
|---|---|
| `scd report` | Generate report from last scan (HTML default) |
| `scd report open` | Generate report and open in browser |
| `scd report serve` | Serve report via local HTTP server |
| `scd report serve --index` | Always show report index page |
| `scd report --scan <id>` | Generate report from a specific saved scan |
| `scd export-findings` | Export all findings from a scan to JSON |
| `scd export-findings --deep-only` | Export only findings that have a deep analysis result |
| `scd export-findings --severity critical` | Filter exported findings by severity |
| `scd export-findings --scan <id>` | Export from a specific saved scan |

### Findings

| Command | Description |
|---|---|
| `scd findings` | List open (unhandled) findings from last scan |
| `scd findings <finding-id>` | Show a specific finding with full detail (problem, scenario, fix) |
| `scd findings --verbose` | Show all open findings with problem description, scenario, and fix |
| `scd findings --all` | All findings including excepted and resolved |
| `scd findings --excepted` | Only excepted findings |
| `scd findings --severity critical` | Filter by severity |
| `scd findings --rule <id>` | Filter by rule ID |
| `scd findings --scan <id>` | Load a specific historic scan |

### Exception management

| Command | Description |
|---|---|
| `scd accept <finding-id> --reason <text>` | Accept finding as acceptable risk (pending team-lead approval) |
| `scd accept <finding-id> --tag <text>` | Optional tag, e.g. `false_positive`, `out_of_scope` |
| `scd ignore <finding-id> --reason <text>` | Ignore a finding (pending team-lead approval) |
| `scd sync` | Pull approved/rejected exceptions from scd-server *(Premium)* |
| `scd exceptions` | List all local exceptions with finding IDs |
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
| `scd repo` | Show store info for current repo |
| `scd repo show` | Full metadata for current repo |
| `scd repo scans` | List all saved scans |
| `scd repo reports` | List saved reports for this repo |
| `scd repo findings` | List findings for this repo (alias for scd findings) |
| `scd repo exceptions` | List exceptions for this repo (alias for scd exceptions) |
| `scd list verify` | Verify all repos exist on disk |
| `scd list verify --clean` | Interactive cleanup of missing/stale repos |
| `scd repo configure` | Show per-repo configuration with source (repo/global/default) |
| `scd repo configure --scan-mode <fast\|full>` | Set scan mode for this repo |
| `scd repo configure --trust-level <value>` | Set trust level for this repo |
| `scd repo configure --block-on-high <bool>` | Set blocking behaviour for this repo |
| `scd remove` | Remove current repo from store (scan history preserved by default) |

### Scope management

| Command | Description |
|---|---|
| `scd scope --show` | Show global scope exclusions (applies to all repos) |
| `scd scope --add-file <pattern> --reason <text>` | Exclude files/directories globally |
| `scd scope --add-rule <id> --reason <text>` | Exclude a rule globally |
| `scd scope --remove-file <pattern> --reason <text>` | Remove a global file exclusion |
| `scd scope --remove-rule <id> --reason <text>` | Remove a global rule exclusion |
| `scd repo scope --show` | Show merged scope for current repo (global + repo + server) |
| `scd repo scope --add-file <pattern> --reason <text>` | Exclude files/directories for this repo |
| `scd repo scope --add-rule <id> --reason <text>` | Exclude a rule for this repo |
| `scd repo scope --remove-file <pattern> --reason <text>` | Remove a repo file exclusion |
| `scd repo scope --remove-rule <id> --reason <text>` | Remove a repo rule exclusion |

All scope exclusions require a `--reason`. Active exclusions are shown prominently in every scan.

For one-off per-scan exclusions without modifying `scope.yml`, use `scd scan --exclude` and `scd scan --exclude-rule`.

### Setup & configuration

| Command | Description |
|---|---|
| `scd init` | Register repo and install git hooks |
| `scd configure --central-url <url>` | Set scd-server URL for team sync *(Premium)* |
| `scd configure --token <token>` | Set scd-server API token *(Premium)* |
| `scd configure --server-timeout <value>` | Set timeout for server API calls (e.g. `30s`, `1m`) *(Premium)* |
| `scd configure --deep-timeout <value>` | Set timeout for deep analysis (e.g. `20m`) *(Premium)* |
| `scd configure --scan-mode <value>` | Set global default scan mode (overridden by per-repo config) |
| `scd configure --trust-level <value>` | Set global default trust level |
| `scd configure --block-on-high <bool>` | Set global default block-on-high |
| `scd version` | Detailed version info |
| `scd doctor` | Verify installation and configuration |

---

## Rule coverage

| Severity | Rules |
|---|---|
| CRITICAL | 63 |
| HIGH | 71 |
| MEDIUM | 10 |
| EXPOSURE | 30 |
| **Total** | **182** |

Languages covered: JavaScript, TypeScript, Python, PHP, ASP.NET (markup + C#).
Covers all OWASP Top 10 categories. Run `scd rules --stats` for full breakdown.

Covers OWASP Top 10 categories including Injection, Broken Access Control, Cryptographic Failures, Security Misconfiguration, and more.

---

## How it works

### Git hooks

`scd init` configures git to use a shared hooks directory (`~/.scd/hooks` on macOS/Linux, `%USERPROFILE%\\.scd\\hooks` on Windows):

```
pre-commit  → fast secrets scan (blocks CRITICAL findings)
pre-push    → full OWASP scan  (blocks CRITICAL + HIGH findings)
```

### Global store

All scan data, configs and reports are stored outside your repository:

```
~/.scd/                        # macOS / Linux
%USERPROFILE%\.scd\           # Windows
├── config                     ← central URL, token, timeouts, global repo defaults
└── repos/
    └── {repoId}/
        ├── meta.json          ← repo identity, last scan, sync timestamps
        ├── config.yml         ← per-repo settings, exceptions and rule overrides
        ├── audit.log          ← full scan history (append-only)
        ├── last-scan.json     ← copy of latest scan
        ├── scans/             ← one JSON per scan, never overwritten
        └── reports/           ← generated HTML/MD/JSON reports
        └── exports/           ← generated JSON-files from scd export-findings command
```

### Scan storage

Every scan is saved with a unique random ID (`s-a3f9b2c1`). This ID is timezone-neutral and is also used as `session_id` on the server for full traceability.

```bash
scd repo scans                     # list all saved scans
scd report --scan s-a3f9b2c1       # regenerate report from a specific scan
```


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

  Full details:  scd report open   or   scd report serve
  All findings:  scd scan --verbose   or   scd export-findings
```

Use `scd scan --verbose` for full per-file and per-rule detail.

### Taint analysis

The scanner tracks user-controlled variables (HTTP input, CLI args) through your code to identify two-step injection patterns:

```
↳ $id assigned from $_GET['id'] on line 30
```

Supports PHP, Python, and JavaScript/TypeScript. Set `scan_mode: fast` with `scd repo configure --scan-mode fast` to skip taint analysis on very large codebases.

### Deep analysis

`scd scan --deep` sends CRITICAL and HIGH findings to scd-server for AI-powered analysis. What is sent per finding:

- The filename
- Rule ID, name, severity, line number
- The exact code line that triggered the rule
- 8 lines of surrounding context

**Whole files are never sent.** Deep analysis requires scd-server with the Deep Analysis Pack. See [securecodebydesign.com](https://securecodebydesign.com) for subscription options.

Set `trust_level: maximum_privacy` with `scd repo configure --trust-level maximum_privacy` to disable all external API calls entirely.

### Exception management

Exceptions are managed by finding ID — shown in scan output, reports, and `scd findings`. Never edit source code comments.

```bash
# View open findings with their IDs
scd findings

# Accept a risk (requires team-lead approval via scd-server)
scd accept f-a1b2c3d4e5 --reason "Parameterized internally, validated input only"

# Ignore a finding (false positive, out of scope etc.)
scd ignore f-a1b2c3d4e5 --reason "Source maps intentionally included in staging" \
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

Per-repository configuration lives in `~/.scd/repos/{repoId}/config.yml` — outside your repository, alongside scan history and exceptions. This keeps your repository clean and avoids committing security configuration to source control.

```yaml
trust_level: balanced        # maximum_privacy | balanced | maximum_analysis
scan_mode: full              # full (with taint analysis) | fast (regex only)
block_on_critical: true
block_on_high: true
```

Edit with `scd repo configure --<option> <value>` or directly in the file.

`trust_level` controls which external connections are permitted:

| Value | Behaviour |
|---|---|
| `maximum_privacy` | No external API calls. Local model only. Strongest privacy guarantee. |
| `balanced` | Default. Local model preferred; cloud available as explicit opt-in. |
| `maximum_analysis` | Cloud provider (Claude API). Maximum analysis depth. |

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

See [INSTALL.md](INSTALL.md) for full platform-specific instructions including Node.js setup for macOS, Linux, and Windows.

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
  deep-analyzer.js        ← Deep analysis via scd-server
  output-terminal.js      ← Compact + verbose terminal output
  report-html.js          ← HTML report generator
  report-markdown.js      ← Markdown report generator
  report-json.js          ← JSON report generator
  export-findings.js      ← Export findings to JSON
  rules/                  ← Rule definitions per language
```

---

## Dependencies

scd is intentionally lightweight. Keeping the dependency surface small is a deliberate design principle — fewer dependencies means fewer supply chain risks, faster installs, and easier security auditing.

| Package | Version | Purpose |
|---|---|---|
| [commander](https://github.com/tj/commander.js) | ^14.0.3 | CLI argument parsing and subcommand structure |

No other runtime dependencies. Node.js built-in modules handle everything else.

Verify at any time:

```bash
npm list          # full dependency tree
npm audit         # check for known vulnerabilities
```

---

## Roadmap

- `scd deps` – Dependency vulnerability scanning against OSV + CISA KEV feeds (designed, in development)
- `scd uninstall` – clean removal with store data options

---

## Disclaimer

Secure Code by Design is a static analysis tool designed to help development teams identify common security vulnerability patterns in source code. It is provided as a technical aid, not as a guarantee of security.

**scd does not replace professional security testing.** No automated tool can detect all vulnerabilities in a codebase. scd does not perform dynamic analysis, penetration testing, runtime monitoring, or threat modelling. Findings depend on rule coverage, code patterns, and the languages supported — classes of vulnerabilities may exist that scd does not and cannot detect.

**No liability for security incidents.** Activemind Solutions AB and the contributors to this project accept no liability for security breaches, data loss, regulatory penalties, or any other damages arising from the use or non-use of this tool, including cases where a vulnerability present in a scanned codebase was not identified by scd. The presence of a passing scan does not constitute a security certification or assurance of any kind.

**scd is one layer of defence.** Effective application security requires multiple overlapping measures: secure design, code review, dependency management, penetration testing, monitoring, and incident response. scd is designed to make one of those layers — routine code scanning — easier and more consistent. It is not a substitute for any of the others.

If your organisation requires a formal security assessment, contact a qualified security professional or penetration testing firm.

---

## Security & responsible disclosure

Secure Code by Design is a security tool — and like any software, it may contain vulnerabilities. We encourage security testing of this product and welcome responsible disclosure.

**Expected behaviour:** Running `scd scan` on this repository will trigger findings in the rule files themselves — patterns that match injection, hardcoded secrets, and similar issues are present by design as test cases. These are expected false positives when scanning the tool's own source code.

**Reporting a vulnerability:** If you discover a genuine security issue, please report it privately to [security@activemind.se](mailto:security@activemind.se). Do not open a public GitHub issue for security vulnerabilities.

We aim to acknowledge reports within 2 business days and resolve confirmed issues as quickly as possible. Credit is given to researchers who report valid findings responsibly.

---

## About

Built by [Activemind Solutions AB](https://activemind.se) — security consulting and penetration testing.

> Secure Code by Design is a commercial product. See LICENSE for terms.
