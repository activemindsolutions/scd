# Secure Code by Design

> Automated security scanning for development teams using classic or AI coding tools.

[![npm](https://img.shields.io/npm/v/@activemind/scd)](https://www.npmjs.com/package/@activemind/scd)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE.md)

> **Actively developed.** Rules are continuously refined based on real-world scanning data across thousands of repositories. Use `--severity critical` to start with the highest-confidence findings, and expect precision to improve with each release.

Secure Code by Design (`scd`) is a CLI tool that catches security vulnerabilities before they reach production — running quietly in the background via git hooks and on-demand scans. Built for SMB companies using traditional coding and AI coding tools (Claude Code, GitHub Copilot, Cursor) which generates code faster than their security awareness can keep up with.

**Not a replacement for penetration testing.** scd helps you find and fix common vulnerability patterns before they reach production, so that professional security assessments can focus on harder, context-specific problems. It does not replace a penetration test, threat model, or security audit.

---

## Features

- **189 security rules** across JavaScript, TypeScript, Python, PHP, ASP.NET, and more
- **Taint analysis** — tracks user-controlled variables from HTTP input to dangerous sinks
- **Pre-scan file classification** — files are classified into source, test, and excluded contexts before any rule runs; test files and vendor code are routed separately
- **Git hooks** – secrets scanning on pre-commit, full OWASP scan on pre-push
- **Zero repo footprint** – no files written or modified to your repository
- **Compact terminal output** – summary + top issues + most affected files (use `--verbose` for full detail)
- **HTML, Markdown and JSON reports** with fix guidance for each finding
- **Deep analysis** – optional AI-powered analysis via scd-server; requires the Deep Analysis Pack (Premium)
- **Per-scan storage** – every scan saved with a unique random ID (`s-a3f9b2c1`), never overwritten; regenerate reports from any historical scan
- **Finding IDs** – every finding gets a stable ID (`f-a1b2c3d4e5`) shown in scan output, reports and export — use directly with `scd accept` and `scd ignore`
- **Exception management** – reviewed exceptions tracked in config, never as code comments
- **Exception sync** – pull team lead approvals from scd-server, sync rejected back with reason
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

See [INSTALL.md](INSTALL.md) for platform-specific Node.js setup, advanced options like running from cloned repo and
[installation troubleshooting](INSTALL.md#troubleshooting).

---

## Quick start

```bash
# 1. Install git hooks globally (once per machine)
scd install

# 2. Register a project and run your first scan
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
| `scd findings --show-suppressed` | Show findings suppressed by file context classification |
| `scd findings --severity critical` | Filter by severity |
| `scd findings --rule <id>` | Filter by rule ID |
| `scd findings --scan <id>` | Load a specific historic scan |

### Exception and scope management

| Command | Description |
|---|---|
| `scd accept <finding-id> --reason "<text>"` | Accept a risk — requires team lead approval via scd-server |
| `scd ignore <finding-id> --reason "<text>"` | Ignore a finding (false positive, out of scope) |
| `scd sync` | Pull approvals/rejections from scd-server |
| `scd exceptions` | List all exceptions and their status |
| `scd scope --show` | Show current scope exclusions |
| `scd scope --add-file <pattern>` | Permanently exclude a file or directory |
| `scd scope --add-rule <id>` | Permanently exclude a rule |
| `scd scope --remove-file <pattern>` | Remove a file exclusion |
| `scd scope --remove-rule <id>` | Remove a rule exclusion |

### Repository management

| Command | Description |
|---|---|
| `scd init` | Register current directory and install git hooks |
| `scd repo` | Show repo info and scan statistics |
| `scd repo configure` | Show or update per-repo configuration |
| `scd repo hooks --disable --reason "<text>"` | Disable git hooks for this repo (reason required) |
| `scd repo hooks --enable` | Re-enable git hooks |
| `scd repo scope` | Manage per-repo scope exclusions |
| `scd list` | List all registered repos |
| `scd hooks` | Show hook status across all repos |
| `scd remove` | Remove repo from scd |

### Rules and insights

| Command | Description |
|---|---|
| `scd rules` | List all rules |
| `scd rules --search <term>` | Search rules by name or ID |
| `scd rules --stats` | Show rule counts by severity |
| `scd insights` | Behavioural analysis across scan history |
| `scd audit` | Show audit log |

### Diagnostics

| Command | Description |
|---|---|
| `scd doctor` | Verify installation, hook status, and server connectivity |
| `scd version` | Show version and rule counts |
| `scd configure --show` | Show server configuration and global defaults |

---

## Privacy and data handling

scd is designed for teams where code privacy is non-negotiable.

**Local scanning.** Standard `scd scan` runs entirely on your machine. No code, no findings, no metadata leaves your network. Nothing is sent anywhere unless you explicitly connect scd-server.

**scd-server.** When configured, scd pushes scan metadata and findings to your own scd-server instance — running in your own infrastructure. Findings never reach Activemind's servers.

**Deep analysis.** `scd scan --deep` sends the triggering code line and 8 lines of surrounding context to your scd-server for AI analysis. The filename, rule ID, and severity are included. Whole files are never sent. Deep analysis requires scd-server with the Deep Analysis Pack. See [securecodebydesign.com](https://securecodebydesign.com) for subscription options.

Set `trust_level: maximum_privacy` with `scd repo configure --trust-level maximum_privacy` to disable all external API calls entirely.

### Exception management

Exceptions are managed by finding ID — shown in scan output, reports, and `scd findings`. Never edit source code comments.

```bash
# View open findings with their IDs
scd findings

# Accept a risk (requires team lead approval via scd-server)
scd accept f-a1b2c3d4e5 --reason "Parameterized internally, validated input only"

# Ignore a finding (false positive, out of scope etc.)
scd ignore f-a1b2c3d4e5 --reason "Source maps intentionally included in staging" \
  --tag false_positive

# Pull approvals/rejections from team server
scd sync

# List exceptions and their status (filter: pending | approved | rejected | all)
scd exceptions --list all
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
  commands/               ← One file per scd command (scan, findings, report, …)
  scanner-full.js         ← OWASP scanner with taint analysis
  scanner-secrets.js      ← Fast secrets scanner (pre-commit)
  file-manifest.js        ← Pre-scan file classification (source/test/excluded)
  file-context.js         ← Per-file classification with two-layer detection
  context-modifiers.js    ← Severity adjustment based on file context + _trace
  comment-map.js          ← Per-file line classifier (CODE/COMMENT/MIXED)
  taint-register.js       ← Single-file taint tracking engine
  store.js                ← Global store path management
  store-verify.js         ← Store health checks and cleanup
  scan-cache.js           ← Per-scan storage (scans/ directory)
  scan-context.js         ← Repo-logging context resolution
  rule-registry.js        ← Normalised catalogue of all rules
  config.js               ← Config loading, isExcepted(), getRuleAction()
  exception-manager.js    ← Exception/ignore create, sync, list
  deep-analyzer.js        ← Deep analysis via scd-server
  cli-helpers.js          ← Shared CLI utilities (warnIfOutdated, openInBrowser, tryFlush)
  output-terminal.js      ← Compact + verbose terminal output
  report-html.js          ← HTML report generator
  report-markdown.js      ← Markdown report generator
  report-json.js          ← JSON report generator
  export-findings.js      ← Export findings to JSON
  rules/                  ← Rule definitions per language
    rule-loader.js        ← JSON→runtime compiler (pattern, antipatterns, extensions)
    rules-js.json         ← JavaScript/TypeScript rules incl. JS-ERR-002/B/C
    rules-infra-leakage.json ← Infrastructure rules incl. INFRA-001/B/C, 002/B/C
    rules-sensitive-files.json ← Sensitive file rules incl. LOG-004, EXPOSURE-001
    rules-secrets.json    ← Secrets detection
    rules-python.json     ← Python rules
    rules-php.json        ← PHP rules
    rules-aspx.json       ← ASP.NET markup rules
    rules-aspx-cs.json    ← ASP.NET C# rules
    rules-ts.json         ← TypeScript-specific rules
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
- Config-context file classification — distinguishes application config, infrastructure config, and schema/documentation files before rules run; improves precision for YAML and configuration-heavy projects
- `scd uninstall` – clean removal with store data options

---

## Verifying releases

Every release is signed with [minisign](https://jedisct1.github.io/minisign/) — a simple tool for verifying that a file has not been tampered with. minisign is available for macOS, Linux, and Windows.

To verify a release independently of npm and GitHub, using Activemind's own distribution server as a third source:

```bash
# Download checksums and signature (replace [version] in the URL with your version, e.g. v1.4.0)
curl -O https://dist.securecodebydesign.com/scd/[version]/checksums.txt
curl -O https://dist.securecodebydesign.com/scd/[version]/checksums.txt.minisig

# Download the public key
curl -O https://dist.securecodebydesign.com/scd/minisign.pub

# Verify
minisign -Vm checksums.txt -p minisign.pub
```

Example for v1.4.0:
```
https://dist.securecodebydesign.com/scd/v1.4.0/checksums.txt
https://dist.securecodebydesign.com/scd/v1.4.0/checksums.txt.minisig
```

The checksums file contains SHA-256 and SHA-512 hashes of the npm package tarball. The public key is also committed to the repository root as `minisign.pub` — cross-reference both sources if you want the strongest guarantee.

---

## License

scd is licensed under the [GNU Affero General Public License v3.0](LICENSE.md) (AGPL-3.0), with a commercial license option for proprietary use.

**Does using scd affect my project's license?** No. Running scd as a development tool — scanning your code with `scd scan`, installing hooks with `scd install`, or using any other scd command — does not impose any license requirements on your code or your product. Your software's license is entirely unaffected.

The AGPL-3.0 applies if you incorporate scd's source code into your own product, distribute scd as part of a commercial offering, or use scd as a component of a network-accessible service provided to third parties. In those cases, a commercial license is available from Activemind Solutions AB — contact [info@activemind.se](mailto:info@activemind.se).

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

> scd CLI is open source under AGPL-3.0. scd-server, which adds team collaboration, dashboards, and compliance reporting, is a commercial product. See [LICENSE](LICENSE.md) for terms.

## Credits and Acknowledgements
Thanks to Olle (0xolle) and Stefan (keets-zero) for helping out with testing, troubleshooting and coming up with good ideas for improvements.