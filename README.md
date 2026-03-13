# Security Co-Pilot

> Automated security scanning for development teams using AI coding tools.

Security Co-Pilot (`sc`) is a CLI tool that catches security vulnerabilities before they reach production — running quietly in the background via git hooks and on-demand scans. Built for SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor) who generate code faster than their security awareness can keep up with.

**Not a replacement for penetration testing.** It minimizes the number of vulnerabilities that reach production so that pentests can focus on harder problems.

---

## Features

- **172 security rules** across JavaScript, TypeScript, Python, PHP, ASP.NET, and more
- **Git hooks** – secrets scanning on pre-commit, full OWASP scan on pre-push
- **Zero repo footprint** – no files written to your repository after init
- **HTML, Markdown and JSON reports** with fix guidance for each finding
- **Exception management** – reviewed exceptions tracked in config, never as code comments
- **Audit trail** – full scan history per repository
- **Deep analysis** – optional Claude API integration for AI-powered finding analysis
- **Infrastructure leakage detection** – hardcoded IPs, internal hostnames, connection strings

---

## Requirements

- Node.js 18 or later
- Git
- npm

---

## Installation

### Clone and link (recommended)

```bash
git clone git@github.com:activemindsolutions/security-copilot.git
cd security-copilot
npm install
npm link
```

### Verify

```bash
sc --version
sc doctor
```

---

## Quick start

```bash
# Register a project and install git hooks
cd /path/to/your/project
sc init

# Run a full security scan
sc scan

# Generate an HTML report from the last scan
sc report

# Open the report in your browser
sc report --open          # macOS / Windows
sc report --serve         # Linux / Firefox (starts local HTTP server)
```

---

## Commands

| Command | Description |
|---|---|
| `sc init` | Register repo and install git hooks |
| `sc scan [target]` | Run a full security scan |
| `sc scan --deep` | Scan with Claude API deep analysis |
| `sc report` | Generate report from last scan (HTML default) |
| `sc report --serve` | Serve report via local HTTP server |
| `sc approve` | Create a reviewed exception for a finding |
| `sc resolve` | Mark a finding as resolved |
| `sc audit` | View scan history and audit trail |
| `sc insights` | Analyze behavioral patterns from audit log |
| `sc rules` | List all security rules |
| `sc rules --lang php` | Filter rules by language |
| `sc rules --id INFRA-001` | Show full detail for a rule |
| `sc rules --search "injection"` | Free-text search across rules |
| `sc rules --stats` | Rule counts by severity and language |
| `sc list` | List all repos registered in store |
| `sc store` | Show store info for current repo |
| `sc store --show` | Full metadata for current repo |
| `sc store --verify` | Verify all repos exist on disk |
| `sc store --verify --clean` | Interactive cleanup of missing/stale repos |
| `sc configure --api-key` | Set Claude API key for deep analysis |
| `sc doctor` | Verify installation and configuration |

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

`sc init` configures git to use a shared hooks directory (`~/.security-copilot/hooks`):

```
pre-commit  → fast secrets scan (blocks CRITICAL findings)
pre-push    → full OWASP scan  (blocks CRITICAL + HIGH findings)
```

### Global store

All scan data, configs and reports are stored outside your repository:

```
~/.security-copilot/
├── config                    ← API key
└── repos/
    └── {repoId}/
        ├── meta.json         ← repo identity and last scan summary
        ├── config.yml        ← exceptions and rule overrides
        ├── audit.log         ← full scan history
        ├── last-scan.json    ← cache for sc report
        └── reports/          ← generated HTML/MD/JSON reports
```

### Project configuration

Place `securityagent.yml` in your project root to configure scanning behaviour:

```yaml
trust_level: balanced        # maximum_privacy | balanced | maximum_analysis
block_on_critical: true
block_on_high: true
```

---

## Exception management

Exceptions for accepted findings are managed in the store config — never as source code comments. Comments like `// sc-ignore` leak information about vulnerabilities to anyone reading the code.

```bash
sc approve --rule FRONT-001 --file src/maps/config.js --line 12
```

Exceptions include a hash of the relevant code line. If the code changes, the exception requires re-approval automatically.

---

## Multi-machine setup

See [INSTALL.md](INSTALL.md) for full instructions including tarball installation and shell configuration.

---

## Project structure

```
bin/
  security-copilot.js    ← CLI entry point (all sc commands)
lib/
  scanner-full.js        ← OWASP scanner
  scanner-secrets.js     ← Fast secrets scanner (pre-commit)
  store.js               ← Global store path management
  store-verify.js        ← Store health checks and cleanup
  rule-registry.js       ← Normalised catalogue of all rules
  report-html.js         ← HTML report generator
  report-markdown.js     ← Markdown report generator
  report-json.js         ← JSON report generator
  rules/                 ← Rule definitions per language
docs/
  ARCHITECTURE.md        ← Product vision and technical architecture
  CODEBASE.md            ← File-by-file reference
  PROGRESS.md            ← Roadmap and current status
```

---

## Roadmap

- `sc deps` – Dependency scanning with CVE lookup via OSV API
- Multi-user portal (Team and Professional tiers)
- VS Code extension
- `sc uninstall` – clean removal with store data options

---

## About

Built by [Activemind Solutions AB](https://activemind.se) — security consulting and penetration testing.

> Security Co-Pilot is a commercial product. See LICENSE for terms.
