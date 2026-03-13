# Security Co-Pilot – Progress & Roadmap

_Last updated: 2026-03-13_

## Status: v0.1.0 – Production-ready CLI

The tool has moved from PoC (`security-copilot-poc`) to a proper project
at `~/Projects/security-copilot` with GitHub at
`git@github.com:activemindsolutions/security-copilot.git`.

Installed and verified working on:
- macOS (primary dev machine, `npm link`)
- Ubuntu (secondary machine, `git clone` + `npm link`)

---

## Completed

### Core CLI
- ✅ `sc init` – register repo, install git hooks via `core.hooksPath`
- ✅ `sc scan [target]` – full OWASP scan with `--lang`, `--severity`, `--rule`, `--format`, `--deep`, `--no-audit`, `--no-limit`
- ✅ `sc scan --deep` – Claude API deep analysis integration
- ✅ `sc report` – generate HTML/MD/JSON from cached scan
- ✅ `sc report --open` – open in browser (macOS/Windows)
- ✅ `sc report --serve` – local HTTP server for Linux/Firefox (auto-closes on keypress)
- ✅ `sc approve` – create exceptions in config.yml
- ✅ `sc resolve` – mark findings as resolved
- ✅ `sc audit` – view audit trail
- ✅ `sc doctor` – verify setup
- ✅ `sc configure --api-key` – global Claude API key management
- ✅ `sc insights [--deep]` – behavioral analysis from audit log
- ✅ `sc list` – list all known repos in store
- ✅ `sc store` – show store info for current repo
- ✅ `sc store --show` – full meta.json view for current repo
- ✅ `sc store --reports` – list saved reports
- ✅ `sc store --open / --open-reports / --path` – navigation helpers
- ✅ `sc store --verify [--verbose] [--clean] [--json]` – verify repos exist on disk, interactive cleanup
- ✅ `sc rules` – list all 172 rules
- ✅ `sc rules --lang / --severity / --id / --search / --stats / --format json`

### Rule coverage (172 rules total)
- ✅ JavaScript/TypeScript – 29 rules
- ✅ Python – 26 rules
- ✅ PHP – 29 rules
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files (filename + content) – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules (INFRA-001–051)

### Infrastructure & quality
- ✅ Global store architecture (`~/.security-copilot/repos/{repoId}/`)
- ✅ Zero repo footprint – no files written to customer's repo after init
- ✅ False-positive filters: minified, vendor, build-tool-configs
- ✅ Antipattern lookbehind (env-var fallbacks correctly excluded)
- ✅ path-based vs remote repo type handling in store-verify
- ✅ All CLI output and rule text in English (was partially Swedish)
- ✅ Git setup: main branch, executable bit, .gitignore, .npmignore
- ✅ INSTALL.md for multi-machine setup
- ✅ Report file permissions: `mode: 0o644` (fixes Linux browser access)

---

## Next on roadmap

### `sc deps` – Dependency scanning
Deliberately moved forward – needs careful design.

**Planned:**
- Level 1: Outdated check (npm, PyPI, Composer, NuGet)
- Level 2: CVE check via OSV API (`api.osv.dev/v1/query`) – covers all ecosystems
- Parsers: `package.json`, `requirements.txt`, `composer.json`, `*.csproj`
- Separate `sc deps` command (not mixed into `sc scan`)
- Output: same severity model as scan findings

### Multi-user & portal
- Portal architecture (Team/Professional tiers)
- Central dashboard for team findings
- Zero-knowledge design (supply chain safety)

### Install/uninstall flow
- `sc uninstall` – removes hooks, optionally cleans store (with confirmation)
- `sc store --nuke` – removes all store data (with explicit confirmation + name-typing)
- Foundation already in place: `store-verify.js` has `deleteRepo()` and `archiveRepo()`

---

## Parked ideas (not forgotten)

- **`scan_sensitivity`**: `strict | balanced | relaxed` per rule category ("volume control")
  - Connects to existing `trust_level` in config
- **Deep analysis in pre-push hook** (optional, with cost warning)
- **IDE extension** (VS Code)
- **NestJS decorator patterns** – rule additions
- **`sc export` + merge** (UUID session IDs already implemented)
- **Config signing** (supply chain protection)
- **Portal tier differentiation**: Starter=local, Team=central portal, Professional=full integration
- **Minified file scanning** – currently skipped entirely; accepted trade-off since source is scanned
  - If needed: subset of HIGH-confidence rules (RFC1918 IPs, connection strings) on minified files

---

## Known issues / technical debt

- `sc report --open` uses `xdg-open` on Linux which opens with `file://` – blocked by Firefox
  → Workaround: use `sc report --serve` on Linux
- Swedish text may remain in older ASP.NET rule comments (not user-facing)
- `securityagent.yml` in project root is a template, not actively used by SC itself yet
  (rule_overrides and exceptions in config.yml are the active mechanism)
