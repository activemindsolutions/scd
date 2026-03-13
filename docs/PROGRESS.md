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
- ✅ `sc report --serve --port <n>` – optional fixed port
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
- ✅ `sc store --verify [--verbose] [--clean] [--json]` – verify repos exist on disk, interactive cleanup with keep/archive/delete/skip
- ✅ `sc rules` – list all 172 rules grouped by category
- ✅ `sc rules --lang / --severity / --id / --search / --stats / --format json`

### Rule coverage (172 rules total)
- ✅ JavaScript/TypeScript – 29 rules
- ✅ Python – 26 rules
- ✅ PHP – 29 rules
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files (filename + content) – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules (INFRA-001–051)

**Severity breakdown:** CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

### Infrastructure & quality
- ✅ Global store architecture (`~/.security-copilot/repos/{repoId}/`)
- ✅ Zero repo footprint – no files written to customer's repo after init
- ✅ False-positive filters: minified, vendor, build-tool-configs
- ✅ Antipattern lookbehind support (env-var fallbacks like `process.env.X || 'localhost'` correctly excluded)
- ✅ path-based vs remote repo type handling (path-based repos don't require `.git/`)
- ✅ All CLI output and rule text in English
- ✅ report-html.js, report-markdown.js, report-json.js write with `mode: 0o644` (fixes Linux browser access)
- ✅ `rule-registry.js` – central normalised catalogue of all rules, used by `sc rules`
- ✅ `store-verify.js` – verify, archive (`tar.gz`), delete with scan-history confirmation
- ✅ Git: main branch, executable bit on bin/security-copilot.js, .gitignore, .npmignore
- ✅ `package.json` – correct `bin: { sc: ... }`, engines, author, files
- ✅ `INSTALL.md` – multi-machine install guide
- ✅ `securityagent.yml` – English template config for customer repos
- ✅ Claude project setup: `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/CODEBASE.md`, `docs/PROGRESS.md`

---

## Next on roadmap

### `sc deps` – Dependency scanning
Deliberately moved forward – needs careful design before implementation.

**Planned architecture:**
- Level 1: Outdated check (npm, PyPI, Composer, NuGet)
- Level 2: CVE check via OSV API (`api.osv.dev/v1/query`) – covers all ecosystems
- Parsers: `package.json`, `requirements.txt`, `composer.json`, `*.csproj`
- Separate `sc deps` command (not mixed into `sc scan`)
- Output: same severity model as scan findings
- CRA documentation angle: evidence of active vulnerability monitoring

### Multi-user & portal
- Portal architecture (Team/Professional tiers)
- Central dashboard for team findings
- Zero-knowledge design (supply chain safety)
- NIS2/CRA compliance reporting

### Install/uninstall flow
- `sc uninstall` – removes hooks from registered repos, optionally cleans store
- `sc store --nuke` – removes all store data (explicit confirmation + name-typing)
- Foundation already in place: `store-verify.js` has `deleteRepo()` and `archiveRepo()`

---

## Parked ideas (not forgotten)

- **`scan_sensitivity`**: `strict | balanced | relaxed` per rule category ("volume control")
- **Deep analysis in pre-push hook** (optional, with cost warning)
- **IDE extension** (VS Code)
- **NestJS decorator patterns** – additional rule coverage
- **`sc export` + merge** (UUID session IDs already implemented in audit)
- **Config signing** (supply chain protection)
- **Portal tier differentiation**: Starter=local, Team=central portal, Professional=full integration
- **Minified file scanning** – currently skipped entirely; accepted trade-off since source is scanned. If needed: subset of HIGH-confidence rules (RFC1918 IPs, connection strings) applied to minified files only

---

## Known issues / technical debt

- `sc report --open` uses `xdg-open` on Linux which opens with `file://` – blocked by Firefox security policy. **Workaround: use `sc report --serve`**
- `securityagent.yml` in project root is a template; `rule_overrides` and `exceptions` in `config.yml` (store) are the active mechanism. These should eventually be unified.
- Swedish text may remain in older ASP.NET rule comments (not user-facing, low priority)

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
