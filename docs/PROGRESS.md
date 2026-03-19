# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-17 (session 2)_

## Status: v0.1.0 – Production-ready CLI

The tool lives at `~/Projects/scd` with GitHub at
`git@github.com:activemindsolutions/scd.git` (main branch).

Installed and verified working on:
- macOS (primary dev machine, `npm link`)
- Ubuntu (secondary machine, `git clone` + `npm link`)

---

## Completed

### Core CLI
- ✅ `scd init` – register repo, install git hooks via `core.hooksPath`
- ✅ `scd scan [target]` – full OWASP scan with `--lang`, `--severity`, `--rule`, `--format`, `--deep`, `--deep-delay`, `--no-audit`, `--no-limit`
- ✅ `scd scan --deep` – Claude API deep analysis (CRITICAL/HIGH only)
- ✅ `scd scan --deep --deep-delay <ms>` – configurable inter-file delay to avoid rate limits
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd report --open` – open in browser (macOS/Windows)
- ✅ `scd report --serve` – local HTTP server (auto-closes on keypress)
- ✅ `scd report --serve --index` – always show report index page
- ✅ `scd report --serve --port <n>` – optional fixed port
- ✅ `scd report --scan <id>` – generate report from a specific saved scan
- ✅ `scd export-findings` – export findings to structured JSON for external review; filters: `--severity`, `--rule`, `--scan`, `--all`, `--output`
- ✅ `scd approve` – create exceptions in config.yml
- ✅ `scd resolve` – mark findings as resolved
- ✅ `scd audit` – view audit trail
- ✅ `scd doctor` – verify setup
- ✅ `scd configure --api-key` – global Claude API key management
- ✅ `scd insights [--deep]` – behavioral analysis from audit log
- ✅ `scd list` – list all known repos in store
- ✅ `scd store` – show store info for current repo
- ✅ `scd store --show` – full meta.json view for current repo
- ✅ `scd store --reports` – list saved reports
- ✅ `scd store --scans` – list all saved scans with deep indicator
- ✅ `scd store --open / --open-reports / --path` – navigation helpers
- ✅ `scd store --verify [--verbose] [--clean] [--json]` – verify repos exist on disk
- ✅ `scd rules` – list all 172 rules
- ✅ `scd rules --lang / --severity / --id / --search / --stats / --format json`
- ✅ `scd version` – detailed version info (CLI + rules + Node + OS)
- ✅ `scd --version` – short version string (e.g. `0.1.0  (rules 1.0.0)`)

### Rule coverage (172 rules total)
- ✅ JavaScript/TypeScript – 29 rules
- ✅ Python – 26 rules
- ✅ PHP – 29 rules
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files (filename + content) – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules (INFRA-001–051)

**Severity breakdown:** CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

### Finding export (`scd export-findings` / `scd review-rules`)
- ✅ `lib/export-findings.js` – shared core module for both commands
- ✅ Output format: `meta`, `summary`, `findings[]`, `rule_analysis{}` blocks
- ✅ Default filter: deep-only (findings that have a Claude deep analysis result)
- ✅ `--all` flag includes findings without deep analysis (`deep: null`)
- ✅ `--severity` / `--rule` / `--scan` / `--output` filters
- ✅ Per-rule FP rate stats: `fp_rate = false_positives / (confirmed + false_positives)`, no_verdict excluded
- ✅ `high_fp_rules` in summary: rules with `fp_rate >= 0.5` and `sample_size >= 3`
- ✅ `languages_scanned` derived from file extensions in findings (EXT_TO_LANG map)
- ✅ Best-effort context lines read from source files at export time (falls back to snippet)
- ✅ `scd review-rules` (internal, hidden from `scd --help` and README) adds `pattern` and `antipattern` (RegExp source strings) to each `rule_analysis` entry

### Scan storage
- ✅ Per-scan JSON files in `~/.scd/repos/{id}/scans/{scanId}.json`
- ✅ Scan ID format: `2026-03-17T132421` (date with dashes, time without)
- ✅ `last-scan.json` kept as copy of latest for backwards compatibility
- ✅ Deep results stored alongside findings in same scan file – never lost on re-scan
- ✅ Report filenames include full timestamp: `security-report-2026-03-17T132421.html`
- ✅ `scd report --scan <id>` to regenerate report from any historical scan

### HTML report
- ✅ Three tabs: Executive Summary, Remediation Plan, All Findings
- ✅ Deep Analysis tab (shown only when deep results exist)
  - Filtering by severity + false positive toggle
  - Sorting by severity (default, confirmed first / FP last) or file name
  - Original finding context (rule, category, code snippet, why) alongside Claude analysis
  - Per-finding: confirmed/false-positive, confidence, attack scenario, fix explanation, fix code
- ✅ Report index page (`--serve` auto-shows index when >1 report exists)
- ✅ Repo name shown in report header (from meta.json)
- ✅ Report files written with `mode: 0o644` (fixes Linux browser access)

### Deep analysis (`--deep`)
- ✅ Sends only: filename + rule ID + triggering code line + 8 lines of context
- ✅ Never sends whole files, repo structure, or unrelated code
- ✅ Blocked when `trust_level: maximum_privacy` in config
- ✅ Exponential backoff retry on rate limit (429): 15s → 30s → 60s → 120s
- ✅ `--deep-delay <ms>` flag for configurable inter-file pause
- ✅ `deep_delay_ms` in `securityagent.yml` for persistent project-level default
- ✅ All prompts and responses in English
- ✅ Confidence values: HIGH / MEDIUM / LOW

### Infrastructure & quality
- ✅ Global store architecture (`~/.scd/repos/{repoId}/`)
- ✅ Zero repo footprint – no files written to customer's repo after init
- ✅ False-positive filters: minified, vendor, build-tool-configs
- ✅ Antipattern lookbehind (env-var fallbacks correctly excluded)
- ✅ path-based vs remote repo type handling in store-verify
- ✅ All CLI output, rule text, and deep analysis prompts in English
- ✅ Git: main branch, executable bit (via `prepare` npm script), .gitignore, .npmignore
- ✅ `package.json` – `bin: { scd }`, engines, author, files, `@anthropic-ai/sdk` dependency
- ✅ `INSTALL.md` – multi-machine install guide
- ✅ `securityagent.yml` – English template config with `deep_delay_ms`
- ✅ Version system: CLI from `package.json`, rules from `rule-registry.js` (independent)
- ✅ `report-index.js` – separate module for HTTP server index page

### Versioning convention
| What changes | CLI (`package.json`) | Rules (`rule-registry.js`) |
|---|---|---|
| New CLI feature | bump minor: `0.2.0` | unchanged |
| New rule or rule fix | bump minor: `0.2.0` | bump minor: `1.1.0` |
| Rule engine separation | bump major: `1.0.0` | bump major: `2.0.0` |
| Critical bugfix | bump patch: `0.1.1` | bump patch: `1.0.1` |

---

## Next on roadmap

### `scd deps` – Dependency scanning
Deliberately parked – needs careful design.

**Planned:**
- Level 1: Outdated check (npm, PyPI, Composer, NuGet)
- Level 2: CVE check via OSV API (`api.osv.dev/v1/query`)
- Parsers: `package.json`, `requirements.txt`, `composer.json`, `*.csproj`
- Separate `scd deps` command (not mixed into `scd scan`)
- CRA documentation angle: evidence of active vulnerability monitoring

### Multi-user & portal (Fas 1–2)
- Push queue architecture (events → `push-queue.jsonl` → sc-server)
- License validation (Ed25519 offline + 24h heartbeat)
- sc-server MVP (Node.js binary via `pkg`)
- Team dashboard, knowledge gap analysis, trend view

### Install/uninstall flow
- `scd uninstall` – removes hooks, optionally cleans store
- `scd store --nuke` – removes all store data (explicit confirmation)
- Foundation in place: `store-verify.js` has `deleteRepo()` and `archiveRepo()`

---

## Parked ideas (not forgotten)

- **`scan_sensitivity`**: `strict | balanced | relaxed` per rule category
- **Deep analysis in pre-push hook** (optional, with cost warning)
- **IDE extension** (VS Code)
- **NestJS decorator patterns** – rule additions
- **`scd export-findings` merge** – `scd export-findings` is implemented; a complementary merge/import flow for aggregating results across machines is still parked
- **Config signing** (supply chain protection)
- **Minified file scanning** – currently skipped; accepted trade-off
- **`scd report --from <date>`** – filter scans by date range (foundation exists)

---

## Known issues / technical debt

- `scd report --open` uses `xdg-open` on Linux → blocked by Firefox `file://` policy. **Workaround: `scd report --serve`**
- `securityagent.yml` in project root is a template; `config.yml` in store is the active mechanism. Should eventually be unified or auto-synced by `scd init`.
- Some Swedish text remains in terminal output for `scd scan` (words like "Manuell scanning", "fil(er) hittade") – low priority, non-customer-facing in current state.
- `scd store --verify` STALE status only applies to `remote`-type repos (path-based repos don't require `.git/`)

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
