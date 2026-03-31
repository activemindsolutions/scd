# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-30_

## Status: v0.5.3 – Insights page + Scan ID refactor + Store UX

**scd CLI** lives at `~/Projects/scd`
`git@github.com:activemindsolutions/scd.git` (main branch, public)

**scd-server** lives at `~/Projects/scd-server`
`git@github.com:activemindsolutions/scd-server.git` (main branch, private)

**scd-admin** lives at `~/Projects/scd-admin`
Internal tools: `generate-license.js`, keypair management (not in any repo)

Installed and verified working on:
- macOS (primary dev machine, `npm link`)
- Ubuntu (secondary machine, `git clone` + `npm link`)

---

## Completed

### Core CLI (scd)
- ✅ `scd init` – register repo, install git hooks via `core.hooksPath`
- ✅ `scd scan [target]` – full OWASP scan with all flags
- ✅ `scd scan --deep` – Claude API deep analysis (CRITICAL/HIGH only)
- ✅ `scd scan --verbose` – full file-grouped + rule-grouped output (default: compact)
- ✅ `scd scan --include-vendor` – include vendor/dependency code in scan
- ✅ `scd scan --vendor-only` – scan only vendor/dependency code (supply chain audit)
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd export-findings` – export all findings to JSON (default: all findings)
- ✅ `scd export-findings --deep-only` – export only findings with deep analysis
- ✅ `scd approve --reason <text>` – create accepted-risk exception (pending team-lead approval)
- ✅ `scd ignore --reason <text> [--tag <text>]` – general-purpose ignore with optional free-text tag
- ✅ `scd sync` – pull approved/rejected exceptions from scd-server, write to config.yml
- ✅ `scd exceptions [--list pending|approved|rejected|all]` – list local exceptions
- ✅ `scd resolve --rejected <id>` – remove rejected exception from config, notify server
- ✅ `scd audit` – view audit trail
- ✅ `scd doctor` – verify setup + push queue status
- ✅ `scd configure` – API key, central URL, token management
- ✅ `scd insights [--deep]` – behavioral analysis from audit log
- ✅ `scd list / store / rules / version` – store and rule navigation

### Scan ID refactor (2026-03-30)
- ✅ `makeScanId()` generates `s-{8 hex chars}` e.g. `s-a3f9b2c1`
- ✅ Not date/time-based — avoids timezone confusion entirely
- ✅ Actual timestamp lives in `scanDate` field inside the scan file
- ✅ Same ID used as `session_id` on server — full CLI↔server traceability
- ✅ `logScan()` accepts `scanId` parameter, uses it as `session_id` in audit.log + push
- ✅ `saveCache()` accepts optional `scanId` parameter, returns ID used
- ✅ Single `scanId` created per scan in `bin/scd.js`, passed to both `logScan` and `saveCache`

### Store UX improvements (2026-03-30)
- ✅ `scd store --scans` — shows working directory, store ID, scans path on "no scans" error
- ✅ `scd store --scans` — column headers: "Scan ID" and "Date (local)" to clarify UTC vs local
- ✅ `scd store --show` — working directory shown as first line always
- ✅ `scd store --show` — shows working directory + store path on "not initialised" error
- ✅ `scd store` (default) — working directory shown as first line

### Terminal output (2026-03-26)
- ✅ **Compact mode** (default): Summary + Top issues (8 rules) + Most affected files (5)
- ✅ **Verbose mode** (`--verbose`): full file-grouped + rule-grouped output
- ✅ Progress bar, rejected-exception marking, sync notice

### Exception flow – end-to-end (2026-03-26)
- ✅ Full lifecycle: CLI → server → approval → sync → scan suppression → resolve
- ✅ `scd ignore --tag <text>`, `scd sync`, `scd exceptions`, `scd resolve --rejected <id>`

### Rule coverage (180 rules total)
- ✅ JavaScript/TypeScript – 32 rules (+3 taintAware, +1 unparameterized)
- ✅ Python – 31 rules (+3 taintAware, +1 unparameterized)
- ✅ PHP – 29 rules (+ taintAware variants)
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules

**Severity breakdown:** CRITICAL: 63, HIGH: 77, MEDIUM: 10, EXPOSURE: 30

### Taint analysis — Python and JS/TS (2026-03-27)
- ✅ Six taintAware rules: PY-INJ-001, PY-INJ-002, PY-PATH-001, INJ-001, INJ-002, INJ-003
- ✅ taintExtract strategies extended for Python/JS (no $ prefix)
- ✅ HTML report: taint-source rendered inside code snippet box
- ✅ Dedup: at file:line collision, higher severity wins

### Unparameterized query rules (2026-03-27)
- ✅ PY-INJ-006 (HIGH) — cursor.execute() with .format(), + concat, reversed concat
- ✅ INJ-004 (HIGH) — db/pool/knex.raw() with template literal or + concat
- ✅ Inline negative lookahead — immune to nearby-code suppression

### scd-server — Foundation + Auth
- ✅ Express + SQLite, JWT session auth, rate limiting, Bearer token support
- ✅ Ed25519 license validation, machine fingerprint binding

### scd-server — Admin UI (`/admin`)
- ✅ Server status, license info, installations, scans, user management

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Stat cards, trend chart, knowledge gaps, top rules, recent scans, repos
- ✅ Recent Scans: Scan ID column added, click opens detail modal
- ✅ Navbar: Dashboard, Insights, Exceptions, Data ▾, Reports, Admin

### scd-server — Exception approval flow
- ✅ Full lifecycle: pending → approved | rejected → resolved
- ✅ CLI push, dashboard approve/reject, CLI sync pull

### scd-server — Exceptions page (`/dashboard/exceptions`)
- ✅ Four tabs, inline modals, ID column (#12), tag chip, type pill

### scd-server — Reports (`/reports`)
- ✅ CRA Compliance Report — seven sections, Chart.js trend, print CSS, cover page
- ✅ Section: Developer Coverage & Knowledge Gaps (CRA Annex I Part I §2, Annex II §2, NIS2 Art. 21 §2(b))
  - Scanning coverage table per developer machine (active/inactive status)
  - Team knowledge gaps with training recommendations per OWASP category
- ✅ Reports index with coming reports listed

### scd-server — Data pages (`/data/*`)
- ✅ Repositories, Installations, Rules, Scans
- ✅ Client-side search, column sort, row count
- ✅ Scans page: Scan ID as first column, clickable → detail modal
- ✅ Scan detail modal: ID, repo, host, platform, scd version, hook, timestamp,
  files, findings by severity, blocked, exceptions, top rules, OWASP categories
- ✅ Modal: 720px wide, 2-column metadata grid (grid2col helper)
- ✅ "Data ▾" dropdown in navbar

### scd-server — Insights (`/insights`)
- ✅ Own navbar entry — visible to all roles
- ✅ Filters: period (30/90/180/365 days), repository, developer (was: installation)
- ✅ Six stat cards: total scans, active repos, active developers, clean scan rate, total critical, blocked
- ✅ Finding Trend — stacked bar chart (Chart.js) per week, Critical/High/Medium
- ✅ Knowledge Gaps — OWASP categories as horizontal bars, dominant gap CTA ("Consider workshop")
- ✅ Most Triggered Rules — top 8 rules with bars, clickable links to drill-down
- ✅ Scanning Activity — repos with color dot (green/yellow/red by recency), stale warning
- ✅ Risk Decisions — most accepted exceptions, flags rules with 5+ accepted exceptions
- ✅ Developer Breakdown — per-developer table: scans, clean rate, critical/high, top OWASP gap, last scan
- ✅ All sections update on filter change, chart rebuilt without flicker

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ Rule, Repo, Installation detail with 12-week trend charts

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`, `exceptions`

New db queries: `getInsightsSummary`, `getInsightsScanActivity`,
`getInsightsExceptionRate`, `getInsightsTrend`,
`getInsightsDeveloperSummary`, `getInsightsDeveloperGaps`

---

## Next on roadmap

### `pkg` – Binary distribution (before first customer)
- Eliminates Node version conflicts for customers
- Requires solving `better-sqlite3` native addon packaging
- One binary per platform: macOS (arm64 + x64), Linux (x64)

### Per-developer breakdown (Fas 2 remaining)
- Knowledge gap analysis per developer (Insights page extension)
- Drill-down Nivå 2: per-finding aggregates in push events

### `scd deps` — Dependency scanning
- CVE lookup via OSV API
- Natural complement to code scanning

### Fas 3
- CRA/NIS2 compliance reports — additional report types
- Plugin API + commercial rule packs
- Rule signing (Activemind-verified vs community)

### Feature backlog (not forgotten)
- Export filtered data from Data pages (CSV/JSON)
- audit.log sync CLI→server (Drill-down Nivå 3 prerequisite)
- Per-developer breakdown in Insights
- Server-side PDF generation for reports

---

## Reports Roadmap (Fas 3+)

| Report | Status | CRA/NIS2 ref |
|---|---|---|
| CRA Compliance Report | ✅ MVP | Art. 13, 14, Annex I+II |
| NIS2 Compliance Report | Planned | Art. 21 NIS2 |
| Vulnerability Disclosure Register | Planned | CRA Art. 14 |
| Remediation Timeline | Planned | CRA Art. 13 §2 |
| SDLC Security Evidence | Planned | CRA Annex II |
| Per-repo / per-installation filters | ✅ Done | All |
| Server-side PDF generation | Planned | All |
| audit.log sync CLI→server | Prerequisite | Drill-down Nivå 3 |

---

## Parked ideas (not forgotten)

- Full AST-based taint analysis engine
- Rule customization per repo
- Drill-down Nivå 3: full findings in scd-server
- scan_sensitivity: strict | balanced | relaxed per rule category
- Deep analysis in pre-push hook
- IDE extension (VS Code)
- Config signing (supply chain protection)
- Activemind-hosted cloud central
- Server-side notifications (email/Discord/webhook)

---

## Known issues / technical debt

- `scd report --open` on Linux blocked by Firefox `file://` policy → use `--serve`
- scd-server requires Node 18 (better-sqlite3 native addon)
- **PY-INJ-001** false positive: `cursor.execute("SELECT ... %s", (val,))` — pre-existing issue
- CRA report Section 2 shows aggregated scan totals, not unique findings
- Taint antipattern window can suppress valid findings when safe/unsafe code are adjacent

### Key design rules (accumulated learnings)
- **onclick with function args in HTML strings**: always use `data-*` + `addEventListener`.
  Never `onclick="fn('value')"` or escaped quotes — causes SyntaxError in browser.
- **Inline negative lookahead** in patterns (not antipattern window) for unparameterized query rules
- **taintAware rules**: must not fall through when no varName extracted
- **Dedup**: Pass 1 ruleId:file:line (taintSource wins), Pass 2 file:line (higher severity wins)
- **Scan ID**: s-XXXXXXXX format — random, timezone-free, same ID in CLI file + server session_id
- **UI terminology**: "installation" is internal/technical. In all user-facing UI use "developer" or "developer machine". URLs and DB schema unchanged.

### Exception flow design notes
- `updateExceptionStatus` uses line-by-line YAML parsing
- `db_id` written to config.yml on sync so `scd resolve --rejected` can notify server
- `handledExceptionIds` in meta.json prevents sync-notice re-appearing after resolve

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
