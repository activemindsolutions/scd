# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-31_

## Status: v0.6.0 (scd CLI) / v0.7.0 (scd-server)

**scd CLI** lives at `~/Projects/scd`
`git@github.com:activemindsolutions/scd.git` (main branch, public)

**scd-server** lives at `~/Projects/scd-server`
`git@github.com:activemindsolutions/scd-server.git` (main branch, private)

**scd-admin** lives at `~/Projects/scd-admin`
Internal tools: `generate-license.js`, keypair management (not in any repo)

---

## Completed

### Core CLI (scd)
- ✅ `scd init` – register repo, install git hooks via `core.hooksPath`
- ✅ `scd scan [target]` – full OWASP scan with all flags
- ✅ `scd scan --deep` – Claude API deep analysis (CRITICAL/HIGH only)
- ✅ `scd scan --verbose` – full file-grouped + rule-grouped output
- ✅ `scd scan --include-vendor` / `--vendor-only` – vendor code scanning
- ✅ `scd scan --no-sync` – skip push to scd-server for this scan (audit log kept locally)
- ✅ `scd scan --no-audit` – skip audit logging entirely
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd export-findings` – export findings to JSON with filters
- ✅ `scd approve` / `scd ignore` – exception management
- ✅ `scd sync` – pull approved/rejected exceptions from scd-server
- ✅ `scd exceptions` / `scd resolve` – exception lifecycle
- ✅ `scd audit` / `scd insights` – local analysis
- ✅ `scd store` / `scd rules` / `scd doctor` / `scd version` – navigation

### Scan ID refactor
- ✅ `makeScanId()` generates `s-{8 hex chars}` — not date/time-based
- ✅ Same ID used as `session_id` on server — full CLI↔server traceability
- ✅ `logScan()` accepts `scanId` + `noSync` parameters
- ✅ `saveCache()` accepts optional `scanId` parameter

### --no-sync flag
- ✅ Skips `enqueue()` and all `tryFlush()` calls
- ✅ audit.log still written — local traceability preserved
- ✅ Terminal notice shown when active
- ✅ Compatible with all other flags

### Store UX improvements
- ✅ Working directory shown in `scd store`, `--scans`, `--show`
- ✅ Clear error messages with store path when uninitialised or no scans
- ✅ Scan ID column header: "Scan ID" / "Date (local)"

### Rule coverage (180 rules total)
- ✅ JavaScript/TypeScript – 32 rules
- ✅ Python – 31 rules
- ✅ PHP – 29 rules
- ✅ ASP.NET markup – 17 rules
- ✅ ASP.NET C# – 26 rules
- ✅ Sensitive files – 50 rules
- ✅ Infrastructure leakage – 21 rules
- **Severity:** CRITICAL: 63, HIGH: 77, MEDIUM: 10, EXPOSURE: 30

### Taint analysis — PHP, Python, JS/TS
- ✅ Six taintAware rules for Python and JS/TS
- ✅ Unparameterized query rules: PY-INJ-006, INJ-004

### scd-server — Foundation
- ✅ Express + SQLite, JWT session auth, Bearer token, Ed25519 license

### scd-server — Dashboard (`/dashboard`)
- ✅ Stat cards, trend chart, knowledge gaps, top rules, recent scans
- ✅ Scan ID column in Recent Scans — click opens detail modal

### scd-server — Insights (`/insights`)
- ✅ Own navbar entry, visible to all roles
- ✅ Filters: period, repository, developer machine
- ✅ Six stat cards, Finding Trend (Chart.js), Knowledge Gaps with CTA
- ✅ Most Triggered Rules, Scanning Activity, Risk Decisions
- ✅ Developer Breakdown — per-developer table with clean rate, top gap, last scan

### scd-server — Reports (`/reports`)
- ✅ CRA Compliance Report — seven sections, Chart.js trend, print CSS
- ✅ Section 6: Developer Coverage & Knowledge Gaps
  - Scanning coverage per developer machine (active/inactive status)
  - Team knowledge gaps with training recommendations (NIS2 Art. 21 §2(b))
  - CRA refs: Annex I Part I §2, Annex II §2

### scd-server — Data pages (`/data/*`)
- ✅ Repositories, Developer machines, Rules, Scans
- ✅ Client-side search, column sort, row count
- ✅ Scan detail modal (720px, 2-column grid)
- ✅ "Data ▾" dropdown in navbar
- ✅ Status column (Active/Excluded) on repos and developer machines
- ✅ Exclude toggle in list modals with role-based disabled state

### scd-server — Exclude from statistics
- ✅ `excluded_from_stats` column on both `installations` and `repos`
- ✅ Migration runs automatically on startup
- ✅ Toggle on detail pages (admin only) — disabled/greyed for other roles
- ✅ Toggle in data list modals — same role-based behaviour
- ✅ All insights queries filter excluded machines and repos
- ✅ CRA report developer section filters excluded machines
- ✅ Defense in depth: UI disables, backend (`requireAdmin`) protects

### scd-server — Exception approval flow
- ✅ Full lifecycle: pending → approved | rejected → resolved

### scd-server — Drill-down detail pages
- ✅ Rule, Repo, Installation detail with 12-week trend charts
- ✅ Exclude toggle on Repo and Installation detail pages

### scd-server — Database
- Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
  `findings`, `raw_events`, `server_config`, `sessions`, `users`, `exceptions`,
  `deep_results`, `ai_config`
- Key queries: `getInsightsSummary`, `getInsightsScanActivity`,
  `getInsightsExceptionRate`, `getInsightsTrend`,
  `getInsightsDeveloperSummary`, `getInsightsDeveloperGaps`,
  `getScanDetail`, `getCRAScanSummary`, `getCRAOpenFindings`, `getCRARiskRegister`,
  `setInstallationExcluded`, `setRepoExcluded`, `insertFindings`

### UI terminology
- "installation" is internal/technical — DB schema and URLs unchanged
- All user-facing UI uses "developer" or "developer machine"

---

## Next on roadmap

### Findings drill-down på servern
- Findings per repo (prioritet 1)
- Findings globalt (prioritet 2)  
- Findings per scan (prioritet 3)

### audit.log sync CLI→server
- ✅ `findings_batch` event i push-queue — alla findings synkas automatiskt vid varje scan
- ✅ `snippet` och `taint_source` inkluderas i finding-events (audit.log + push-queue)
- ✅ `scd sync --history` — engångsync av befintlig audit.log (idempotent, safe att köra flera ggr)
- ✅ Historik chunkas i grupper om 10 sessioner per request
- ✅ Ny `findings`-tabell på servern med UNIQUE constraint
- ✅ `insertFindings()` med transaktionsbaserad batch-insert
- ✅ `routes-events.js` separerar `findings_batch` från scan-events
- ✅ Body limit höjd till 10mb i server.js för stora historik-syncar
- ✅ Starter→Team uppgradering: kör `scd sync --history` i varje repo

### `pkg` — Binary distribution (before first customer)
- Eliminates Node version conflicts
- One binary per platform: macOS (arm64 + x64), Linux (x64)

### `scd deps` — Dependency scanning
- CVE lookup via OSV API

### `deep-analyzer.js` refactor
- `--deep` should route via scd-server instead of direct Anthropic API
- Waiting for more info before implementing

### Fas 3
- NIS2 Compliance Report
- Plugin API + commercial rule packs
- Rule signing

### Feature backlog
- Export from Data pages (CSV/JSON)
- Per-developer breakdown in Insights (extended)
- Server-side PDF generation

---

## Known issues / technical debt

- `scd report --open` on Linux blocked by Firefox `file://` policy → use `--serve`
- **PY-INJ-001** false positive: `cursor.execute("SELECT ... %s", (val,))` — pre-existing
- CRA report Section 2 shows aggregated scan totals, not unique findings

### Key design rules (accumulated learnings)
- **onclick with function args**: always use `data-*` + `addEventListener` — never inline quotes
- **Inline negative lookahead** for unparameterized query rules
- **taintAware rules**: must not fall through when no varName extracted
- **Scan ID**: `s-XXXXXXXX` format — random, timezone-free, same in CLI + server `session_id`
- **UI terminology**: "installation" = internal. UI says "developer" / "developer machine"
- **Exclude pattern**: UI disables button (opacity + disabled attr), backend uses `requireAdmin`
- **Template literals in Node.js HTML**: use string concatenation — nested backticks cause syntax errors
- **`findings_batch` event**: skickas alltid via push-queue efter scan (utöver `scan_completed`)
- **`scd sync --history`**: läser hela audit.log, rekonstruerar findings per session_id, chunkar 10 sessioner/request
- **`--no-sync`**: skips enqueue + tryFlush, audit.log still written locally

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in scd repo, commit and push
3. Replace the file in Claude Project Knowledge
