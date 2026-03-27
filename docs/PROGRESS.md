# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-26_

## Status: v0.5.1 – Terminal UX + Exception flow end-to-end + CRA Report MVP

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

### Terminal output (2026-03-26)
- ✅ **Compact mode** (default): Summary + Top issues (8 rules) + Most affected files (5)
  with line numbers `(Lines: 33, 51, …)` + next-steps footer
- ✅ **Verbose mode** (`--verbose`): full file-grouped + rule-grouped output
- ✅ Progress bar during scan on same line (stderr, TTY only, clears on completion)
- ✅ `Discovering files…` and `Saving results…` status lines cover silent phases
- ✅ Rejected-exception marking: `⛔ rejected – fix required` per finding in verbose
- ✅ Rejected section in compact: list with rule/file + hint about `scd exceptions`
- ✅ `⛔ N rejected` in summary line
- ✅ Sync notice after scan: `ℹ N exception(s) pending – run scd sync` (local read, zero network)
  - `⚠` if >24h since last sync or never synced
  - Excludes exceptions already handled by server (via `handledExceptionIds` in meta.json)

### Exception flow – end-to-end (2026-03-26)
Complete lifecycle: CLI → server → approval → sync → scan suppression → resolve

- ✅ `scd ignore` / `scd approve` — file-not-found prompts y/N before creating without hash
  - Warns that hash-less exception matches ALL occurrences of that rule in the file
- ✅ `scd ignore --tag <text>` — optional free-text tag (max 40 chars, spaces → underscores)
  - Tag stored in config.yml and DB, shown as blue chip in exceptions UI
- ✅ `scd sync` — improved: fetches both approved and rejected in one run
  - Approved: updates status + writes `reviewed_by`, `review_comment`, `db_id` to config.yml
  - Rejected: notifies developer with reason, marks config.yml as rejected
  - `lastSynced` + `handledExceptionIds` written to meta.json
  - Matching: by CLI id first, falls back to rule+file+line (handles DB vs CLI id mismatch)
  - `updateExceptionStatus` rewritten with line-by-line approach — no regex on YAML
- ✅ `isExcepted()` — rejected exceptions no longer suppress findings (returns `rejected: true`)
- ✅ `scd exceptions --list [status]` — lists local exceptions with hint for rejected ones
- ✅ `scd resolve --rejected <id>` — removes from config.yml + POSTs to server (`status=resolved`)
- ✅ `db_id` written to config.yml on sync so resolve can notify server with correct integer ID

### Rule coverage (172 rules total)
- ✅ JavaScript/TypeScript – 29 rules
- ✅ Python – 26 rules
- ✅ PHP – 29 rules (+ taintAware variants)
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules

**Severity breakdown:** CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

### Rule improvements (2026-03-25)
- ✅ **PY-INJ-002** — subprocess command injection now requires `shell=True`
- ✅ **PY-PATH-001** — path traversal now requires explicit web-input context
- ✅ **INFRA-001/002/003/012** — exclude validation/comparison code (ADDR_AS_DATA constant)
- ✅ **INFRA-022** — exclude `e.g.` examples in error messages
- ✅ **INFRA-036** — exclude `log.*` calls
- ✅ **INFRA-040** — lookbehind `(?<!:)` prevents `://` matching as comment marker
- ✅ **PHP-INJ-002c** — taintAware: assign-then-use SQL injection
- ✅ **PHP-INJ-002d** — taintAware: interpolated tainted variable in SQL string
- ✅ **PHP-INJ-004b** — taintAware: tainted variable in shell command
- ✅ **PHP-AUTH-002b** — taintAware: tainted variable in include/require (LFI)

### Taint analysis engine (2026-03-25/26)
- ✅ `lib/taint-register.js` — `buildTaintRegister(content, language)` → `TaintRegister`
- ✅ PHP, Python, JS/TS sources supported
- ✅ Three extraction strategies: `concat`, `interpolation`, `func_concat`
- ✅ Terminal: `↳ $id assigned from $_GET['id'] on line 30`
- ✅ JSON export includes `taint_source: { variable, line, source }`
- ✅ `scan_mode: fast` skips taint analysis; `full` (default) includes it
- ✅ Early exit when taint register is empty; pre-built line offsets (binary search)

**Verified on SuiteCRM (5000+ files):** 269 findings, 141 (52%) taint-tracked, 19s full scan.

### scd-server — Foundation + Auth
- ✅ Express + SQLite, JWT session auth, rate limiting, Bearer token support
- ✅ Ed25519 license validation, machine fingerprint binding

### scd-server — Admin UI (`/admin`)
- ✅ Server status, license info, installations, scans, user management

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Stat cards including clickable "Pending approvals" card (admin/team-lead only)
- ✅ Findings trend chart (12 weeks), knowledge gaps, top rules, recent scans, repos
- ✅ Navbar: Reports link (all roles), Exceptions link with red badge (admin/team-lead)

### scd-server — Exception approval flow
- ✅ Exceptions table: `type`, `tag`, `status`, `reviewed_by`, `review_comment`, `db_id`
- ✅ Auto-migration: `tag` column added on startup if missing
- ✅ Status lifecycle: `pending` → `approved` | `rejected` → `resolved`
- ✅ `POST /api/v1/exceptions/batch` — CLI pushes exceptions (Bearer)
- ✅ `GET /api/v1/exceptions/approved?status=approved|rejected` — CLI sync pull
- ✅ `POST /api/v1/exceptions/:id/resolved` — CLI marks rejected as resolved (Bearer)
- ✅ `POST /dashboard/api/exceptions/:id/approve|reject` — dashboard approval (JWT)

### scd-server — Exceptions page (`/dashboard/exceptions`)
- ✅ Admin + team-lead only (requireApprover)
- ✅ Four tabs: Pending / Approved / Rejected / Resolved
- ✅ Pending: Approve/Reject buttons open modal with mandatory comment
- ✅ Approved/Rejected/Resolved: View modal with full audit trail
- ✅ Resolved modal shows `updated_at` as "fixed" timestamp
- ✅ Tag shown as blue chip in table and modal
- ✅ `type` pill: `ignore` or `exception`

### scd-server — Reports (`/reports`) — MVP
- ✅ Reports index page — lists available and coming reports
- ✅ CRA Compliance Report (`/reports/cra`) — HTML, printable to PDF via browser
  - Period filter: 30 / 90 / 180 / 365 days (default 90)
  - Repository filter: all repos or specific repo
  - Section 1: Executive Summary (scans, repos, installations, clean scans, period, status)
  - Section 2: Vulnerability Management Activity (findings by severity, monthly trend)
  - Section 3: OWASP Top 10 Coverage (findings per category with distribution bar)
  - Section 4: Documented Risk Decisions (approved exceptions with reviewer + rationale)
  - Section 5: Remediated Vulnerabilities (resolved exceptions — shown if any exist)
  - Section 6: Open Vulnerabilities (current CRITICAL/HIGH per repo, latest scan)
  - `@media print` CSS for clean PDF output (white background, hidden filters/navbar)
- ✅ `GET /reports/api/cra` — JSON data endpoint (used by report page)
- ✅ Three CRA db queries: `getCRAScanSummary`, `getCRAOpenFindings`, `getCRARiskRegister`

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ Rule detail, Repo detail, Installation detail with 12-week trend charts

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`, `exceptions`

Exception status values: `pending` | `approved` | `rejected` | `resolved`

---

## Next on roadmap

### PDF layout polish (next — before demo)
- `@media print` improvements: page headers, footers with page numbers
- Section break-inside: avoid on tables and stat boxes
- Cover page with org name, report date, classification
- Consider puppeteer/wkhtmltopdf for server-side PDF generation (future)

### `pkg` – Binary distribution (before first customer)
- Eliminates Node version conflicts for customers
- Requires solving `better-sqlite3` native addon packaging
- One binary per platform: macOS (arm64 + x64), Linux (x64)

### Taint analysis — expand to Python and JS
- Python: `open(path)`, `subprocess.run(cmd)`, `cursor.execute(query)` with tainted vars
- JS: `fs.readFile(path)`, `exec(cmd)`, `db.query(query)` with tainted vars

### Fas 2 remaining
- Per-developer breakdown in knowledge gap analysis
- Drill-down Nivå 2: per-finding aggregates in push events

### Fas 3
- CRA/NIS2 compliance reports — polish and additional report types (see Reports Roadmap)
- Plugin API + commercial rule packs
- Rule signing (Activemind-verified vs community)

---

## Reports Roadmap (Fas 3+)

| Report | Status | CRA/NIS2 ref |
|---|---|---|
| CRA Compliance Report | ✅ MVP | Art. 13, 14, Annex I+II |
| NIS2 Compliance Report | Planned | Art. 21 NIS2 |
| Vulnerability Disclosure Register | Planned | CRA Art. 14 |
| Remediation Timeline | Planned | CRA Art. 13 §2 |
| SDLC Security Evidence | Planned | CRA Annex II |
| Per-repo / per-installation filters | Planned | All |
| Server-side PDF generation | Planned | All |
| audit.log sync CLI→server | Prerequisite | Drill-down Nivå 3 |

---

## Parked ideas (not forgotten)

- **Taint analysis engine** — full AST-based multi-pass tracking
- **Rule customization per repo** — needs design to prevent risk normalisation
- Drill-down Nivå 3: full findings in scd-server (filenames, code lines, deep analysis)
- `scan_sensitivity`: `strict | balanced | relaxed` per rule category
- Deep analysis in pre-push hook (optional, with cost warning)
- IDE extension (VS Code)
- `scd report --from <date>` – filter scans by date range
- `scd store --nuke` – remove all store data
- Config signing (supply chain protection)
- Activemind-hosted cloud central (deferred until local central is stable)
- Admin menu item visibility based on role
- Server-side notifications (email/Discord/webhook for pending approvals) — Fas 3+

---

## Known issues / technical debt

- `scd report --open` on Linux blocked by Firefox `file://` policy → use `--serve`
- `securityagent.yml` in repo root is template; `config.yml` in store is active — should be unified
- scd-server requires Node 18 (better-sqlite3 native addon) — dev machine uses nvm wrapper
- PY-PATH-001 misses taint-tracked cases — requires Python taintAware rules (on roadmap)
- CRA report Section 2 shows aggregated scan totals, not unique findings — needs clarification note

### Regex design rules (learned from taint implementation)
- All patterns using `[^"]+` or `[^']+` with `matchAll` on full file content **must**
  include `\n` in the negated set (`[^\n"]+`) to prevent cross-line matching
- taintAware rules **must not** fall through when no variable name can be extracted
- taintAware rules skip matchAll entirely when taint register is empty (early exit)

### Exception flow design notes
- `updateExceptionStatus` uses line-by-line YAML parsing — no regex on multi-line blocks
- Matching: CLI id first (`exc-xxxxx`), falls back to `rule+file+line`
- `db_id` written to config.yml on sync so `scd resolve --rejected` can notify server
- `handledExceptionIds` in meta.json prevents sync-notice re-appearing after resolve

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
