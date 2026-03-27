# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-27_

## Status: v0.5.2 – Python/JS taint analysis + Unparameterized query rules + scd-server Data pages

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

### Rule coverage (180 rules total) — updated 2026-03-27
- ✅ JavaScript/TypeScript – 32 rules (+3 taintAware, +1 unparameterized)
- ✅ Python – 31 rules (+3 taintAware, +1 unparameterized)
- ✅ PHP – 29 rules (+ taintAware variants)
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules

**Severity breakdown:** CRITICAL: 63, HIGH: 77, MEDIUM: 10, EXPOSURE: 30

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

### Taint analysis — Python and JS/TS (2026-03-27)
Six new taintAware rules covering assign-then-use patterns across Python and JavaScript.
Verified with dedicated test files (`vulnerable_app.py`, `vulnerable_app.js`).

**New Python taintAware rules:**
- ✅ **PY-INJ-001** (taintAware) — `user_id = request.args.get(...)` → `cursor.execute(... + user_id)`
- ✅ **PY-INJ-002** (taintAware) — `cmd = request.form.get(...)` → `os.system(cmd)`
- ✅ **PY-PATH-001** (taintAware) — `filename = request.args.get(...)` → `open(filename)`

**New JavaScript/TypeScript taintAware rules:**
- ✅ **INJ-001** (taintAware) — `const id = req.query.id` → `db.query("SELECT..." + id)`
- ✅ **INJ-002** (taintAware) — `const name = req.body.name` → `el.innerHTML = name`
- ✅ **INJ-003** (taintAware) — `const cmd = req.query.cmd` → `exec(cmd)`

TypeScript covered by JS taintAware rules — no separate implementation needed.
Destructuring (`const { id } = req.query`) handled in taint-register for JS/TS.

**Scanner improvements (scanner-full.js):**
- ✅ `taintExtract` logic extended for Python/JS (no `$`-prefix) via `func_concat` and `concat` strategies
- ✅ Dedup logic extended: at `file:line` collision across different rules, higher severity wins

### Taint analysis engine (2026-03-25/26)
- ✅ `lib/taint-register.js` — `buildTaintRegister(content, language)` → `TaintRegister`
- ✅ PHP, Python, JS/TS sources supported
- ✅ Three extraction strategies: `concat`, `interpolation`, `func_concat`
- ✅ HTML report: taint-source rendered as second line inside code snippet box (`↳ var from source on line N`)
- ✅ Terminal: `↳ $id assigned from $_GET['id'] on line 30`
- ✅ JSON export includes `taint_source: { variable, line, source }`
- ✅ `scan_mode: fast` skips taint analysis; `full` (default) includes it
- ✅ Early exit when taint register is empty; pre-built line offsets (binary search)

**Verified on SuiteCRM (5000+ files):** 269 findings, 141 (52%) taint-tracked, 19s full scan.

### Unparameterized query rules (2026-03-27)
Detect dynamic SQL query construction as a pattern risk — even without a confirmed tainted variable.
Complements injection rules (CRITICAL) with earlier warning (HIGH).
Verified with `unparam_queries.py` and `unparam_queries.js`.

- ✅ **PY-INJ-006** (HIGH) — `cursor.execute()` with `.format()`, `+`-concat, reversed concat
  - Excludes f-strings and `%`-formatting (covered as CRITICAL by PY-INJ-001)
  - Excludes safe parameterised calls: `execute("...", (val,))` or `execute("...", [val])`
  - Uses inline negative lookahead — immune to nearby-code antipattern suppression
- ✅ **INJ-004** (HIGH) — `db.query()`, `pool.query()`, `knex.raw()` etc. with template literal or concat
  - Covers: `db`, `pool`, `conn`, `client`, `connection`, `knex`, `sequelize`, `pgClient`, `mysql`
  - Excludes safe parameterised calls with second argument
  - TypeScript covered by same rule

**Known edge case:** `IN (` + `placeholders` + `)` triggers PY-INJ-006 even when values are
parameterised. Accepted FP — use `scd ignore --tag false_positive` if needed.

### scd-server — Foundation + Auth
- ✅ Express + SQLite, JWT session auth, rate limiting, Bearer token support
- ✅ Ed25519 license validation, machine fingerprint binding

### scd-server — Admin UI (`/admin`)
- ✅ Server status, license info, installations, scans, user management

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Stat cards including clickable "Pending approvals" card (admin/team-lead only)
- ✅ Findings trend chart (12 weeks), knowledge gaps, top rules, recent scans, repos
- ✅ Navbar: "Data ▾" dropdown + Reports link (all roles), Exceptions link with red badge (admin/team-lead)

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
- ✅ Tag shown as blue chip in table and modal; `type` pill: `ignore` or `exception`
- ✅ ID column (`#12`) in table and modal

### scd-server — Reports (`/reports`)
- ✅ Reports index page — lists available and coming reports
- ✅ CRA Compliance Report (`/reports/cra`) — HTML, printable to PDF via browser
  - Period filter: 30 / 90 / 180 / 365 days (default 90); repository filter
  - Six sections covering CRA Art. 13, 14, Annex I+II
  - Chart.js stacked bar for monthly trend (prints correctly from canvas)
  - Polished `@media print` CSS: A4 `@page`, cover page, footer, `break-inside: avoid`
- ✅ `GET /reports/api/cra` — JSON data endpoint
- ✅ Three CRA db queries: `getCRAScanSummary`, `getCRAOpenFindings`, `getCRARiskRegister`

### scd-server — Data pages (`/data/*`) — new 2026-03-27
- ✅ `/data/repositories` — all repos with scan counts, CRITICAL/HIGH totals, last scan
- ✅ `/data/installations` — all developer machines with hostname, platform, scd version
- ✅ `/data/rules` — all triggered rules with severity filter and occurrence counts
- ✅ Client-side search (real-time), column sort (click header), row count "X of Y"
- ✅ Row click opens detail modal with key info + "Open full details →" drill-down link
- ✅ "Data ▾" dropdown in navbar (closes on outside click)
- New API endpoints: `GET /data/api/repo/:id`, `/data/api/installation/:id`, `/data/api/rule/:id`

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ Rule detail, Repo detail, Installation detail with 12-week trend charts

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`, `exceptions`

Exception status values: `pending` | `approved` | `rejected` | `resolved`

---

## Next on roadmap

### `pkg` – Binary distribution (before first customer)
- Eliminates Node version conflicts for customers
- Requires solving `better-sqlite3` native addon packaging
- One binary per platform: macOS (arm64 + x64), Linux (x64)

### Per-developer breakdown (Fas 2 remaining)
- Knowledge gap analysis per developer, not just per team
- Drill-down Nivå 2: per-finding aggregates in push events

### `scd deps` — Dependency scanning
- CVE lookup via OSV API
- Natural complement to code scanning

### Fas 3
- CRA/NIS2 compliance reports — additional report types (see Reports Roadmap)
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
| Per-repo / per-installation filters | ✅ Done | All |
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
- **PY-INJ-001** false positive: `cursor.execute("SELECT ... %s", (val,))` triggers because
  pattern matches `%s` inside the string literal. Pre-existing issue, not introduced by current work.
- CRA report Section 2 shows aggregated scan totals, not unique findings — needs clarification note
- Taint antipattern window can suppress valid findings when safe code is adjacent to vulnerable code
  in the same file — known limitation of window-based antipatterns

### Regex / rule design rules (key learnings)
- All patterns with `[^"]+` in `matchAll` must include `\n` → `[^\n"]+` to prevent cross-line matching
- taintAware rules must not fall through when no varName extracted; skip matchAll when register is empty
- Unparameterized query rules use **inline negative lookahead** in pattern (not antipattern window)
  — the only reliable way to exclude safe parameterised calls when safe/unsafe code coexists in same file

### Dedup design notes (scanner-full.js)
- Pass 1: exact `ruleId:file:line` — prefers taintAware findings (with `taintSource`)
- Pass 2: `file:line` across different rules — higher severity wins (CRITICAL > HIGH > MEDIUM)
  Prevents unparameterized query rules (HIGH) from duplicating injection rules (CRITICAL) on same line

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
