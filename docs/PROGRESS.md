# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-26_

## Status: v0.5.0 – CLI + scd-server Fas 1 & 2 (MVP) + Rule improvements + Taint analysis

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
- ✅ `scd scan --include-vendor` – include vendor/dependency code in scan
- ✅ `scd scan --vendor-only` – scan only vendor/dependency code (supply chain audit)
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd export-findings` – export all findings to JSON (default: all findings)
- ✅ `scd export-findings --deep-only` – export only findings with deep analysis
- ✅ `scd approve --reason <text>` – create exception request (pending team-lead approval)
- ✅ `scd ignore --reason <text>` – mark finding as false positive (pending approval)
- ✅ `scd sync` – pull approved exceptions from scd-server
- ✅ `scd audit` – view audit trail
- ✅ `scd doctor` – verify setup + push queue status
- ✅ `scd configure` – API key, central URL, token management
- ✅ `scd insights [--deep]` – behavioral analysis from audit log
- ✅ `scd list / store / rules / version` – store and rule navigation

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
- ✅ **PHP-INJ-002c** — taintAware: assign-then-use SQL injection (`$id = $_GET['id']; $query = "...WHERE id = " . $id`)
- ✅ **PHP-INJ-002d** — taintAware: interpolated tainted variable in SQL string
- ✅ **PHP-INJ-004b** — taintAware: tainted variable in shell command
- ✅ **PHP-AUTH-002b** — taintAware: tainted variable in include/require (LFI)

### Taint analysis engine (2026-03-25/26)
Single-file pre-scan taint tracking — identifies variables assigned from user-controlled
sources and passes the register to taintAware rules.

- ✅ `lib/taint-register.js` — NEW: `buildTaintRegister(content, language)` → `TaintRegister`
- ✅ PHP sources: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SESSION`, `$_SERVER`
- ✅ Python sources: `request.args`, `request.form`, `request.json`, `sys.argv`
- ✅ JS/TS sources: `req.query`, `req.body`, `req.params` (incl. destructuring)
- ✅ Three extraction strategies: `concat`, `interpolation`, `func_concat`
- ✅ Terminal output shows taint annotation: `↳ $id assigned from $_GET['id'] on line 30`
- ✅ JSON export includes `taint_source: { variable, line, source }`
- ✅ `scan_mode: fast` in config.yml skips taint analysis for large codebases
- ✅ Pre-built line offsets (binary search) replaces substring+split for line number lookup
- ✅ Early exit for taintAware rules when no tainted variables in file

**Verified on SuiteCRM (5000+ files):** 269 findings, 141 (52%) taint-tracked, 19s full scan.
**Verified on 800-file PHP project:** 431 findings, ~10s fast / ~19s full.

### Vendor filtering
- ✅ `isVendorPath()` — regex-based vendor path detection
- ✅ Default scan excludes vendor code
- ✅ `--include-vendor` / `--vendor-only` flags
- ✅ Vendor mode shown in scan banner: `[+vendor]` / `[vendor-only]`

### export-findings behaviour
- ✅ Default exports **all findings**
- ✅ `--deep-only` flag for filtering on deep analysis results

### Push queue (scd CLI)
- ✅ Offline-first queue, Bearer token auth, machine fingerprint
- ✅ OWASP category breakdown + top rules sent with each scan event
- ✅ `tryFlush()` awaited before `process.exit()` in scan commands

### scd-server — Foundation + Auth
- ✅ Express + SQLite, `data/scd.db`
- ✅ JWT session auth (httpOnly cookie, HS256, server-side invalidation)
- ✅ HTML login form, proper logout, rate limiting (15min lockout after 11 attempts)
- ✅ `node server.js --host / --port / --help`
- ✅ All protected routes accept JWT cookie OR API Bearer token
- ✅ API token role configurable via `POST /admin/api/token-role` or `SCD_API_TOKEN_ROLE` env

### scd-server — License validation
- ✅ Ed25519 offline signature verification, machine fingerprint binding
- 🔲 Heartbeat (api.activemind.se) — parked

### scd-server — Admin UI (`/admin`)
- ✅ Admin role only, server status, license info, installations, recent scans
- ✅ User management: list users, create users (roles: admin, team-lead, viewer), change passwords

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Admin + viewer + team-lead roles
- ✅ Stat cards: scans 30d/7d, active repos, installations, critical, high, medium+exposure, total
- ✅ Findings trend chart — 12 weeks (Critical + High + Medium)
- ✅ Knowledge gaps — OWASP categories ranked by findings (30d)
- ✅ Top rules — most-triggered (30d), clickable → rule detail
- ✅ Recent scans — repo + host clickable, hook, C/H counts
- ✅ Repositories section — all repos, clickable → repo detail
- ✅ Pending Approvals section — exception requests from CLI, approve/reject with mandatory comment

### scd-server — Exception approval flow
- ✅ `exceptions` table with full audit trail (type, status, reason, reviewed_by, review_comment)
- ✅ Roles: `team-lead` can approve, `viewer` cannot (403 with clear error)
- ✅ `requireApprover` middleware — admin + team-lead only
- ✅ `POST /api/v1/exceptions/batch` — CLI pushes exception requests (Bearer token)
- ✅ `GET /api/v1/exceptions/approved` — CLI pulls approved exceptions for `scd sync`
- ✅ Dashboard UI shows pending exceptions, approve/reject with mandatory comment
- ✅ Comment required server-side (400 if missing) — not just client-side validation

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ Rule detail, Repo detail, Installation detail
- ✅ 12-week trend charts, cross-navigation between all views

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`, `exceptions`

---

## Next on roadmap

### Exception approval UI — modal
Current approve/reject uses browser `prompt()` — needs a proper inline modal with
context display (rule, file, reason) and comment field. Parked until exception flow
is end-to-end tested.

### Taint analysis — expand to Python and JS
PHP taintAware rules are complete. Python and JS have similar sink patterns:
- Python: `open(path)`, `subprocess.run(cmd)`, `cursor.execute(query)` with tainted vars
- JS: `fs.readFile(path)`, `exec(cmd)`, `db.query(query)` with tainted vars
Design separately with test files, same approach as PHP.

### Rule engine — full taint analysis (future)
Current single-file, single-assignment taint tracking does not handle:
- Cross-function taint propagation
- Chained assignments (`$a = $b; $b = $_GET['x']`)
- Conditional assignments
Full taint analysis requires a proper AST-based approach. Planned as a medium-term
architectural improvement — see Architecture doc.

### Fas 2 remaining
- Exception approval UI modal (replace browser prompt)
- Per-developer breakdown in knowledge gap analysis
- `scd sync` end-to-end testing
- Drill-down Nivå 2: per-finding aggregates in push events

### `pkg` – Binary distribution (parked, revisit before first customer)
- Eliminates Node version conflicts for customers
- Requires solving `better-sqlite3` native addon packaging

### Fas 3
- CRA/NIS2 compliance reports
- Plugin API + commercial rule packs
- Rule signing (Activemind-verified vs community)

### `scd deps` – Dependency scanning (parked)
- CVE check via OSV API (`api.osv.dev/v1/query`)

### Heartbeat (api.activemind.se)
- 24h heartbeat for license validation, 7-day grace period

---

## Parked ideas (not forgotten)

- **Taint analysis engine** — full AST-based multi-pass tracking (see above)
- **Rule customization per repo** — enable/disable specific rules in config.yml with
  mandatory reason + team-lead approval to prevent risk normalisation. Design needed.
- Drill-down Nivå 3: full findings in scd-server (filenames, code lines, deep analysis)
- `scan_sensitivity`: `strict | balanced | relaxed` per rule category
- Deep analysis in pre-push hook (optional, with cost warning)
- IDE extension (VS Code)
- `scd report --from <date>` – filter scans by date range
- `scd store --nuke` – remove all store data
- Config signing (supply chain protection)
- Activemind-hosted cloud central (deferred until local central is stable)
- Admin menu item visibility based on role (currently visible to viewer)

---

## Known issues / technical debt

- `scd report --open` on Linux blocked by Firefox `file://` policy → use `--serve`
- `securityagent.yml` in repo root is template; `config.yml` in store is active — should be unified
- scd-server requires Node 18 (better-sqlite3 native addon) — dev machine uses nvm wrapper
- Input sanitization in change-password route (length check only) — acceptable for now
- PY-PATH-001 misses taint-tracked cases — requires Python taintAware rules (on roadmap)
- Exception approval UI uses browser `prompt()` — needs proper modal

### Regex design rules (learned from taint implementation)
- All patterns using `[^"]+` or `[^']+` with `matchAll` on full file content **must**
  include `\n` in the negated set (`[^\n"]+`) to prevent cross-line matching
- taintAware rules **must not** fall through when no variable name can be extracted —
  skip the finding instead (no varName = no taint path = no finding)
- taintAware rules are skipped entirely when taint register is empty (early exit)

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
