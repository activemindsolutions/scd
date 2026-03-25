# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-25_

## Status: v0.5.0 – CLI + scd-server Fas 1 & 2 (MVP) + Rule improvements

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
- ✅ `scd approve / resolve` – exception and resolution management
- ✅ `scd audit` – view audit trail
- ✅ `scd doctor` – verify setup + push queue status
- ✅ `scd configure` – API key, central URL, token management
- ✅ `scd insights [--deep]` – behavioral analysis from audit log
- ✅ `scd list / store / rules / version` – store and rule navigation

### Rule coverage (172 rules total)
- ✅ JavaScript/TypeScript – 29 rules
- ✅ Python – 26 rules
- ✅ PHP – 29 rules
- ✅ ASP.NET markup (aspx/ascx) – 17 rules
- ✅ ASP.NET C# code-behind – 26 rules
- ✅ Sensitive files – 50 rules (includes EXPOSURE)
- ✅ Infrastructure leakage – 21 rules

**Severity breakdown:** CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

### Rule improvements (2026-03-25)
- ✅ **PY-INJ-002** — subprocess command injection now requires `shell=True` (was triggering all subprocess calls)
- ✅ **PY-PATH-001** — path traversal now requires explicit web-input context (was triggering all `open(path, ...)`)
- ✅ **INFRA-001** — localhost rule now excludes equality checks, docstrings, log statements
- ✅ **INFRA-002/003/012** — loopback/RFC1918 rules now exclude validation/comparison code
- ✅ **INFRA-022** — hostname rule now excludes `e.g.` examples in error messages
- ✅ **INFRA-036** — admin port rule now excludes `log.*` calls
- ✅ **INFRA-040** — comment IP rule fixed: lookbehind `(?<!:)` prevents `://` matching as comment marker
- ✅ New `ADDR_AS_DATA` antipattern constant for address-as-data vs address-as-config distinction

### Vendor filtering
- ✅ `isVendorPath()` — regex-based vendor path detection (site-packages, node_modules, vendor/, venv etc.)
- ✅ Default scan excludes vendor code
- ✅ `--include-vendor` flag for full scan including dependencies
- ✅ `--vendor-only` flag for supply chain audit
- ✅ Vendor mode shown in scan banner: `[+vendor]` / `[vendor-only]`

### export-findings behaviour change
- ✅ Default now exports **all findings** (was: deep-only)
- ✅ `--deep-only` flag replaces old `--all` flag for filtering on deep analysis results

### Push queue (scd CLI)
- ✅ Offline-first queue, Bearer token auth, machine fingerprint
- ✅ OWASP category breakdown + top rules sent with each scan event
- ✅ `tryFlush()` awaited before `process.exit()` in scan commands

### scd-server — Foundation + Auth
- ✅ Express + SQLite, `data/scd.db`
- ✅ JWT session auth (httpOnly cookie, HS256, server-side invalidation)
- ✅ HTML login form, proper logout, rate limiting (15min lockout after 11 attempts)
- ✅ `node server.js --host / --port / --help`

### scd-server — License validation
- ✅ Ed25519 offline signature verification, machine fingerprint binding
- 🔲 Heartbeat (api.activemind.se) — parked

### scd-server — Admin UI (`/admin`)
- ✅ Admin role only, server status, license info, installations, recent scans
- ✅ User management: list users, change passwords

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Admin + viewer roles
- ✅ Stat cards: scans 30d/7d, active repos, installations, critical, high, medium+exposure, total
- ✅ Findings trend chart — 12 weeks (Critical + High + Medium)
- ✅ Knowledge gaps — OWASP categories ranked by findings (30d)
- ✅ Top rules — most-triggered (30d), clickable → rule detail
- ✅ Recent scans — repo + host clickable, hook, C/H counts
- ✅ Repositories section — all repos, clickable → repo detail

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ Rule detail, Repo detail, Installation detail
- ✅ 12-week trend charts, cross-navigation between all views
- ✅ `db.js` — `getRuleDetail`, `getRepoDetail`, `getInstallationDetail`

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`

---

## Next on roadmap

### Rule engine — taint analysis (future feature)
Current regex-based rules cannot track data flow across variable assignments.
A multi-pass taint analysis engine is needed to follow "tainted" data (external input)
through variable assignments to dangerous sinks (open(), execute(), system() etc.).
This is a medium-term architectural improvement — see Architecture doc for design notes.

### Fas 2 remaining
- Exception approval flow (developer requests → team lead approves in dashboard)
- Per-developer breakdown in knowledge gap analysis
- `scd sync` command to pull approved exceptions from scd-server
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

- **Taint analysis engine** — multi-pass data flow tracking for Python/JS/PHP rules
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
- PY-PATH-001 still misses cases where path variable is assigned from web input earlier in function — requires taint analysis (on roadmap)

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
