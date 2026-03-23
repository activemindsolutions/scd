# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-23_

## Status: v0.5.0 – CLI + scd-server Fas 1 & 2 (MVP)

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
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd export-findings` – export to structured JSON
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

### Push queue (scd CLI)
- ✅ Offline-first queue, `~/.scd/push-queue.jsonl`
- ✅ Bearer token auth, machine fingerprint, repo identity in meta
- ✅ OWASP category breakdown + top rules sent with each scan event
- ✅ `tryFlush()` awaited before `process.exit()` in scan commands
- ✅ `scd doctor` shows push queue status, stale events, grace period

### scd-server — Foundation
- ✅ Express + SQLite, `data/scd.db`
- ✅ `lib/server-config.js` — config hierarchy: ENV → config.yml → defaults
- ✅ `GET /api/v1/health`, `POST /api/v1/events/batch`, `GET /api/v1/entitlements`
- ✅ `node server.js --host / --port / --help` — CLI overrides for network binding

### scd-server — License validation
- ✅ Ed25519 offline signature verification
- ✅ Public key from `data/scd-public.pem` (priority: ENV → file → dev mode)
- ✅ Machine fingerprint binding, expiry check, graceful degradation to Starter
- 🔲 Heartbeat (api.activemind.se) — parked

### scd-server — JWT session auth
- ✅ `lib/session-auth.js` — JWT HS256, httpOnly+SameSite=Strict cookie
- ✅ `lib/routes-auth.js` — `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`
- ✅ HTML login form — replaces Basic Auth completely
- ✅ JWT secret auto-generated and stored in DB on first startup
- ✅ Sessions tracked in DB — server-side invalidation on logout
- ✅ Rate limiting: delay after 5 failed attempts, 15min lockout after 11
- ✅ Max password length before scrypt — prevents DoS
- ✅ Timing-safe credential check — constant time even for unknown users
- ✅ `session_ttl_hours` configurable in `config.yml` (default: 8h)

### scd-server — Admin UI (`/admin`)
- ✅ Admin role only — viewer gets HTML 403 error page
- ✅ Server status, license info, DB stats, installations, recent scans
- ✅ User management: list users, change any user's password

### scd-server — Team Dashboard (`/dashboard`)
- ✅ Admin + viewer roles
- ✅ Stat cards: scans 30d/7d, active repos, installations, critical, high, medium+exposure, total
- ✅ Findings trend chart — 12 weeks (Critical + High + Medium)
- ✅ Knowledge gaps — OWASP categories with C/H/M/E breakdown, bar visualization
- ✅ Top rules — most-triggered (30d), clickable → rule detail
- ✅ Recent scans — repo (clickable) + host (clickable), hook, C/H counts
- ✅ Repositories section — all known repos, clickable → repo detail

### scd-server — Drill-down detail pages (Nivå 1)
- ✅ `lib/routes-detail.js` — three detail views, all auth-protected
- ✅ **Rule detail** (`/dashboard/rule/:id`) — 12w trend, repos affected, installations
- ✅ **Repo detail** (`/dashboard/repo/:id`) — stats, trend, knowledge gaps, top rules, scans, installations
- ✅ **Installation detail** (`/dashboard/installation/:id`) — stats, trend, repos, top rules, scans
- ✅ Cross-navigation between all detail pages
- ✅ `db.js` — `getRuleDetail`, `getRepoDetail`, `getInstallationDetail`

### scd-server — Auth & navigation
- ✅ Shared navbar (`lib/ui-helpers.js`) — role-aware links, Sign out
- ✅ HTML 403 page for browser, JSON 403 for API calls
- ✅ `GET /` → redirect to `/dashboard`, `GET /login` → login page

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `sessions`, `users`

---

## Next on roadmap

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

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
