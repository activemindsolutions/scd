# Secure Code by Design – Progress & Roadmap

_Last updated: 2026-03-20_

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
- ✅ `scd scan [target]` – full OWASP scan with `--lang`, `--severity`, `--rule`, `--format`, `--deep`, `--deep-delay`, `--no-audit`, `--no-limit`
- ✅ `scd scan --deep` – Claude API deep analysis (CRITICAL/HIGH only)
- ✅ `scd report` – generate HTML/MD/JSON from latest scan
- ✅ `scd report --open / --serve / --scan <id>`
- ✅ `scd export-findings` – export to structured JSON; filters: `--severity`, `--rule`, `--scan`, `--all`, `--output`
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
- ✅ `lib/push-queue.js` — offline-first queue, `~/.scd/push-queue.jsonl`
- ✅ Bearer token auth (`Authorization: Bearer <token>`)
- ✅ Machine fingerprint in meta (`fp-` + SHA-256)
- ✅ Repo identity (repoId, repoName, repoRemote) sent with each flush
- ✅ `categories` breakdown per OWASP category per scan
- ✅ `top_rules` aggregated rule counts per scan (max 20)
- ✅ `tryFlush()` — awaited before `process.exit()` in scan commands
- ✅ `scd configure --central-url / --token / --clear-*`
- ✅ `scd doctor` shows push queue status, stale events, grace period
- ✅ `setImmediate` push worker triggers after all other commands

### scd-server MVP
- ✅ Express server, Node.js 18+
- ✅ SQLite via `better-sqlite3` (db abstraction layer, Postgres-ready)
- ✅ Database: `data/scd.db`
- ✅ Config: `config.yml` (gitignored), `config.example.yml` (committed)
- ✅ `lib/server-config.js` — config hierarchy: ENV → config.yml → defaults
- ✅ `GET /api/v1/health` — public, returns license + db stats
- ✅ `POST /api/v1/events/batch` — Bearer token auth, ingests scan events
- ✅ `GET /api/v1/entitlements` — returns license features/rule packs

### scd-server — License validation
- ✅ Ed25519 offline signature verification
- ✅ Public key loaded from `data/scd-public.pem` (priority: ENV → file → placeholder)
- ✅ Machine fingerprint binding (first activation binds to machine)
- ✅ Expiry check
- ✅ Development mode when no license file present
- ✅ Graceful degradation to Starter on invalid license
- ✅ `features` and `rulePacks` in license payload (prepared for Fas 3)
- ✅ `lib/auth.js` — `hasFeature()`, `hasRulePack()`, `requireFeature()` middleware
- 🔲 Heartbeat (api.activemind.se) — parked, designed for Fas 2

### scd-admin (internal Activemind tools)
- ✅ `generate-license.js` — Ed25519 keypair generation + license signing/verification
- ✅ License payload: customerId, tier, seats, expiry, features, rulePacks, signature
- ✅ Keypair files: `scd-license-private.pem`, `scd-license-public.pem`

### scd-server — Admin UI (`/admin`)
- ✅ HTTP Basic Auth against `users` table (scrypt-hashed passwords)
- ✅ `admin` role only — `viewer` gets HTML 403 error page
- ✅ Server status, license info, DB stats
- ✅ Installations table (all connected scd CLI machines)
- ✅ Recent scans table (with repo name, hostname, findings)
- ✅ `GET /admin/api/status` — JSON data endpoint
- ✅ `GET /admin/api/users` — list users
- ✅ `POST /admin/api/change-password` — admin can change any user's password
- ✅ Auto-refresh every 30s

### scd-server — Team Dashboard (`/dashboard`)
- ✅ `admin` + `viewer` roles — separated from admin
- ✅ Stat cards: scans 30d, scans 7d, active repos, installations, critical/high findings
- ✅ Findings trend chart — 12 weeks (Chart.js, Critical + High series)
- ✅ Knowledge gaps — OWASP categories ranked by findings (30d)
- ✅ Top rules — most-triggered rules (30d) with severity
- ✅ Recent scans table — repo, host, hook, C/H counts, time
- ✅ `GET /dashboard/api/data` — all dashboard data in one call
- ✅ Auto-refresh every 30s

### scd-server — Auth & navigation
- ✅ `admin` and `viewer` accounts created on first startup with random passwords
- ✅ `lib/admin-auth.js` — scrypt password hashing, `requireAdminAuth`, `requireDashboardAuth`
- ✅ `lib/ui-helpers.js` — shared navbar and logout script
- ✅ HTML 403 error page (not JSON) for browser navigation
- ✅ `GET /` → redirect to `/dashboard`
- ✅ `GET /login` — logout landing page with credential clearing
- ✅ Navbar: Dashboard link, Admin link (admin only), username/role badge, Sign out
- 🔲 JWT + session-based auth — parked, replaces Basic Auth properly

### scd-server — Database schema
Tables: `installations`, `repos`, `scans`, `scan_categories`, `scan_top_rules`,
`raw_events`, `server_config`, `users`

### Windows compatibility
- ✅ `store-verify.js` — archive uses Node.js file copy on Windows (no `tar` dependency)
- ✅ `doctor.js` — skips `X_OK` check on Windows
- ✅ `report --serve` — falls back to Enter/Ctrl-C on non-TTY (cmd.exe)
- ✅ Documented minimum requirement: Windows 10 build 1803+, Git for Windows

---

## Next on roadmap

### JWT + session auth (next priority after Basic Auth issues)
Replace HTTP Basic Auth with proper session-based auth:
- Login form (HTML, no browser dialog)
- JWT token (httpOnly cookie, 8h lifetime)
- Refresh token (longer lifetime)
- Server-side token invalidation (proper logout)
- Solves the logout problem permanently

### `pkg` – Binary distribution (parked, revisit before first customer)
Compile scd CLI and scd-server to standalone binaries.
- Eliminates Node version conflicts for customers
- Requires solving `better-sqlite3` native addon packaging
- macOS requires Apple Developer signing for Gatekeeper

### Fas 2 remaining
- Exception approval flow (developer requests → team lead approves in dashboard)
- Per-developer breakdown in knowledge gap analysis
- `scd sync` command to pull approved exceptions from scd-server

### Fas 3
- CRA/NIS2 compliance reports
- Plugin API + commercial rule packs
- Rule signing (Activemind-verified vs community)

### `scd deps` – Dependency scanning (parked)
- CVE check via OSV API (`api.osv.dev/v1/query`)
- Parsers: `package.json`, `requirements.txt`, `composer.json`, `*.csproj`

### Heartbeat (api.activemind.se)
- 24h heartbeat for license validation
- Grace period: 7 days offline → degrade to Starter
- Requires setting up api.activemind.se endpoint first

---

## Parked ideas (not forgotten)

- `scan_sensitivity`: `strict | balanced | relaxed` per rule category
- Deep analysis in pre-push hook (optional, with cost warning)
- IDE extension (VS Code)
- `scd report --from <date>` – filter scans by date range
- `scd store --nuke` – remove all store data
- Config signing (supply chain protection)
- Activemind-hosted cloud central (deferred until local central is stable)

---

## Known issues / technical debt

- Basic Auth logout is unreliable — solved by JWT auth (upcoming)
- Admin menu item visible to viewer role — hidden in upcoming UI pass
- `scd report --open` on Linux blocked by Firefox `file://` policy → use `--serve`
- `securityagent.yml` in repo root is template; `config.yml` in store is active — should be unified
- scd-server requires Node 18 (better-sqlite3 native addon) — dev machine uses nvm wrapper
- `input` fields in `routes-admin.js` POST `/admin/api/change-password` not sanitised beyond length check — acceptable until JWT auth

---

## How to update this file

At the end of each work session:
1. Ask Claude to generate an updated `PROGRESS.md`
2. Copy into `docs/PROGRESS.md` in repo, commit and push
3. Replace the file in Claude Project Knowledge (delete old, upload new)
