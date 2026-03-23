# Secure Code by Design – Claude Project Instructions

## Who I am
Mikael Jansson, penetration tester and security consultant at Activemind Solutions AB (Sweden).
CEH certified. Works exclusively within authorized, legal boundaries.
Philosophy: "360-degree security thinking / think like a hacker."

## What this project is
**Secure Code by Design** – a Node.js CLI tool (`scd`) that automatically scans code for security
vulnerabilities, targeting SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor)
who lack in-house security expertise.

**Not a replacement for pentesting** – it minimizes the number of vulnerabilities that reach
production so that pentests can focus on harder problems.

## Repositories
| Repo | URL | Visibility |
|---|---|---|
| scd (CLI) | `git@github.com:activemindsolutions/scd.git` | Public |
| scd-server | `git@github.com:activemindsolutions/scd-server.git` | Private |
| scd-admin | Local only (`~/Projects/scd-admin`) | Internal |

- scd installed via `npm link` (dev) or `git clone && npm install && npm link`
- scd-server runs with `node server.js` (Node 18 via nvm on dev machine)
- scd-admin contains `generate-license.js` and Ed25519 keypair (never committed)

## Tech stack – scd CLI
- Node.js 18+ (CommonJS, no transpilation)
- commander@11 (CLI framework)
- `@anthropic-ai/sdk` for deep analysis
- No other runtime dependencies – deliberately lightweight

## Tech stack – scd-server
- Node.js 18+ (required for better-sqlite3 native addon)
- Express 4
- better-sqlite3 (SQLite, db abstraction layer is Postgres-ready)
- jsonwebtoken (JWT signing/verification)
- cookie-parser (httpOnly session cookies)
- No other runtime dependencies

## Key design principles
1. **Zero repo footprint** – scd never writes files to the customer's repo
2. **Global store** – all CLI data in `~/.scd/repos/{repoId}/`
3. **Self-hosted** – scd-server runs in customer's infrastructure, no data leaves their network
4. **Data philosophy** – store as much data as possible in scd-server (it stays with customer)
5. **repoId** = SHA-256 of git remote URL (stable across re-clones)
6. **English only** – all rule text, CLI output, comments in English
7. **Rule IDs are stable** – never renumber or rename existing rule IDs
8. **No npm dependencies added without discussion** – keep install lightweight
9. **SQL** – always parameterised statements, never string concatenation

## Code conventions
- CommonJS (`require`/`module.exports`), no ES modules
- `'use strict'` in all lib files
- Descriptive variable names, comments for non-obvious logic
- ANSI color via raw escape codes (no chalk dependency)
- All user-facing strings in English
- HTML generation in JS: always use string concatenation, never nested template literals
  (template literals inside Node.js template literals cause `\${...}` escape issues)

## Working style
- Mikael is hands-on and reviews all code before committing
- Discuss architecture decisions before implementing
- Always run `node --check` on modified files before presenting
- Present files via the file tool so Mikael can download and copy them in
- Commits and pushes are done by Mikael manually

## What NOT to do
- Do not add new npm dependencies without explicit discussion
- Do not rename or restructure existing rule IDs
- Do not write files to the customer's repo (zero footprint principle)
- Do not use ES module syntax (`import`/`export`)
- Do not use Swedish in code, comments, or CLI output
- Do not use nested template literals for HTML generation in route files

---

## Commercial model

### Core brand message
> "Vi är så seriösa med integritet att vi inte ens vill ha din data."

Self-hosted by design, not as a limitation.

### Business goals (priority order)
1. Lead generation for consulting and penetration testing engagements
2. Lead generation for security training (workshops, e-learning, certification)
3. Recurring revenue from commercial licenses (Team/Professional tiers)

### License tiers
| Tier | Price | Key differentiator |
|---|---|---|
| Starter | Free / Open Source | Full CLI + all core rules, local reports |
| Team | 2 499 SEK/month | Local scd-server, team dashboard, up to 5 developers |
| Professional | 7 499 SEK/month | CRA/NIS2 reports, commercial rule packs, quarterly reviews |

- Team tier: +X SEK/month per developer beyond 5 (price TBD)
- No per-repo pricing – ever
- Professional is an add-on to Team, not a separate product

### scd-server – commercial core
The commercial server runs entirely in the customer's infrastructure.
- License: Ed25519-signed JSON file (`data/license.key`)
- Public key: `data/scd-public.pem` (priority: `SCD_PUBLIC_KEY` env → file → placeholder)
- Machine fingerprint binding: SHA-256(hostname + platform + MAC)
- License payload: customerId, customerName, tier, seats, expiry, features[], rulePacks[]
- Development mode: no license file = full access (for internal dev)
- License generation: `~/Projects/scd-admin/generate-license.js` (internal, never in repo)

### Push queue architecture
Each `scd` installation pushes audit events to scd-server via a local offline queue:
- Events always written to `audit.log` first
- Events queued in `~/.scd/push-queue.jsonl`
- Each event includes: scan summary + OWASP category breakdown + top rules (max 20)
- Meta: installationId (machine fingerprint), repoId, hostname, platform, scdVersion
- `tryFlush()` awaited before `process.exit()` in scan commands
- 7-day grace before stale warning; stale events reported by `scd doctor`

### scd-server routes
| Route | Auth | Purpose |
|---|---|---|
| `GET /` | none | Redirect to `/dashboard` |
| `GET /login` | none | Login form HTML |
| `POST /auth/login` | none | Validate credentials, set JWT cookie |
| `POST /auth/logout` | JWT | Invalidate session, clear cookie |
| `GET /auth/me` | JWT | Current user info |
| `GET /api/v1/health` | none | Server + license status |
| `POST /api/v1/events/batch` | Bearer token | Receive scan events from CLI |
| `GET /api/v1/entitlements` | Bearer token | License features for CLI |
| `GET /admin` | admin role | Admin UI |
| `GET /admin/api/*` | admin role | Admin API |
| `GET /dashboard` | admin + viewer | Team dashboard UI |
| `GET /dashboard/api/*` | admin + viewer | Dashboard API |
| `GET /dashboard/rule/:id` | admin + viewer | Rule detail page |
| `GET /dashboard/repo/:id` | admin + viewer | Repo detail page |
| `GET /dashboard/installation/:id` | admin + viewer | Installation detail page |
| `GET /dashboard/api/rule/:id` | admin + viewer | Rule detail data (JSON) |
| `GET /dashboard/api/repo/:id` | admin + viewer | Repo detail data (JSON) |
| `GET /dashboard/api/installation/:id` | admin + viewer | Installation detail data (JSON) |

### Auth (current – JWT + sessions)
- `sessions` table in SQLite: tracks active JWT sessions (JTI-based)
- `users` table: admin + viewer accounts with scrypt-hashed passwords
- JWT signed with HS256, verified with explicit algorithm check
- httpOnly + SameSite=Strict cookie — no JS access
- Rate limiting: 5 free → 2s delay → 15min lockout
- `requireAdmin` — admin role only
- `requireDashboard` — admin or viewer

### Team dashboard
- `/dashboard` — accessible by admin and viewer roles
- Stat cards: scans 30d/7d, active repos, installations, critical, high, medium+exposure, total
- Findings trend chart: 12 weeks (Critical + High + Medium)
- Knowledge gaps: OWASP categories with C/H/M/E breakdown
- Top rules: clickable → `/dashboard/rule/:id`
- Recent scans: clickable repo → `/dashboard/repo/:id`, clickable host → `/dashboard/installation/:id`
- Repositories section: all repos with remote URL, clickable

### Drill-down detail pages (Nivå 1)
- Rule detail: 12-week trend, repos it appears in, installations
- Repo detail: stats, trend, categories, top rules, recent scans, active installations
- Installation detail: stats, trend, repos scanned, top rules, recent scans
- All pages cross-link to each other

### Commercial roadmap phases
| Phase | Name | Key deliverables |
|---|---|---|
| Fas 1 | Foundation | Push queue, license validation, scd-server MVP, admin UI ✅ |
| Fas 2 | Team value | Team dashboard ✅, drill-down Nivå 1 ✅, exception approvals 🔲 |
| Fas 3 | Professional add-ons | CRA/NIS2 reports, plugin API, rule packs, rule signing |

### Internal commands (not in README or scd --help)
`scd review-rules` — Activemind-internal rule quality analysis. Registered with `{ hidden: true }`.

### Parked (not forgotten)
- Heartbeat (api.activemind.se) — designed, not implemented
- `pkg` binary distribution — revisit before first customer
- Activemind-hosted cloud central — deferred until local central is stable
- Config signing (supply chain protection)
- Drill-down Nivå 3: full findings in scd-server (strategic decision pending)
