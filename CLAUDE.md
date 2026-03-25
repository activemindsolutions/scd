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
- jsonwebtoken + cookie-parser (JWT session auth)
- No other runtime dependencies

## Key design principles
1. **Zero repo footprint** – scd never writes files to the customer's repo
2. **Global store** – all CLI data in `~/.scd/repos/{repoId}/`
3. **Self-hosted** – scd-server runs in customer's infrastructure, no data leaves their network
4. **repoId** = SHA-256 of git remote URL (stable across re-clones)
5. **English only** – all rule text, CLI output, comments in English
6. **Rule IDs are stable** – never renumber or rename existing rule IDs
7. **No npm dependencies added without discussion** – keep install lightweight

## Code conventions
- CommonJS (`require`/`module.exports`), no ES modules
- `'use strict'` in all lib files
- Descriptive variable names, comments for non-obvious logic
- ANSI color via raw escape codes (no chalk dependency)
- All user-facing strings in English
- SQL: always parameterised statements, never string concatenation
- HTML in Node.js template literals: use string concatenation for embedded JS
  (avoid nested template literals — causes `\${...}` escape issues)

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
- Do not use nested template literals in HTML-generating Node.js code

---

## Rule engine principles

### Current approach: regex-based
Rules use regex patterns with optional antipatterns. Antipattern check uses a sliding
window (120 chars behind, 300 chars ahead of match). This works well for obvious patterns
but cannot track data flow across variable assignments.

### Known limitation: no taint analysis
Regex rules cannot determine where a variable's value came from. Example:
```python
path = request.args.get('file')   # tainted
# ... 50 lines later ...
open(path, 'r')                   # danger — but regex won't connect these
```
This is a planned improvement (see roadmap). Current mitigation: `--deep` analysis
via Claude API provides contextual understanding that bridges this gap.

### Rule design guidelines
- **Pattern**: should match the dangerous construct, as specifically as possible
- **Antipattern**: should exclude safe patterns in a window around the match
- **Prefer precision over recall** for project-code rules (fewer FP is better than more TP)
- **ADDR_AS_DATA**: use this antipattern constant for INFRA rules to exclude cases
  where addresses are treated as data (comparisons, validation, log output)
- **Vendor code**: handled by `isVendorPath()` filter, not by rule antipatterns

### Vendor filtering
- `lib/scanner-manual.js` exports `isVendorPath(filePath)`
- Default scan excludes vendor paths
- `--include-vendor` and `--vendor-only` flags control this
- Vendor paths: site-packages, node_modules, vendor/, venv, __pycache__, bin/Release, obj/Debug

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

### scd-server routes
| Route | Auth | Purpose |
|---|---|---|
| `GET /` | none | Redirect to `/dashboard` |
| `GET /login` | none | Login page (HTML form) |
| `POST /auth/login` | none | Validate credentials, set JWT cookie |
| `POST /auth/logout` | JWT | Invalidate session, clear cookie |
| `GET /auth/me` | JWT | Current user info |
| `GET /api/v1/health` | none | Server + license status |
| `POST /api/v1/events/batch` | Bearer token | Receive scan events from CLI |
| `GET /api/v1/entitlements` | Bearer token | License features for CLI |
| `GET /admin` | JWT (admin) | Admin dashboard UI |
| `GET /admin/api/*` | JWT (admin) | Admin API |
| `GET /dashboard` | JWT (admin+viewer) | Team dashboard UI |
| `GET /dashboard/api/*` | JWT (admin+viewer) | Dashboard API |
| `GET /dashboard/rule/:id` | JWT (admin+viewer) | Rule detail page |
| `GET /dashboard/repo/:id` | JWT (admin+viewer) | Repo detail page |
| `GET /dashboard/installation/:id` | JWT (admin+viewer) | Installation detail page |

### Auth (JWT)
- `lib/session-auth.js` — JWT HS256, httpOnly+SameSite=Strict cookie
- `lib/admin-auth.js` — scrypt password hashing, first-run setup
- `lib/routes-auth.js` — login/logout/me + HTML login page
- Two roles: `admin` and `viewer`
- Sessions in `sessions` table — invalidated on logout
- Rate limiting: 15min lockout after 11 failed attempts

### Commercial roadmap phases
| Phase | Name | Key deliverables |
|---|---|---|
| Fas 1 | Foundation | Push queue, license validation, scd-server MVP, admin UI ✅ |
| Fas 2 | Team value | Dashboard ✅, drill-down Nivå 1 ✅, exception approvals 🔲 |
| Fas 3 | Professional add-ons | CRA/NIS2 reports, plugin API, rule packs, rule signing |

### Internal commands (not in README or scd --help)
`scd review-rules` — hidden command for Activemind-internal rule quality analysis.

### Parked (not forgotten)
- Taint analysis engine — multi-pass data flow tracking for rules
- Heartbeat (api.activemind.se)
- `pkg` binary distribution — revisit before first customer
- Activemind-hosted cloud central
- Config signing
