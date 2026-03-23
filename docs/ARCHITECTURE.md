# Secure Code by Design – Architecture

## Product vision

Secure Code by Design is a hybrid product: an automated security scanning CLI that runs locally
in the developer's workflow, combined with a self-hosted central server for team visibility,
and optional AI-powered deep analysis via Claude API.

Target market: SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor)
who generate code faster than their security awareness can keep up with.

## Business model – Open Core

| Tier | Price | Features |
|---|---|---|
| Starter | Free / Open Source | Local scanning, git hooks, HTML reports |
| Team | 2 499 SEK/month | + scd-server, team dashboard, trend analysis |
| Professional | 7 499 SEK/month | + CRA/NIS2 reports, commercial rule packs, consulting upsell |

The product findings create a natural upsell funnel to Activemind's consulting engagements.

## Three-tier deployment architecture

```
Maximum Privacy    – Everything local, zero external calls
Balanced           – Default. Deep analysis via Claude API (code fragments only)
Maximum Analysis   – Full Claude API integration, maximum findings
```

Controlled by `trust_level` in `securityagent.yml` (placed in customer's repo root).

## System overview

```
Developer machine
  scd CLI  ──────────────────────────────────────┐
  ~/.scd/                                         │ push queue
    push-queue.jsonl                               │ (offline-first)
    repos/{repoId}/                               ▼
      audit.log                           scd-server
      scans/                              (customer infrastructure)
      reports/                              data/scd.db
                                            /api/v1/events/batch
                                            /admin
                                            /dashboard
                                            /dashboard/rule/:id
                                            /dashboard/repo/:id
                                            /dashboard/installation/:id
```

## Global store architecture (scd CLI)

```
~/.scd/
├── config                          ← API key, central URL, token
├── push-queue.jsonl                ← offline event queue
└── repos/
    └── {repoId}/                   ← SHA-256(git remote URL) or SHA-256(abs path)
        ├── meta.json               ← name, remote, localPath, type, lastSeen, lastScan
        ├── config.yml              ← exceptions, locked_rules, trust_level
        ├── audit.log               ← full findings history (JSONL)
        ├── last-scan.json          ← cache for scd report
        ├── scans/                  ← individual scan files (never overwritten)
        └── reports/                ← generated reports (html, md, json)
```

**Key principle:** The customer's repository is never touched after `scd init`.
All data lives in the global store.

## Push queue architecture

```
scd scan completes
  → audit.js: logScan() writes to audit.log (always)
  → audit.js: enqueue() adds to push-queue.jsonl (if central URL configured)
  → bin/scd.js: tryFlush() before process.exit()
  → push-queue.js: flush() POSTs to /api/v1/events/batch
  → scd-server: insertEvents() writes to SQLite
```

Each event includes:
- Scan summary (files, findings by severity, blocked, exceptions)
- OWASP category breakdown (`categories` object)
- Top 20 rules by count (`top_rules` array)
- Meta: installationId, repoId, hostname, platform, scdVersion

**Offline behaviour:** Queue entries accumulate with `attempts` counter.
After 10 failed attempts entries are stale. Grace period: 7 days before `scd doctor` warns.

## scd-server architecture

```
server.js                     ← Entry point. --host/--port/--help flags.
lib/
  server-config.js            ← Config hierarchy: ENV → config.yml → defaults
  db.js                       ← SQLite abstraction (Postgres-ready)
  auth.js                     ← License validation + Bearer token auth
  session-auth.js             ← JWT sessions, httpOnly cookie, rate limiter
  admin-auth.js               ← Password hashing, first-run setup, error pages
  ui-helpers.js               ← Shared navbar, logout script
  routes-auth.js              ← POST /auth/login, POST /auth/logout, GET /login
  routes-health.js            ← GET /api/v1/health, GET /api/v1/entitlements
  routes-events.js            ← POST /api/v1/events/batch
  routes-admin.js             ← /admin UI + API (admin role only)
  routes-dashboard.js         ← /dashboard UI + API (admin + viewer)
  routes-detail.js            ← /dashboard/rule|repo|installation/:id
data/
  scd.db                      ← SQLite database (gitignored)
  scd-public.pem              ← Ed25519 public key (gitignored)
  license.key                 ← Signed license file (gitignored)
config.yml                    ← Server configuration (gitignored)
config.example.yml            ← Configuration template (committed)
```

## Auth architecture (JWT)

```
POST /auth/login
  → validate credentials against users table (scrypt)
  → rate limit check (in-memory per IP)
  → sign JWT (HS256, jti claim)
  → create session record in sessions table
  → set httpOnly SameSite=Strict cookie
  → redirect to /dashboard

Every protected request
  → extract JWT from cookie (or Authorization: Bearer)
  → jwt.verify() — throws on invalid signature, expired, alg:none
  → db.getSession(jti) — checks not invalidated, not expired
  → attach user to req.user

POST /auth/logout
  → db.invalidateSession(jti)
  → clearCookie()

Roles:
  admin  → /admin/* + /dashboard/*
  viewer → /dashboard/* only
```

## Dashboard drill-down navigation (Nivå 1)

```
/dashboard
  ├── Top Rules → /dashboard/rule/:ruleId
  │     ├── Repos     → /dashboard/repo/:repoId
  │     └── Installs  → /dashboard/installation/:id
  ├── Recent Scans (repo link) → /dashboard/repo/:repoId
  │     ├── Top rules → /dashboard/rule/:ruleId
  │     └── Installs  → /dashboard/installation/:id
  ├── Recent Scans (host link) → /dashboard/installation/:id
  │     ├── Repos     → /dashboard/repo/:repoId
  │     └── Top rules → /dashboard/rule/:ruleId
  └── Repositories → /dashboard/repo/:repoId
```

## License validation

```
scd-server startup
  → auth.js: validateLicense()
  → Read data/license.key (JSON)
  → Verify Ed25519 signature against data/scd-public.pem
  → Check expiry date
  → Check machine fingerprint (bind on first activation)
  → No license file → development mode (full access)
  → Invalid → degrade to Starter tier
```

## Git hooks

`scd init` installs hooks via `git config core.hooksPath ~/.scd/hooks`:
- **pre-commit** – secrets scanning (fast, blocks on CRITICAL)
- **pre-push** – full OWASP scan (comprehensive, blocks on CRITICAL + HIGH)

## CRA (EU Cyber Resilience Act) alignment

- Audit trail (`audit.log`) supports manufacturer accountability
- Exception management with approval workflow supports documented risk decisions
- Reports support evidence collection for conformity assessments
- `scd deps` (planned) supports vulnerability disclosure requirements

## Supply chain security

- Rule signing planned for Fas 3 (Activemind-signed vs community)
- Binary distribution with checksums planned before first customer
