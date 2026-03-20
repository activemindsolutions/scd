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
Balanced           – Default. Deep analysis via Claude API (anonymised code fragments only)
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
        ├── audit-summary.log       ← anonymised statistics (JSONL)
        ├── last-scan.json          ← cache for scd report
        ├── scans/                  ← individual scan files (never overwritten)
        └── reports/                ← generated reports (html, md, json)
```

**Key principle:** The customer's repository is never touched after `scd init` installs git hooks.
All data lives in the global store.

## Push queue architecture

Events flow from CLI → scd-server via an offline-first queue:

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
- Meta: installationId (machine fingerprint), repoId, hostname, platform, scdVersion

**Offline behaviour:** Queue entries accumulate with `attempts` counter. After 10 failed
attempts entries are considered stale. Grace period: 7 days before `scd doctor` warns.

## scd-server architecture

```
server.js                     ← Entry point, startup, graceful shutdown
lib/
  server-config.js            ← Config hierarchy: ENV → config.yml → defaults
  db.js                       ← SQLite abstraction (Postgres-ready interface)
  auth.js                     ← License validation + Bearer token auth
  admin-auth.js               ← User accounts, scrypt hashing, role middleware
  ui-helpers.js               ← Shared navbar, logout script
  routes-health.js            ← GET /api/v1/health, GET /api/v1/entitlements
  routes-events.js            ← POST /api/v1/events/batch
  routes-admin.js             ← /admin UI + API (admin role only)
  routes-dashboard.js         ← /dashboard UI + API (admin + viewer)
data/
  scd.db                      ← SQLite database (gitignored)
  scd-public.pem              ← Ed25519 public key for license verification (gitignored)
  license.key                 ← Signed license file (gitignored)
config.yml                    ← Server configuration (gitignored)
config.example.yml            ← Configuration template (committed)
```

## License validation

```
scd-server startup
  → auth.js: validateLicense()
  → Read data/license.key (JSON)
  → Verify Ed25519 signature against data/scd-public.pem
  → Check expiry date
  → Check machine fingerprint (bind on first activation)
  → Return: { valid, tier, seats, expiry, features[], rulePacks[] }
  → No license file → development mode (full access)
  → Invalid → degrade to Starter tier
```

Keypair management (Activemind-internal, `~/Projects/scd-admin`):
```
node generate-license.js --generate-keys        → creates scd-license-private.pem + scd-license-public.pem
node generate-license.js --customer "Acme AB" … → creates signed license file
cp scd-license-public.pem ~/Projects/scd-server/data/scd-public.pem
```

## Git hooks

`scd init` installs hooks via `git config core.hooksPath ~/.scd/hooks`:
- **pre-commit** – secrets scanning (fast, blocks on CRITICAL)
- **pre-push** – full OWASP scan (comprehensive, blocks on CRITICAL + HIGH)

## Auth architecture (current)

```
/api/v1/*     → Bearer token (scd CLI ↔ scd-server)
/admin/*      → HTTP Basic Auth, admin role only
/dashboard/*  → HTTP Basic Auth, admin or viewer role
/             → redirect to /dashboard
/login        → logout landing page
```

Users stored in `users` table with scrypt-hashed passwords.
Two accounts created on first startup: `admin` and `viewer`.

**Planned:** Replace Basic Auth with JWT + httpOnly cookie sessions.

## CRA (EU Cyber Resilience Act) alignment

- Audit trail (`audit.log`) supports manufacturer accountability requirements
- Exception management with approval workflow supports documented risk decisions
- Reports support evidence collection for conformity assessments
- `scd deps` (planned) supports vulnerability disclosure requirements

## Supply chain security consideration

The global hooks architecture means scd itself is a potential supply chain attack vector.
Future considerations:
- Rule signing (Activemind-signed vs community rules)
- Binary distribution with checksums (Alt 2 + Alt 3 decision)
- Config signing
