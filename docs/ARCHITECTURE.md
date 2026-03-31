# Secure Code by Design – Architecture

## Product vision

Secure Code by Design is a hybrid product: an automated security scanning CLI that runs locally
in the developer's workflow, combined with a self-hosted central server for team visibility,
and optional AI-powered deep analysis. Deep analysis runs either via Claude API (cloud) or
via a fully local model through the scd-ai layer — no code leaves the customer's network.

Target market: SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor)
who generate code faster than their security awareness can keep up with.

## Business model – Open Core

| Tier | Price | Features |
|---|---|---|
| Starter | Free / Open Source | Local scanning, git hooks, HTML reports |
| Team | 499 SEK/mth + 149 SEK/active dev | + scd-server, team dashboard, trend analysis |
| Professional | 999 SEK/mth + 249 SEK/active dev | + CRA/NIS2 reports, commercial rule packs, consulting upsell |

Add-ons (available on any paid tier):

| Add-on | Price | Description |
|---|---|---|
| Deep Analysis – Cloud | 299 SEK/month | `--deep` via Claude API; code fragments only |
| Deep Analysis – Local (scd-ai) | 299 SEK/month | `--deep` via local model; no code leaves network |
| Compliance Pack | 499 SEK/month | NIS2 report, disclosure register, SDLC evidence |
| Rule Packs | from 299 SEK/month | PCI-DSS, HIPAA, advanced JS, CRA-specific rules |
| Training Add-on | 999 SEK/month | e-learning linked to team knowledge gaps |
| Partner Add-on | 3 500 SEK/month | 4h/month consulting, dedicated contact, SLA |

The product findings create a natural upsell funnel to Activemind's consulting engagements.
See PRICING.md for full pricing detail and open decisions.

## Three-tier deployment architecture

```
maximum_privacy   – Everything local. scd-ai (local model) only. External API calls blocked.
balanced          – Default. Local model preferred; Claude API available as explicit opt-in.
maximum_analysis  – Claude API (cloud). Maximum findings, code fragments sent externally.
```

Controlled by `trust_level` in `securityagent.yml` (placed in customer's repo root).

## System overview

```
Developer machine
  scd CLI  ──────────────────────────────────────┐
  ~/.scd/                                         │ push queue + deep analyze
    push-queue.jsonl                               │ (offline-first)
    repos/{repoId}/                               ▼
      audit.log                           scd-server
      scans/                              (customer infrastructure)
      reports/                              data/scd.db       ← app data
                                            data/scd-kb.db    ← KB embeddings
                                            /api/v1/events/batch
                                            /api/v1/deep/analyze  ← scd-ai
                                            /api/v1/ai/health
                                            /admin
                                            /dashboard
                                            /dashboard/rule/:id
                                            /dashboard/repo/:id
                                            /dashboard/installation/:id
                                                    │
                                                    │ Ollama HTTP API
                                                    ▼
                                            Ollama (customer infrastructure)
                                              qwen2.5-coder:14b
                                              nomic-embed-text
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

## scd-ai — Local AI analysis layer

scd-ai is the commercial add-on that enables fully local AI-powered deep
analysis. It runs inside scd-server — no separate process or binary.

**Core principle:** The CLI is a transport layer. All AI logic lives in scd-server.
The CLI sends findings to `/api/v1/deep/analyze` and receives structured results.
It has no direct knowledge of Ollama or which provider is active.

```
scd scan --deep
    │
    POST /api/v1/deep/analyze
    ▼
scd-server: lib/ai-engine.js
    ├── Layer 1 KB: rule-specific guidance (deterministic, ruleId lookup)
    ├── Layer 2 KB: semantic context (sqlite-vec, nomic-embed-text embeddings)
    ├── Live context: scd.db repo history, exceptions, OWASP trends
    └── Ollama API → local model → structured JSON
    ▼
deep_results stored in scd.db
deep_source tagged on every result (provider, model, code_left_environment)
```

**deep_source audit trail:** Every finding carries provenance metadata including
`code_left_environment: false` for local analysis. This supports CRA/NIS2
compliance documentation — customers can prove, per finding, that code stayed local.

**Open source boundary:** `--deep` is present in the CLI as a discoverable
teaser. Without scd-server + scd-ai entitlement, it prints a subscription
prompt and exits. No AI functionality runs in the open source tier.

**Database separation:**
- `data/scd.db` — application data (unchanged schema + new `deep_results`, `ai_config` tables)
- `data/scd-kb.db` — KB embeddings only (sqlite-vec); contains no customer code;
  replaceable with Postgres/pgvector without touching application data

For full scd-ai architecture, see **ARCHITECTURE-AI.md**.
For file-level reference, see **CODEBASE-AI.md**.
