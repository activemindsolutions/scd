# Secure Code by Design – Codebase Reference

## scd CLI

### Entry point

```
bin/scd.js                  ← CLI entry point. All scd commands defined here.
                               Uses commander@11. tryFlush() before process.exit() in scan.
```

### lib/ – Core modules

#### Scanning
| File | Responsibility |
|---|---|
| `scanner-full.js` | Full OWASP scan. Loads all rule modules, applies vendor/minified/build-tool filters, runs antipattern checks with lookbehind support. |
| `scanner-secrets.js` | Fast secrets-only scan. Used by pre-commit hook. |
| `scanner-manual.js` | Interactive manual scan mode. |
| `deep-analyzer.js` | Sends findings to Claude API. Sends only: filename + rule ID + triggering line + 8 lines context. Respects `trust_level`. |

#### Rules
| File | Rules | Coverage |
|---|---|---|
| `rules/rules-js.js` | ~24 | JS/TS injection, auth, JWT, crypto, SSRF, exposure |
| `rules/rules-ts.js` | 5 | TypeScript-specific additions |
| `rules/rules-python.js` | ~26 | Python injection, auth, crypto, deserialization |
| `rules/rules-php.js` | ~29 | PHP injection, auth, crypto, IDOR, exposure |
| `rules/rules-aspx.js` | 17 | ASP.NET markup (aspx/ascx) |
| `rules/rules-aspx-cs.js` | 26 | ASP.NET C# code-behind |
| `rules/rules-sensitive-files.js` | ~50 | Sensitive filenames + content patterns |
| `rules/rules-infra-leakage.js` | 21 | Infrastructure leakage (localhost, RFC1918, connection strings) |

**Total: 172 rules** – CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

#### Store & config
| File | Responsibility |
|---|---|
| `store.js` | Central path management. `getRepoId()`, `getRepoIdentity()`, `updateMeta()`, `listRepos()`, all store paths. |
| `store-verify.js` | Verify repos against disk. Statuses: OK/MISSING/STALE/ORPHAN. Windows-compatible archive (Node.js copy, no tar). |
| `scan-cache.js` | Per-scan storage. `saveCache()`, `loadCache()`, `loadScan()`. |
| `config.js` | Reads `config.yml` from store. Handles `trust_level`, `deep_delay_ms`, rule overrides, exceptions. |
| `global-config.js` | Manages `~/.scd/config`. API key, central URL, central token. Functions: `getApiKey`, `getCentralUrl`, `setCentralUrl`, `getCentralToken`, `setCentralToken`. |

#### Push queue
| File | Responsibility |
|---|---|
| `push-queue.js` | Offline-first event queue. `enqueue()`, `flush()`, `queueSize()`, `staleCount()`, `isPastGrace()`, `purgeStale()`. Sends `meta` (installationId, repoId, hostname, platform, scdVersion) with each flush. |

#### Reports
| File | Responsibility |
|---|---|
| `report-html.js` | Full HTML report. Tabs: Executive Summary, Remediation Plan, All Findings, Deep Analysis. |
| `report-index.js` | HTTP server index page. |
| `report-markdown.js` | Markdown report. |
| `report-json.js` | JSON report. Version read dynamically from `package.json`. |
| `audit.js` | Writes to `audit.log` (JSONL). Also calls `enqueue()` with category breakdown and top rules if central URL configured. |
| `audit-report.js` | Reads and formats audit log. |

#### CLI support
| File | Responsibility |
|---|---|
| `rule-registry.js` | Central catalogue of all 172 rules. Exports `RULES_VERSION` (independent from CLI version). |
| `output-terminal.js` | Terminal output formatting for scan results. |
| `init-repo.js` | `scd init` logic. |
| `installer.js` | Hook installation/removal. `HOOKS_DIR = ~/.scd/hooks`. |
| `doctor.js` | `scd doctor` – verifies setup, push queue status, stale events, grace period. |
| `exception-manager.js` | Manages exceptions in `config.yml`. |
| `resolve-manager.js` | Marks findings as resolved. |
| `insights-analyzer.js` | Reads audit log, computes behavioral statistics. |
| `insights-output.js` | Formats insights for terminal. |
| `git-utils.js` | Git helpers: remote URL, repo root, branch, changed files. |

### Version system

- CLI version: `package.json` → `pkg.version` → read at runtime
- Rules version: `lib/rule-registry.js` → `RULES_VERSION` constant
- Both shown in `scd --version` and `scd version`
- Versions are independent

---

## scd-server

### Entry point

```
server.js                   ← Express app, startup, graceful shutdown, route registration
                               Registers: routes-health, routes-events, routes-admin, routes-dashboard
                               Root / → redirect to /dashboard
                               /login → logout landing page
```

### lib/

| File | Responsibility |
|---|---|
| `server-config.js` | Config hierarchy: ENV → `config.yml` → defaults. Fields: host, port, log_level, public_key_path, license_path, db_path. |
| `db.js` | SQLite abstraction layer via `better-sqlite3`. Postgres-ready interface. Tables: installations, repos, scans, scan_categories, scan_top_rules, raw_events, server_config, users. Functions: insertEvents, getRecentScans (with repo JOIN), getCategoryBreakdown, getTopRules, getUserByUsername, createUser, updatePassword. |
| `auth.js` | License validation (Ed25519 + machine fingerprint), Bearer token auth, `requireFeature()` middleware. `validateLicense()` cached in memory per startup. |
| `admin-auth.js` | User account management, scrypt password hashing, `requireAdminAuth` (admin only), `requireDashboardAuth` (admin + viewer), HTML 403 error page, `ensureAdminExists()`. |
| `ui-helpers.js` | `renderNavbar(user, activePage)` — shared nav with Dashboard/Admin links and Sign out. `renderLogoutScript()` — redirects to /login. |
| `routes-health.js` | `GET /api/v1/health` (public), `GET /api/v1/entitlements` (Bearer token). |
| `routes-events.js` | `POST /api/v1/events/batch` (Bearer token). Validates input, calls `db.insertEvents()`. Max 500 events per batch. |
| `routes-admin.js` | `/admin` UI + API. Admin role only. Status, installations, repos, recent scans, users. Change-password for any user. |
| `routes-dashboard.js` | `/dashboard` UI + API. Admin + viewer. Stat cards, 12-week trend chart, knowledge gaps, top rules, recent scans. |

### Database schema

```sql
installations   id (fingerprint), hostname, platform, scd_version, first/last_seen
repos           id (repoId), name, remote, first/last_seen
scans           session_id, installation_id, repo_id, hook, findings by severity, ts
scan_categories scan_id → category, critical, high, medium, exposure counts
scan_top_rules  scan_id → rule_id, rule_name, severity, count
raw_events      received_at, payload (JSON verbatim)
server_config   key/value (api_token, machine_fingerprint)
users           username, password_hash, salt, role, created_at, last_login
```

### Configuration

```
config.yml          ← gitignored, active configuration
config.example.yml  ← committed template
data/scd.db         ← SQLite database (gitignored)
data/scd-public.pem ← Ed25519 public key (gitignored)
data/license.key    ← Signed license file (gitignored)
```

---

## scd-admin (internal)

```
~/Projects/scd-admin/
  generate-license.js      ← Keypair generation + license signing/verification
  scd-license-private.pem  ← Ed25519 private key (NEVER commit)
  scd-license-public.pem   ← Ed25519 public key (copy to scd-server/data/scd-public.pem)
```

Usage:
```bash
node generate-license.js --generate-keys
node generate-license.js --customer "Acme AB" --customer-id acme-001 \
  --tier team --seats 5 --expiry 2027-03-19 \
  --features "dashboard,deep_analysis"
node generate-license.js --verify scd-license-acme-001-team.key
```
