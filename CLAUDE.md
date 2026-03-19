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

## Repository
- GitHub: `git@github.com:activemindsolutions/scd.git`
- Local (primary dev): `~/Projects/scd`
- Installed via: `npm link` (dev) or `git clone && npm install && npm link` (other machines)
- Command: `scd`

## Tech stack
- Node.js 18+ (CommonJS, no transpilation)
- commander@11 (CLI framework)
- No other runtime dependencies – deliberately lightweight
- Claude API (Anthropic) for deep analysis features (`scd insights --deep`, `scd scan --deep`)

## Key design principles
1. **Zero repo footprint** – SC never writes files to the customer's repo
2. **Global store** – all data in `~/.scd/repos/{repoId}/`
3. **repoId** = SHA-256 of git remote URL (stable across re-clones), fallback = SHA-256 of abs path
4. **English only** – all rule text, CLI output, comments in English
5. **Rule IDs are stable** – never renumber or rename existing rule IDs
6. **No npm dependencies added without discussion** – keep the install lightweight

## Code conventions
- CommonJS (`require`/`module.exports`), no ES modules
- `'use strict'` in all lib files
- Descriptive variable names, comments for non-obvious logic
- ANSI color via raw escape codes (no chalk dependency)
- All user-facing strings in English

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

---

## Commercial model

### Core brand message
> "Vi är så seriösa med integritet att vi inte ens vill ha din data."

This is the primary marketing message. Self-hosted by design, not as a limitation.

### Business goals (priority order)
1. Lead generation for consulting and penetration testing engagements
2. Lead generation for security training (workshops, e-learning, certification)
3. Recurring revenue from commercial licenses (Team/Professional tiers)

### License tiers
| Tier | Price | Key differentiator |
|---|---|---|
| Starter | Free / Open Source | Full CLI + all core rules, local reports |
| Team | 2 499 SEK/month | Local sc-server, team dashboard, up to 5 developers |
| Professional | 7 499 SEK/month | CRA/NIS2 reports, commercial rule packs, quarterly reviews |

- Team tier: +X SEK/month per developer beyond 5 (price TBD)
- No per-repo pricing – ever
- Professional is an add-on to Team, not a separate product

### sc-server (local central) – commercial core
The commercial server runs entirely in the customer's infrastructure. No data leaves their network.
- Distributed as a compiled binary via `pkg` (one binary per platform: macOS arm64/x64, Linux x64)
- License validated at startup (offline, Ed25519 signature check) + heartbeat every 24h
- Grace period: 7 days offline before degrading to Starter functionality (never hard shutdown)
- Machine fingerprint: SHA-256(hostname + platform + primary MAC)
- License key contains: customer ID, tier, seats, expiry, Ed25519 signature

### Push queue architecture
Each `scd` installation pushes audit events to sc-server via a local offline queue:
- Events always written to `audit.log` first (existing behavior, unchanged)
- Events also queued in `~/.scd/push-queue.jsonl`
- Push worker triggers on every `scd` command (not a daemon)
- Sends batch when central is reachable, queues silently when not
- 7-day grace before stale warning; stale events reported by `scd doctor`
- sc-server API: `POST /api/v1/events/batch`, `GET /api/v1/health`

### Team dashboard (Fas 2)
- Aggregated team overview: active repos, findings trend, unresolved CRITICALs
- Knowledge gap analysis at team level (OWASP categories, per-developer breakdown)
- Trend view over 12 weeks (key sales argument: visible improvement after workshops)
- Exception approval flow for team leads

### Plugin API & rule packs (Fas 3 / roadmap)
Three categories of rules:
1. **Core rules** – open source, included in Starter, maintained by Activemind
2. **Community rules** – loaded at user's own risk, explicit CLI warning (à la Caido)
3. **Activemind rule packs** – commercial, cryptographically signed, guaranteed

Commercial rule pack examples: `pack-fintech`, `pack-healthcare`, `pack-cra`, `pack-advanced-js`

Plugin API and signing design to be specified in a separate design session.

### Commercial roadmap phases
| Phase | Name | Key deliverables |
|---|---|---|
| Fas 1 | Foundation | Push queue in CLI, license validation, sc-server MVP, admin UI |
| Fas 2 | Team value | Team dashboard, knowledge gaps, trend view, exception approvals |
| Fas 3 | Professional add-ons | CRA/NIS2 reports, plugin API, commercial rule packs, rule signing |

### Internal commands (not in README or scd --help)

`scd review-rules` is an Activemind-internal command for rule quality analysis. It is registered with `program.addCommand(cmd, { hidden: true })` so it is invisible in `scd --help` and is not documented in README.md. It is discoverable only via `scd review-rules --help`.

Both `scd export-findings` and `scd review-rules` share the same implementation in `lib/export-findings.js`. The only runtime difference is the `includeRuleInternals` flag: when `true` (review-rules), the `rule_analysis` block in the output JSON includes `pattern` and `antipattern` (RegExp source strings) from the raw rule definitions — intended for internal rule quality review. These fields are omitted entirely from customer-facing exports.

### Parked (not forgotten)
- Activemind-hosted cloud central – deferred until local central is stable
- `scd export` + merge – natural complement to push queue
- Config signing – next after push queue is implemented
