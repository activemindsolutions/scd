# Secure Code by Design – Architecture

## Product vision

Secure Code by Design is a hybrid product: an automated security scanning CLI that runs locally
in the developer's workflow, combined with optional AI-powered deep analysis via Claude API.

Target market: SMB companies using AI coding tools (Claude Code, GitHub Copilot, Cursor)
who generate code faster than their security awareness can keep up with.

## Business model – Open Core

| Tier | Price | Features |
|---|---|---|
| Starter | 599 SEK/month | Local scanning, git hooks, HTML reports |
| Team | 2 499 SEK/month | + Portal, team dashboard, trend analysis |
| Professional | 7 499 SEK/month | + Deep AI analysis, compliance reports, consulting upsell |

The product findings create a natural upsell funnel to Activemind's consulting engagements.

## Three-tier deployment architecture

```
Maximum Privacy    – Everything local, zero external calls
Balanced           – Default. Anonymised patterns sent for deep analysis
Maximum Analysis   – Full Claude API integration, maximum findings
```

Controlled by `trust_level` in `securityagent.yml` (placed in customer's repo root).

## Global store architecture

```
~/.scd/
├── config                          ← API key (sc configure --api-key)
└── repos/
    └── {repoId}/                   ← SHA-256(git remote URL) or SHA-256(abs path)
        ├── meta.json               ← name, remote, localPath, type, lastSeen, lastScan, findings
        ├── config.yml              ← exceptions, locked_rules, trust_level
        ├── audit.log               ← full findings history (JSONL)
        ├── audit-summary.log       ← anonymised statistics (JSONL)
        ├── last-scan.json          ← cache for scd report
        └── reports/                ← generated reports (html, md, json)
```

**Key principle:** The customer's repository is never touched after `sc init` installs git hooks.
All data lives in the global store. `repoId` is stable across re-clones if a git remote exists.

## Git hooks

`sc init` installs hooks via `git config core.hooksPath ~/.scd/hooks`:
- **pre-commit** – secrets scanning (fast, blocks on CRITICAL)
- **pre-push** – full OWASP scan (comprehensive, blocks on CRITICAL + HIGH)

This approach uses a global hooks directory rather than per-repo `.git/hooks/`,
keeping the repo clean and hooks consistent across all registered repos.

## Plugin/module architecture (planned)

Four MVP security modules:
1. Input Validation (SQL injection, XSS, command injection, path traversal)
2. Auth/Authorization (IDOR, missing auth, session issues)
3. Secrets/API keys (hardcoded credentials, exposed tokens)
4. JWT handling (algorithm none, missing verification)

## Supply chain security consideration

The global hooks architecture means SC itself is a potential supply chain attack vector
(like SolarWinds, Kaseya, tj-actions). Future portal architecture must be zero-knowledge:
customers should be able to verify the tool independently of Activemind's infrastructure.

## CRA (EU Cyber Resilience Act) alignment

SC is designed with CRA compliance as a requirement from the start:
- Audit trail (`audit.log`) supports manufacturer accountability requirements
- Exception management with approval workflow supports documented risk decisions
- Dependency scanning (`sc deps`, planned) supports vulnerability disclosure requirements
- Reports support evidence collection for conformity assessments
