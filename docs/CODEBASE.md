# Security Co-Pilot – Codebase Reference

## Entry point

```
bin/security-copilot.js     ← CLI entry point. All sc commands defined here.
                               Uses commander@11. Async actions where needed.
```

## lib/ – Core modules

### Scanning
| File | Responsibility |
|---|---|
| `scanner-full.js` | Full OWASP scan. Loads all rule modules, applies vendor/minified/build-tool filters, runs antipattern checks with lookbehind support. Used by pre-push hook and `sc scan`. |
| `scanner-secrets.js` | Fast secrets-only scan. Used by pre-commit hook. |
| `scanner-manual.js` | Interactive manual scan mode. |
| `deep-analyzer.js` | Sends findings to Claude API for deep analysis. Respects trust_level. |

### Rules
| File | Rules | Coverage |
|---|---|---|
| `rules/rules-js.js` | ~24 | JS/TS injection, auth, JWT, crypto, SSRF, exposure |
| `rules/rules-ts.js` | 5 | TypeScript-specific additions |
| `rules/rules-python.js` | ~26 | Python injection, auth, crypto, deserialization, exposure |
| `rules/rules-php.js` | ~29 | PHP injection, auth, crypto, IDOR, exposure |
| `rules/rules-aspx.js` | 17 | ASP.NET markup (aspx/ascx) |
| `rules/rules-aspx-cs.js` | 26 | ASP.NET C# code-behind |
| `rules/rules-sensitive-files.js` | ~50 | Sensitive filenames + content patterns |
| `rules/rules-infra-leakage.js` | 21 | Infrastructure leakage (localhost, RFC1918, internal hostnames, ports, connection strings) |

**Total: 172 rules** – CRITICAL: 63, HIGH: 69, MEDIUM: 10, EXPOSURE: 30

Rule structure:
```js
{
  id:          'PHP-INJ-001',
  name:        'SQL Injection – string concatenation in query',
  severity:    'CRITICAL',              // CRITICAL | HIGH | MEDIUM | EXPOSURE
  category:    'Injection (OWASP A03)',
  fileTypes:   ['php'],
  pattern:     /regex/g,
  antipattern: /false-positive-filter/i,  // optional
  lookahead:   200,                     // chars forward from match for antipattern
  lookbehind:  120,                     // chars backward from match for antipattern
  why:         'Why this is dangerous',
  scenario:    'Attack scenario',
  fix:         'How to fix',
}
```

### Store & config
| File | Responsibility |
|---|---|
| `store.js` | Central path management for global store. `getRepoId()`, `updateMeta()`, `listRepos()`, `listReports()`. All store paths go through here. |
| `store-verify.js` | Verify repos in store against disk. Statuses: OK/MISSING/STALE/ORPHAN. Interactive cleanup (`--clean`). Archive to .tar.gz or delete with confirmation. |
| `config.js` | Reads `config.yml` from store. Handles trust_level, rule overrides, exceptions. |
| `global-config.js` | Manages `~/.security-copilot/config` (API key). |
| `scan-cache.js` | Reads/writes `last-scan.json`. Used by `sc report` to regenerate without re-scanning. |

### Reports
| File | Responsibility |
|---|---|
| `report-html.js` | Generates full HTML report with findings, severity breakdown, fix guidance. Written with `mode: 0o644`. |
| `report-markdown.js` | Markdown report. |
| `report-json.js` | JSON report for machine consumption. |
| `audit.js` | Writes to `audit.log` (JSONL). Full findings history. |
| `audit-report.js` | Reads and formats audit log. |

### CLI support
| File | Responsibility |
|---|---|
| `rule-registry.js` | Central catalogue of all 172 rules. Normalises, deduplicates, sorts. Used by `sc rules`. |
| `output-terminal.js` | Terminal output formatting for scan results. ANSI colors, severity icons. |
| `init-repo.js` | `sc init` logic. Creates store entry, installs git hooks via `core.hooksPath`. |
| `installer.js` | Hook installation/removal helpers. |
| `doctor.js` | `sc doctor` – verifies setup, checks node version, git config, API key. |
| `exception-manager.js` | Manages exceptions in `config.yml`. Created via `sc approve`. |
| `resolve-manager.js` | Marks findings as resolved. |
| `insights-analyzer.js` | Reads audit log, computes behavioral statistics. |
| `insights-output.js` | Formats insights for terminal output. |
| `git-utils.js` | Git helpers: remote URL, repo root detection, branch name. |

## Key false-positive filters in scanner-full.js

```js
isMinified  // lines avg >500 chars → skip entirely (bundles, generated code)
isVendor    // phpmailer/, vendor/, node_modules/, jquery., .min.js etc.
isBuildTool // webpack.config.*, vite.config.*, jest.config.* etc.
```

`isAntipatternPresent()` checks both forward (lookahead) and backward (lookbehind)
from the match position – necessary because env-var fallbacks like
`process.env.HOST || 'localhost'` appear *before* the localhost match.

## securityagent.yml

Template config file placed in the customer's repo root by `sc init`.
Controls: `trust_level`, `ai_coding_tool`, `block_on_critical`, `block_on_high`,
`rule_overrides`, `exceptions`.

Exceptions are never added as source code comments (security anti-pattern) –
always managed in this file via `sc approve`.
