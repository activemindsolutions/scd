# Secure Code by Design – Codebase Reference

## Entry point

```
bin/scd.js                  ← CLI entry point. All scd commands defined here.
                               Uses commander@11. Async actions where needed.
```

## lib/ – Core modules

### Scanning
| File | Responsibility |
|---|---|
| `scanner-full.js` | Full OWASP scan. Loads all rule modules, applies vendor/minified/build-tool filters, runs antipattern checks with lookbehind support. Used by pre-push hook and `scd scan`. |
| `scanner-secrets.js` | Fast secrets-only scan. Used by pre-commit hook. |
| `scanner-manual.js` | Interactive manual scan mode. |
| `deep-analyzer.js` | Sends findings to Claude API for deep analysis. Sends only: filename + rule ID + triggering line + 8 lines context. Respects `trust_level`. Includes exponential backoff retry (429) and configurable inter-file delay (`delayMs`). |

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
| `store.js` | Central path management for global store. `getRepoId()`, `updateMeta()`, `listRepos()`, `listReports()`, `scansDir()`, `scanPath()`, `listScans()`. All store paths go through here. |
| `store-verify.js` | Verify repos in store against disk. Statuses: OK/MISSING/STALE/ORPHAN. path-based repos don't require `.git/`. Interactive cleanup (`--clean`). Archive to .tar.gz or delete with confirmation. |
| `scan-cache.js` | Per-scan storage. `saveCache()` writes to `scans/{scanId}.json` (never overwritten) and updates `last-scan.json` as a copy. `loadCache()` reads latest. `loadScan(repoRoot, scanId)` reads a specific scan. Scan ID format: `2026-03-17T132421`. |
| `config.js` | Reads `config.yml` from store. Handles `trust_level`, `deep_delay_ms`, rule overrides, exceptions. DEFAULTS includes `deep_delay_ms: 0`. |
| `global-config.js` | Manages `~/.scd/config` (API key). |

### Reports
| File | Responsibility |
|---|---|
| `report-html.js` | Generates full HTML report. Tabs: Executive Summary, Remediation Plan, All Findings, Deep Analysis (conditional). Deep tab has filtering, sorting (severity/file), and shows original finding context alongside Claude analysis. Written with `mode: 0o644`. |
| `report-index.js` | Generates the HTTP server index page listing all reports. Matches report theme (dark, Syne/JetBrains Mono). Open and download buttons per report. |
| `report-markdown.js` | Markdown report. |
| `report-json.js` | JSON report for machine consumption. |
| `audit.js` | Writes to `audit.log` (append-only JSONL). Full findings history. |
| `audit-report.js` | Reads and formats audit log. |

### CLI support
| File | Responsibility |
|---|---|
| `rule-registry.js` | Central catalogue of all 172 rules. Normalises, deduplicates, sorts. Exports `RULES_VERSION` (independent from CLI version). Used by `scd rules` and `scd version`. |
| `output-terminal.js` | Terminal output formatting for scan results. ANSI colors, severity icons. |
| `init-repo.js` | `sc init` logic. Creates store entry, installs git hooks via `core.hooksPath`. |
| `installer.js` | Hook installation/removal helpers. |
| `doctor.js` | `scd doctor` – verifies setup, checks node version, git config, API key. |
| `exception-manager.js` | Manages exceptions in `config.yml`. Created via `scd approve`. |
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

## Scan storage layout

```
~/.scd/repos/{repoId}/
  last-scan.json              ← copy of latest scan (backwards compat)
  scans/
    2026-03-17T132421.json    ← individual scan with findings + deepResults
    2026-03-17T091500.json    ← earlier scan, never overwritten
  reports/
    security-report-2026-03-17T132421.html
    security-report-2026-03-17T091500.html
```

Each scan file contains: `scanId`, `scanDate`, `target`, `totalFiles`, `skipped`,
`findings`, `deepResults` (null if `--deep` not used), `hasDeep`.

## securityagent.yml

Template config file placed in the customer's repo root by `sc init`.
Controls: `trust_level`, `deep_delay_ms`, `ai_coding_tool`, `block_on_critical`,
`block_on_high`, `rule_overrides`, `exceptions`.

Key settings:
- `trust_level: maximum_privacy` – disables `--deep` entirely (no external API calls)
- `deep_delay_ms: 2000` – 2s pause between `--deep` API calls (prevents rate limiting)

Exceptions are never added as source code comments (security anti-pattern) –
always managed in this file via `scd approve`.

## Version system

- CLI version: `package.json` → `pkg.version` → read at runtime
- Rules version: `lib/rule-registry.js` → `RULES_VERSION` constant
- Both shown in `scd --version` and `scd version`
- Versions are independent – a CLI update doesn't require a rules version bump

## knownOptionFlags in scd scan

The `scd scan` command uses a manual `process.argv` parser (commander is unreliable
with variadic `[targets...]`). Any new option that takes a value must be added to
`knownOptionFlags` in `bin/scd.js` to prevent its value being
interpreted as a scan target:

```js
const knownOptionFlags = new Set([
  '--hook', '--lang', '--severity', '--rule', '--format', '--output', '--deep-delay'
]);
```
