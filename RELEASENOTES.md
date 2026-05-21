# scd – Release Notes

## v1.4.0 (2026-05-20)

This release delivers a major reduction in false positives through targeted rule redesigns, new rules, and structural improvements to how the scanner handles file types. The result is a 78.5% total reduction in findings versus the v1.2.16 baseline across 88 representative repositories — down from 14,801 to 3,181.

**Rule redesigns.** Seven rules were redesigned or replaced. The approach in every case was the same: replace broad, easily-triggered patterns with narrower, structurally-grounded ones. A rule that requires two or three antipatterns to be usable is a sign that the pattern itself is wrong — this release resets several such rules from scratch.

**JS-ERR-002 split into three focused rules.** The original rule triggered on any `console.log` call that contained a sensitive-sounding word anywhere on the line — including in static strings, variable names unrelated to secrets, and log messages about authentication flows. 554 findings; 63% were static strings with no variable interpolation at all. The rule is replaced by three precise variants:

- **JS-ERR-002** — `req.body`, `req.headers`, or `req.cookies` passed as a direct argument to a console method. Not a property access — `req.body.field` does not trigger. Severity HIGH, confidence HIGH.
- **JS-ERR-002B** — `process.env.VARNAME` (all-caps, at least three characters) interpolated or passed to a console method. Known non-sensitive variables (`NODE_ENV`, `PORT`, `HOST`, `LOG_LEVEL`, `APP_ENV`, `DEBUG`, `TZ`) excluded via inline negative lookahead in the pattern rather than in antipatterns — prevents the antipattern window from accidentally matching across line boundaries. Severity HIGH, confidence HIGH.
- **JS-ERR-002C** — Console calls containing variable names that suggest sensitive data (`authToken`, `privateKey`, `secret`, `credentials`, etc.). Explicitly MEDIUM confidence — a best-effort semantic rule, not a structural one. No exhaustive variable name list is maintained; this is an intentional design boundary.

**INFRA-001 and INFRA-002 precision overhaul.** These rules previously matched any occurrence of `localhost` or `127.0.0.1` across all file types, producing thousands of false positives in infrastructure config files, documentation, and SSRF guard code. Both rules were redesigned as targeted triples:

- **INFRA-001 / INFRA-002** — `http(s)://localhost` or `127.0.0.1` URL patterns in frontend code (`.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.vue`, `.svelte`, `.html`). Severity EXPOSURE.
- **INFRA-001B / INFRA-002B** — `localhost` or `127.0.0.1` in committed config files (`.ini`, `.conf`, `.toml`, `.env`, `.php` config — YAML/YML excluded pending a config-context classification step in a future release). Severity EXPOSURE.
- **INFRA-001C / INFRA-002C** — `http(s)://localhost` or `127.0.0.1` in JSON files. Severity LOW — JSON context is structurally different; many legitimate configs contain these values.

INFRA-021 (non-public TLD) received a regex fix: the TLD terminator is now required to be at the end of the hostname, preventing matches inside longer strings where `.local` or `.internal` appears as a substring.

**YAML-001 antipattern expansion.** The OpenAPI and schema document patterns that caused the most false positives — type names, property declarations, and `$ref` paths — are now covered by antipatterns. Approximately 282 of the remaining findings are in Kong/OpenAPI files and will be resolved automatically when config-context file classification is introduced in a future release.

**JSON-001 antipattern expansion.** Values that are clearly not secrets — readable text with spaces, placeholder strings (`<Your API Key>`, `{{env.SECRET}}`), all-caps variable-name placeholders (`YOUR_API_KEY`), and short alphabetic-only strings — are now excluded. A lookbehind-based antipattern suppresses Home Assistant i18n reference files (`[%key:...]` format) without introducing a framework-specific rule.

**LOG-004 file type restriction.** Email address detection in log files now applies only to `.log` files. `.txt` files were producing false positives across documentation, AI prompt files, IBAN reference tables, and ad-block filter lists. `.txt` coverage will be restored when data-context file classification (distinguishing list-data from prose) is available.

**EXPOSURE-001 (new rule).** Detects exported email address lists in CSV files. Email addresses are personal data subject to GDPR; a committed CSV file containing them is an exposure risk regardless of intent. File type: `.csv` only. `.txt` support deferred to a future release pending data-context classification.

**AUTH-001 antipatterns.** Routes that are intentionally public by design no longer trigger this rule: health and infrastructure endpoints (`/health`, `/healthz`, `/ping`, `/status`, `/metrics`, `/readiness`, `/liveness`), authentication flow endpoints (`/auth/*`, `/login`, `/logout`, `/oauth/*`, `/sso/*`, `/token`, `/callback`, `/register`, `/signup`, `/forgot-password`, `/reset-password`), root GET handlers (`app.get('/')`), API documentation endpoints (`/swagger*`, `/openapi`, `/api-docs`, `/redoc`), well-known endpoints (`/.well-known/`), static assets and GET routes serving known static file extensions (`.png`, `.jpg`, `.ico`, `.svg`, `.css`, etc.). A `lookahead: 200` setting restricts the antipattern window to a single line, preventing the antipattern from inadvertently matching content from adjacent lines in the file.

**Rule count: 189** (up from 184). Severity distribution: CRITICAL 69, HIGH 76, MEDIUM 10, EXPOSURE 32, LOW 2.

**Measured impact.** On 88 representative repositories versus prior versions:

| Snapshot | Change | Findings | vs v1.2.16 |
|---|---|---|---|
| v1.2.16 | baseline | 14,801 | — |
| v1.3.0 | file context + severity modifiers | 10,317 | −30.3% |
| v1.3.1 | scan-context architecture + hash fix | 7,401 | −50.0% |
| **v1.4.0** | **rule redesigns + targeted antipatterns** | **3,181** | **−78.5%** |

The false positive reduction is structural — no legitimate CRITICAL or HIGH findings on production source files were suppressed. The rules that remain are either genuine vulnerability patterns or explicitly lower-confidence rules (MEDIUM) where the signal is worth showing but the confidence is limited.

**Snippet redaction removed.** The pre-commit hook scanner (`scanner-secrets.js`) previously replaced the triggering line with `[REDACTED]` before storing the finding. This has been removed. scd CLI and scd-server are designed to run in the customer's own infrastructure — the snippet stays on the same machine as the source file it came from, and treating that machine as untrusted is inconsistent with the product's architecture. More concretely, redaction breaks `--deep` AI analysis: the AI cannot assess whether a finding is a true or false positive when the evidence has been removed. A proper presentation-layer redaction (storing the original, redacting dynamically at render time with configurable levels) is planned as a future feature. Until then, snippets are stored as-is.

**Lookahead window behaviour documented.** Rule antipatterns are tested against a content window (default: 120 characters lookbehind, 300 characters lookahead from the match position). This window can span multiple lines. Rules that use antipatterns sensitive to line boundaries now carry explicit `lookahead` values to prevent cross-line contamination. Rule authors should be aware of this behaviour when designing antipatterns that match structural patterns (quotes, parentheses, colons) rather than keywords.

---

## v1.3.1 (2026-05-15)

This release overhauls how scd decides which files to scan — moving from post-scan severity compensation to pre-scan file routing. The result is a structurally sounder false positive reduction and a 50% total reduction in findings versus the v1.2.16 baseline across 88 representative repositories.

**The problem with the previous approach.** v1.3.0 introduced file context classification and severity modifiers — a meaningful improvement, but architecturally limited. Modifiers ran *after* rules had already fired. A test file could be correctly identified as a test file, but if a SECRET-005 rule produced a HIGH finding, the modifier reduced it to MEDIUM — still above the suppress threshold. The file context was known, but too late to act on it cleanly.

**Pre-scan file manifest.** A new module (`lib/file-manifest.js`) classifies every file in the scan queue into a scan context *before* any rule runs. Three contexts are defined:

- **source** — production code, scanned with the full rule set
- **test** — test and fixture files, routed to a separate rule set (currently a defined stub; test-specific rules will be introduced in a future release)
- **excluded** — vendor and generated files, not scanned, documented in scan output

Classification uses `lib/file-context.js` internally with two-layer detection (path/filename signals confirmed by content). The conservative principle applies: when classification is uncertain, the file is treated as source. A file in `/tests/` without any recognisable test framework import is treated as source, not test — intentional, because misclassifying production code as test is a worse error than the reverse.

A `fileContexts` map is built once per scan and shared across all scanner passes, including the secrets scanner. This prevents a class of mismatch bugs where different passes reached different classification conclusions for the same file.

**Scan context summary in terminal output.** Before scanning begins, scd shows a one-line manifest summary:

```
  312 source · 47 test (separate context) · 12 excluded (vendor/generated)
```

This appears early — before analysis starts — consistent with the principle that important information must never be deferred.

**Strong filename classification.** Files with unambiguous test naming conventions (`.test.js`, `.spec.ts`, `test_*.py`, `_test.go`) that also reside in a recognised test path (`/tests/`, `/spec/`, `/__tests__/` etc.) are classified as test definitively, without requiring content confirmation. Files matching the naming pattern but located outside test paths remain tentative and require content confirmation — a file named `kunddata.test.js` in `/src/models/` is treated as source unless its content confirms test framework usage.

**bun:test framework detection.** `from 'bun:test'` and `require('bun:test')` added to `FRAMEWORK_CONTENT_SIGNALS`. Bun's test runner is now recognised as a definitive content signal alongside Jest, Vitest, Pytest, node:test, and 10 other frameworks.

**Internal finding trace (`_trace`).** Every finding now carries an internal `_trace` object recording the full classification pipeline: manifest context, file type, signals, each modifier with its delta and reason, comment line type, effective score, and suppress decision. The trace is written to all scan JSON files but never shown in terminal output or reports. Enable with `SCAN_TRACE=true` in `~/.scd/config` (not exposed via `scd configure` — internal analysis tool).

**Finding ID collision fix.** Finding IDs are now computed from `ruleId + filePath + matched line content` rather than `ruleId + matched line content` alone. The previous algorithm produced identical IDs for different findings in different files when the matched line content was identical — a common occurrence with build artefacts (`.js` and `.cjs` variants of the same source file). IDs are now 10 hex characters (40 bits). **Breaking change:** existing finding IDs in `.scd/` (exceptions, resolved findings) will not match findings from new scans. Exceptions will need to be re-approved after upgrading.

**Measured impact.** On 88 representative repositories versus v1.2.16 baseline:

| Snapshot | Change | Findings | vs baseline |
|---|---|---|---|
| v1.2.16 | baseline | 14,801 | — |
| v1.3.0 | file context + severity modifiers | 10,317 | −30.3% |
| v1.3.1 | scan-context architecture + hash fix | 7,401 | −50.0% |

The 50% reduction reflects genuine false positive elimination — no CRITICAL or HIGH findings on production source files were suppressed as a result of these changes.

---

## v1.3.0 (2026-05-15)

This release introduces file context awareness — a new intelligence layer that classifies files before security rules are applied and adjusts finding severity based on context. The result is a significant reduction in false positives without changing a single rule pattern.

**The problem.** scd's rules are strong at pattern detection but context-blind. A hardcoded password in a test fixture and a hardcoded password in production code are both flagged at the same severity — even though their risk profiles are fundamentally different. On a representative set of 88 real-world repositories, this caused disproportionate noise from test files, generated code, and vendor dependencies.

**File context classification.** A new module (`lib/file-context.js`) classifies every file before any rule runs. Classification uses two layers. Layer 1 reads path and filename signals: vendor directories, generated output (`/dist/`, `/build/`, `/gen/`), test paths (`/tests/`, `/spec/`, `/__tests__/`), and test filename patterns (`*.test.js`, `*_test.py`). Layer 2 reads the first 50 lines of content to confirm tentative classifications — a file named `vulnerable-test.js` that contains no test framework code is classified as source, not test. Vendor and generated files are classified definitively from path alone; all other test and fixture classifications require content confirmation.

Test framework detection covers: Jest, Vitest, Mocha, Pytest, PHPUnit (including indirect inheritance via `use PHPUnit\` and `namespace \Test\` patterns), and RSpec.

**Severity modifiers.** A new module (`lib/context-modifiers.js`) applies cumulative severity modifiers based on classification. Modifiers are additive: a Jest test in a `/fixtures/` path accumulates both the test modifier and the fixture path modifier. Config files receive a modifier of zero — a `.env` file with a real secret is still a real finding regardless of context. The suppress threshold is fixed at zero: any finding whose effective score falls to zero or below is flagged suppressed rather than deleted.

**No silent suppression.** Every finding is created. Suppressed findings live in a separate `suppressed_findings[]` key in scan JSON and are always accessible. This preserves a complete audit trail, which is relevant for CRA Article 13 and NIS2 Article 21 evidence requirements.

**CLI output.** When suppressions exist, `scd scan` shows a summary line after the findings list:

```
  10 finding(s) suppressed by file context  ·  scd findings --show-suppressed
```

`scd findings --show-suppressed` lists suppressed findings with full detail: base severity, effective score, file context classification, each modifier with its value, and suppress reason. Normal findings output now shows a severity downgrade indicator (`↓ HIGH → MEDIUM`) when context modifiers reduced but did not suppress a finding.

**Suppressed findings are persisted.** Scan cache (`last-scan.json`) includes `suppressed_findings` so `scd findings --show-suppressed` works across sessions without re-scanning.

**Measured impact.** On 88 representative repositories:

| Metric | Before | After | Change |
|---|---|---|---|
| Total findings | 14,801 | 10,317 | −4,484 (−30.3%) |
| INFRA family | 7,878 | 4,407 | −3,471 (−44.1%) |
| INFRA-002 (127.0.0.1) | 1,570 | 687 | −56% |
| INFRA-012 (192.168.x.x) | 558 | 55 | −90% |
| TS-TYPE-001 (as any) | 463 | 123 | −73% |
| INFRA-030 (DB port) | 82 | 4 | −95% |

No unexpected reductions in CRITICAL or HIGH findings on production source files were observed.

---

## v1.2.16 (2026-05-13)

Maintenance release. Rule improvements and bug fixes.

---

## v1.2.15 – v1.2.2

See git history for incremental rule additions and bug fixes.

---

## v1.2.1 (2026-04-27)

This release fixes a long-standing bug where scanning a file outside the current repo would contaminate the wrong repo with findings, or silently create a spurious repo entry.

**Scan context resolved from target, not CWD.** Previously, `scd scan` always used the current working directory as the repo context, regardless of where the scan target was. Scanning a file in another repo (`scd scan ~/other-project/file.js`) would log findings under the wrong repo. Running `scd scan` from the home directory would create a new repo entry named after the user's home folder.

scd now determines the correct context from the scan target itself. Four cases are handled:

- **Target inside CWD repo** — no change, normal flow.
- **Target in a different git repo** — prompts with four choices: log to target repo (recommended), log to CWD repo, scan without logging, or cancel.
- **Targets span multiple repos** — warns and uses CWD if available.
- **Target outside all git repos** — prompts: scan without logging, log to CWD repo, or cancel.

`--no-audit` and `--no-sync` skip the context check entirely — the user has already opted out of logging. When `skipLogging` is active, a notice is shown in the scan header.

---

## v1.2.0 (2026-04-17)

This release adds per-repo hook management with full audit trail, and fixes the browser-open bug on Windows.

**`scd repo hooks`** enables per-repo control of git hooks with a mandatory audit trail. `scd repo hooks --disable --reason "<text>"` sets `core.hooksPath /dev/null` locally so hooks stop triggering for that repo without affecting other repos on the machine. `scd repo hooks --enable` re-enables them. The reason is required — bypasses are intentional and must be visible. All actions are logged to audit.log and, when scd-server is configured, pushed to the server where team leads can see them in the dashboard. `scd remove` now automatically disables hooks for the removed repo.

**`scd hooks`** provides a global overview of hook status across all registered repos, showing whether each repo is enabled (green), disabled (yellow), or has a broken global config (red). Repos that no longer exist on disk or are not git repositories are silently skipped. Removed repos are excluded.

**`scd doctor` hook diagnostics.** scd doctor now detects and reports three hook failure modes: global `core.hooksPath` pointing to `/dev/null` (disables all repos on the machine), global pointing to an unexpected directory, and per-repo hooks disabled via `scd repo hooks`. Each case includes the exact git command to fix it.

**Windows `--open` and `--serve` bug fixed.** `scd report --open` and `scd report --serve` were opening a new terminal window instead of the browser on Windows. The root cause was `execSync('start "url"')` treating the quoted argument as a window title. Replaced with a shared `openInBrowser()` helper using `spawn('cmd', ['/c', 'start', '', target])` with detached mode — correct on all platforms.

---

## v1.1.0 (2026-04-14)

This release introduces per-repo configuration via CLI, global repo defaults, and renames `scd store` to `scd repo`.

**Per-repo configuration** can now be managed directly from the command line without editing config files manually. `scd repo configure` shows the current effective configuration for the repo you're standing in, with each setting's source clearly indicated — whether it comes from the repo's own `config.yml`, a global user default, or the built-in default. Use `scd repo configure --scan-mode fast`, `--trust-level maximum_privacy`, `--block-on-high false`, or `--block-on-critical false` to update settings in place.

**Global repo defaults** let you set a user-level fallback that applies to all repos unless overridden. Run `scd configure --scan-mode fast` (or `--trust-level`, `--block-on-high`, `--block-on-critical`) to set a global default stored in `~/.scd/config`. The priority order is: `repo config.yml` → `global defaults` → `built-in defaults`. `scd configure --show` now displays both server configuration and global repo defaults in one view.

**`scd store` has been renamed to `scd repo`** — a more intuitive name that reflects what the command is actually about. All existing flags (`--scans`, `--show`, `--verify`, `--verify --clean`, `--reports`, `--open`, `--path`) work exactly as before under the new name.

**`scan_mode` recorded in audit log and synced to scd-server.** The scan mode (`full` or `fast`) is now included in `audit.log` on the developer's machine and in the push-queue payload sent to scd-server. This allows scd-server to distinguish between full scans (with taint analysis) and fast scans, and display the information in the findings view and scan detail.

**`scd init`** now generates a `config.yml` with all active settings documented, including `scan_mode`. The unused fields `ai_coding_tool` and `report_all` have been removed from both the template and the codebase. `securityagent.yml` has also been removed — it was never read by the CLI.

---

## v1.0.1 (2026-03-XX)

Maintenance release with configurable timeouts and scanner improvements.

**Configurable timeouts.** `scd configure --server-timeout <value>` and `scd configure --deep-timeout <value>` allow customising API call timeouts. Accepts human-readable values (`15s`, `5m`, `20m`) or raw milliseconds. Defaults: 30s for server calls, 20m for deep analysis.

**Scanner excludeFileTypes.** Rules can now specify file extensions to exclude. Applied to infrastructure leakage rules to avoid false positives in documentation and configuration files.

**Scan ID format.** Scan IDs are now `s-XXXXXXXX` (random 8 hex chars) — timezone-neutral and used as `session_id` on scd-server for full CLI↔server traceability.

---

## v1.0.0 (2026-03-XX)

First stable release.

**174 security rules** across JavaScript, TypeScript, Python, PHP, and ASP.NET (markup + C#). Covers all OWASP Top 10 categories. Severity distribution: 63 CRITICAL, 71 HIGH, 10 MEDIUM, 30 EXPOSURE.

**Taint analysis** for PHP, Python, and JavaScript/TypeScript — tracks user-controlled variables from HTTP input through assignments to dangerous sinks. Six taint-aware rules across Python and JS/TS.

**Git hooks** installed via `scd init`. Pre-commit runs secrets scan, pre-push runs full OWASP scan. Zero repo footprint — no files written to the repository.

**Exception management.** Approved and ignored findings tracked in `config.yml` with hash-based change detection. Exception sync with scd-server for team workflows.

**Reports.** HTML, Markdown, and JSON reports with fix guidance per finding. Per-scan storage with unique scan IDs — regenerate reports from any historical scan.

**scd-server integration.** Push queue for offline-first event sync. Deep analysis via `scd scan --deep`. Exception approval flow with team leads via scd-server.

**`scd doctor`.** Verifies installation, hook status, push queue health, and server connectivity.
