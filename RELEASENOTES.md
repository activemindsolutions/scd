# scd – Release Notes

---

## v1.2.12 (2026-05-07)

This release introduces scope.yml — a dedicated mechanism for managing scan scope exclusions — along with two refactoring changes that improve code organisation.

**scope.yml — scan scope management.** Developers can now explicitly exclude files, directories, and security rules from scanning via `scope.yml`. Exclusions are security decisions, not operational config: every entry requires a documented reason, records who made it and when, and is prominently displayed in every scan that applies it. Nothing is silently skipped.

Three scope sources are merged in priority order: `~/.scd/scope.yml` (global, all repos), `~/.scd/repos/{id}/scope.yml` (per-repo), and `~/.scd/repos/{id}/scope-server.yml` (server-managed, delivered via heartbeat in a future release). The server source takes precedence when a server URL is configured; the server never touches global scope.

Exclusions are managed via `scd scope` (global) and `scd repo scope` (per-repo):

```
scd repo scope --add-file "tests/fixtures/" --reason "Test fixtures with intentional vulns"
scd repo scope --add-rule INFRA-001 --reason "Cloud-managed infrastructure"
scd repo scope --add-rule JS-ERR-002 --files "lib/rules/,**/*.test.js" --reason "Rule definition files"
scd repo scope --remove-file "tests/fixtures/" --reason "No longer needed"
scd repo scope --show
```

Every scan shows a `⚠ Active scope exclusions` block when exclusions are active, with pattern/rule, reason, added_by, and timestamp per entry. Exclusions are also logged to `audit.log` and stored in the scan JSON `exclusions` field.

**`lib/gitignore-filter.js` renamed to `lib/file-filter.js`.** The module's responsibility extends beyond git-specific filtering — it now also applies scope.yml file exclusions. The rename reflects the broader scope. `buildIgnoreFilter()` is unchanged.

**`getMachineFingerprint()` moved to `lib/store.js`.** The installation identity function now lives alongside other identity functions (`getRepoId()`, `getRepoIdentity()`) rather than inside the push-queue module where it happened to first be needed. Both `push-queue.js` and the new scope commands import it from `store.js`.

---

## v1.2.11 (2026-05-06)

This release completes the CLI refactoring by splitting `bin/scd.js` into individual command modules.

**`bin/scd.js` split into `lib/commands/`.** The 2223-line entry point has been broken into 20 focused command files under `lib/commands/`, each exporting a `register(program)` function. `bin/scd.js` is now 171 lines — a 92% reduction. Shared CLI utilities (`warnIfOutdated`, `openInBrowser`, `tryFlush`) have been extracted into `lib/cli-helpers.js`. This is a structural refactoring with no behaviour changes — verified with a golden output diff across all commands.

**No functional changes.** All commands work identically to v1.2.10. The `tests/integrity/files.json` manifest has been updated to reflect the new file layout.

---

## v1.2.10 (2026-05-06)

This release converts all security rule files from JavaScript modules to JSON, moves the rules directory to the repo root, and fixes two rule pattern regressions discovered during the conversion.

**All security rules are now JSON.** The eight rule files that define scd's 174 security rules have been converted from JavaScript modules to JSON. Patterns are stored as strings and compiled at load time by a new `rules/rule-loader.js` module. This makes rules inspectable without running code, enables future server-side rule distribution and custom rule packs, and prepares the ground for the plugin system planned post-release. The conversion was verified with a golden output diff — findings are identical before and after on a full scan.

**`rules/` moved to repo root.** The rules directory has moved from `lib/rules/` to `rules/` at the repository root. Rule files are JSON data, not library code, and placing them alongside `bin/` and `lib/` reflects that. This also matches the intended layout for future community and commercial rule packs.

**`lib/rule-registry.js` now exports `getRuleById()`.** A new function provides a single lookup point for compiled rule objects including pattern and antipattern strings. `lib/export-findings.js` (`scd review-rules`) uses this instead of importing rule files directly, removing the last direct dependency on the old JS rule module format.

**Two rule pattern fixes included in this release:**

*PY-INJ-006 — unparameterized query detection.* The pattern for detecting string concatenation into `cursor.execute()` calls was missing one variant. `cursor.execute("SELECT ... " + user_id)` (string before variable, no comma) was not matched. The pattern now correctly covers all three concat forms: `.format()`, string + variable, and variable + string.

*CS-SECRET-001 — hardcoded connection string detection.* During conversion, a backslash was inadvertently added to the negated character class used to match connection string content. This caused Windows-style connection strings containing `Server=HOST\\INSTANCE` to not be matched. The character class has been corrected to exclude only newlines, not backslashes.

---

## v1.2.9 (2026-05-05)

This release adds a canonical scan object schema as the first step of the pre-release refactoring plan.

**Scan object schema (`lib/scan-schema.js`).** A new module defines the canonical shape of a scan object and the list of required fields. `validateScan()` is called at write time in `scan-cache.js` and warns to the console if any required field is missing — it never throws. This provides a single reference point for the eight modules that read scan data, and makes it immediately visible if a future change to the scanner omits a field that other modules depend on. The `exclusions` field has also been added as a `null` placeholder for the upcoming `.scdignore` feature.

---

## v1.2.8 (2026-04-30)

This release fixes several bugs in the exception flow, improves `scd findings` with verbose output and single-finding lookup, adds a legal disclaimer, and translates all remaining Swedish strings to English.

**Exception flow fixed for standalone and server modes.** In standalone mode (no scd-server configured), exceptions created with `scd accept` or `scd ignore` are now approved immediately — the `pending` status only makes sense when a server is available for team-lead approval. Previously, standalone exceptions were marked as pending and the finding continued to appear in scan output.

**`scd findings` live exception update.** After running `scd accept` or `scd ignore`, the accepted finding now disappears from `scd findings` immediately — without requiring a new scan. Previously, the finding would remain visible until the next scan re-evaluated it.

**`scd findings <finding-id>`.** Show detailed information for a specific finding directly: `scd findings f-a1b2c3d4`. Displays the finding with full Problem, Scenario, and Fix sections. Also works for excepted findings — searching all findings regardless of status.

**`scd findings --verbose`.** Show Problem description, attack Scenario, and Fix guidance for all findings in the list. Useful for reviewing findings without opening a report.

**Exception hash matching fixed.** Exceptions created before v1.2.5 used a 16-character hash format, while newer exceptions use 32 characters. The exception matcher now accepts both formats, so old exceptions continue to work correctly after upgrading.

**Legal disclaimer.** `DISCLAIMER.md` has been added to the repository root, covering the scope and limitations of static analysis tooling and liability. A brief notice with a link to the full text is shown once during `scd install`.

**Translation.** All remaining Swedish strings in terminal output, prompts, and code comments have been translated to English.

---

## v1.2.7 (2026-04-30)

This release adds `scd uninstall`, makes `scd install` visible in help output, improves installation guidance, and adds a version warning when the CLI is outdated relative to the connected scd-server.

**`scd uninstall`.** A new command removes the global git hooks and clears the `core.hooksPath` git configuration from the machine. The `~/.scd/` store is intentionally preserved so scan history, exceptions, and audit logs are not lost.

**`scd install` now appears in `scd --help`.** The command was previously hidden from help output despite being a required step in the installation flow.

**`scd init` warns when `scd install` has not been run.** After initialising a repo, scd now checks whether global hooks are active and shows `scd install (not done yet)` in the Next steps list if they are not installed. This check works correctly even outside a git repository.

**Version warning when CLI is outdated.** When connected to scd-server, scd now warns if the local CLI version is below the server's minimum required version. The warning appears in `scd doctor` (always, via health check) and at the end of `scd scan`, `scd findings`, `scd sync`, and `scd exceptions` (from the second run onward, using a cached value). Hook scans write the warning to stderr so it does not interfere with git output. No warning is shown in standalone mode.

**`scd doctor` no longer leaks `fatal: not a git repository`.** Running `scd doctor` outside a git repository previously printed git's error message to the terminal before the scd output. This has been fixed.

---

## v1.2.6 (2026-04-29)

This release adds tech stack detection from project manifest files, enabling scd-server to track which languages, frameworks, and dependencies are in use across repos.

**Repo context from manifest files.** After each scan, scd reads the project's manifest files — `package.json`, `requirements.txt`, `pyproject.toml`, `composer.json`, and `.csproj` files — to extract the current tech stack. This includes detected languages, frameworks (Express, Django, Laravel, Flask, ASP.NET, etc.), the list of manifest files present, and all dependencies with their declared versions.

The context is stored locally in `~/.scd/repos/{id}/repo-context.json` and sent to scd-server as a `repo_context` event when the manifests have changed since the last scan. Re-scanning without changing dependencies does not trigger a new push, avoiding unnecessary events.

On scd-server (v0.10.2 or later), this data is stored as versioned snapshots and visible on the repo detail page and in the repository modal, showing a history of tech stack changes over time.

---

## v1.2.5 (2026-04-28)

This release overhauls exception management with finding IDs, introduces the `scd findings` command, and fixes several bugs in the exception and push-queue subsystems.

**Finding IDs.** Every finding now has a stable, deterministic ID (`f-a1b2c3d4`) derived from its content. For findings where source code is redacted (secrets rules), the ID is derived from rule ID, file path and line number instead. Finding IDs appear in `scd scan --verbose`, `scd findings`, HTML and JSON reports, `scd export-findings`, and `scd exceptions`. They are also sent to scd-server for future server-side reference.

**`scd accept` and `scd ignore` by finding ID.** Both commands now take a finding ID as their primary argument: `scd accept f-a1b2c3d4 --reason "..."`. This eliminates the previous error-prone `--rule --file --line` syntax that made it easy to create exceptions for the wrong finding. The commands look up the finding in the last scan cache and check for duplicates before creating an exception. `scd approve` has been removed — `scd accept` is the correct term for a developer accepting a risk, since approval by a team lead happens separately in scd-server.

**`scd findings` command.** Shows findings from the last scan without re-scanning. Default shows only open (unhandled) findings. Options:
- `--all` — include excepted and resolved findings
- `--excepted` — show only excepted findings
- `--severity <level>` — filter by severity
- `--rule <id>` — filter by rule ID
- `--scan <id>` — load a specific historic scan

Each finding shows its ID for direct use with `scd accept` and `scd ignore`.

**Push-queue stale logic fixed.** Network errors and HTTP 503 responses (server temporarily down) no longer increment the attempts counter. Events now stay in the queue until the server comes back online, or until they are 30 days old. Previously, 10 failed attempts in quick succession would permanently mark events as stale, causing exception requests to disappear silently when the server was briefly unavailable.

**Exception matching bug fixed.** Exceptions created for secrets findings (where source code is redacted) previously never matched because `line_hash` could not be verified against an empty `lineRaw`. scd now falls back to matching on rule ID, file and line number when line content is unavailable. The `line_hash` field is also no longer written to config for these findings, preventing future mismatches.

---

## v1.2.4 (2026-04-28)

This release fixes misleading output when excepted findings are present in a scan.

**Excepted CRITICAL and HIGH findings now shown explicitly.** Previously, excepted findings were only counted in the `✓ N finding(s) excepted` line — invisible to the developer. If a CRITICAL finding was excepted, it disappeared from the summary without any indication of what was excepted or why. scd now lists each excepted CRITICAL or HIGH finding below the excepted count, with severity icon, rule ID, file path and exception type.

**Status message now reflects actual blocking severity.** The message `⚠️ Critical vulnerabilities found` was shown even when only HIGH findings were blocking. The message is now precise: `Critical vulnerabilities found` for CRITICAL, `High-severity vulnerabilities found` for HIGH. Expired exceptions show a separate yellow warning instead of reusing the red critical message.

**HTML report stat cards exclude excepted findings.** The Critical and High counts in the report header previously included excepted findings, causing the report to show a non-zero Critical count even when all critical findings were approved exceptions.

---

## v1.2.3 (2026-04-28)

This release makes scd respect `.gitignore` when discovering files for scanning, dramatically improving scan performance on repos with large log files, build artifacts, or generated output.

**`.gitignore` respected by default.** scd now excludes files and directories that git ignores from manual scans. A repo with a large log file or database in its working directory previously caused thousands of spurious findings and multi-minute scan times. With this change, only files that git would track are scanned by default.

The filter uses two strategies depending on environment: if git is available, `git ls-files --ignored` is used for exact behaviour. If git is not available (e.g. a repo downloaded without `git clone`), scd parses `.gitignore` files manually, including nested `.gitignore` files, negation patterns, anchored patterns, and `**` globs.

Use `scd scan --include-ignored` to scan all files regardless of `.gitignore`.

---

## v1.2.2 (2026-04-27)

This release detects and warns when scanning from a repo that overlaps with another scd repository.

**Overlapping repo detection.** Running `scd scan` from a directory that is a parent or child of another known scd repo now triggers a warning before the scan starts. The warning describes the overlap (parent or child), explains that findings may be duplicated, and offers three choices: continue anyway, scan without logging, or cancel. In hook mode (pre-commit/pre-push), where interactive prompts are not possible, scd warns to the terminal and continues automatically — hooks must never block a commit silently.

The detection reads `localPath` from all known repos in `~/.scd/repos/` and compares path hierarchies. Both manual scans and git hooks are covered.

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
