# scd – Release Notes

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
