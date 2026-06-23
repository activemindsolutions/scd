'use strict';
const { RESET, DIM, RED, YELLOW, GREEN, CYAN } = require('../output-constants');
// lib/commands/scan.js

// Build the "added: X, refreshed: Y[, resolved: Z][, reopened: W]" tail.
// resolved/reopened segments are omitted when zero so the common case stays unchanged.
function formatStatsTail(r) {
  const parts = [`added: ${r.added}`, `refreshed: ${r.refreshed}`];
  if (r.resolved > 0) parts.push(`resolved: ${r.resolved}`);
  if (r.reopened > 0) parts.push(`reopened: ${r.reopened}`);
  return parts.join(', ');
}

module.exports = { register };

function register(program) {
  const pkg = require('../../package.json');

  program
    .command('scan [targets...]')
    .description('Run security scan – hook mode (automatic) or manual')
    .option('--hook <type>', 'Hook mode: pre-commit or pre-push (run by git hooks)')
    .option('--lang <lang>', 'Limit to language: js, ts, py, php ...')
    .option('--severity <level>', 'Show only: CRITICAL, HIGH, EXPOSURE ...')
    .option('--rule <id>', 'Show only specific rule: INJ-001, JWT-001 ...')
    .option('--format <fmt>', 'Output format: terminal (default), html, json', 'terminal')
    .option('--output <file>', 'Save report to file (used with --format html/json)')
    .option('--no-limit', 'Scan files above size limit (30s timeout/file – may be slow)')
    .option('--deep',           'Enable Claude API deep analysis of CRITICAL/HIGH findings')
    .option('--deep-delay <ms>', 'Delay in ms between --deep API calls (overrides config deep_delay_ms)')
    .option('--no-audit',        'Skip audit logging for this scan')
    .option('--no-sync',         'Skip push to scd-server for this scan (audit log kept locally)')
    .option('--include-vendor',  'Include vendor/dependency code in scan (node_modules, site-packages, vendor/ etc.)')
    .option('--vendor-only',     'Scan only vendor/dependency code (supply chain audit)')
    .option('--include-ignored',  'Scan files ignored by .gitignore (default: respect .gitignore)')
    .option('--exclude <pattern>',      'Exclude a file/directory for this scan only (repeatable, not saved)', (v, a) => [...a, v], [])
    .option('--exclude-rule <ruleId>',  'Exclude a rule for this scan only (repeatable, not saved)', (v, a) => [...a, v], [])
    .option('--log-to <mode>',   'Logging mode for non-interactive use: none, current, target (default: prompt if TTY, none if not)')
    .option('--verbose',           'Show full file-grouped and rule-grouped output (default: compact summary)')
    .option('--max-findings <n>', 'Show and analyse top N findings (sorted by severity). Does not affect scan coverage, audit log, or cache.')
    .action(async (targets, opts) => {
      const { scanSecrets } = require('../scanner-secrets');
      const { scanFull }    = require('../scanner-full');
      const { formatTerminal } = require('../output-terminal');
      const { getChangedFiles } = require('../git-utils');
      const { loadConfig, getRepoRoot } = require('../config');
      const { resolveTargetContext, checkRepoOverlap } = require('../scan-context');
      const { logScan } = require('../audit');
      const { saveCache, loadCache, cacheAge, makeScanId } = require('../scan-cache');
      const { warnIfOutdated, tryFlush } = require('../cli-helpers');

      const cwdRepoRoot = getRepoRoot();  // provisional — may be overridden by target context
      let   repoRoot    = cwdRepoRoot;
      let   skipLogging = false;
      const config      = loadConfig(repoRoot);

      // Validate vendor flags
      if (opts.includeVendor && opts.vendorOnly) {
        console.error(RED + '✗ --include-vendor and --vendor-only cannot be used together' + RESET);
        process.exit(1);
      }

      let maxFindings = null;
      if (opts.maxFindings !== undefined) {
        maxFindings = parseInt(opts.maxFindings, 10);
        if (isNaN(maxFindings) || maxFindings < 1) {
          console.error(RED + '✗ --max-findings must be a positive integer' + RESET);
          process.exit(1);
        }
      }

      // ── Hook mode (called by git pre-commit/pre-push) ──────────────────
      if (opts.hook) {
        // Check for overlapping repos — warn but don't block (hooks are non-interactive)
        if (repoRoot) await checkRepoOverlap(repoRoot, { interactive: false });

        // Hook mode: git-tracked changed files only — vendor code never appears here
        const files = await getChangedFiles(opts.hook);
        if (files.length === 0) {
          console.log(DIM + '[scd] No files to scan.' + RESET);
          process.exit(0);
        }

        console.log(`\n${CYAN}╔══════════════════════════════════════════╗${RESET}`);
        const _vt = 'Secure Code by Design v' + pkg.version;
        const _pl = Math.floor((42 - _vt.length) / 2);
        const _pr = 42 - _vt.length - _pl;
        console.log(`${CYAN}║${ ' '.repeat(_pl)}${_vt}${ ' '.repeat(_pr)}║${RESET}`);
        console.log(`${CYAN}╚══════════════════════════════════════════╝${RESET}`);
        console.log(`${DIM} Scanning ${files.length} file(s) – hook: ${opts.hook}${RESET}\n`);

        const scopeExclusions = null; // Hook mode: scope not applied (changed files only)
        // Source the exception list from the machine-local store (Run 2 read-truth);
        // bootstrap-on-read migrates config.yml → exceptions.jsonl on first read.
        // Fires once per command — both scanners reuse config.exceptions.
        config.exceptions = require('../exceptions-store').loadExceptionsWithBootstrap(repoRoot).records;
        const findings = opts.hook === 'pre-commit'
          ? await scanSecrets(files, config)
          : await scanFull(files, config, null);

        const suppressedFindings = findings._suppressedFindings || [];

        const blocked = findings.some(f => f.blocks && !f.excepted);
        const scanId = makeScanId();

        logScan(repoRoot, {
          hookType: opts.hook, files, findings, blocked,
          exceptions_applied: findings.filter(f => f.excepted).length,
          scanId,
          noSync:   opts.sync === false,
          scanMode: config.scan_mode || 'full',
        });

        // Update accumulated findings store (paired with audit.log).
        // Same scanId so store rows can be cross-referenced with the scan file.
        // Step 2: pass coverage + suppressed so resolve/reopen reconciliation runs.
        // Hooks do NOT load scope today (scan.js calls scanFull(files, config, null)
        // above), so scope: null — the rule-exclude guard is a no-op in hook mode.
        const { updateFindings } = require('../findings-store');
        const storeResult = updateFindings(repoRoot, findings, {
          scanId,
          coverage:   findings._coverage,
          suppressed: suppressedFindings,
          scope:      null,
        });

        // Emit resolve/reopen events to audit.log + push queue (if any).
        if (storeResult.resolved > 0 || storeResult.reopened > 0) {
          const { logReconcile } = require('../audit');
          logReconcile(repoRoot, {
            scanId,
            resolved: storeResult.resolvedRecords,
            reopened: storeResult.reopenedRecords,
            hookType: opts.hook,
            noSync:   opts.sync === false,
          });
        }

        // E1c.2: auto-archive exceptions whose finding was resolved by evidence.
        if (storeResult.resolved > 0) {
          require('../exception-manager').archiveResolvedExceptions(repoRoot, storeResult.resolvedRecords);
        }
        // E1c.3: auto-archive expired exceptions (review_expired) — time-based, so
        // it runs every scan regardless of resolve activity.
        require('../exception-manager').archiveExpiredExceptions(repoRoot);

        const { output, exitCode } = formatTerminal(findings, opts.hook, config, { verbose: opts.verbose, scopeExclusions });
        console.log(output);

        // Suppressed findings summary (hook mode — shown before exit)
        if (suppressedFindings.length > 0) {
          console.log(`${DIM}  ${suppressedFindings.length} finding(s) suppressed by file context  ·  scd findings --show-suppressed${RESET}\n`);
        }

        // Findings store summary
        console.log(`${DIM}  Open issues: ${storeResult.totalOpen} (${formatStatsTail(storeResult)})${RESET}`);

        if (opts.sync !== false) await tryFlush(opts);
        warnIfOutdated({ toStderr: true });
        process.exit(exitCode);
      }

      // ── Manual mode ───────────────────────────────────────────────────
      const { discoverFiles, filterFindings } = require('../scanner-manual');

      // Commander with variadic [targets...] is unreliable across versions —
      // it sometimes drops the last argument. Read process.argv directly instead.
      //
      // Strategy: find the last occurrence of 'scan' in argv (avoids matching
      // 'scan' in the script path), then collect everything after it that is
      // not an option flag (-x / --x) and not the VALUE of a known option flag.
      const knownOptionFlags = new Set([
        '--hook', '--lang', '--severity', '--rule', '--format', '--output', '--exclude', '--exclude-rule', '--log-to', '--max-findings'
      ]);
      const allArgv   = process.argv;
      let   scanIdx   = -1;
      for (let i = allArgv.length - 1; i >= 0; i--) {
        if (allArgv[i] === 'scan') { scanIdx = i; break; }
      }
      const rawTargets = [];
      if (scanIdx !== -1) {
        let skipNext = false;
        for (let i = scanIdx + 1; i < allArgv.length; i++) {
          const a = allArgv[i];
          if (skipNext)           { skipNext = false; continue; }
          if (knownOptionFlags.has(a)) { skipNext = true; continue; }  // skip flag + its value
          if (a.startsWith('-'))  { continue; }                         // boolean flags
          rawTargets.push(a);
        }
      }
      const targetList = rawTargets.length > 0 ? rawTargets : ['.'];
      const scanTarget = targetList.length === 1 ? targetList[0] : targetList.join(', ');

      // ── Resolve repo context from target, not just CWD ──────────────────
      // Prevents contaminating the wrong repo when scanning files outside CWD.
      // --no-audit and --no-sync bypass this check (user explicitly opted out of logging).
      if (!opts.noAudit && !opts.noSync) {
        const ctx = await resolveTargetContext(targetList, cwdRepoRoot, { logTo: opts.logTo });
        if (ctx.cancelled) {
          console.log(DIM + '  Scan cancelled.' + RESET + '\n');
          process.exit(0);
        }
        repoRoot    = ctx.repoRoot    || cwdRepoRoot;
        skipLogging = ctx.skipLogging;
      }
      // ── Check for overlapping scd repos ────────────────────────────────
      if (!skipLogging && repoRoot) {
        const overlap = await checkRepoOverlap(repoRoot, { interactive: true });
        if (overlap.cancelled) {
          console.log(DIM + '  Scan cancelled.' + RESET + '\n');
          process.exit(0);
        }
        if (overlap.skipLogging) skipLogging = true;
      }
      // ────────────────────────────────────────────────────────────────────

      // Propagate skipLogging into opts so tryFlush is also suppressed
      if (skipLogging) opts = { ...opts, noSync: true, noAudit: true };
      // ─────────────────────────────────────────────────────────────────────

      // Show discovering status — discoverFiles reads all files from disk which can take a moment
      process.stderr.write('\r' + DIM + ' Discovering files…' + RESET);

      let files = [], skipped = [], scopeExclusions = null, scope = null;
      try {
        if (targetList.length === 1) {
          ({ files, skipped, scopeExclusions, scope } = discoverFiles(targetList[0], { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly, includeIgnored: !!opts.includeIgnored, repoRoot }));
        } else {
          // Multiple targets (shell glob expansion): merge results, deduplicate by filePath
          const seen = new Set();
          for (const t of targetList) {
            try {
              const result = discoverFiles(t, { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly, includeIgnored: !!opts.includeIgnored, repoRoot });
              for (const f of result.files)   { if (!seen.has(f.filePath)) { seen.add(f.filePath); files.push(f); } }
              for (const s of result.skipped) { skipped.push(s); }
              if (!scopeExclusions && result.scopeExclusions) { scopeExclusions = result.scopeExclusions; scope = result.scope; }
            } catch { /* skip targets that don't resolve */ }
          }
          if (files.length === 0) throw new Error(`No files to scan: ${scanTarget}`);
        }
      } catch (err) {
        console.error(`\n${RED}✗ ${err.message}${RESET}\n`);
        process.exit(1);
      }

      // Header
      if (opts.noLimit) {
        console.log(`\n${YELLOW}⚠  --no-limit active – size limit disabled.${RESET}`);
        console.log(`${DIM}   Large files (>512KB) scanned with 30s timeout per file. May be slow.${RESET}`);
      }
      process.stderr.write('\r\x1b[K'); // clear discovering status
      const langLabel     = opts.lang ? ` [${opts.lang}]` : '';
      const vendorLabel   = opts.vendorOnly ? ' ' + YELLOW + '[vendor-only]' + RESET : opts.includeVendor ? ' ' + YELLOW + '[+vendor]' + RESET : '';
      const ignoredLabel  = opts.includeIgnored ? ' ' + YELLOW + '[+ignored]' + RESET : '';
      console.log(`\n${CYAN}╔══════════════════════════════════════════╗${RESET}`);
      const _vt2 = 'Secure Code by Design v' + pkg.version;
      const _pl2 = Math.floor((42 - _vt2.length) / 2);
      const _pr2 = 42 - _vt2.length - _pl2;
      console.log(`${CYAN}║${ ' '.repeat(_pl2)}${_vt2}${ ' '.repeat(_pr2)}║${RESET}`);
      console.log(`${CYAN}╚══════════════════════════════════════════╝${RESET}`);
      console.log(`${DIM} Manual scan${langLabel}${vendorLabel}${ignoredLabel}: ${scanTarget}${RESET}`);
      // For single-file and glob scans, scope is not loaded by discoverFiles.
      // Load it here and filter out any files excluded by scope.
      if (!scope && repoRoot) {
        try {
          const { loadScope, isFileExcluded, validateScope, summariseScope } = require('../scope');
          const path = require('path');
          scope = loadScope(repoRoot);
          const scopeWarnings = validateScope(scope);
          if (scope.file_excludes.length > 0) {
            let scopeExcludedCount = 0;
            files = files.filter(f => {
              const abs = path.resolve(repoRoot, f.filePath);
              const result = isFileExcluded(scope, abs, repoRoot);
              if (result.excluded) { scopeExcludedCount++; return false; }
              return true;
            });
            if (scopeExcludedCount > 0) {
              const summary = summariseScope(scope);
              scopeExclusions = {
                files_excluded: scopeExcludedCount,
                file_excludes:  scope.file_excludes,
                rule_excludes:  scope.rule_excludes,
                _summary:       summary,
                _warnings:      scopeWarnings,
              };
            }
          }
        } catch { /* non-fatal — scope unavailable */ }
      }

      const _scopeFileCount = scopeExclusions?.files_excluded || 0;
      const _scopeFileLabel = _scopeFileCount > 0 ? ` · ${_scopeFileCount} excluded (scope.yml)` : '';
      console.log(`${DIM} ${files.length} file(s) found${skipped.length > 0 ? ` · ${skipped.length} skipped` : ''}${_scopeFileLabel}${RESET}`);

      // ── --exclude / --exclude-rule one-off handling ───────────────────────
      // Build one-off scope entries — same format as scope.yml but source: 'one-off'.
      // Mergea into existing scope (never written to disk).
      const oneOffExcludes     = opts.exclude     || [];
      const oneOffRuleExcludes = opts.excludeRule  || [];

      if (oneOffExcludes.length > 0 || oneOffRuleExcludes.length > 0) {
        const path = require('path');
        const { isFileExcluded, isRuleExcluded } = require('../scope');

        const { getMachineFingerprint } = require('../store');
        const installId = getMachineFingerprint() || 'unknown';
        const addedAt   = new Date().toISOString();   // UTC storage (#18); shown local via formatLocalTime

        // Build one-off scope object
        const oneOffScope = {
          file_excludes: oneOffExcludes.map(p => ({
            pattern:   p,
            reason:    '(one-off)',
            added_by:  installId,
            added_at:  addedAt,
            source:    'one-off',
          })),
          rule_excludes: oneOffRuleExcludes.map(r => ({
            rule:     r,
            files:    null,
            reason:   '(one-off)',
            added_by: installId,
            added_at: addedAt,
            source:   'one-off',
          })),
        };

        // Filter files by one-off file excludes
        let oneOffFileExcludedCount = 0;
        if (oneOffScope.file_excludes.length > 0) {
          const ignoreRoot = repoRoot || process.cwd();
          files = files.filter(f => {
            const abs = path.resolve(ignoreRoot, f.filePath);
            const result = isFileExcluded(oneOffScope, abs, ignoreRoot);
            if (result.excluded) { oneOffFileExcludedCount++; return false; }
            return true;
          });
        }

        // Merge into scope (for rule exclusion in scanFull)
        if (!scope) scope = { file_excludes: [], rule_excludes: [] };
        scope = {
          file_excludes: [...(scope.file_excludes || []), ...oneOffScope.file_excludes],
          rule_excludes: [...(scope.rule_excludes || []), ...oneOffScope.rule_excludes],
        };

        // Build display lines for one-off exclusions
        const oneOffFileLines = oneOffExcludes.map(p => `${p} ${DIM}(one-off)${RESET}`);
        const oneOffRuleLines = oneOffRuleExcludes.map(r => `${r} ${DIM}(one-off)${RESET}`);

        // Merge into scopeExclusions for display
        if (!scopeExclusions) {
          scopeExclusions = { files_excluded: 0, file_excludes: [], rule_excludes: [], _summary: { hasExclusions: false, fileLines: [], ruleLines: [] }, _warnings: [] };
        }
        scopeExclusions.files_excluded = (scopeExclusions.files_excluded || 0) + oneOffFileExcludedCount;
        scopeExclusions.file_excludes  = [...(scopeExclusions.file_excludes || []), ...oneOffScope.file_excludes];
        scopeExclusions.rule_excludes  = [...(scopeExclusions.rule_excludes || []), ...oneOffScope.rule_excludes];
        scopeExclusions._summary = scopeExclusions._summary || { hasExclusions: false, fileLines: [], ruleLines: [] };
        scopeExclusions._summary.hasExclusions = true;
        scopeExclusions._summary.fileLines = [...(scopeExclusions._summary.fileLines || []), ...oneOffFileLines];
        scopeExclusions._summary.ruleLines = [...(scopeExclusions._summary.ruleLines || []), ...oneOffRuleLines];

        if (oneOffFileExcludedCount > 0) {
          console.log(`${DIM} ${oneOffFileExcludedCount} additional file(s) excluded (--exclude)${RESET}`);
        }
      }

      // ── fast mode warning — shown early, before scan begins ───────────────
      if ((config?.scan_mode || 'full') === 'fast') {
        console.log(`\n  ${YELLOW}⚠ fast mode — taint analysis disabled. Some CRITICAL findings may be missed.${RESET}`);
        console.log(`  ${DIM}  Set scan_mode: full in config.yml to enable full scanning.${RESET}`);
      }

      // Show active scope exclusions warning
      if (scopeExclusions?._summary?.hasExclusions) {
        const s = scopeExclusions._summary;
        console.log(`${YELLOW} ⚠ Active scope exclusions:${RESET}`);
        for (const line of s.fileLines)  console.log(`${YELLOW}   Files : ${line.trim()}${RESET}`);
        for (const line of s.ruleLines)  console.log(`${YELLOW}   Rules : ${line.trim()}${RESET}`);
      }
      // Show scope.yml validation warnings if any
      if (scopeExclusions?._warnings?.length) {
        for (const w of scopeExclusions._warnings) {
          console.log(`${YELLOW} ⚠ scope.yml: "${w.identifier}" missing: ${w.missing.join(', ')} — run: scd repo scope --show${RESET}`);
        }
      }
      if (skipLogging) {
        const logToNote = opts.logTo === 'none' ? ' (--log-to none)' : ' — target is outside any known repository';
        console.log(`${YELLOW} ↷ Scanning without logging${logToNote}${RESET}`);
      }
      console.log();

      if (files.length === 0) {
        console.log(YELLOW + ' No supported files found.' + RESET);
        console.log(`${DIM} Supported extensions: .js .ts .jsx .tsx .mjs .py .php${RESET}\n`);
        process.exit(0);
      }

      // Source the exception list from the machine-local store (Run 2 read-truth)
      // for the finalized repoRoot; bootstrap-on-read migrates config.yml →
      // exceptions.jsonl on first read. Fires once per command.
      config.exceptions = require('../exceptions-store').loadExceptionsWithBootstrap(repoRoot).records;

      // Scan – always full OWASP + secrets in manual mode
      let findings = await scanFull(files, config, scope);

      // Extract suppressed findings before applying CLI filters.
      // CLI filters (--severity, --rule) apply to active findings only —
      // suppressed findings are always kept as a complete audit set.
      const suppressedFindings = findings._suppressedFindings || [];

      // Capture the unfiltered scanner output before --severity/--rule are applied.
      // audit.log and findings.jsonl must reflect what the scanner actually found,
      // not what the operator chose to display.
      const scannerFindings = findings;

      // Apply CLI filters (--severity, --rule)
      findings = filterFindings(findings, { severity: opts.severity, rule: opts.rule });

      // Show saving status during audit + cache write
      if (process.stderr.isTTY) process.stderr.write('\r' + DIM + ' Analyzing and saving results…' + RESET);

      // Parse repo context from manifest files (package.json, requirements.txt, etc.)
      const { parseRepoContext, saveRepoContext } = require('../repo-context');
      const repoContext = parseRepoContext(repoRoot);
      let repoContextChanged = false;

      // Create one scanId — shared by audit log and scan file for full traceability
      const scanId = makeScanId();

      // Notify if --no-sync is active
      if (opts.sync === false) {
        process.stderr.write('\r\x1b[K');
        console.log(DIM + ' ↷ --no-sync: results saved locally, not pushed to scd-server' + RESET);
      }

      // Save repo context if changed
      if (!skipLogging && repoContext) {
        repoContextChanged = saveRepoContext(repoRoot, repoContext);
      }

      // Audit (unless --no-audit)
      // logScan receives the unfiltered scanner output (scannerFindings) — audit.log
      // is a raw record of what the scanner found, not what the operator chose to see.
      if (opts.audit !== false) {
        if (!skipLogging) logScan(repoRoot, {
          hookType: 'manual', files, findings: scannerFindings,
          blocked:  false,  // manual scan never blocks
          exceptions_applied: scannerFindings.filter(f => f.excepted).length,
          scanId,
          noSync:   opts.sync === false,
          scanMode: config.scan_mode || 'full',
          repoContext:        repoContext        || null,
          repoContextChanged: repoContextChanged || false,
        });
      }

      // Update accumulated findings store (always paired with audit.log).
      // Guarded by !skipLogging (same as save_cache) — --no-audit alone does
      // NOT suppress this; the store is the user's running state for
      // `scd findings`, not an audit-trail concern.
      // Step 2: pass coverage + suppressed + scope so resolve/reopen reconciliation
      // runs. Manual mode has scope from discoverFiles (line ~186) or the loadScope
      // fallback (line ~227) — both branches set `scope` in this function scope.
      let storeResult = null;
      if (!skipLogging) {
        const { updateFindings } = require('../findings-store');
        storeResult = updateFindings(repoRoot, scannerFindings, {
          scanId,
          coverage:   scannerFindings._coverage,
          suppressed: suppressedFindings,
          scope,
        });

        // Emit resolve/reopen events to audit.log + push queue (if any).
        if (storeResult.resolved > 0 || storeResult.reopened > 0) {
          const { logReconcile } = require('../audit');
          logReconcile(repoRoot, {
            scanId,
            resolved: storeResult.resolvedRecords,
            reopened: storeResult.reopenedRecords,
            hookType: 'manual',
            noSync:   opts.sync === false,
          });
        }

        // E1c.2: auto-archive exceptions whose finding was resolved by evidence.
        if (storeResult.resolved > 0) {
          require('../exception-manager').archiveResolvedExceptions(repoRoot, storeResult.resolvedRecords);
        }
        // E1c.3: auto-archive expired exceptions (review_expired) — time-based, so
        // it runs every scan regardless of resolve activity.
        require('../exception-manager').archiveExpiredExceptions(repoRoot);
      }

      if (process.stderr.isTTY) process.stderr.write('\r\x1b[K'); // clear saving status

      // displayFindings: post-filter + maxFindings-sliced → terminal/JSON/HTML output.
      // allFindings: post-filter, pre-slice → "X of Y" truncation message + deep analysis sizing.
      // (Audit log, scan cache and findings.jsonl use scannerFindings — unfiltered — so they
      // record what the scanner actually found, not what the operator chose to display.)
      const allFindings = findings;
      let displayFindings = findings;
      if (maxFindings !== null && findings.length > maxFindings) {
        const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, LOW: 4 };
        displayFindings = [...findings]
          .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
          .slice(0, maxFindings);
      }

      // Output
      if (opts.format === 'json') {
        const jsonOut = JSON.stringify({ scan: 'manual', target: scanTarget, findings: displayFindings, suppressed_findings: suppressedFindings }, null, 2);
        if (opts.output) {
          const fs   = require('fs');
          const path = require('path');
          const outPath = path.resolve(process.cwd(), opts.output);
          fs.writeFileSync(outPath, jsonOut, 'utf8');
          console.log(`\n${GREEN}✓ JSON report saved: ${outPath}${RESET}\n`);
        } else {
          console.log(jsonOut);
        }
        await tryFlush(opts);
        process.exit(0);
      }

      if (opts.format === 'html') {
        const { generateReport, writeReport } = require('../report-html');
        const path = require('path');

        const defaultName = `security-report-${new Date().toISOString().split('T')[0]}.html`;
        const outPath     = path.resolve(process.cwd(), opts.output || defaultName);

        const html = generateReport(displayFindings, {
          target:     scanTarget,
          scanDate:   new Date(),
          totalFiles: files.length,
          skipped,
          repoRoot:   repoRoot || process.cwd(),
        });

        writeReport(html, outPath);

        // Terminal summary first
        const timedOut2 = allFindings._timedOut || [];
        const { output: termOut } = formatTerminal(displayFindings, 'manual', config, { skipped, timedOut: timedOut2, verbose: opts.verbose, scopeExclusions });
        console.log(termOut);

        // Suppressed findings summary
        if (suppressedFindings.length > 0) {
          console.log(`${DIM}  ${suppressedFindings.length} finding(s) suppressed by file context  ·  scd findings --show-suppressed${RESET}\n`);
        }

        // Findings store summary
        if (storeResult) {
          console.log(`${DIM}  Open issues: ${storeResult.totalOpen} (${formatStatsTail(storeResult)})${RESET}`);
        }

        // OSC 8 clickable link to report (same terminal detection as output-terminal.js)
        const term = process.env.TERM_PROGRAM || '';
        const supportsOsc8 = ['iTerm.app', 'vscode', 'WarpTerminal', 'ghostty', 'JetBrains'].some(t => term.includes(t));
        const fileUri  = `file://${outPath}`;
        const linkText = outPath;

        if (supportsOsc8) {
          const osc8Link = `\x1b]8;;${fileUri}\x07${linkText}\x1b]8;;\x07`;
          console.log(`\n${GREEN}✓ HTML report:${RESET} ${CYAN}${osc8Link}${RESET}`);
        } else {
          console.log(`\n${GREEN}✓ HTML report:${RESET} ${CYAN}${linkText}${RESET}`);
        }
        console.log(`${DIM}  open ${outPath}${RESET}\n`);
        await tryFlush(opts);
        process.exit(0);
      }

      if (maxFindings !== null && allFindings.length > maxFindings) {
        console.log(
          `\n${YELLOW}⚠  Showing top ${maxFindings} of ${allFindings.length} findings (sorted by severity).${RESET}` +
          `\n   Scan coverage and logs are unaffected — all ${allFindings.length} findings are recorded.` +
          `\n   Run without --max-findings to see all findings.\n`
        );
      }
      const timedOut = allFindings._timedOut || [];
      const { output } = formatTerminal(displayFindings, 'manual', config, { skipped, timedOut, verbose: opts.verbose, scopeExclusions });
      console.log(output);

      // ── Suppressed findings summary ──────────────────────────────────────
      // Shown after the findings list when suppressions exist.
      // Design rule: never silent — always tell the user something was suppressed.
      if (suppressedFindings.length > 0) {
        console.log(`${DIM}  ${suppressedFindings.length} finding(s) suppressed by file context  ·  scd findings --show-suppressed${RESET}\n`);
      }

      // ── Findings store summary ───────────────────────────────────────────
      if (storeResult) {
        console.log(`${DIM}  Open issues: ${storeResult.totalOpen} (${formatStatsTail(storeResult)})${RESET}`);
      }

      // ── Deep analysis (--deep) ───────────────────────────────────────────
      let deepResults = null;
      if (opts.deep) {
        // maximum_privacy blocks all external calls — deep analysis not permitted
        if (config.trust_level === 'maximum_privacy') {
          console.log('\n' + YELLOW + '⚠  --deep is disabled when trust_level is maximum_privacy.' + RESET);
          console.log(DIM + '   Set trust_level: balanced in ~/.scd/repos/{repoId}/config.yml to enable.' + RESET + '\n');
        } else {
          const { deepAnalyze, formatDeepSection } = require('../deep-analyzer');
          const { getCentralUrl, getCentralToken }  = require('../global-config');

          const centralUrl = getCentralUrl();
          const token      = getCentralToken();
          const repoId     = require('../store').getRepoId(repoRoot);

          deepResults = await deepAnalyze(displayFindings, {
            centralUrl,
            token,
            repoId,
            scanId,
            trustLevel:    config.trust_level || 'balanced',
            verbose:       true,
            maxFindings,
            totalFindings: allFindings.length,
          });

          const deepOutput = formatDeepSection(displayFindings, deepResults);
          if (deepOutput) console.log(deepOutput);

          // Show which provider + model was used
          if (deepResults && deepResults.size > 0) {
            let deepSrc = null;
            for (const [, results] of deepResults) {
              const found = results.find(r => r.deep_source);
              if (found) { deepSrc = found.deep_source; break; }
            }
            if (deepSrc) {
              const modelStr = deepSrc.model ? ` · ${deepSrc.model}` : '';
              const envNote  = deepSrc.code_left_environment ? '  ·  code left environment' : '';
              console.log(`${DIM} [AI] ${deepSrc.provider}${modelStr}${envNote}${RESET}`);
            }
          }

          // Merge deep results into allFindings so deepAnalysis is persisted in the scan file
          if (deepResults && deepResults.size > 0) {
            for (const [filePath, results] of deepResults) {
              for (const result of results) {
                const match = allFindings.find(f =>
                  f.ruleId === result.ruleId &&
                  f.line   === result.line   &&
                  f.filePath && f.filePath.endsWith(filePath)
                );
                if (match) match.deepAnalysis = result;
              }
            }
          }
        }
      }

      // Cache findings (including suppressed findings for audit trail and --show-suppressed).
      // Use scannerFindings (unfiltered) — last-scan.json and scans/{scanId}.json must
      // record what the scanner found, not what the operator filtered to display.
      // Bootstrap-on-read for findings.jsonl relies on this completeness.
      if (!skipLogging) saveCache(repoRoot, {
        findings: scannerFindings,
        suppressed_findings: suppressedFindings,
        target:      scanTarget,
        totalFiles:  files.length,
        skipped,
        scanDate:    new Date(),
        deepResults: deepResults ? Array.from(deepResults.entries()) : null,
        repoRoot:    repoRoot || process.cwd(),
        scanMode:    config.scan_mode || 'full',
        scopeExclusions,
      }, scanId);

      // Manual scan: always exit 0 (informational, never blocks workflow)
      await tryFlush(opts);

      // ── Sync notice ──────────────────────────────────────────────────────
      // Rendered AFTER the flush, recomputed from current state. The flush can
      // apply a server decision (e.g. approve the pending exception) and refresh
      // lastSynced — both inputs to getSyncNotice. Computing it before the flush
      // made it contradict the flush's own "✓ approved" line one row later.
      // Offline/failed flush leaves pending + lastSynced unchanged, so the
      // notice is still accurate.
      try {
        const { getSyncNotice } = require('../exception-manager');
        const notice = getSyncNotice(repoRoot);
        if (notice) console.log('  ' + notice + '\n');
      } catch { /* non-fatal */ }

      warnIfOutdated();
      process.exit(0);
    });
}
