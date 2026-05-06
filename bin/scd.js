#!/usr/bin/env node
/**
 * scd – CLI entry point
 * Config-aware with audit logging
 */

const { Command } = require('commander');

const { warnIfOutdated, openInBrowser, tryFlush } = require('../lib/cli-helpers');
const { scanSecrets } = require('../lib/scanner-secrets');
const { scanFull }    = require('../lib/scanner-full');
const { formatTerminal } = require('../lib/output-terminal');
const { getChangedFiles } = require('../lib/git-utils');
const { loadConfig, getRepoRoot } = require('../lib/config');
const { resolveTargetContext, findGitRoot, checkRepoOverlap } = require('../lib/scan-context');
const { logScan } = require('../lib/audit');
const { saveCache, loadCache, cacheAge, makeScanId } = require('../lib/scan-cache');

const program = new Command();

const pkg = require('../package.json');

const { RULES_VERSION } = require('../lib/rule-registry');

program
  .name('scd')
  .description('Secure Code by Design – automated security scanning')
  .version(pkg.version + '  (rules ' + RULES_VERSION + ')');

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
  .option('--verbose',           'Show full file-grouped and rule-grouped output (default: compact summary)')
  .action(async (targets, opts) => {
    const cwdRepoRoot = getRepoRoot();  // provisional — may be overridden by target context
    let   repoRoot    = cwdRepoRoot;
    let   skipLogging = false;
    const config      = loadConfig(repoRoot);

    // Validate vendor flags
    if (opts.includeVendor && opts.vendorOnly) {
      console.error('\x1b[31m❌ --include-vendor and --vendor-only cannot be used together\x1b[0m');
      process.exit(1);
    }

    // ── Hook mode (called by git pre-commit/pre-push) ──────────────────
    if (opts.hook) {
      // Check for overlapping repos — warn but don't block (hooks are non-interactive)
      if (repoRoot) await checkRepoOverlap(repoRoot, { interactive: false });

      // Hook mode: git-tracked changed files only — vendor code never appears here
      const files = await getChangedFiles(opts.hook);
      if (files.length === 0) {
        console.log('\x1b[90m[scd] No files to scan.\x1b[0m');
        process.exit(0);
      }

      console.log(`\n\x1b[36m╔══════════════════════════════════════════╗\x1b[0m`);
      const _vt = 'Secure Code by Design v' + pkg.version;
      const _pl = Math.floor((42 - _vt.length) / 2);
      const _pr = 42 - _vt.length - _pl;
      console.log(`\x1b[36m║${ ' '.repeat(_pl)}${_vt}${ ' '.repeat(_pr)}║\x1b[0m`);
      console.log(`\x1b[36m╚══════════════════════════════════════════╝\x1b[0m`);
      console.log(`\x1b[90m Scanning ${files.length} file(s) – hook: ${opts.hook}\x1b[0m\n`);

      const findings = opts.hook === 'pre-commit'
        ? await scanSecrets(files, config)
        : await scanFull(files, config);

      const blocked = findings.some(f => f.blocks && !f.excepted);
      const scanId = makeScanId();

      logScan(repoRoot, {
        hookType: opts.hook, files, findings, blocked,
        exceptions_applied: findings.filter(f => f.excepted).length,
        scanId,
        noSync:   opts.sync === false,
        scanMode: config.scan_mode || 'full',
      });

      const { output, exitCode } = formatTerminal(findings, opts.hook, config, { verbose: opts.verbose });
      console.log(output);
      if (opts.sync !== false) await tryFlush(opts);
      warnIfOutdated({ toStderr: true });
      process.exit(exitCode);
    }

    // ── Manual mode ───────────────────────────────────────────────────
    const { discoverFiles, filterFindings } = require('../lib/scanner-manual');

    // Commander with variadic [targets...] is unreliable across versions —
    // it sometimes drops the last argument. Read process.argv directly instead.
    //
    // Strategy: find the last occurrence of 'scan' in argv (avoids matching
    // 'scan' in the script path), then collect everything after it that is
    // not an option flag (-x / --x) and not the VALUE of a known option flag.
    const knownOptionFlags = new Set([
      '--hook', '--lang', '--severity', '--rule', '--format', '--output'
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
      const ctx = await resolveTargetContext(targetList, cwdRepoRoot);
      if (ctx.cancelled) {
        console.log('\x1b[90m  Scan cancelled.\x1b[0m\n');
        process.exit(0);
      }
      repoRoot    = ctx.repoRoot    || cwdRepoRoot;
      skipLogging = ctx.skipLogging;
    }
    // ── Check for overlapping scd repos ────────────────────────────────
    if (!skipLogging && repoRoot) {
      const overlap = await checkRepoOverlap(repoRoot, { interactive: true });
      if (overlap.cancelled) {
        console.log('\x1b[90m  Scan cancelled.\x1b[0m\n');
        process.exit(0);
      }
      if (overlap.skipLogging) skipLogging = true;
    }
    // ────────────────────────────────────────────────────────────────────

    // Propagate skipLogging into opts so tryFlush is also suppressed
    if (skipLogging) opts = { ...opts, noSync: true, noAudit: true };
    // ─────────────────────────────────────────────────────────────────────

    // Show discovering status — discoverFiles reads all files from disk which can take a moment
    process.stderr.write('\r\x1b[90m Discovering files…\x1b[0m');

    let files = [], skipped = [];
    try {
      if (targetList.length === 1) {
        ({ files, skipped } = discoverFiles(targetList[0], { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly, includeIgnored: !!opts.includeIgnored, repoRoot }));
      } else {
        // Multiple targets (shell glob expansion): merge results, deduplicate by filePath
        const seen = new Set();
        for (const t of targetList) {
          try {
            const result = discoverFiles(t, { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly, includeIgnored: !!opts.includeIgnored, repoRoot });
            for (const f of result.files)   { if (!seen.has(f.filePath)) { seen.add(f.filePath); files.push(f); } }
            for (const s of result.skipped) { skipped.push(s); }
          } catch { /* skip targets that don't resolve */ }
        }
        if (files.length === 0) throw new Error(`Hittade inga filer att scanna: ${scanTarget}`);
      }
    } catch (err) {
      console.error(`\n\x1b[31m❌ ${err.message}\x1b[0m\n`);
      process.exit(1);
    }

    // Header
    if (opts.noLimit) {
      console.log(`\n\x1b[33m⚠️  --no-limit active – size limit disabled.\x1b[0m`);
      console.log(`\x1b[90m   Large files (>512KB) scanned with 30s timeout per file. May be slow.\x1b[0m`);
    }
    process.stderr.write('\r\x1b[K'); // clear discovering status
    const langLabel = opts.lang ? ` [${opts.lang}]` : '';
    const vendorLabel   = opts.vendorOnly ? ' \x1b[33m[vendor-only]\x1b[0m' : opts.includeVendor ? ' \x1b[33m[+vendor]\x1b[0m' : '';
    const ignoredLabel  = opts.includeIgnored ? ' \x1b[33m[+ignored]\x1b[0m' : '';
    console.log(`\n\x1b[36m╔══════════════════════════════════════════╗\x1b[0m`);
    const _vt2 = 'Secure Code by Design v' + pkg.version;
    const _pl2 = Math.floor((42 - _vt2.length) / 2);
    const _pr2 = 42 - _vt2.length - _pl2;
    console.log(`\x1b[36m║${ ' '.repeat(_pl2)}${_vt2}${ ' '.repeat(_pr2)}║\x1b[0m`);
    console.log(`\x1b[36m╚══════════════════════════════════════════╝\x1b[0m`);
    console.log(`\x1b[90m Manual scan${langLabel}${vendorLabel}${ignoredLabel}: ${scanTarget}\x1b[0m`);
    console.log(`\x1b[90m ${files.length} file(s) found${skipped.length > 0 ? ` · ${skipped.length} skipped` : ''}\x1b[0m`);
    if (skipLogging) console.log(`\x1b[33m ↷ Results not saved — target is outside any known repository\x1b[0m`);
    console.log();

    if (files.length === 0) {
      console.log('\x1b[33m No supported files found.\x1b[0m');
      console.log(`\x1b[90m Supported extensions: .js .ts .jsx .tsx .mjs .py .php\x1b[0m\n`);
      process.exit(0);
    }

    // Scan – always full OWASP + secrets in manual mode
    let findings = await scanFull(files, config);

    // Apply CLI filters (--severity, --rule)
    findings = filterFindings(findings, { severity: opts.severity, rule: opts.rule });

    // Show saving status during audit + cache write
    if (process.stderr.isTTY) process.stderr.write('\r\x1b[90m Saving results…\x1b[0m');

    // Parse repo context from manifest files (package.json, requirements.txt, etc.)
    const { parseRepoContext, saveRepoContext } = require('../lib/repo-context');
    const repoContext = parseRepoContext(repoRoot);
    let repoContextChanged = false;

    // Create one scanId — shared by audit log and scan file for full traceability
    const scanId = makeScanId();

    // Notify if --no-sync is active
    if (opts.sync === false) {
      process.stderr.write('\r\x1b[K');
      console.log('\x1b[90m ↷ --no-sync: results saved locally, not pushed to scd-server\x1b[0m');
    }

    // Save repo context if changed
    if (!skipLogging && repoContext) {
      repoContextChanged = saveRepoContext(repoRoot, repoContext);
    }

    // Audit (unless --no-audit)
    if (opts.audit !== false) {
      if (!skipLogging) logScan(repoRoot, {
        hookType: 'manual', files, findings,
        blocked:  false,  // manual scan never blocks
        exceptions_applied: findings.filter(f => f.excepted).length,
        scanId,
        noSync:   opts.sync === false,
        scanMode: config.scan_mode || 'full',
        repoContext:        repoContext        || null,
        repoContextChanged: repoContextChanged || false,
      });
    }

    if (process.stderr.isTTY) process.stderr.write('\r\x1b[K'); // clear saving status

    // Output
    if (opts.format === 'json') {
      const jsonOut = JSON.stringify({ scan: 'manual', target: scanTarget, findings }, null, 2);
      if (opts.output) {
        const fs   = require('fs');
        const path = require('path');
        const outPath = path.resolve(process.cwd(), opts.output);
        fs.writeFileSync(outPath, jsonOut, 'utf8');
        console.log(`\n\x1b[32m✓ JSON-rapport sparad: ${outPath}\x1b[0m\n`);
      } else {
        console.log(jsonOut);
      }
      await tryFlush(opts);
      process.exit(0);
    }

    if (opts.format === 'html') {
      const { generateReport, writeReport } = require('../lib/report-html');
      const path = require('path');

      const defaultName = `security-report-${new Date().toISOString().split('T')[0]}.html`;
      const outPath     = path.resolve(process.cwd(), opts.output || defaultName);

      const html = generateReport(findings, {
        target:     scanTarget,
        scanDate:   new Date(),
        totalFiles: files.length,
        skipped,
        repoRoot:   repoRoot || process.cwd(),
      });

      writeReport(html, outPath);

      // Terminal summary first
      const timedOut2 = findings._timedOut || [];
      const { output: termOut } = formatTerminal(findings, 'manual', config, { skipped, timedOut: timedOut2, verbose: opts.verbose });
      console.log(termOut);

      // OSC 8 clickable link to report (same terminal detection as output-terminal.js)
      const term = process.env.TERM_PROGRAM || '';
      const supportsOsc8 = ['iTerm.app', 'vscode', 'WarpTerminal', 'ghostty', 'JetBrains'].some(t => term.includes(t));
      const fileUri  = `file://${outPath}`;
      const linkText = outPath;

      if (supportsOsc8) {
        const osc8Link = `\x1b]8;;${fileUri}\x07${linkText}\x1b]8;;\x07`;
        console.log(`\n\x1b[32m✓ HTML report:\x1b[0m \x1b[36m${osc8Link}\x1b[0m`);
      } else {
        console.log(`\n\x1b[32m✓ HTML report:\x1b[0m \x1b[36m${linkText}\x1b[0m`);
      }
      console.log(`\x1b[90m  open ${outPath}\x1b[0m\n`);
      await tryFlush(opts);
      process.exit(0);
    }

    const timedOut = findings._timedOut || [];
    const { output } = formatTerminal(findings, 'manual', config, { skipped, timedOut, verbose: opts.verbose });
    console.log(output);

    // ── Sync notice ──────────────────────────────────────────────────────
    try {
      const { getSyncNotice } = require('../lib/exception-manager');
      const notice = getSyncNotice(repoRoot);
      if (notice) console.log('  ' + notice + '\n');
    } catch { /* non-fatal */ }

    // ── Deep analysis (--deep) ───────────────────────────────────────────
    let deepResults = null;
    if (opts.deep) {
      // maximum_privacy blocks all external calls — deep analysis not permitted
      if (config.trust_level === 'maximum_privacy') {
        console.log('\n\x1b[33m⚠️  --deep is disabled when trust_level is maximum_privacy.\x1b[0m');
        console.log('\x1b[90m   Set trust_level: balanced in ~/.scd/repos/{repoId}/config.yml to enable.\x1b[0m\n');
      } else {
        const { deepAnalyze, formatDeepSection } = require('../lib/deep-analyzer');
        const { getCentralUrl, getCentralToken }  = require('../lib/global-config');

        const centralUrl = getCentralUrl();
        const token      = getCentralToken();
        const repoId     = require('../lib/store').getRepoId(repoRoot);

        deepResults = await deepAnalyze(findings, {
          centralUrl,
          token,
          repoId,
          scanId,
          trustLevel: config.trust_level || 'balanced',
          verbose:    true,
        });

        const deepOutput = formatDeepSection(findings, deepResults);
        if (deepOutput) console.log(deepOutput);
      }
    }

    // Cache findings (including deep results if available)
    if (!skipLogging) saveCache(repoRoot, {
      findings,
      target:     scanTarget,
      totalFiles: files.length,
      skipped,
      scanDate:   new Date(),
      deepResults: deepResults ? Array.from(deepResults.entries()) : null,
      repoRoot:   repoRoot || process.cwd(),
      scanMode:   config.scan_mode || 'full',
    }, scanId);

    // Manual scan: always exit 0 (informational, never blocks workflow)
    await tryFlush(opts);
    warnIfOutdated();
    process.exit(0);
  });

require('../lib/commands/install').register(program);
require('../lib/commands/uninstall').register(program);

require('../lib/commands/doctor').register(program);

require('../lib/commands/accept').register(program);

require('../lib/commands/ignore').register(program);

require('../lib/commands/findings').register(program);


require('../lib/commands/sync').register(program);

require('../lib/commands/exceptions').register(program);

require('../lib/commands/resolve').register(program);

require('../lib/commands/init').register(program);

require('../lib/commands/remove').register(program);

require('../lib/commands/report').register(program);

require('../lib/commands/insights').register(program);

require('../lib/commands/configure').register(program);


require('../lib/commands/repo').register(program);

require('../lib/commands/version').register(program);
require('../lib/commands/list').register(program);
require('../lib/commands/rules').register(program);

// ── scd export-findings ─────────────────────────────────────────────────────
program
  .command('export-findings')
  .description('Export findings from a scan for external review')
  .option('--scan <id>',        'Scan ID to export (default: latest scan)')
  .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
  .option('--rule <id>',        'Filter to a specific rule ID')
  .option('--deep-only',        'Export only findings that have a deep analysis result')
  .option('--output <path>',    'Output file path (default: ~/.scd/repos/{id}/exports/scd-findings-{scanId}.json)')
  .action(async (opts) => {
    const path  = require('path');
    const store = require('../lib/store');
    const { exportFindings } = require('../lib/export-findings');
    const { loadCache } = require('../lib/scan-cache');
    const repoRoot = getRepoRoot();

    // Resolve scan ID first so we can use it in the default filename
    let resolvedScanId = opts.scan || null;
    if (!resolvedScanId) {
      const latest = loadCache(repoRoot);
      if (latest) resolvedScanId = latest.scanId;
    }

    const defaultName = 'scd-findings-' + (resolvedScanId || 'scan') + '.json';
    const outputPath  = opts.output
      ? path.resolve(process.cwd(), opts.output)
      : store.exportPath(repoRoot, defaultName);

    await exportFindings({
      repoRoot,
      scanId:               opts.scan     || null,
      severity:             opts.severity || null,
      rule:                 opts.rule     || null,
      deepOnly:             !!opts.deepOnly,
      outputPath,
      includeRuleInternals: false,
      command:              'export-findings',
    });
  });


// ── scd review-rules (Activemind-internal, hidden from scd --help) ───────────
{
  const { Command } = require('commander');
  const reviewCmd = new Command('review-rules');
  reviewCmd
    .description('Export findings with rule internals for Activemind rule quality review')
    .option('--scan <id>',        'Scan ID to export (default: latest scan)')
    .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
    .option('--rule <id>',        'Filter to a specific rule ID')
    .option('--deep-only',        'Export only findings that have a deep analysis result')
    .option('--output <path>',    'Output file path (default: ~/.scd/repos/{id}/exports/scd-review-{scanId}.json)')
    .action(async (opts) => {
      const path  = require('path');
      const store = require('../lib/store');
      const { exportFindings } = require('../lib/export-findings');
      const { loadCache } = require('../lib/scan-cache');
      const repoRoot = getRepoRoot();

      let resolvedScanId = opts.scan || null;
      if (!resolvedScanId) {
        const latest = loadCache(repoRoot);
        if (latest) resolvedScanId = latest.scanId;
      }

      const defaultName = 'scd-review-' + (resolvedScanId || 'scan') + '.json';
      const outputPath  = opts.output
        ? path.resolve(process.cwd(), opts.output)
        : store.exportPath(repoRoot, defaultName);

      await exportFindings({
        repoRoot,
        scanId:               opts.scan     || null,
        severity:             opts.severity || null,
        rule:                 opts.rule     || null,
        deepOnly:             !!opts.deepOnly,
        outputPath,
        includeRuleInternals: true,
        command:              'review-rules',
      });
    });

  program.addCommand(reviewCmd, { hidden: true });
}


program.parse(process.argv);

// ── Push worker – trigger after every command ─────────────────────────────
// Non-blocking: runs after the CLI command completes.
// Only active when a central URL is configured.
// Failures are silent – never affect CLI output or exit code.
setImmediate(() => {
  try {
    const { getCentralUrl } = require('../lib/global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;

    const { flush, queueSize } = require('../lib/push-queue');
    if (queueSize() === 0) return;

    // Pass repoRoot so meta includes repo and installation identity
    const repoRoot = (() => {
      try { return require('../lib/config').getRepoRoot(); } catch { return null; }
    })();

    flush(centralUrl, { repoRoot }).catch(() => {});
  } catch {
    // Non-fatal
  }
});
