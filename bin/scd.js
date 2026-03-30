#!/usr/bin/env node
/**
 * scd – CLI entry point
 * Config-aware with audit logging
 */

const { Command } = require('commander');
const { scanSecrets } = require('../lib/scanner-secrets');
const { scanFull }    = require('../lib/scanner-full');
const { formatTerminal } = require('../lib/output-terminal');
const { getChangedFiles } = require('../lib/git-utils');
const { loadConfig, getRepoRoot } = require('../lib/config');
const { logScan } = require('../lib/audit');
const { saveCache, loadCache, cacheAge } = require('../lib/scan-cache');

const program = new Command();

// ── Push queue flush helper ───────────────────────────────────────────────
// Awaitable flush — called before process.exit() in scan commands.
// Non-blocking: resolves immediately if no central URL or empty queue.
async function tryFlush() {
  try {
    const { getCentralUrl } = require('../lib/global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;
    const { flush, queueSize } = require('../lib/push-queue');
    if (queueSize() === 0) return;
    const repoRoot = (() => {
      try { return require('../lib/config').getRepoRoot(); } catch { return null; }
    })();
    await flush(centralUrl, { repoRoot });
  } catch { /* non-fatal */ }
}

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
  .option('--lang <lang>', 'Begränsa till språk: js, ts, py, php ...')
  .option('--severity <level>', 'Visa bara: CRITICAL, HIGH, EXPOSURE ...')
  .option('--rule <id>', 'Visa bara specifik regel: INJ-001, JWT-001 ...')
  .option('--format <fmt>', 'Output-format: terminal (default), html, json', 'terminal')
  .option('--output <file>', 'Spara rapport till fil (används med --format html/json)')
  .option('--no-limit', 'Scanna även filer över storleksgränsen (30s timeout/fil – kan vara långsamt)')
  .option('--deep',           'Enable Claude API deep analysis of CRITICAL/HIGH findings')
  .option('--deep-delay <ms>', 'Delay in ms between --deep API calls (overrides config deep_delay_ms)')
  .option('--no-audit',        'Skip audit logging for this scan')
  .option('--include-vendor',  'Include vendor/dependency code in scan (node_modules, site-packages, vendor/ etc.)')
  .option('--vendor-only',     'Scan only vendor/dependency code (supply chain audit)')
  .option('--verbose',           'Show full file-grouped and rule-grouped output (default: compact summary)')
  .action(async (targets, opts) => {
    const repoRoot = getRepoRoot();
    const config   = loadConfig(repoRoot);

    // Validate vendor flags
    if (opts.includeVendor && opts.vendorOnly) {
      console.error('\x1b[31m❌ --include-vendor and --vendor-only cannot be used together\x1b[0m');
      process.exit(1);
    }

    // ── Hook-läge (anropat av git pre-commit/pre-push) ──────────────────
    if (opts.hook) {
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

      logScan(repoRoot, {
        hookType: opts.hook, files, findings, blocked,
        exceptions_applied: findings.filter(f => f.excepted).length,
      });

      const { output, exitCode } = formatTerminal(findings, opts.hook, config, { verbose: opts.verbose });
      console.log(output);
      await tryFlush();
      process.exit(exitCode);
    }

    // ── Manuellt läge ───────────────────────────────────────────────────
    const { discoverFiles, filterFindings } = require('../lib/scanner-manual');

    // Commander with variadic [targets...] is unreliable across versions —
    // it sometimes drops the last argument. Read process.argv directly instead.
    //
    // Strategy: find the last occurrence of 'scan' in argv (avoids matching
    // 'scan' in the script path), then collect everything after it that is
    // not an option flag (-x / --x) and not the VALUE of a known option flag.
    const knownOptionFlags = new Set([
      '--hook', '--lang', '--severity', '--rule', '--format', '--output', '--deep-delay'
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

    // Show discovering status — discoverFiles reads all files from disk which can take a moment
    process.stderr.write('\r\x1b[90m Discovering files…\x1b[0m');

    let files = [], skipped = [];
    try {
      if (targetList.length === 1) {
        ({ files, skipped } = discoverFiles(targetList[0], { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly }));
      } else {
        // Multiple targets (shell glob expansion): merge results, deduplicate by filePath
        const seen = new Set();
        for (const t of targetList) {
          try {
            const result = discoverFiles(t, { lang: opts.lang, config, noLimit: opts.noLimit || false, includeVendor: !!opts.includeVendor, vendorOnly: !!opts.vendorOnly });
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
      console.log(`\n\x1b[33m⚠️  --no-limit aktivt – storleksgränsen är inaktiverad.\x1b[0m`);
      console.log(`\x1b[90m   Stora filer (>512KB) scannas med 30s timeout per fil. Kan vara långsamt.\x1b[0m`);
    }
    process.stderr.write('\r\x1b[K'); // clear discovering status
    const langLabel = opts.lang ? ` [${opts.lang}]` : '';
    const vendorLabel = opts.vendorOnly ? ' \x1b[33m[vendor-only]\x1b[0m' : opts.includeVendor ? ' \x1b[33m[+vendor]\x1b[0m' : '';
    console.log(`\n\x1b[36m╔══════════════════════════════════════════╗\x1b[0m`);
    const _vt2 = 'Secure Code by Design v' + pkg.version;
    const _pl2 = Math.floor((42 - _vt2.length) / 2);
    const _pr2 = 42 - _vt2.length - _pl2;
    console.log(`\x1b[36m║${ ' '.repeat(_pl2)}${_vt2}${ ' '.repeat(_pr2)}║\x1b[0m`);
    console.log(`\x1b[36m╚══════════════════════════════════════════╝\x1b[0m`);
    console.log(`\x1b[90m Manual scan${langLabel}${vendorLabel}: ${scanTarget}\x1b[0m`);
    console.log(`\x1b[90m ${files.length} file(s) found${skipped.length > 0 ? ` · ${skipped.length} skipped` : ''}\x1b[0m\n`);

    if (files.length === 0) {
      console.log('\x1b[33m No supported files found.\x1b[0m');
      console.log(`\x1b[90m Stödda filändelser: .js .ts .jsx .tsx .mjs .py .php\x1b[0m\n`);
      process.exit(0);
    }

    // Scan – always full OWASP + secrets in manual mode
    let findings = await scanFull(files, config);

    // Apply CLI filters (--severity, --rule)
    findings = filterFindings(findings, { severity: opts.severity, rule: opts.rule });

    // Show saving status during audit + cache write
    if (process.stderr.isTTY) process.stderr.write('\r\x1b[90m Saving results…\x1b[0m');

    // Audit (unless --no-audit)
    if (opts.audit !== false) {
      logScan(repoRoot, {
        hookType: 'manual', files, findings,
        blocked: false,  // manual scan never blocks
        exceptions_applied: findings.filter(f => f.excepted).length,
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
      await tryFlush();
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
      await tryFlush();
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
      // Respect trust_level – maximum_privacy means no external API calls
      if (config.trust_level === 'maximum_privacy') {
        console.log('\n\x1b[33m⚠️  --deep is disabled when trust_level is maximum_privacy.\x1b[0m');
        console.log('\x1b[90m   No code is sent externally. Set trust_level: balanced in securityagent.yml to enable.\x1b[0m\n');
        await tryFlush();
        process.exit(0);
      }

      const { deepAnalyze, formatDeepSection } = require('../lib/deep-analyzer');
      const { getApiKey } = require('../lib/global-config');
      const apiKey = getApiKey();

      if (!apiKey) {
        console.log('\n\x1b[31m❌ --deep requires an Anthropic API key.\x1b[0m');
        console.log('\x1b[90m   Run: scd configure --api-key sk-ant-...\x1b[0m\n');
        await tryFlush();
        process.exit(0);
      }

      const critHighCount = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
      if (critHighCount === 0) {
        console.log('\n\x1b[90m ℹ️  No CRITICAL/HIGH findings to deep-analyse.\x1b[0m\n');
      } else {
        console.log(`\n\x1b[90m 🔍 Starting Claude deep analysis of ${critHighCount} CRITICAL/HIGH findings...\x1b[0m`);
        try {
          // Resolve delay: --delay flag > config deep_delay_ms > 0
          const delayMs = opts.deepDelay
            ? parseInt(opts.deepDelay, 10)
            : (config && config.deep_delay_ms ? config.deep_delay_ms : 0);

          deepResults = await deepAnalyze(findings, {
            apiKey,
            interactive: true,
            verbose: true,
            delayMs,
          });
          const deepOutput = formatDeepSection(findings, deepResults);
          if (deepOutput) console.log(deepOutput);
        } catch (err) {
          console.log(`\n\x1b[31m❌ Deep analysis failed: ${err.message}\x1b[0m\n`);
        }
      }
    }

    // Cache findings (including deep results if available)
    saveCache(repoRoot, {
      findings,
      target:     scanTarget,
      totalFiles: files.length,
      skipped,
      scanDate:   new Date(),
      deepResults: deepResults ? Array.from(deepResults.entries()) : null,
    });

    // Manual scan: always exit 0 (informational, never blocks workflow)
    await tryFlush();
    process.exit(0);
  });

const installCmd = new Command('install')
  .description('Install global git hooks')
  .action(async () => {
    const { install } = require('../lib/installer');
    await install();
  });
program.addCommand(installCmd, { hidden: true });

program
  .command('doctor')
  .description('Check installation health')
  .action(async () => {
    const { doctor } = require('../lib/doctor');
    await doctor();
  });

program
  .command('audit')
  .description('Show recent audit log')
  .option('--limit <n>', 'Number of events', '50')
  .action(async (opts) => {
    const { showAuditReport } = require('../lib/audit-report');
    const repoRoot = getRepoRoot();
    await showAuditReport(repoRoot, parseInt(opts.limit));
  });

program
  .command('approve')
  .description('Mark a finding as an accepted risk exception (requires team-lead approval via scd-server)')
  .option('--rule <id>',    'Rule ID (e.g. PY-INJ-001)')
  .option('--file <path>',  'File path')
  .option('--line <n>',     'Line number')
  .option('--reason <text>','Reason why this risk is accepted (required)')
  .action(async (opts) => {
    const { addException } = require('../lib/exception-manager');
    const repoRoot = getRepoRoot();
    await addException(repoRoot, opts, 'exception');
  });


program
  .command('ignore')
  .description('Ignore a finding (requires team-lead approval via scd-server)')
  .option('--rule <id>',    'Rule ID (e.g. PY-PATH-001)')
  .option('--file <path>',  'File path')
  .option('--line <n>',     'Line number')
  .option('--reason <text>','Reason for ignoring this finding (required)')
  .option('--tag <tag>',    'Optional tag for filtering (e.g. false_positive, out_of_scope, third_party)')
  .action(async (opts) => {
    const { addException } = require('../lib/exception-manager');
    const repoRoot = getRepoRoot();
    await addException(repoRoot, opts, 'ignore');
  });


program
  .command('sync')
  .description('Pull approved exceptions from scd-server and update local config')
  .action(async () => {
    const { syncExceptions } = require('../lib/exception-manager');
    const repoRoot = getRepoRoot();
    await syncExceptions(repoRoot);
  });


program
  .command('exceptions')
  .description('List exceptions and ignores in the local store')
  .option('--list <status>', 'Filter by status: pending | approved | rejected | all (default: all)')
  .action(async (opts) => {
    const { listExceptions } = require('../lib/exception-manager');
    const repoRoot = getRepoRoot();
    listExceptions(repoRoot, opts.list || 'all');
  });


program
  .command('resolve')
  .description('Mark an EXPOSURE finding as handled, or remove a rejected exception by ID')
  .option('--rule <id>',      'Rule ID (for EXPOSURE findings)')
  .option('--file <path>',   'File path (for EXPOSURE findings)')
  .option('--line <n>',      'Line number (for EXPOSURE findings)')
  .option('--rejected <id>', 'Remove a rejected exception from local config by exception ID')
  .action(async (opts) => {
    const repoRoot = getRepoRoot();
    if (opts.rejected) {
      const { removeRejected } = require('../lib/exception-manager');
      removeRejected(repoRoot, opts.rejected);
    } else {
      const { resolveExposure } = require('../lib/resolve-manager');
      await resolveExposure(repoRoot, opts);
    }
  });


program
  .command('init')
  .description('Initialise Secure Code by Design in this repo and install git hooks')
  .action(async () => {
    const { initRepo } = require('../lib/init-repo');
    const repoRoot = getRepoRoot();
    await initRepo(repoRoot);
  });


program
  .command('report')
  .description('Generate HTML, Markdown or JSON report from the last scan (without re-scanning)')
  .option('--format <fmt>', 'html (default), md, json', 'html')
  .option('--output <file>', 'Spara till angiven fil (default: security-report-DATUM.html)')
  .option('--open',          'Open report in browser after generating (macOS/Windows)')
  .option('--serve',         'Serve report via local HTTP server and open in browser (works on all platforms)')
  .option('--port <port>',   'Port for --serve (default: random available port)')
  .option('--index',         'Always show report index page (use with --serve)')
  .option('--scan <id>',     'Generate report from a specific scan ID (scd store --scans to list)')
  .action(async (opts) => {
    const path = require('path');
    const fs   = require('fs');
    const repoRoot = getRepoRoot();

    let cache;
    if (opts.scan) {
      const { loadScan } = require('../lib/scan-cache');
      cache = loadScan(repoRoot, opts.scan);
      if (!cache) {
        console.error('\n\x1b[31m✗ Scan not found: ' + opts.scan + '\x1b[0m');
        console.error('  Run \x1b[36mscd store --scans\x1b[0m to list available scans.\n');
        process.exit(1);
      }
    } else {
      cache = loadCache(repoRoot);
      if (!cache) {
        console.error('\n\x1b[31m✗ No saved scan found.\x1b[0m');
        console.error("  Run 'scd scan' first to generate findings to report from.\n");
        process.exit(1);
      }
    }

    const { findings, target, totalFiles, skipped, scanDate, deepResults } = cache;
    const age = cacheAge(scanDate);
    const deepMap = deepResults ? new Map(deepResults) : null;
    console.log('\n\x1b[2m↺ Using cached scan from ' + age + ' (' + new Date(scanDate).toLocaleString('en-SE') + ')\x1b[0m');
    console.log('  Target: ' + target + '  ·  ' + findings.length + ' findings  ·  ' + totalFiles + ' files' +
      (deepMap && deepMap.size > 0 ? '  ·  \x1b[36mdeep analysis included\x1b[0m' : '') + '\n');

    const fmt     = (opts.format || 'html').toLowerCase();
    const store   = require('../lib/store');
    const scanIdStr = cache.scanId || new Date(scanDate).toISOString().slice(0,19).replace(/:/g,'-');
    const ext     = fmt === 'markdown' ? 'md' : fmt;
    const defaultName = 'security-report-' + scanIdStr + '.' + ext;

    // Default: store reports in ~/.scd/repos/{id}/reports/
    // Override with --output for explicit path
    const outPath = opts.output
      ? path.resolve(process.cwd(), opts.output)
      : store.reportPath(repoRoot, defaultName);

    // Read repo name from meta.json for the report header
    const metaPath = path.join(store.storeDir(repoRoot), 'meta.json');
    let repoName = null;
    try { repoName = JSON.parse(fs.readFileSync(metaPath, 'utf8')).name || null; } catch {}
    if (!repoName) repoName = path.basename(path.resolve(repoRoot));

    const reportOpts = {
      target,
      repoName,
      scanDate:   new Date(scanDate),
      totalFiles,
      skipped:    skipped || [],
      repoRoot,
      deepResults: deepMap,
    };

    if (fmt === 'json') {
      const { generateJson, writeJson } = require('../lib/report-json');
      writeJson(generateJson(findings, reportOpts), outPath);
      console.log('\x1b[32m✓ JSON report saved:\x1b[0m \x1b[36m' + outPath + '\x1b[0m\n');
      process.exit(0);
    }

    if (fmt === 'md' || fmt === 'markdown') {
      const { generateMarkdown, writeMarkdown } = require('../lib/report-markdown');
      writeMarkdown(generateMarkdown(findings, reportOpts), outPath);
      console.log('\x1b[32m✓ Markdown report saved:\x1b[0m \x1b[36m' + outPath + '\x1b[0m\n');
      process.exit(0);
    }

    // HTML (default)
    const { generateReport, writeReport } = require('../lib/report-html');
    writeReport(generateReport(findings, reportOpts), outPath);

    // OSC 8 clickable link
    const term = process.env.TERM_PROGRAM || '';
    const supportsOsc8 = ['iTerm.app', 'vscode', 'WarpTerminal', 'ghostty', 'JetBrains'].some(function(t) { return term.includes(t); });
    const fileUri = 'file://' + outPath;
    if (supportsOsc8) {
      const osc8Link = '\x1b]8;;' + fileUri + '\x07' + outPath + '\x1b]8;;\x07';
      console.log('\x1b[32m✓ HTML report:\x1b[0m \x1b[36m' + osc8Link + '\x1b[0m');
    } else {
      console.log('\x1b[32m✓ HTML report:\x1b[0m \x1b[36m' + outPath + '\x1b[0m');
    }

    if (opts.serve) {
      const http = require('http');
      const fs   = require('fs');
      const path = require('path');
      const { buildIndexPage } = require('../lib/report-index');

      const store      = require('../lib/store');
      const reportDir  = store.reportsDir(repoRoot);
      const reportFile = path.basename(outPath);
      const allReports = store.listReports(repoRoot).filter(r => r.filename.endsWith('.html'));
      const showIndex  = opts.index || allReports.length > 1;

      const getPort = () => new Promise((resolve, reject) => {
        const srv = require('net').createServer();
        srv.listen(opts.port ? parseInt(opts.port) : 0, () => {
          const p = srv.address().port;
          srv.close(() => resolve(p));
        });
        srv.on('error', reject);
      });

      const port    = await getPort();
      const baseUrl = 'http://localhost:' + port;

      const server = http.createServer((req, res) => {
        const url = decodeURIComponent(req.url.split('?')[0]);

        // Download all – show path hint (real zip would need extra dep)
        if (url === '/download-all') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end('<p style="font-family:monospace;padding:2rem;background:#0a0f1a;color:#e2e8f0">' +
            'Reports folder: <code>' + reportDir + '</code></p>');
          return;
        }

        // Download single file
        if (url.startsWith('/download/')) {
          const fname = path.basename(url.slice('/download/'.length));
          const fpath = path.join(reportDir, fname);
          if (!fpath.startsWith(reportDir) || !fs.existsSync(fpath)) {
            res.writeHead(404); res.end('Not found'); return;
          }
          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': 'attachment; filename="' + fname + '"',
          });
          fs.createReadStream(fpath).pipe(res);
          return;
        }

        // Index page
        if (url === '/' || url === '/index.html') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(buildIndexPage(allReports, reportDir, reportFile));
          return;
        }

        // Serve report file
        const fname = path.basename(url);
        const fpath = path.join(reportDir, fname);
        if (!fpath.startsWith(reportDir) || !fs.existsSync(fpath)) {
          res.writeHead(404); res.end('Not found'); return;
        }
        const ext  = path.extname(fpath).toLowerCase();
        const mime = { '.html': 'text/html', '.json': 'application/json',
                       '.md': 'text/plain' }[ext] || 'text/plain';
        res.writeHead(200, { 'Content-Type': mime + '; charset=utf-8' });
        fs.createReadStream(fpath).pipe(res);
      });

      server.listen(port, '127.0.0.1', () => {
        const openUrl = showIndex
          ? baseUrl + '/'
          : baseUrl + '/' + encodeURIComponent(reportFile);

        if (showIndex) {
          console.log('\x1b[36m⇢  Report index: ' + baseUrl + '/\x1b[0m');
          console.log('\x1b[90m   ' + allReports.length + ' report' +
            (allReports.length !== 1 ? 's' : '') + ' available\x1b[0m');
        } else {
          console.log('\x1b[36m⇢  Serving report: ' + openUrl + '\x1b[0m');
        }

        const { execSync } = require('child_process');
        const openCmd = process.platform === 'darwin' ? 'open'
                      : process.platform === 'win32'  ? 'start'
                      : 'xdg-open';
        try { execSync(openCmd + ' "' + openUrl + '"'); } catch {}
        console.log('\x1b[90m   Press any key to stop the server…\x1b[0m');
      });

      await new Promise((resolve) => {
        const cleanup = () => {
          server.close();
          try {
            process.stdin.pause();
            if (process.stdin.setRawMode) process.stdin.setRawMode(false);
          } catch {}
          console.log('\x1b[90m   Server stopped.\x1b[0m\n');
          resolve();
        };
        // setRawMode is not available in cmd.exe / non-TTY environments (e.g. Windows)
        // Fall back to line-based input (press Enter) or Ctrl-C
        const hasRawMode = process.stdin.isTTY && typeof process.stdin.setRawMode === 'function';
        if (hasRawMode) {
          try {
            process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.once('data', cleanup);
          } catch {
            // If raw mode fails despite isTTY, fall through to SIGINT only
            console.log('\x1b[90m   Press Ctrl-C to stop the server.\x1b[0m');
          }
        } else {
          // Windows cmd.exe or non-TTY: wait for Enter or Ctrl-C
          console.log('\x1b[90m   Press Enter or Ctrl-C to stop the server.\x1b[0m');
          process.stdin.resume();
          process.stdin.once('data', cleanup);
        }
        process.once('SIGINT', cleanup);
      });
      return;
    }

    if (opts.open) {
      const { execSync } = require('child_process');
      const openCmd = process.platform === 'darwin' ? 'open'
                    : process.platform === 'win32'  ? 'start'
                    : 'xdg-open';
      try { execSync(openCmd + ' "' + outPath + '"'); } catch(e) { /* ignore */ }
    }

    console.log();
  });




program
  .command('insights')
  .description('Analyze behavioral patterns and knowledge gaps from the audit log')
  .option('--days <n>',  'Analyze the last N days (default: 90)', '90')
  .option('--deep',      'Send statistics to Claude API for deep analysis')
  .action(async (opts) => {
    const { analyzeInsights }  = require('../lib/insights-analyzer');
    const { renderInsights }   = require('../lib/insights-output');
    const { getApiKey }        = require('../lib/global-config');
    const repoRoot             = getRepoRoot();
    const days                 = Math.max(1, parseInt(opts.days) || 90);

    console.log(`\n\x1b[2m↺ Analyzing audit log (last ${days} days)…\x1b[0m`);

    let apiKey = null;
    if (opts.deep) {
      apiKey = getApiKey();
      if (!apiKey) {
        console.log('\n\x1b[31m❌ --deep requires an Anthropic API key.\x1b[0m');
        console.log('\x1b[90m   scd configure --api-key sk-ant-...\x1b[0m\n');
        process.exit(1);
      }
      console.log('\x1b[2m  Sending statistics to Claude API…\x1b[0m');
    }

    const analysis = await analyzeInsights(repoRoot, { deep: opts.deep, apiKey, days });
    renderInsights(analysis);
  });



program
  .command('configure')
  .description('Manage global configuration (API key etc.)')
  .option('--api-key <key>',    'Save Anthropic API key for --deep analysis')
  .option('--clear-api-key',    'Remove saved API key')
  .option('--show',             'Show current global configuration')
  .option('--central-url <url>',  'Set scd-server URL (enables push queue)')
  .option('--clear-central-url',  'Remove scd-server URL (disables push queue)')
  .option('--token <token>',       'Set scd-server API token')
  .option('--clear-token',         'Remove scd-server API token')
  .action((opts) => {
    const { get, set, remove, maskApiKey, showConfig, getCentralUrl, setCentralUrl, removeCentralUrl, getCentralToken, setCentralToken, removeCentralToken, GLOBAL_CONFIG } =
      require('../lib/global-config');

    const CYAN  = '\x1b[36m';
    const GREEN = '\x1b[32m';
    const RED   = '\x1b[31m';
    const DIM   = '\x1b[2m';
    const BOLD  = '\x1b[1m';
    const RESET = '\x1b[0m';

    // ── --api-key <key> ───────────────────────────────────────────────────
    if (opts.apiKey) {
      const key = opts.apiKey.trim();

      // Basic format validation – Anthropic keys start with sk-ant-
      if (!key.startsWith('sk-ant-')) {
        console.error(`\n${RED}✗ Invalid API key.${RESET}`);
        console.error(`  Anthropic API keys start with ${DIM}sk-ant-${RESET}`);
        console.error(`  Get your key at: ${CYAN}https://console.anthropic.com/settings/keys${RESET}\n`);
        process.exit(1);
      }

      set('ANTHROPIC_API_KEY', key);
      console.log(`\n${GREEN}✓ API key saved${RESET} → ${DIM}${GLOBAL_CONFIG}${RESET}`);
      console.log(`  ${DIM}${maskApiKey(key)}${RESET}`);
      console.log(`\n  ${DIM}Use 'scd scan --deep' to enable Claude analysis.${RESET}\n`);
      process.exit(0);
    }

    // ── --clear-api-key ───────────────────────────────────────────────────
    if (opts.clearApiKey) {
      const removed = remove('ANTHROPIC_API_KEY');
      if (removed) {
        console.log(`\n${GREEN}✓ API key removed${RESET} from ${DIM}${GLOBAL_CONFIG}${RESET}\n`);
      } else {
        console.log(`\n${DIM}No API key to remove.${RESET}\n`);
      }
      process.exit(0);
    }

    // ── --central-url <url> ───────────────────────────────────────────────
    if (opts.centralUrl) {
      const url = opts.centralUrl.trim();
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        console.error(`\n${RED}✗ Invalid URL – must start with http:// or https://${RESET}\n`);
        process.exit(1);
      }
      setCentralUrl(url);
      console.log(`\n${GREEN}✓ Central URL saved${RESET} → ${DIM}${url}${RESET}`);
      console.log(`  ${DIM}Push queue enabled – events will sync on each scd command.${RESET}\n`);
      process.exit(0);
    }

    // ── --clear-central-url ───────────────────────────────────────────────
    if (opts.clearCentralUrl) {
      const removed = removeCentralUrl();
      if (removed) {
        console.log(`\n${GREEN}✓ Central URL removed${RESET} – push queue disabled.\n`);
      } else {
        console.log(`\n${DIM}No central URL configured.${RESET}\n`);
      }
      process.exit(0);
    }

    // ── --token <token> ───────────────────────────────────────────────────
    if (opts.token) {
      const token = opts.token.trim();
      if (!token.startsWith('scd-')) {
        console.error(`\n${RED}✗ Invalid token format – scd-server tokens start with scd-${RESET}\n`);
        process.exit(1);
      }
      setCentralToken(token);
      console.log(`\n${GREEN}✓ Token saved${RESET} → ${DIM}${GLOBAL_CONFIG}${RESET}`);
      console.log(`  ${DIM}${token.slice(0, 12)}...${RESET}\n`);
      process.exit(0);
    }

    // ── --clear-token ─────────────────────────────────────────────────────
    if (opts.clearToken) {
      const removed = removeCentralToken();
      if (removed) {
        console.log(`\n${GREEN}✓ Token removed${RESET} from ${DIM}${GLOBAL_CONFIG}${RESET}\n`);
      } else {
        console.log(`\n${DIM}No token to remove.${RESET}\n`);
      }
      process.exit(0);
    }

    // ── --show (default if no flags) ──────────────────────────────────────
    const info = showConfig();
    const centralUrl = getCentralUrl();

    console.log(`\n${CYAN}${BOLD}Secure Code by Design – Global configuration${RESET}\n`);
    console.log(`  Config file:  ${DIM}${info.configPath}${RESET}`);
    console.log(`  File exists:  ${info.exists ? GREEN + 'yes' : DIM + 'no (no settings saved yet)'}${RESET}`);
    console.log('');
    console.log(`  API key:      ${info.apiKey}`);
    console.log(`  Source:       ${DIM}${info.apiKeySource}${RESET}`);
    console.log('');

    if (!info.apiKeySource || info.apiKeySource === '(not set)') {
      console.log(`  ${DIM}Set API key:     scd configure --api-key sk-ant-...${RESET}`);
      console.log(`  ${DIM}Alternative:     export ANTHROPIC_API_KEY="sk-ant-..."${RESET}`);
    } else {
      console.log(`  ${DIM}Clear key:       scd configure --clear-api-key${RESET}`);
      console.log(`  ${DIM}Deep analysis:   scd scan --deep${RESET}`);
    }
    console.log('');
    console.log(`  Central URL:  ${centralUrl ? GREEN + centralUrl : DIM + '(not set – push queue disabled)'}${RESET}`);
    console.log('');
    if (centralUrl) {
      const token   = getCentralToken();
      const { queueSize, staleCount } = require('../lib/push-queue');
      const pending = queueSize();
      const stale   = staleCount();
      console.log(`  Token:        ${token ? DIM + token.slice(0, 12) + '...' + RESET : RED + '(not set)' + RESET}`);
      console.log(`  Queue:        ${DIM}${pending} pending event(s)${stale > 0 ? '  ' + RED + stale + ' stale' + RESET : ''}${RESET}`);
      console.log('');
      console.log(`  ${DIM}Clear URL:       scd configure --clear-central-url${RESET}`);
      if (token) {
        console.log(`  ${DIM}Clear token:     scd configure --clear-token${RESET}`);
      } else {
        console.log(`  ${DIM}Set token:       scd configure --token <token>${RESET}`);
      }
    } else {
      console.log(`  ${DIM}Set server URL:  scd configure --central-url https://your-server:3000${RESET}`);
      console.log(`  ${DIM}Then set token:  scd configure --token <token>${RESET}`);
    }
    console.log('');
  });




// ── scd list ────────────────────────────────────────────────────────────────
program
  .command('list')
  .description('List all repos registered with Secure Code by Design')
  .option('--json', 'Output as JSON')
  .action((opts) => {
    const store = require('../lib/store');
    const repos = store.listRepos();

    if (opts.json) {
      console.log(JSON.stringify(repos, null, 2));
      return;
    }

    if (repos.length === 0) {
      console.log('\n\x1b[90m No repos found. Run scd init in a project to get started.\x1b[0m\n');
      return;
    }

    const { cacheAge } = require('../lib/scan-cache');

    console.log('\n\x1b[1mSecure Code by Design – Known repos\x1b[0m');
    console.log('\x1b[90m' + '─'.repeat(72) + '\x1b[0m');

    const namW = 24, scanW = 18, findW = 10;
    console.log(
      '\x1b[90m' +
      'Name'.padEnd(namW) +
      'Last scan'.padEnd(scanW) +
      'Findings'.padEnd(findW) +
      'Type'.padEnd(10) +
      'Store ID' +
      '\x1b[0m'
    );
    console.log('\x1b[90m' + '─'.repeat(72) + '\x1b[0m');

    for (const r of repos.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''))) {
      const name     = (r.name || r.repoId).slice(0, namW - 1).padEnd(namW);
      const lastScan = r.lastScan ? cacheAge(r.lastScan).padEnd(scanW) : '\x1b[90m(never)\x1b[0m'.padEnd(scanW + 8);
      const findings = r.lastScanFindings != null
        ? (String(r.lastScanFindings) + (r.lastScanCritical ? ' \x1b[31m(' + r.lastScanCritical + 'C)\x1b[0m' : '')).padEnd(findW + (r.lastScanCritical ? 12 : 0))
        : '\x1b[90m–\x1b[0m'.padEnd(findW + 4);
      const type     = r.type === 'path-based' ? '\x1b[33mpath\x1b[0m    ' : '\x1b[90mgit\x1b[0m     ';
      const id       = '\x1b[90m' + r.repoId + '\x1b[0m';

      console.log(name + lastScan + findings + type + id);
    }
    console.log();

    const pathBased = repos.filter(r => r.type === 'path-based');
    if (pathBased.length > 0) {
      console.log('\x1b[33m⚠  ' + pathBased.length + ' repo(s) use path-based IDs (no git remote).');
      console.log('   IDs may change if the folder is renamed or moved.\x1b[0m\n');
    }
  });


// ── scd store ───────────────────────────────────────────────────────────────
program
  .command('store')
  .description('Show and navigate the store for the current repo')
  .option('--open',         'Open store folder in Finder / Explorer / file manager')
  .option('--open-reports', 'Open reports folder')
  .option('--reports',      'List saved reports for this repo')
  .option('--path',         'Print store path (for scripting)')
  .option('--show',         'Show full meta.json info for the current repo')
  .option('--scans',         'List all saved scans for current repo')
  .option('--verify',       'Verify all repos in store still exist on disk')
  .option('--clean',        'Interactive cleanup of missing/stale repos (use with --verify)')
  .option('--verbose',      'Show detail lines for each issue (use with --verify)')
  .option('--json',         'Output verification results as JSON (use with --verify)')
  .action(async (opts) => {
    const store    = require('../lib/store');
    const repoRoot = getRepoRoot();
    const dir      = store.storeDir(repoRoot);
    const identity = store.getRepoIdentity(repoRoot);

    // --path  – minimal output for scripting
    if (opts.path) {
      console.log(dir);
      return;
    }

    // --show  – full meta.json for current repo
    if (opts.show) {
      const fs   = require('fs');
      const path = require('path');
      const store    = require('../lib/store');
      const repoRoot = getRepoRoot();
      const dir      = store.storeDir(repoRoot);
      const metaPath = path.join(dir, 'meta.json');

      const BOLD  = '\x1b[1m';
      const DIM   = '\x1b[90m';
      const CYAN  = '\x1b[36m';
      const RESET = '\x1b[0m';

      let meta;
      try {
        meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      } catch {
        const repoId = store.getRepoId(repoRoot);
        console.log('\n\x1b[33m No meta.json found — this repo has not been initialised.\x1b[0m');
        console.log(DIM + '  Working directory : ' + RESET + CYAN + repoRoot + RESET);
        console.log(DIM + '  Store ID          : ' + RESET + DIM + repoId + RESET);
        console.log(DIM + '  Store path        : ' + RESET + DIM + dir + RESET);
        console.log(DIM + '\n  Run ' + RESET + CYAN + 'scd init' + RESET + DIM + ' to register this repo and install git hooks.\n' + RESET);
        return;
      }

      const { cacheAge } = require('../lib/scan-cache');

      console.log('\n' + BOLD + 'Secure Code by Design – Repo meta' + RESET);
      console.log(DIM + '─'.repeat(52) + RESET + '\n');
      console.log('  ' + DIM + 'Working directory'.padEnd(18) + RESET + CYAN + repoRoot + RESET);
      console.log(DIM + '─'.repeat(52) + RESET + '\n');

      const row = (label, value, color) =>
        console.log('  ' + DIM + label.padEnd(18) + RESET + (color||'') + value + RESET);

      row('Name:',       meta.name     || '(unknown)');
      row('Store ID:',   meta.repoId,    DIM);
      row('Type:',       meta.type === 'remote' ? 'remote (git)' : 'path-based (directory scan)',
          meta.type === 'path-based' ? '\x1b[33m' : '');

      if (meta.remote) row('Remote:',    meta.remote,  DIM);
      row('Local path:', meta.localPath || '(none)',    CYAN);

      console.log();

      if (meta.lastSeen) {
        row('Last seen:',  cacheAge(meta.lastSeen) + '  ' + DIM + meta.lastSeen + RESET);
      }
      if (meta.lastScan) {
        const critStr = meta.lastScanCritical > 0
          ? '  \x1b[31m' + meta.lastScanCritical + ' CRITICAL\x1b[0m' : '';
        row('Last scan:',  cacheAge(meta.lastScan) + '  '
          + DIM + (meta.lastScanFindings ?? '?') + ' findings' + RESET + critStr);
      } else {
        row('Last scan:',  '(none yet)', DIM);
      }

      // Reports
      const reports = store.listReports(repoRoot);
      row('Reports:',    reports.length + ' saved', DIM);

      // Store location
      console.log();
      row('Store path:', dir, CYAN);

      console.log();
      return;
    }

    // --scans – list saved scans
    if (opts.scans) {
      const store    = require('../lib/store');
      const repoRoot = getRepoRoot();
      const scans    = store.listScans(repoRoot);

      const BOLD  = '\x1b[1m';
      const DIM   = '\x1b[90m';
      const CYAN  = '\x1b[36m';
      const GREEN = '\x1b[32m';
      const RESET = '\x1b[0m';

      const repoId   = store.getRepoId(repoRoot);
      const scansPath = store.scansDir(repoRoot);

      if (scans.length === 0) {
        console.log('\n\x1b[33m No scans found for this repo.\x1b[0m');
        console.log(DIM + '  Working directory : ' + RESET + CYAN + repoRoot + RESET);
        console.log(DIM + '  Store ID          : ' + RESET + DIM + repoId + RESET);
        console.log(DIM + '  Scans directory   : ' + RESET + DIM + scansPath + RESET);
        console.log(DIM + '\n  Run ' + RESET + CYAN + 'scd scan' + RESET + DIM + ' from your project root to create a scan.\n' + RESET);
        return;
      }

      console.log('\n' + BOLD + 'Saved scans' + RESET + '  ' + DIM + scansPath + RESET);
      console.log(DIM + 'Working directory: ' + RESET + CYAN + repoRoot + RESET);
      console.log(DIM + '─'.repeat(70) + RESET);
      console.log(DIM + 'Scan ID'.padEnd(22) + 'Date'.padEnd(14) + 'Findings'.padEnd(10) + 'Files'.padEnd(8) + 'Deep' + RESET);
      console.log(DIM + '─'.repeat(70) + RESET);

      for (const s of scans) {
        const date    = s.scanDate ? new Date(s.scanDate).toLocaleString('en-SE') : '—';
        const deepStr = s.hasDeep ? GREEN + '✓' + RESET : DIM + '—' + RESET;
        console.log(
          CYAN + s.scanId.padEnd(22) + RESET +
          DIM  + date.padEnd(14)     + RESET +
          (String(s.findingCount)).padEnd(10) +
          DIM + String(s.totalFiles).padEnd(8) + RESET +
          deepStr
        );
      }
      console.log(DIM + '─'.repeat(70) + RESET);
      console.log('  ' + scans.length + ' scan' + (scans.length !== 1 ? 's' : '') + ' saved\n');
      console.log(DIM + '  scd report --scan <id>   generate report from a specific scan\n' + RESET);
      return;
    }

    // --verify  – check all repos in store
    if (opts.verify) {
      const { verifyAll, renderResults, promptClean } = require('../lib/store-verify');
      const results = verifyAll();

      if (results.length === 0) {
        console.log('\n\x1b[90m No repos found in store.\x1b[0m\n');
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(results.map(r => ({
          repoId:            r.repoId,
          name:              r.name,
          status:            r.status,
          localPath:         r.localPath,
          remote:            r.remote,
          type:              r.type,
          daysSinceLastSeen: r.daysSinceLastSeen,
          lastScan:          r.lastScan,
          detail:            r.detail,
          stats:             r.stats,
        })), null, 2));
        return;
      }

      const issues = results.filter(r => r.status !== 'OK');
      console.log('\n\x1b[1mSecure Code by Design – Store verify\x1b[0m');
      console.log('\x1b[90m' + '─'.repeat(60) + '\x1b[0m');
      console.log('\x1b[90m Checking ' + results.length + ' repo' + (results.length !== 1 ? 's' : '') + ' in store…\x1b[0m');

      renderResults(results, { verbose: opts.verbose || opts.clean });

      if (opts.clean && issues.length > 0) {
        await promptClean(results);
      }
      return;
    }

    // --reports  – list saved reports
    if (opts.reports) {
      const reports = store.listReports(repoRoot);
      if (reports.length === 0) {
        console.log('\n\x1b[90m No reports found. Run scd report to generate one.\x1b[0m\n');
        return;
      }
      console.log('\n\x1b[1mSaved reports\x1b[0m  \x1b[90m' + dir + '/reports\x1b[0m\n');
      for (const r of reports) {
        const size = r.size > 1024 * 1024
          ? (r.size / 1024 / 1024).toFixed(1) + ' MB'
          : Math.round(r.size / 1024) + ' KB';
        const age  = require('../lib/scan-cache').cacheAge(r.mtime);
        console.log('  \x1b[36m' + r.filename.padEnd(48) + '\x1b[0m' +
          '\x1b[90m' + size.padStart(8) + '  ' + age + '\x1b[0m');
      }
      console.log();
      return;
    }

    // --open / --open-reports
    if (opts.open || opts.openReports) {
      const { execSync } = require('child_process');
      const target  = opts.openReports ? store.reportsDir(repoRoot) : dir;
      const openCmd = process.platform === 'darwin' ? 'open'
                    : process.platform === 'win32'  ? 'explorer'
                    : 'xdg-open';
      try {
        execSync(openCmd + ' "' + target + '"');
        console.log('\x1b[90m Opened: ' + target + '\x1b[0m\n');
      } catch {
        console.log('\x1b[33m Could not open file manager. Path:\x1b[0m\n  ' + target + '\n');
      }
      return;
    }

    // Default – show store info for current repo
    const fs = require('fs');
    const path = require('path');
    const meta = (() => {
      try { return JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')); }
      catch { return null; }
    })();

    console.log('\n\x1b[1mSecure Code by Design – Store\x1b[0m');
    console.log('\x1b[90m' + '─'.repeat(52) + '\x1b[0m\n');
    console.log('  Working dir: \x1b[36m' + repoRoot + '\x1b[0m');
    console.log('  Repo:        \x1b[1m' + (meta?.name || path.basename(repoRoot)) + '\x1b[0m');
    if (identity.type === 'remote') {
      console.log('  Remote:      \x1b[90m' + identity.identifier + '\x1b[0m');
    } else {
      console.log('  Type:        \x1b[33mpath-based\x1b[0m (no git remote – ID may change if folder moves)');
    }
    console.log('  Store ID:    \x1b[90m' + store.getRepoId(repoRoot) + '\x1b[0m');
    console.log('  Location:    \x1b[36m' + dir + '\x1b[0m\n');

    if (meta?.lastScan) {
      const { cacheAge } = require('../lib/scan-cache');
      const critStr = meta.lastScanCritical > 0
        ? ' \x1b[31m(' + meta.lastScanCritical + ' CRITICAL)\x1b[0m' : '';
      console.log('  Last scan: ' + cacheAge(meta.lastScan) +
        '  \x1b[90m' + meta.lastScanFindings + ' findings\x1b[0m' + critStr);
    } else {
      console.log('  Last scan: \x1b[90m(none yet)\x1b[0m');
    }

    const reports = store.listReports(repoRoot);
    console.log('  Reports:   \x1b[90m' + reports.length + ' saved\x1b[0m');
    console.log();
    console.log('  \x1b[90mscd store --reports          list saved reports\x1b[0m');
    console.log('  \x1b[90mscd store --open             open in file manager\x1b[0m');
    console.log('  \x1b[90mscd store --open-reports     open reports folder\x1b[0m');
    console.log('  \x1b[90mscd store --path             print path (for scripting)\x1b[0m');
    console.log('  \x1b[90mscd store --show             show full meta info for current repo\x1b[0m');
    console.log('  \x1b[90mscd store --scans            list all saved scans\x1b[0m');
    console.log('  \x1b[90mscd store --verify           verify all repos exist on disk\x1b[0m');
    console.log('  \x1b[90mscd store --verify --clean   interactive cleanup of stale repos\x1b[0m\n');
  });



// ── scd rules ───────────────────────────────────────────────────────────────
program
  .command('rules')
  .description('List, search and inspect security rules')
  .option('--lang <langs>',     'Filter by language (js, ts, py, php, cs, aspx, all) — comma-separated')
  .option('--severity <level>', 'Filter by severity (critical, high, medium, exposure)')
  .option('--id <id>',          'Show full detail for a specific rule ID (e.g. INFRA-001)')
  .option('--search <query>',   'Free-text search in ID, name, category, why, fix')
  .option('--stats',            'Show rule counts by severity, language and category')
  .option('--format <fmt>',     'Output format: table (default) | json')
  .action((opts) => {
    const { queryRules, getStats, getRegistry, SEV_ORDER } = require('../lib/rule-registry');

    const SEV_COLOR = {
      CRITICAL: '\x1b[31m',  // red
      HIGH:     '\x1b[33m',  // yellow
      MEDIUM:   '\x1b[34m',  // blue
      EXPOSURE: '\x1b[36m',  // cyan
      LOW:      '\x1b[90m',  // dim
    };
    const RESET = '\x1b[0m';
    const BOLD  = '\x1b[1m';
    const DIM   = '\x1b[90m';

    const colorSev = (s) => (SEV_COLOR[s] || '') + s.padEnd(8) + RESET;

    // ── JSON output ──────────────────────────────────────────────────────
    if (opts.format === 'json') {
      const rules = queryRules({ lang: opts.lang, severity: opts.severity,
                                  id: opts.id, search: opts.search });
      if (opts.stats) {
        console.log(JSON.stringify(getStats(rules), null, 2));
      } else {
        console.log(JSON.stringify(rules, null, 2));
      }
      return;
    }

    // ── Stats view ───────────────────────────────────────────────────────
    if (opts.stats) {
      const rules = queryRules({ lang: opts.lang, severity: opts.severity, search: opts.search });
      const s = getStats(rules);
      console.log('\n' + BOLD + 'Secure Code by Design – Rule stats' + RESET);
      console.log(DIM + '─'.repeat(50) + RESET + '\n');
      console.log('  Total rules: ' + BOLD + s.total + RESET + '\n');

      console.log('  By severity:');
      for (const [sev, n] of Object.entries(s.bySeverity).sort((a,b) => (SEV_ORDER[a[0]]??9)-(SEV_ORDER[b[0]]??9))) {
        console.log('    ' + colorSev(sev) + '  ' + n);
      }

      console.log('\n  By language:');
      const langEntries = Object.entries(s.byLanguage).sort((a,b) => b[1]-a[1]);
      for (const [lang, n] of langEntries) {
        console.log('    ' + lang.padEnd(12) + DIM + n + RESET);
      }

      console.log('\n  By category:');
      const catEntries = Object.entries(s.byCategory).sort((a,b) => b[1]-a[1]);
      for (const [cat, n] of catEntries) {
        const short = cat.replace(/\s*\(OWASP.*?\)/,'').trim();
        console.log('    ' + short.padEnd(40) + DIM + n + RESET);
      }
      console.log();
      return;
    }

    // ── Detail view (--id) ───────────────────────────────────────────────
    if (opts.id) {
      const rules = queryRules({ id: opts.id });
      if (rules.length === 0) {
        console.log('\n\x1b[33m Rule not found: ' + opts.id + RESET);
        console.log(DIM + ' Use scd rules --search <term> to find rules.\n' + RESET);
        process.exit(1);
      }
      const r = rules[0];
      const sev = SEV_COLOR[r.severity] || '';
      console.log('\n' + BOLD + r.id + RESET + '  ' + sev + r.severity + RESET);
      console.log(DIM + '─'.repeat(60) + RESET);
      console.log(BOLD + r.name + RESET + '\n');
      console.log('  Category:  ' + r.category);
      console.log('  Languages: ' + r.languages.join(', '));
      console.log('  Match:     ' + r.matchMode);

      if (r.why) {
        console.log('\n' + BOLD + 'Why this matters' + RESET);
        console.log(wordWrap(r.why, 70, '  '));
      }
      if (r.scenario) {
        console.log('\n' + BOLD + 'Attack scenario' + RESET);
        console.log(wordWrap(r.scenario, 70, '  '));
      }
      if (r.fix) {
        console.log('\n' + BOLD + 'How to fix' + RESET);
        console.log(wordWrap(r.fix, 70, '  '));
      }
      if (r.checklist && r.checklist.length) {
        console.log('\n' + BOLD + 'Verification checklist' + RESET);
        for (const item of r.checklist) {
          console.log('  ☐ ' + item);
        }
      }
      console.log();
      return;
    }

    // ── List view (default) ──────────────────────────────────────────────
    const rules = queryRules({ lang: opts.lang, severity: opts.severity, search: opts.search });

    if (rules.length === 0) {
      console.log('\n' + DIM + ' No rules match the given filters.\n' + RESET);
      return;
    }

    const title = buildTitle(opts);
    console.log('\n' + BOLD + 'Secure Code by Design – Rules' + (title ? '  ' + DIM + title + RESET : '') + RESET);
    console.log(DIM + '─'.repeat(90) + RESET);

    // Column widths
    const ID_W = 16, SEV_W = 10, LANG_W = 18, CAT_W = 32;
    console.log(
      DIM +
      'ID'.padEnd(ID_W) +
      'Severity'.padEnd(SEV_W) +
      'Languages'.padEnd(LANG_W) +
      'Category'.padEnd(CAT_W) +
      'Name' +
      RESET
    );
    console.log(DIM + '─'.repeat(90) + RESET);

    // Group by category for readability
    const byCategory = {};
    for (const r of rules) {
      const cat = r.category.replace(/\s*\(OWASP.*?\)/,'').trim();
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(r);
    }

    for (const [cat, catRules] of Object.entries(byCategory)) {
      for (const r of catRules) {
        const id   = r.id.padEnd(ID_W);
        const sev  = (SEV_COLOR[r.severity]||'') + r.severity.padEnd(SEV_W - 1) + RESET + ' ';
        const langs = r.languages.join(',').slice(0, LANG_W - 1).padEnd(LANG_W);
        const category = cat.slice(0, CAT_W - 1).padEnd(CAT_W);
        const name = r.name.slice(0, 46) + (r.name.length > 46 ? '…' : '');
        console.log(id + sev + DIM + langs + RESET + DIM + category + RESET + name);
      }
    }

    console.log(DIM + '─'.repeat(90) + RESET);
    console.log('  ' + rules.length + ' rule' + (rules.length !== 1 ? 's' : '') +
      (rules.length < getRegistry().length ? ' (filtered from ' + getRegistry().length + ' total)' : ' total') + '\n');
    console.log(DIM +
      '  scd rules --id <ID>          full detail for a rule\n' +
      '  scd rules --lang php         filter by language\n' +
      '  scd rules --severity critical filter by severity\n' +
      '  scd rules --search <term>    free-text search\n' +
      '  scd rules --stats            counts by severity / language / category\n' +
      RESET);
  });

function wordWrap(text, width, indent) {
  const words = text.split(' ');
  const lines = [];
  let line = '';
  for (const word of words) {
    if ((line + word).length > width) { lines.push(indent + line.trim()); line = ''; }
    line += word + ' ';
  }
  if (line.trim()) lines.push(indent + line.trim());
  return lines.join('\n');
}

function buildTitle(opts) {
  const parts = [];
  if (opts.lang)     parts.push('lang=' + opts.lang);
  if (opts.severity) parts.push('severity=' + opts.severity);
  if (opts.search)   parts.push('search="' + opts.search + '"');
  return parts.join('  ');
}


// ── scd version ────────────────────────────────────────────────────────────
program
  .command('version')
  .description('Show detailed version information')
  .action(() => {
    const os  = require('os');
    const { getRegistry } = require('../lib/rule-registry');
    const rules = getRegistry();

    const BOLD  = '\x1b[1m';
    const DIM   = '\x1b[90m';
    const CYAN  = '\x1b[36m';
    const RESET = '\x1b[0m';

    const sevCount = (sev) => rules.filter(r => r.severity === sev).length;

    console.log('\n' + BOLD + 'Secure Code by Design' + RESET);
    console.log(DIM + '─'.repeat(40) + RESET);
    console.log('  CLI:    ' + BOLD + pkg.version + RESET);
    console.log('  Rules:  ' + BOLD + RULES_VERSION + RESET +
      DIM + '  (' + rules.length + ' rules' +
      '  ·  CRITICAL: ' + sevCount('CRITICAL') +
      '  HIGH: ' + sevCount('HIGH') +
      '  MEDIUM: ' + sevCount('MEDIUM') +
      '  EXPOSURE: ' + sevCount('EXPOSURE') + ')' + RESET);
    console.log('  Node:   ' + DIM + process.version + RESET);
    console.log('  OS:     ' + DIM + os.platform() + ' ' + os.arch() + RESET);
    console.log();
  });


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
