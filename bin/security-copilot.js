#!/usr/bin/env node
/**
 * Security Copilot – CLI Agent
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

const pkg = require('../package.json');

const { RULES_VERSION } = require('../lib/rule-registry');

program
  .name('sc')
  .description('Security Co-Pilot – AI-assisted security scanning')
  .version(pkg.version + '  (rules ' + RULES_VERSION + ')');

program
  .command('scan [targets...]')
  .description('Kör säkerhetsscanning – hook-läge (automatiskt) eller manuellt')
  .option('--hook <type>', 'Hook-läge: pre-commit eller pre-push (körs av git hooks)')
  .option('--lang <lang>', 'Begränsa till språk: js, ts, py, php ...')
  .option('--severity <level>', 'Visa bara: CRITICAL, HIGH, EXPOSURE ...')
  .option('--rule <id>', 'Visa bara specifik regel: INJ-001, JWT-001 ...')
  .option('--format <fmt>', 'Output-format: terminal (default), html, json', 'terminal')
  .option('--output <file>', 'Spara rapport till fil (används med --format html/json)')
  .option('--no-limit', 'Scanna även filer över storleksgränsen (30s timeout/fil – kan vara långsamt)')
  .option('--deep', 'Aktivera Claude API-djupanalys av CRITICAL/HIGH findings')
  .option('--no-audit', 'Logga inte denna scanning i audit trail')
  .action(async (targets, opts) => {
    const repoRoot = getRepoRoot();
    const config   = loadConfig(repoRoot);

    // ── Hook-läge (anropat av git pre-commit/pre-push) ──────────────────
    if (opts.hook) {
      const files = await getChangedFiles(opts.hook);
      if (files.length === 0) {
        console.log('\x1b[90m[Security Copilot] Inga filer att scanna.\x1b[0m');
        process.exit(0);
      }

      console.log(`\n\x1b[36m╔══════════════════════════════════════════╗\x1b[0m`);
      console.log(`\x1b[36m║       Security Copilot v0.1.0            ║\x1b[0m`);
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

      const { output, exitCode } = formatTerminal(findings, opts.hook, config);
      console.log(output);
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

    let files = [], skipped = [];
    try {
      if (targetList.length === 1) {
        ({ files, skipped } = discoverFiles(targetList[0], { lang: opts.lang, config, noLimit: opts.noLimit || false }));
      } else {
        // Multiple targets (shell glob expansion): merge results, deduplicate by filePath
        const seen = new Set();
        for (const t of targetList) {
          try {
            const result = discoverFiles(t, { lang: opts.lang, config, noLimit: opts.noLimit || false });
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
    const langLabel = opts.lang ? ` [${opts.lang}]` : '';
    console.log(`\n\x1b[36m╔══════════════════════════════════════════╗\x1b[0m`);
    console.log(`\x1b[36m║       Security Copilot v0.1.0            ║\x1b[0m`);
    console.log(`\x1b[36m╚══════════════════════════════════════════╝\x1b[0m`);
    console.log(`\x1b[90m Manuell scanning${langLabel}: ${scanTarget}\x1b[0m`);
    console.log(`\x1b[90m ${files.length} fil(er) hittade${skipped.length > 0 ? ` · ${skipped.length} hoppades över` : ''}\x1b[0m\n`);

    if (files.length === 0) {
      console.log('\x1b[33m Inga stödda filer hittades.\x1b[0m');
      console.log(`\x1b[90m Stödda filändelser: .js .ts .jsx .tsx .mjs .py .php\x1b[0m\n`);
      process.exit(0);
    }

    // Scan – always full OWASP + secrets in manual mode
    let findings = await scanFull(files, config);

    // Apply CLI filters (--severity, --rule)
    findings = filterFindings(findings, { severity: opts.severity, rule: opts.rule });

    // Audit (unless --no-audit)
    if (opts.audit !== false) {
      logScan(repoRoot, {
        hookType: 'manual', files, findings,
        blocked: false,  // manual scan never blocks
        exceptions_applied: findings.filter(f => f.excepted).length,
      });
    }

    // Cache findings for `sc report`
    saveCache(repoRoot, {
      findings,
      target:     scanTarget,
      totalFiles: files.length,
      skipped,
      scanDate:   new Date(),
    });

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
      const { output: termOut } = formatTerminal(findings, 'manual', config, { skipped, timedOut: timedOut2 });
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
      process.exit(0);
    }

    const timedOut = findings._timedOut || [];
    const { output } = formatTerminal(findings, 'manual', config, { skipped, timedOut });
    console.log(output);

    // ── Djupanalys (--deep) ───────────────────────────────────────────────
    if (opts.deep) {
      const { deepAnalyze, formatDeepSection } = require('../lib/deep-analyzer');
      const { getApiKey } = require('../lib/global-config');
      const apiKey = getApiKey();

      if (!apiKey) {
        console.log('\n\x1b[31m❌ --deep kräver en Anthropic API-nyckel.\x1b[0m');
        console.log('\x1b[90m   Alternativ 1 (rekommenderat): sc configure --api-key sk-ant-...\x1b[0m');
        console.log('\x1b[90m   Alternativ 2 (tillfälligt):   export ANTHROPIC_API_KEY="sk-ant-..."\x1b[0m\n');
        process.exit(0);
      }

      const critHighCount = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
      if (critHighCount === 0) {
        console.log('\n\x1b[90m ℹ️  Inga CRITICAL/HIGH findings att djupanalysera.\x1b[0m\n');
        process.exit(0);
      }

      console.log(`\n\x1b[90m 🔍 Startar Claude djupanalys av ${critHighCount} CRITICAL/HIGH findings...\x1b[0m`);

      try {
        const deepResults = await deepAnalyze(findings, {
          apiKey,
          interactive: true,
          verbose: true,
        });

        const deepOutput = formatDeepSection(findings, deepResults);
        if (deepOutput) console.log(deepOutput);
      } catch (err) {
        console.log(`\n\x1b[31m❌ Djupanalys misslyckades: ${err.message}\x1b[0m\n`);
      }
    }

    // Manual scan: always exit 0 (informational, never blocks workflow)
    process.exit(0);
  });

program
  .command('install')
  .description('Install global git hooks')
  .action(async () => {
    const { install } = require('../lib/installer');
    await install();
  });

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
  .description('Add a config exception for a finding')
  .option('--rule <id>', 'Rule ID to except (e.g. FRONT-001)')
  .option('--file <path>', 'File path')
  .option('--line <n>', 'Line number')
  .action(async (opts) => {
    const { addException } = require('../lib/exception-manager');
    const repoRoot = getRepoRoot();
    await addException(repoRoot, opts);
  });


program
  .command('resolve')
  .description('Markera ett EXPOSURE-finding som hanterat på tjänstnivå')
  .option('--rule <id>', 'Regel-ID (t.ex. FRONT-001)')
  .option('--file <path>', 'Fil')
  .option('--line <n>', 'Radnummer')
  .action(async (opts) => {
    const { resolveExposure } = require('../lib/resolve-manager');
    const repoRoot = getRepoRoot();
    await resolveExposure(repoRoot, opts);
  });


program
  .command('init')
  .description('Initialisera Security Copilot i detta repo – skapar .securityagent.yml')
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
  .action(async (opts) => {
    const path = require('path');
    const fs   = require('fs');
    const repoRoot = getRepoRoot();

    const cache = loadCache(repoRoot);
    if (!cache) {
      console.error('\n\x1b[31m✗ No saved scan found.\x1b[0m');
      console.error("  Run 'sc scan' first to generate findings to report from.\n");
      process.exit(1);
    }

    const { findings, target, totalFiles, skipped, scanDate } = cache;
    const age = cacheAge(scanDate);
    console.log('\n\x1b[2m↺ Using cached scan from ' + age + ' (' + new Date(scanDate).toLocaleString('en-SE') + ')\x1b[0m');
    console.log('  Target: ' + target + '  ·  ' + findings.length + ' findings  ·  ' + totalFiles + ' files\n');

    const fmt     = (opts.format || 'html').toLowerCase();
    const store   = require('../lib/store');
    const dateStr = new Date(scanDate).toISOString().split('T')[0];
    const ext     = fmt === 'markdown' ? 'md' : fmt;
    const defaultName = 'security-report-' + dateStr + '.' + ext;

    // Default: store reports in ~/.security-copilot/repos/{id}/reports/
    // Override with --output for explicit path
    const outPath = opts.output
      ? path.resolve(process.cwd(), opts.output)
      : store.reportPath(repoRoot, defaultName);

    const reportOpts = {
      target,
      scanDate:   new Date(scanDate),
      totalFiles,
      skipped:    skipped || [],
      repoRoot,
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
        try {
          if (process.stdin.setRawMode) process.stdin.setRawMode(true);
          process.stdin.resume();
          process.stdin.once('data', cleanup);
        } catch {}
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
        console.log('\x1b[90m   sc configure --api-key sk-ant-...\x1b[0m\n');
        process.exit(1);
      }
      console.log('\x1b[2m  Sending statistics to Claude API…\x1b[0m');
    }

    const analysis = await analyzeInsights(repoRoot, { deep: opts.deep, apiKey, days });
    renderInsights(analysis);
  });



program
  .command('configure')
  .description('Hantera global Security Co-Pilot-konfiguration (API-nyckel m.m.)')
  .option('--api-key <key>',    'Spara Anthropic API-nyckel för --deep analys')
  .option('--clear-api-key',    'Ta bort sparad API-nyckel')
  .option('--show',             'Visa aktuell global konfiguration')
  .action((opts) => {
    const { get, set, remove, maskApiKey, showConfig, GLOBAL_CONFIG } =
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
        console.error(`\n${RED}✗ Ogiltig API-nyckel.${RESET}`);
        console.error(`  Anthropic API-nycklar börjar med ${DIM}sk-ant-${RESET}`);
        console.error(`  Hämta din nyckel på: ${CYAN}https://console.anthropic.com/settings/keys${RESET}\n`);
        process.exit(1);
      }

      set('ANTHROPIC_API_KEY', key);
      console.log(`\n${GREEN}✓ API-nyckel sparad${RESET} → ${DIM}${GLOBAL_CONFIG}${RESET}`);
      console.log(`  ${DIM}${maskApiKey(key)}${RESET}`);
      console.log(`\n  ${DIM}Använd 'sc scan --deep' för att aktivera Claude-analys.${RESET}\n`);
      process.exit(0);
    }

    // ── --clear-api-key ───────────────────────────────────────────────────
    if (opts.clearApiKey) {
      const removed = remove('ANTHROPIC_API_KEY');
      if (removed) {
        console.log(`\n${GREEN}✓ API-nyckel borttagen${RESET} från ${DIM}${GLOBAL_CONFIG}${RESET}\n`);
      } else {
        console.log(`\n${DIM}Ingen API-nyckel att ta bort.${RESET}\n`);
      }
      process.exit(0);
    }

    // ── --show (default om inga flaggor) ──────────────────────────────────
    const info = showConfig();

    console.log(`\n${CYAN}${BOLD}Security Co-Pilot – Global konfiguration${RESET}\n`);
    console.log(`  Konfigfil:    ${DIM}${info.configPath}${RESET}`);
    console.log(`  Filen finns:  ${info.exists ? GREEN + 'ja' : DIM + 'nej (inga inställningar sparade)'}${RESET}`);
    console.log('');
    console.log(`  API-nyckel:   ${info.apiKey}`);
    console.log(`  Källa:        ${DIM}${info.apiKeySource}${RESET}`);
    console.log('');

    if (!info.apiKeySource || info.apiKeySource === '(inte satt)') {
      console.log(`  ${DIM}Sätt API-nyckel:  sc configure --api-key sk-ant-...${RESET}`);
      console.log(`  ${DIM}Alternativt:     export ANTHROPIC_API_KEY="sk-ant-..."${RESET}`);
    } else {
      console.log(`  ${DIM}Rensa nyckel:    sc configure --clear-api-key${RESET}`);
      console.log(`  ${DIM}Djupanalys:      sc scan --deep${RESET}`);
    }
    console.log('');
  });




// ── sc list ────────────────────────────────────────────────────────────────
program
  .command('list')
  .description('List all repos known to Security Co-Pilot')
  .option('--json', 'Output as JSON')
  .action((opts) => {
    const store = require('../lib/store');
    const repos = store.listRepos();

    if (opts.json) {
      console.log(JSON.stringify(repos, null, 2));
      return;
    }

    if (repos.length === 0) {
      console.log('\n\x1b[90m No repos found. Run sc init in a project to get started.\x1b[0m\n');
      return;
    }

    const { cacheAge } = require('../lib/scan-cache');

    console.log('\n\x1b[1mSecurity Co-Pilot – Known repos\x1b[0m');
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


// ── sc store ───────────────────────────────────────────────────────────────
program
  .command('store')
  .description('Show and navigate the store for the current repo')
  .option('--open',         'Open store folder in Finder / Explorer / file manager')
  .option('--open-reports', 'Open reports folder')
  .option('--reports',      'List saved reports for this repo')
  .option('--path',         'Print store path (for scripting)')
  .option('--show',         'Show full meta.json info for the current repo')
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
        console.log('\n\x1b[33m No meta.json found for this repo.\x1b[0m');
        console.log(DIM + ' Run sc init to register this repo.\n' + RESET);
        return;
      }

      const { cacheAge } = require('../lib/scan-cache');

      console.log('\n' + BOLD + 'Security Co-Pilot – Repo meta' + RESET);
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
      console.log('\n\x1b[1mSecurity Co-Pilot – Store verify\x1b[0m');
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
        console.log('\n\x1b[90m No reports found. Run sc report to generate one.\x1b[0m\n');
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

    console.log('\n\x1b[1mSecurity Co-Pilot – Store\x1b[0m');
    console.log('\x1b[90m' + '─'.repeat(52) + '\x1b[0m\n');
    console.log('  Repo:      \x1b[1m' + (meta?.name || path.basename(repoRoot)) + '\x1b[0m');
    if (identity.type === 'remote') {
      console.log('  Remote:    \x1b[90m' + identity.identifier + '\x1b[0m');
    } else {
      console.log('  Type:      \x1b[33mpath-based\x1b[0m (no git remote – ID may change if folder moves)');
    }
    console.log('  Store ID:  \x1b[90m' + store.getRepoId(repoRoot) + '\x1b[0m');
    console.log('  Location:  \x1b[36m' + dir + '\x1b[0m\n');

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
    console.log('  \x1b[90msc store --reports          list saved reports\x1b[0m');
    console.log('  \x1b[90msc store --open             open in file manager\x1b[0m');
    console.log('  \x1b[90msc store --open-reports     open reports folder\x1b[0m');
    console.log('  \x1b[90msc store --path             print path (for scripting)\x1b[0m');
    console.log('  \x1b[90msc store --show             show full meta info for current repo\x1b[0m');
    console.log('  \x1b[90msc store --verify           verify all repos exist on disk\x1b[0m');
    console.log('  \x1b[90msc store --verify --clean   interactive cleanup of stale repos\x1b[0m\n');
  });



// ── sc rules ───────────────────────────────────────────────────────────────
program
  .command('rules')
  .description('List, search and inspect Security Co-Pilot rules')
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
      console.log('\n' + BOLD + 'Security Co-Pilot – Rule stats' + RESET);
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
        console.log(DIM + ' Use sc rules --search <term> to find rules.\n' + RESET);
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
    console.log('\n' + BOLD + 'Security Co-Pilot – Rules' + (title ? '  ' + DIM + title + RESET : '') + RESET);
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
      '  sc rules --id <ID>          full detail for a rule\n' +
      '  sc rules --lang php         filter by language\n' +
      '  sc rules --severity critical filter by severity\n' +
      '  sc rules --search <term>    free-text search\n' +
      '  sc rules --stats            counts by severity / language / category\n' +
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


// ── sc version ────────────────────────────────────────────────────────────
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

    console.log('\n' + BOLD + 'Security Co-Pilot' + RESET);
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


program.parse(process.argv);



