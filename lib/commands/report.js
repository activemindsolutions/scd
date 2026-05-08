'use strict';
const { RESET, DIM, GREEN, CYAN, RED } = require('../output-constants');
// lib/commands/report.js

module.exports = { register };

// ── shared: load scan cache ───────────────────────────────────────────────────
function loadReportCache(repoRoot, scanId) {
  const { loadCache, loadScan } = require('../scan-cache');
  if (scanId) {
    const cache = loadScan(repoRoot, scanId);
    if (!cache) {
      console.error('\n' + RED + '✗ Scan not found: ' + scanId + RESET);
      console.error('  Run ' + CYAN + 'scd repo scans' + RESET + ' to list available scans.\n');
      process.exit(1);
    }
    return cache;
  }
  const cache = loadCache(repoRoot);
  if (!cache) {
    console.error('\n' + RED + '✗ No saved scan found.' + RESET);
    console.error("  Run 'scd scan' first to generate findings to report from.\n");
    process.exit(1);
  }
  return cache;
}

// ── shared: generate report file ─────────────────────────────────────────────
async function generateReportFile(repoRoot, opts) {
  const path = require('path');
  const fs   = require('fs');
  const { cacheAge } = require('../scan-cache');
  const store = require('../store');

  const cache = loadReportCache(repoRoot, opts.scan);
  const { findings, target, totalFiles, skipped, scanDate, deepResults } = cache;
  const age    = cacheAge(scanDate);
  const deepMap = deepResults ? new Map(deepResults) : null;

  console.log('\n' + DIM + '↺ Using cached scan from ' + age + ' (' + new Date(scanDate).toLocaleString('en-SE') + ')' + RESET);
  console.log('  Target: ' + target + '  ·  ' + findings.length + ' findings  ·  ' + totalFiles + ' files' +
    (deepMap && deepMap.size > 0 ? '  ·  ' + CYAN + 'deep analysis included' + RESET : '') + '\n');

  const fmt       = (opts.format || 'html').toLowerCase();
  const scanIdStr = cache.scanId || new Date(scanDate).toISOString().slice(0,19).replace(/:/g,'-');
  const ext       = fmt === 'markdown' ? 'md' : fmt;
  const defaultName = 'security-report-' + scanIdStr + '.' + ext;
  const outPath   = opts.output
    ? path.resolve(process.cwd(), opts.output)
    : store.reportPath(repoRoot, defaultName);

  const metaPath = path.join(store.storeDir(repoRoot), 'meta.json');
  let repoName = null;
  try { repoName = JSON.parse(fs.readFileSync(metaPath, 'utf8')).name || null; } catch {}
  if (!repoName) repoName = path.basename(path.resolve(repoRoot));

  const reportOpts = {
    target, repoName,
    scanDate:    new Date(scanDate),
    totalFiles,
    skipped:     skipped || [],
    repoRoot,
    deepResults: deepMap,
  };

  if (fmt === 'json') {
    const { generateJson, writeJson } = require('../report-json');
    writeJson(generateJson(findings, reportOpts), outPath);
    console.log(GREEN + '✓ JSON report saved:' + RESET + ' ' + CYAN + outPath + RESET + '\n');
    return { outPath, fmt };
  }

  if (fmt === 'md' || fmt === 'markdown') {
    const { generateMarkdown, writeMarkdown } = require('../report-markdown');
    writeMarkdown(generateMarkdown(findings, reportOpts), outPath);
    console.log(GREEN + '✓ Markdown report saved:' + RESET + ' ' + CYAN + outPath + RESET + '\n');
    return { outPath, fmt };
  }

  // HTML (default)
  const { generateReport, writeReport } = require('../report-html');
  writeReport(generateReport(findings, reportOpts), outPath);

  const term = process.env.TERM_PROGRAM || '';
  const supportsOsc8 = ['iTerm.app', 'vscode', 'WarpTerminal', 'ghostty', 'JetBrains'].some(t => term.includes(t));
  const fileUri = 'file://' + outPath;
  if (supportsOsc8) {
    const osc8Link = '\x1b]8;;' + fileUri + '\x07' + outPath + '\x1b]8;;\x07';
    console.log(GREEN + '✓ HTML report:' + RESET + ' ' + CYAN + osc8Link + RESET);
  } else {
    console.log(GREEN + '✓ HTML report:' + RESET + ' ' + CYAN + outPath + RESET);
  }

  return { outPath, fmt };
}

// ── shared: HTTP server logic ─────────────────────────────────────────────────
async function serveReport(repoRoot, outPath, opts) {
  const http = require('http');
  const fs   = require('fs');
  const path = require('path');
  const { buildIndexPage } = require('../report-index');
  const { openInBrowser }  = require('../cli-helpers');
  const store = require('../store');

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

    if (url === '/download-all') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<p style="font-family:monospace;padding:2rem;background:#0a0f1a;color:#e2e8f0">' +
        'Reports folder: <code>' + reportDir + '</code></p>');
      return;
    }
    if (url.startsWith('/download/')) {
      const fname = path.basename(url.slice('/download/'.length));
      const fpath = path.join(reportDir, fname);
      if (!fpath.startsWith(reportDir) || !fs.existsSync(fpath)) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + fname + '"' });
      fs.createReadStream(fpath).pipe(res);
      return;
    }
    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(buildIndexPage(allReports, reportDir, reportFile));
      return;
    }
    const fname = path.basename(url);
    const fpath = path.join(reportDir, fname);
    if (!fpath.startsWith(reportDir) || !fs.existsSync(fpath)) { res.writeHead(404); res.end('Not found'); return; }
    const ext  = path.extname(fpath).toLowerCase();
    const mime = { '.html': 'text/html', '.json': 'application/json', '.md': 'text/plain' }[ext] || 'text/plain';
    res.writeHead(200, { 'Content-Type': mime + '; charset=utf-8' });
    fs.createReadStream(fpath).pipe(res);
  });

  server.listen(port, '127.0.0.1', () => {
    const openUrl = showIndex ? baseUrl + '/' : baseUrl + '/' + encodeURIComponent(reportFile);
    if (showIndex) {
      console.log(CYAN + '⇢  Report index: ' + baseUrl + '/' + RESET);
      console.log(DIM + '   ' + allReports.length + ' report' + (allReports.length !== 1 ? 's' : '') + ' available' + RESET);
    } else {
      console.log(CYAN + '⇢  Serving report: ' + openUrl + RESET);
    }
    openInBrowser(openUrl);
    console.log(DIM + '   Press any key to stop the server…' + RESET);
  });

  await new Promise((resolve) => {
    const cleanup = () => {
      server.close();
      try { process.stdin.pause(); if (process.stdin.setRawMode) process.stdin.setRawMode(false); } catch {}
      console.log(DIM + '   Server stopped.' + RESET + '\n');
      resolve();
    };
    const hasRawMode = process.stdin.isTTY && typeof process.stdin.setRawMode === 'function';
    if (hasRawMode) {
      try { process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.once('data', cleanup); }
      catch { console.log(DIM + '   Press Ctrl-C to stop the server.' + RESET); }
    } else {
      console.log(DIM + '   Press Enter or Ctrl-C to stop the server.' + RESET);
      process.stdin.resume();
      process.stdin.once('data', cleanup);
    }
    process.once('SIGINT', cleanup);
  });
}

function register(program) {
  const { Command } = require('commander');

  const reportCmd = new Command('report')
    .description('Generate HTML, Markdown or JSON report from the last scan (without re-scanning)')
    .option('--format <fmt>', 'Output format: html (default), md, json', 'html')
    .option('--output <file>', 'Save to specified file (default: ~/.scd/repos/{id}/reports/security-report-{id}.html)')
    .option('--scan <id>',     'Generate report from a specific scan ID (scd repo scans to list)')
    .action(async (opts) => {
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      await generateReportFile(repoRoot, opts);
      console.log();
    });

  // ── scd report open ───────────────────────────────────────────────────────
  const reportOpenCmd = new Command('open')
    .description('Generate report and open in browser')
    .option('--format <fmt>', 'Output format: html (default), md, json', 'html')
    .option('--output <file>', 'Save to specified file')
    .option('--scan <id>',     'Use a specific scan ID')
    .action(async (opts) => {
      const { getRepoRoot } = require('../config');
      const { openInBrowser } = require('../cli-helpers');
      const repoRoot = getRepoRoot();
      const { outPath } = await generateReportFile(repoRoot, opts);
      openInBrowser(outPath);
      console.log();
    });

  // ── scd report serve ──────────────────────────────────────────────────────
  const reportServeCmd = new Command('serve')
    .description('Generate report and serve via local HTTP server (works on all platforms)')
    .option('--format <fmt>', 'Output format: html (default), md, json', 'html')
    .option('--output <file>', 'Save to specified file')
    .option('--scan <id>',     'Use a specific scan ID')
    .option('--port <port>',   'Port for HTTP server (default: random available port)')
    .option('--index',         'Always show report index page')
    .action(async (opts) => {
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      const { outPath } = await generateReportFile(repoRoot, opts);
      await serveReport(repoRoot, outPath, opts);
    });

  reportCmd.addCommand(reportOpenCmd);
  reportCmd.addCommand(reportServeCmd);
  program.addCommand(reportCmd);
}
