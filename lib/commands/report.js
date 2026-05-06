'use strict';
// lib/commands/report.js

module.exports = { register };

function register(program) {
  program
    .command('report')
    .description('Generate HTML, Markdown or JSON report from the last scan (without re-scanning)')
    .option('--format <fmt>', 'html (default), md, json', 'html')
    .option('--output <file>', 'Spara till angiven fil (default: security-report-DATUM.html)')
    .option('--open',          'Open report in browser after generating (macOS/Windows)')
    .option('--serve',         'Serve report via local HTTP server and open in browser (works on all platforms)')
    .option('--port <port>',   'Port for --serve (default: random available port)')
    .option('--index',         'Always show report index page (use with --serve)')
    .option('--scan <id>',     'Generate report from a specific scan ID (scd repo --scans to list)')
    .action(async (opts) => {
      const path = require('path');
      const fs   = require('fs');
      const { getRepoRoot } = require('../config');
      const { loadCache, loadScan, cacheAge } = require('../scan-cache');
      const { openInBrowser } = require('../cli-helpers');
      const repoRoot = getRepoRoot();

      let cache;
      if (opts.scan) {
        cache = loadScan(repoRoot, opts.scan);
        if (!cache) {
          console.error('\n\x1b[31m✗ Scan not found: ' + opts.scan + '\x1b[0m');
          console.error('  Run \x1b[36mscd repo --scans\x1b[0m to list available scans.\n');
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
      const store   = require('../store');
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
        const { generateJson, writeJson } = require('../report-json');
        writeJson(generateJson(findings, reportOpts), outPath);
        console.log('\x1b[32m✓ JSON report saved:\x1b[0m \x1b[36m' + outPath + '\x1b[0m\n');
        process.exit(0);
      }

      if (fmt === 'md' || fmt === 'markdown') {
        const { generateMarkdown, writeMarkdown } = require('../report-markdown');
        writeMarkdown(generateMarkdown(findings, reportOpts), outPath);
        console.log('\x1b[32m✓ Markdown report saved:\x1b[0m \x1b[36m' + outPath + '\x1b[0m\n');
        process.exit(0);
      }

      // HTML (default)
      const { generateReport, writeReport } = require('../report-html');
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
        const { buildIndexPage } = require('../report-index');

        const store      = require('../store');
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

          openInBrowser(openUrl);
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
        openInBrowser(outPath);
      }

      console.log();
    });
}
