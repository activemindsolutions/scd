'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN } = require('../output-constants');
// lib/commands/findings.js

module.exports = { register };

function register(program) {
  program
    .command('findings [findingId]')
    .description('List findings from the last scan (default: open/unhandled only)')
    .option('--all',              'Show all findings including excepted and resolved')
    .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
    .option('--rule <id>',        'Filter by rule ID (e.g. JS-ERR-002)')
    .option('--scan <id>',        'Load a specific scan by ID instead of last scan')
    .option('--excepted',         'Show only excepted findings')
    .option('--verbose',          'Show problem description, attack scenario, and fix for each finding')
    .action(async (findingId, opts) => {
      const { loadCache, loadScan, cacheAge } = require('../scan-cache');
      const { getRepoRoot } = require('../config');
      const { warnIfOutdated } = require('../cli-helpers');
      const repoRoot = getRepoRoot();


      const SEV_ICON  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', EXPOSURE: '🔷', INFO: '⬜' };
      const SEV_COLOR = { CRITICAL: RED, HIGH: YELLOW, MEDIUM: YELLOW, EXPOSURE: BLUE, INFO: DIM };

      // Load scan data
      let scan = null;
      let isHistoric = false;
      if (opts.scan) {
        scan = loadScan(repoRoot, opts.scan);
        isHistoric = true;
        if (!scan) {
          console.error(`\nRED❌ Scan not found: ${opts.scan}${RESET}`);
          console.error(`${DIM}   Run scd repo --scans to list available scans${RESET}\n`);
          process.exit(1);
        }
      } else {
        scan = loadCache(repoRoot);
        if (!scan) {
          console.error(`\nRED❌ No scan found for this repo.${RESET}`);
          console.error(`${DIM}   Run scd scan first${RESET}\n`);
          process.exit(1);
        }
      }

      let findings = scan.findings || [];
      const showAll      = opts.all || opts.excepted || !!findingId; // single finding searches all
      const showExcepted = opts.excepted;
      const showVerbose  = opts.verbose || !!findingId; // single finding always verbose
      const scanAge      = scan.scanDate ? cacheAge(scan.scanDate) : 'unknown';

      // Re-evaluate exception status against current config.yml — a finding may have been
      // accepted/ignored since the last scan without re-running the scan.
      if (!isHistoric && repoRoot) {
        try {
          const { loadConfig, isExcepted } = require('../config');
          const cfg = loadConfig(repoRoot);
          findings = findings.map(f => {
            if (f.excepted) return f; // already marked excepted in cache
            const lineContent = f.snippet && f.snippet !== '[REDACTED]' ? f.snippet : null;
            const result = isExcepted(cfg, f, lineContent);
            if (result.excepted) return { ...f, excepted: true };
            if (result.rejected) return { ...f, rejected: true };
            return f;
          });
        } catch { /* non-fatal — fall back to cached values */ }
      }

      // If a specific findingId was given, filter to that one finding and show verbose
      if (findingId) {
        findings = findings.filter(f => f.findingId === findingId);
        if (findings.length === 0) {
          console.error(`\nRED❌ Finding ${findingId} not found in this scan.${RESET}`);
          console.error(`${DIM}   Run scd findings to see all finding IDs${RESET}\n`);
          process.exit(1);
        }
      }

      // Apply --open filter (default) — exclude excepted and resolved
      if (!showAll) {
        findings = findings.filter(f => !f.excepted && !f.resolved);
      }

      // Apply --excepted filter
      if (showExcepted) {
        findings = findings.filter(f => f.excepted);
      }

      // Apply --severity filter
      if (opts.severity) {
        const sev = opts.severity.toUpperCase();
        findings = findings.filter(f => f.severity === sev);
      }

      // Apply --rule filter
      if (opts.rule) {
        findings = findings.filter(f => f.ruleId === opts.rule);
      }

      // Header
      const scanLabel = opts.scan ? `Scan ${scan.scanId}` : `Last scan`;
      const modeLabel = findingId
        ? `finding ${findingId}`
        : showExcepted ? 'excepted findings' : showAll ? 'all findings' : 'open findings only';
      console.log(`\n${BOLD}Findings${RESET}  ${DIM}${scanLabel} · ${scanAge} · ${modeLabel}${RESET}`);
      if (!showAll) {
        console.log(`${DIM}  Showing unhandled findings. Use --all to include excepted and resolved.${RESET}`);
      }
      if (isHistoric && opts.open) {
        console.log(`${YELLOW}  Note: --open on a historic scan reflects exception status at scan time.${RESET}`);
      }
      console.log(`${DIM}${'─'.repeat(64)}${RESET}\n`);

      if (findings.length === 0) {
        if (showExcepted) {
          console.log(`${DIM}  No excepted findings in this scan.${RESET}\n`);
        } else if (!showAll) {
          console.log(`${GREEN}  ✅ No open findings.${RESET}${opts.severity || opts.rule ? '' : ' All findings are excepted or resolved.'}\n`);
        } else {
          console.log(`${DIM}  No findings match the current filters.${RESET}\n`);
        }
        return;
      }

      // Group by file
      const byFile = {};
      for (const f of findings) {
        if (!byFile[f.filePath]) byFile[f.filePath] = [];
        byFile[f.filePath].push(f);
      }

      const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, INFO: 4 };

      for (const [filePath, filefindings] of Object.entries(byFile).sort()) {
        console.log(`  ${BOLD}${filePath}${RESET}`);
        const sorted = [...filefindings].sort((a, b) =>
          (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
        );
        for (const f of sorted) {
          const icon  = SEV_ICON[f.severity]  || '⬜';
          const color = SEV_COLOR[f.severity] || DIM;
          const fid   = f.findingId ? `  ${DIM}${f.findingId}${RESET}` : '';
          const exc   = f.excepted  ? `  ${DIM}[excepted]${RESET}` : '';
          const res   = f.resolved  ? `  ${DIM}[resolved]${RESET}` : '';
          const line  = f.line      ? `:${f.line}` : '';
          console.log(`    ${icon}  ${color}${f.name}${RESET}  ${DIM}${f.ruleId}${line}${RESET}${fid}${exc}${res}`);
          if (f.snippet && f.snippet !== '[REDACTED]') {
            const snip = f.snippet.trim().slice(0, 80);
            console.log(`       ${DIM}${snip}${snip.length === 80 ? '…' : ''}${RESET}`);
          }
          if (showVerbose) {
            if (f.why) {
              console.log(`\n       ${BOLD}Problem${RESET}`);
              const whyWords = f.why.split(' ');
              let whyLine = '       ';
              for (const word of whyWords) {
                if (whyLine.length + word.length > 79) { console.log(whyLine); whyLine = '       ' + word + ' '; }
                else whyLine += word + ' ';
              }
              if (whyLine.trim()) console.log(whyLine);
            }
            if (f.scenario) {
              console.log(`\n       ${BOLD}Scenario${RESET}`);
              // Word-wrap at 72 chars
              const words = f.scenario.split(' ');
              let line2 = '       ';
              for (const word of words) {
                if (line2.length + word.length > 79) {
                  console.log(line2);
                  line2 = '       ' + word + ' ';
                } else {
                  line2 += word + ' ';
                }
              }
              if (line2.trim()) console.log(line2);
            }
            if (f.fix) {
              console.log(`\n       ${BOLD}Fix${RESET}`);
              const words = f.fix.split(' ');
              let line2 = '       ';
              for (const word of words) {
                if (line2.length + word.length > 79) {
                  console.log(line2);
                  line2 = '       ' + word + ' ';
                } else {
                  line2 += word + ' ';
                }
              }
              if (line2.trim()) console.log(line2);
            }
            console.log('');
          }
        }
        console.log('');
      }

      // Summary + hints
      const counts = {};
      for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
      const parts = ['CRITICAL','HIGH','MEDIUM','EXPOSURE']
        .filter(s => counts[s])
        .map(s => `${SEV_ICON[s]} ${counts[s]} ${s.toLowerCase()}`);
      console.log(`${DIM}  ${findings.length} finding(s)${parts.length ? ': ' + parts.join('  ') : ''}${RESET}`);
      if (!showAll && !showExcepted && findings.length > 0) {
        console.log(`${DIM}  scd accept <finding-id> --reason "..."   or   scd ignore <finding-id> --reason "..."${RESET}`);
      }
      console.log('');
      warnIfOutdated();
    });
}
