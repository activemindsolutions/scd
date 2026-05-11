'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN } = require('../output-constants');
// lib/commands/findings.js

module.exports = { register, findingsAction };

async function findingsAction(findingId, opts) {
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
          console.error(`${DIM}   Run scd repo scans to list available scans${RESET}\n`);
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

      // ── --show-suppressed mode ─────────────────────────────────────────────
      // Entirely separate display path — suppressed findings are a different data
      // set with different fields (base_severity, context_modifiers, suppress_reason).
      if (opts.showSuppressed) {
        const suppressed = scan.suppressed_findings || [];
        const scanAge    = scan.scanDate ? cacheAge(scan.scanDate) : 'unknown';
        const scanLabel  = opts.scan ? `Scan ${scan.scanId}` : 'Last scan';

        console.log(`\n${BOLD}Suppressed Findings${RESET}  ${DIM}${scanLabel} · ${scanAge} · suppressed by file context${RESET}`);
        console.log(`${DIM}  These findings were detected but suppressed — their effective severity fell below threshold.${RESET}`);
        console.log(`${DIM}${'─'.repeat(64)}${RESET}\n`);

        if (suppressed.length === 0) {
          console.log(`${DIM}  No suppressed findings in this scan.${RESET}\n`);
          return;
        }

        // Apply --rule filter if given
        let toShow = suppressed;
        if (opts.rule) {
          toShow = toShow.filter(f => f.ruleId === opts.rule);
        }

        // Group by file
        const byFile = {};
        for (const f of toShow) {
          if (!byFile[f.filePath]) byFile[f.filePath] = [];
          byFile[f.filePath].push(f);
        }

        for (const [filePath, fileFindings] of Object.entries(byFile).sort()) {
          console.log(`  ${BOLD}${filePath}${RESET}`);
          for (const f of fileFindings) {
            const baseSev  = f.base_severity || '?';
            const basIcon  = SEV_ICON[baseSev]  || '⬜';
            const basColor = SEV_COLOR[baseSev] || DIM;
            const fid      = f.findingId ? `  ${DIM}${f.findingId}${RESET}` : '';
            const line     = f.line      ? `:${f.line}` : '';
            // Show base severity (what the rule said) → suppressed
            console.log(`    ${basIcon}  ${basColor}${f.name}${RESET}  ${DIM}${f.ruleId}${line}${RESET}${fid}  ${DIM}[suppressed]${RESET}`);
            if (f.snippet && f.snippet !== '[REDACTED]') {
              const snip = f.snippet.trim().slice(0, 80);
              console.log(`       ${DIM}${snip}${snip.length === 80 ? '…' : ''}${RESET}`);
            }
            // File context that drove suppression
            if (f.file_context) {
              const fc = f.file_context;
              const fcParts = [fc.file_type];
              if (fc.test_framework) fcParts.push(fc.test_framework);
              if (fc.language)       fcParts.push(fc.language);
              console.log(`       ${DIM}context: ${fcParts.join(' · ')}${RESET}`);
            }
            // Show each modifier that contributed
            if (f.context_modifiers && f.context_modifiers.length > 0) {
              for (const m of f.context_modifiers) {
                console.log(`       ${DIM}modifier: ${m.signal}  (${m.modifier})${RESET}`);
              }
            }
            // Suppress reason
            if (f.suppress_reason) {
              console.log(`       ${DIM}reason: ${f.suppress_reason}${RESET}`);
            }
            console.log('');
          }
          console.log('');
        }

        console.log(`${DIM}  ${toShow.length} suppressed finding(s)${RESET}`);
        console.log(`${DIM}  Base severity shown — effective score fell to ≤ 0 after context modifiers.${RESET}\n`);
        return;
      }

      // ── Normal findings mode ───────────────────────────────────────────────

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
      // Hint about suppressed findings if any exist in this scan
      const suppressedCount = (scan.suppressed_findings || []).length;
      if (suppressedCount > 0) {
        console.log(`${DIM}  ${suppressedCount} finding(s) suppressed by file context  ·  scd findings --show-suppressed${RESET}`);
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
          // Show severity downgrade hint when context modifiers reduced severity
          const sevDowngrade = (f.base_severity && f.base_severity !== f.severity)
            ? `  ${DIM}↓ ${f.base_severity} → ${f.severity}${RESET}`
            : '';
          console.log(`    ${icon}  ${color}${f.name}${RESET}  ${DIM}${f.ruleId}${line}${RESET}${fid}${exc}${res}${sevDowngrade}`);
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
            // Show context modifiers in verbose mode when severity was adjusted
            if (f.context_modifiers && f.context_modifiers.length > 0) {
              console.log(`\n       ${BOLD}File context${RESET}`);
              for (const m of f.context_modifiers) {
                console.log(`       ${DIM}${m.signal}  (${m.modifier})${RESET}`);
              }
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
}

function register(program) {
  program
    .command('findings [findingId]')
    .description('List findings from the last scan (default: open/unhandled only)')
    .option('--all',              'Show all findings including excepted and resolved')
    .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
    .option('--rule <id>',        'Filter by rule ID (e.g. JS-ERR-002)')
    .option('--scan <id>',        'Load a specific scan by ID instead of last scan')
    .option('--excepted',         'Show only excepted findings')
    .option('--show-suppressed',  'Show findings suppressed by file context (test files, vendor code, etc.)')
    .option('--verbose',          'Show problem description, attack scenario, and fix for each finding')
    .action(async (findingId, opts) => {
      await findingsAction(findingId, opts);
    });
}
