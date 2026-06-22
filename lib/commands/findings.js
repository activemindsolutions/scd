'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN } = require('../output-constants');
// lib/commands/findings.js

module.exports = { register, findingsAction };

async function findingsAction(findingId, opts) {
      const fs = require('fs');
      const { loadCache, loadScan, cacheAge } = require('../scan-cache');
      const { loadFindingsWithBootstrap }     = require('../findings-store');
      const { findingsPathReadOnly }          = require('../store');
      const { getRuleById }                   = require('../rule-registry');
      const { formatLocalDate }               = require('../format-time');
      const { getRepoRoot } = require('../config');
      const { warnIfOutdated } = require('../cli-helpers');
      const repoRoot = getRepoRoot();


      const SEV_ICON  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', EXPOSURE: '🔷', INFO: '⬜' };
      const SEV_COLOR = { CRITICAL: RED, HIGH: YELLOW, MEDIUM: YELLOW, EXPOSURE: BLUE, INFO: DIM };

      // Map a findings.jsonl record (snake_case, minimal) to the display-shape
      // the rest of this command works against (camelCase + hydrated rule text).
      function recordToFinding(record) {
        const rule = getRuleById(record.rule_id);
        const out = {
          findingId:     record.finding_id,
          ruleId:        record.rule_id,
          filePath:      record.file,
          line:          record.line,
          codeHash:      record.code_hash,
          severity:      record.severity,
          base_severity: record.base_severity,
          confidence:    record.confidence,
          snippet:       record.snippet,
          // excepted is DERIVED at read time by the gatekeeper (reconcileException),
          // never persisted on a CLI record — the store only ever writes 'open' or
          // 'resolved'. Initialise false; the read-time re-eval below sets it.
          excepted:      false,
          resolved:      record.status === 'resolved',
          resolved_at:   record.resolved_at,
          // Store-side persistence fields — drive the "seen Nx · last Yh ago" indicator
          times_seen:    record.times_seen,
          first_seen:    record.first_seen,
          last_seen:     record.last_seen,
          // Hydrated from rule metadata — record stores only what cannot be derived
          name:          (rule && rule.name)      || record.rule_id,
          category:      (rule && rule.category)  || null,
          why:           (rule && rule.why)       || null,
          scenario:      (rule && rule.scenario)  || null,
          fix:           (rule && rule.fix)       || null,
          checklist:     (rule && rule.checklist) || null,
        };
        return out;
      }

      // Format the "seen Nx · Yh ago" indicator.
      // Returns an empty string for the trivial case (just-discovered: times_seen=1
      // and last_seen < 5 min) so brand-new findings stay quiet. Otherwise renders:
      //   times_seen > 1, recent  → "· seen 3× · 2 hours ago"
      //   times_seen > 1, > 30d   → "· seen 8× · since 2026-04-15"
      //   times_seen = 1, > 5 min → "· 30 minutes ago"
      function formatSeen(f) {
        if (!f.last_seen) return '';
        const ts = f.times_seen || 1;
        const lastAgeMs = Date.now() - new Date(f.last_seen).getTime();
        if (ts === 1 && lastAgeMs < 5 * 60 * 1000) return '';

        const firstAgeMs = f.first_seen
          ? Date.now() - new Date(f.first_seen).getTime()
          : lastAgeMs;
        const isLongLived = firstAgeMs > 30 * 24 * 60 * 60 * 1000;

        const timeRef = (isLongLived && f.first_seen)
          ? `since ${formatLocalDate(f.first_seen)}`
          : cacheAge(f.last_seen);
        const seenPart = ts > 1 ? `seen ${ts}× · ` : '';
        return `  ${DIM}· ${seenPart}${timeRef}${RESET}`;
      }

      // Load data — three modes:
      //   --scan <id>       → historic scan file (loadScan)
      //   --show-suppressed → cache (suppressed are not stored in findings.jsonl)
      //   default           → accumulated findings.jsonl + bootstrap-on-read
      let scan = null;
      let isHistoric    = false;
      let isAccumulated = false;
      let suppressedFromCache = 0;

      if (opts.scan) {
        scan = loadScan(repoRoot, opts.scan);
        isHistoric = true;
        if (!scan) {
          console.error(`\n${RED}❌ Scan not found: ${opts.scan}${RESET}`);
          console.error(`${DIM}   Run scd repo scans to list available scans${RESET}\n`);
          process.exit(1);
        }
      } else if (opts.showSuppressed) {
        scan = loadCache(repoRoot);
        if (!scan) {
          console.error(`\n${RED}❌ No scan found for this repo.${RESET}`);
          console.error(`${DIM}   Run scd scan first${RESET}\n`);
          process.exit(1);
        }
      } else {
        isAccumulated = true;
        const storeExists = fs.existsSync(findingsPathReadOnly(repoRoot));
        const cache       = loadCache(repoRoot);
        if (!storeExists && !cache) {
          console.error(`\n${RED}❌ No scan found for this repo.${RESET}`);
          console.error(`${DIM}   Run scd scan first${RESET}\n`);
          process.exit(1);
        }
        const result = loadFindingsWithBootstrap(repoRoot);
        scan = {
          findings:            result.records.map(recordToFinding),
          scanDate:            result.lastScanDate,
          scanId:              null,
          suppressed_findings: [],
        };
        if (cache) suppressedFromCache = (cache.suppressed_findings || []).length;
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
      const showExcepted = opts.excepted || opts.showExcepted;   // --show-excepted aliases --excepted
      const showAll      = opts.all || showExcepted || !!findingId; // single finding searches all
      const showVerbose  = opts.verbose || !!findingId; // single finding always verbose
      const scanAge      = scan.scanDate ? cacheAge(scan.scanDate) : 'unknown';

      // Re-evaluate exception status against current config.yml — a finding may have been
      // accepted/ignored (or had its exception removed) since the last scan.
      let expiringSoonCount = 0;   // E1c.3 — exceptions nearing their review deadline
      if (!isHistoric && repoRoot) {
        try {
          const { loadExceptionsWithBootstrap } = require('../exceptions-store');
          const { reconcileException, effectiveExpiry } = require('../exception-gatekeeper');
          // Run 2 read-truth: exceptions come from the machine-local store
          // (bootstrap-on-read migrates config.yml → exceptions.jsonl on first read).
          const exceptions = loadExceptionsWithBootstrap(repoRoot).records;
          // Derive from scratch through the single gatekeeper — bidirectional:
          // sets excepted/rejected true on a match AND clears a stale excepted/rejected
          // when the exception no longer exists. Never trusts the incoming flag.
          findings = findings.map(f => {
            const result = reconcileException(f, exceptions);
            return { ...f, excepted: result.excepted, rejected: result.rejected };
          });
          // Warn before expiry (E1c.3): count active exceptions expiring within 7 days.
          const now = Date.now(), soon = now + 7 * 86400000;
          for (const e of exceptions) {
            if (e.archived_at) continue;
            const exp = effectiveExpiry(e);
            if (exp && exp.getTime() > now && exp.getTime() <= soon) expiringSoonCount++;
          }
        } catch { /* non-fatal — fall back to cached values */ }
      }

      // If a specific findingId was given, filter to that one finding and show verbose
      if (findingId) {
        findings = findings.filter(f => f.findingId === findingId);
        if (findings.length === 0) {
          console.error(`\n${RED}❌ Finding ${findingId} not found in this scan.${RESET}`);
          console.error(`${DIM}   Run scd findings to see all finding IDs${RESET}\n`);
          process.exit(1);
        }
      }

      // Count excepted findings up front (post-reconciliation) so the default
      // view can surface a hint instead of hiding them silently — parity with the
      // suppressed-findings hint below.
      const exceptedCount = findings.filter(f => f.excepted).length;

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
      const scanLabel = opts.scan
        ? `Scan ${scan.scanId}`
        : isAccumulated
          ? `Accumulated · last scan ${scanAge}`
          : `Last scan`;
      const modeLabel = findingId
        ? `finding ${findingId}`
        : showExcepted ? 'excepted findings' : showAll ? 'all findings' : 'open findings only';
      const headerAge = isAccumulated ? '' : ` · ${scanAge}`;
      console.log(`\n${BOLD}Findings${RESET}  ${DIM}${scanLabel}${headerAge} · ${modeLabel}${RESET}`);
      if (!showAll) {
        console.log(`${DIM}  Showing unhandled findings. Use --all to include excepted and resolved.${RESET}`);
      }
      if (isHistoric && opts.open) {
        console.log(`${YELLOW}  Note: --open on a historic scan reflects exception status at scan time.${RESET}`);
      }
      // Hint about excepted findings hidden by the default view — not silent
      // (parity with the suppressed hint). Only in the default --open listing.
      if (!showAll && exceptedCount > 0) {
        console.log(`${DIM}  ${exceptedCount} finding(s) excepted  ·  scd findings --excepted${RESET}`);
      }
      // Warn before expiry (E1c.3): exceptions nearing their review deadline.
      if (expiringSoonCount > 0) {
        console.log(`${YELLOW}  ⚠ ${expiringSoonCount} exception(s) expiring within 7 days${RESET}${DIM}  ·  scd exceptions${RESET}`);
      }
      // Hint about suppressed findings — accumulated mode reads count from cache
      // (suppressed findings are not persisted in findings.jsonl by design)
      const suppressedCount = isAccumulated
        ? suppressedFromCache
        : (scan.suppressed_findings || []).length;
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

      // Sort files by their worst severity (lowest SEV_ORDER = most critical first).
      // Tie-break alphabetically so output is stable across runs.
      const fileEntries = Object.entries(byFile).map(([fp, list]) => {
        const worst = list.reduce(
          (acc, f) => Math.min(acc, SEV_ORDER[f.severity] ?? 9), 9);
        return [fp, list, worst];
      }).sort((a, b) => (a[2] - b[2]) || a[0].localeCompare(b[0]));

      // Dynamic snippet truncation: use terminal width when available (TTY),
      // fall back to 80 cols for non-TTY (CI logs, redirected output).
      const termWidth = process.stdout.columns || 80;
      const snipLimit = Math.max(60, termWidth - 10);

      for (const [filePath, filefindings] of fileEntries) {
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
          const seen = formatSeen(f);
          console.log(`    ${icon}  ${color}${f.name}${RESET}  ${DIM}${f.ruleId}${line}${RESET}${fid}${exc}${res}${sevDowngrade}${seen}`);
          if (f.snippet && f.snippet !== '[REDACTED]') {
            const snip = f.snippet.trim().slice(0, snipLimit);
            console.log(`       ${DIM}${snip}${snip.length === snipLimit ? '…' : ''}${RESET}`);
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
      if (findings.length > 0 && !showVerbose) {
        console.log(`${DIM}  --verbose for problem/scenario/fix  ·  --rule <id> or --severity <level> to filter${RESET}`);
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
    .option('--show-excepted',    'Alias for --excepted')
    .option('--show-suppressed',  'Show findings suppressed by file context (test files, vendor code, etc.)')
    .option('--verbose',          'Show problem description, attack scenario, and fix for each finding')
    .action(async (findingId, opts) => {
      await findingsAction(findingId, opts);
    });
}
