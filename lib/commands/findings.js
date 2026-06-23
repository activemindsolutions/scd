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
      const path = require('path');
      const { sevConfig, sevOrder } = require('../severity');
      const { sourceLink } = require('../terminal-links');

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
            const baseSev  = f.base_severity || 'INFO';
            const { color: basColor, tag: basTag } = sevConfig(baseSev);
            const idCell   = f.findingId ? `${basColor}${f.findingId.padEnd(12)}${RESET}  ` : '';
            const line     = f.line      ? `:${f.line}` : '';
            // Show base severity (what the rule said) → suppressed
            console.log(`    ${idCell}${basColor}${BOLD}${basTag.padEnd(4)}${RESET}  ${f.name}  ${DIM}${f.ruleId}${line}${RESET}  ${DIM}[suppressed]${RESET}`);
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
        console.log(`${YELLOW}  ⚠ ${exceptedCount} finding(s) excepted${RESET}${DIM}  ·  scd findings --excepted${RESET}`);
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

      // ── Render ──────────────────────────────────────────────────────────────
      // Default: severity-grouped (worst first) so the list reads top-down and can be
      // stopped after CRITICAL/HIGH. `--by-file` keeps the file-grouped view. Each
      // finding is one aligned row led by its finding-id (severity-coloured, OSC8-linked
      // to the source line); the snippet + problem/scenario/fix move to --verbose (and
      // the single-finding view, which is always verbose).
      const termWidth = process.stdout.columns || 100;
      const snipLimit = Math.max(60, termWidth - 10);

      // Short churn indicator for the one-line row: "23×" (times seen), or
      // "8× · since 2026-04-15" for a finding that has lingered > 30 days.
      function seenCompact(f) {
        if (!f.last_seen) return '';
        const ts = f.times_seen || 1;
        const firstAgeMs = f.first_seen ? Date.now() - new Date(f.first_seen).getTime() : 0;
        if (firstAgeMs > 30 * 86400000 && f.first_seen) return `${ts}× · since ${formatLocalDate(f.first_seen)}`;
        return ts > 1 ? `${ts}×` : '';
      }

      // Title column width for a group — aligns the meta column without over-padding
      // short titles or letting a long one blow past the terminal width.
      function titleWidth(list) {
        const longest = list.reduce((m, f) => Math.max(m, (f.name || f.ruleId).length), 0);
        return Math.max(20, Math.min(54, longest, termWidth - 46));
      }

      // Verbose detail under a row (snippet + problem/scenario/fix + file context).
      // Verbose-only: the default list stays one line per finding.
      function renderDetail(f) {
        if (!showVerbose) return;
        if (f.snippet && f.snippet !== '[REDACTED]') {
          const snip = f.snippet.trim().slice(0, snipLimit);
          console.log(`       ${DIM}${snip}${snip.length === snipLimit ? '…' : ''}${RESET}`);
        }
        const wrap = (label, text) => {
          if (!text) return;
          console.log(`\n       ${BOLD}${label}${RESET}`);
          let buf = '       ';
          for (const word of text.split(' ')) {
            if (buf.length + word.length > 79) { console.log(buf); buf = '       ' + word + ' '; }
            else buf += word + ' ';
          }
          if (buf.trim()) console.log(buf);
        };
        wrap('Problem', f.why);
        wrap('Scenario', f.scenario);
        wrap('Fix', f.fix);
        if (f.context_modifiers && f.context_modifiers.length > 0) {
          console.log(`\n       ${BOLD}File context${RESET}`);
          for (const m of f.context_modifiers) console.log(`       ${DIM}${m.signal}  (${m.modifier})${RESET}`);
        }
        console.log('');
      }

      // One aligned finding row. `showFile` puts file:line in the meta column
      // (severity-grouped view); otherwise rule:line (file-grouped — file is the group
      // header). Finding-id leads, severity-coloured + OSC8-linked to the source.
      function renderRow(f, titleW, showFile) {
        const { color, tag } = sevConfig(f.severity);
        // Finding-id leads as plain (severity-coloured) text — easy to select/copy.
        // Click-to-run a command needs a custom URL scheme + OS handler (tracked future).
        const idCell = f.findingId
          ? `${color}${f.findingId.padEnd(12)}${RESET}`
          : ' '.repeat(12);
        let title = f.name || f.ruleId;
        if (title.length > titleW) title = title.slice(0, titleW - 1) + '…';
        const line  = f.line ? `:${f.line}` : '';
        // severity-grouped: file:line locates it and is OSC8-linked to the source
        // (CMD/Ctrl+click opens the code), rule-id trails for --rule context.
        // file-grouped: file is the linked group header, so the locator is rule:line.
        const idAbs = repoRoot ? path.resolve(repoRoot, f.filePath) : f.filePath;
        const meta  = showFile ? sourceLink(idAbs, `${f.filePath}${line}`) : `${f.ruleId}${line}`;
        const ruleCell = showFile ? `  ${DIM}${f.ruleId}${RESET}` : '';
        const flags = (f.excepted ? `  ${DIM}[excepted]${RESET}` : '') +
                      (f.resolved ? `  ${DIM}[resolved]${RESET}` : '');
        const down  = (f.base_severity && f.base_severity !== f.severity)
          ? `  ${DIM}↓${f.base_severity}${RESET}` : '';
        const seen  = seenCompact(f);
        const seenCell = seen ? `  ${DIM}${seen}${RESET}` : '';
        console.log(`    ${idCell}  ${color}${BOLD}${tag.padEnd(4)}${RESET}  ${title.padEnd(titleW)}  ${DIM}${meta}${RESET}${ruleCell}${flags}${down}${seenCell}`);
        renderDetail(f);
      }

      if (opts.byFile) {
        // File-grouped — files ordered by their worst severity, then name.
        const byFile = {};
        for (const f of findings) (byFile[f.filePath] = byFile[f.filePath] || []).push(f);
        const fileEntries = Object.entries(byFile).map(([fp, list]) => {
          const worst = list.reduce((acc, f) => Math.min(acc, sevOrder(f.severity)), 9);
          return [fp, list, worst];
        }).sort((a, b) => (a[2] - b[2]) || a[0].localeCompare(b[0]));
        for (const [filePath, list] of fileEntries) {
          const absFile = repoRoot ? path.resolve(repoRoot, filePath) : filePath;
          console.log(`  ${BOLD}${sourceLink(absFile, filePath)}${RESET}`);
          const sorted = [...list].sort((a, b) =>
            sevOrder(a.severity) - sevOrder(b.severity) || (a.line || 0) - (b.line || 0));
          const titleW = titleWidth(sorted);
          for (const f of sorted) renderRow(f, titleW, false);
          console.log('');
        }
      } else {
        // Severity-grouped (default) — worst first, files/lines ordered within.
        for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'EXPOSURE', 'INFO']) {
          const list = findings.filter(f => f.severity === sev);
          if (!list.length) continue;
          const { color, label } = sevConfig(sev);
          console.log(`  ${color}${BOLD}${label}${RESET} ${DIM}(${list.length})${RESET}`);
          const sorted = [...list].sort((a, b) =>
            a.filePath.localeCompare(b.filePath) || (a.line || 0) - (b.line || 0));
          const titleW = titleWidth(sorted);
          for (const f of sorted) renderRow(f, titleW, true);
          console.log('');
        }
      }

      // Summary + hints
      const counts = {};
      for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
      const parts = ['CRITICAL','HIGH','MEDIUM','EXPOSURE']
        .filter(s => counts[s])
        .map(s => { const { color, label } = sevConfig(s); return `${color}${counts[s]} ${label.toLowerCase()}${RESET}`; });
      console.log(`  ${DIM}${findings.length} finding(s)${RESET}${parts.length ? '   ' + parts.join('  ') : ''}`);
      if (!showAll && !showExcepted && findings.length > 0) {
        console.log(`${DIM}  scd accept <finding-id> --reason "..."   or   scd ignore <finding-id> --reason "..."${RESET}`);
      }
      if (findings.length > 0 && !showVerbose) {
        console.log(`${DIM}  --verbose for snippet/problem/fix  ·  --by-file to group by file  ·  --rule/--severity to filter${RESET}`);
      }
      // Repeat the excepted warning at the foot too — easy to miss the header line on a
      // long list, and excepted findings are a deliberate risk decision worth re-surfacing.
      if (!showAll && !showExcepted && exceptedCount > 0) {
        console.log(`${YELLOW}  ⚠ ${exceptedCount} finding(s) excepted${RESET}${DIM}  ·  scd findings --excepted${RESET}`);
      }
      console.log('');
      warnIfOutdated();
}

function register(program) {
  program
    .command('findings [findingId]')
    .description('List findings from the last scan (default: open/unhandled only)')
    .option('--all',              'Show all findings including excepted and resolved')
    .option('--by-file',          'Group findings by file instead of by severity')
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
