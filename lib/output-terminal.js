const { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN } = require('./output-constants');
const { formatLocalTime } = require('./format-time');
const { sevConfig, sevOrder } = require('./severity');
const { fileLink } = require('./terminal-links');
/**
 * output-terminal.js
 * Two-part terminal output:
 *   1. Summary + file-grouped overview  ← visible without scrolling
 *   2. Full details per finding          ← scroll down for explanations
 */

// Severity colours/tags/order come from lib/severity.js; OSC 8 file links from
// lib/terminal-links.js (both centralised — no per-file emoji maps or link helpers).

function formatTerminal(findings, hookType, config = null, meta = {}) {
  if (findings.length === 0) {
    return {
      output: `\n${GREEN}${BOLD} ✓ No security issues found.${RESET}\n`,
      exitCode: 0,
    };
  }

  const verbose = config?.verbose || meta.verbose || false;

  // ── Deduplicate & sort ────────────────────────────────────────────────────
  const seen = new Set();
  const unique = findings.filter(f => {
    const key = `${f.ruleId}:${f.filePath}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  unique.sort((a, b) => {
    if (a.excepted !== b.excepted) return a.excepted ? 1 : -1;
    return sevOrder(a.severity) - sevOrder(b.severity);
  });

  const active    = unique.filter(f => !f.excepted && !f.resolved && f.severity !== 'EXPOSURE');
  const exposures = unique.filter(f => !f.excepted && !f.resolved && f.severity === 'EXPOSURE');
  const excepted  = unique.filter(f => f.excepted);
  const rejected  = unique.filter(f => f.exception_rejected);

  let shouldBlock = active.some(f => f.blocks) ||
                    excepted.some(f => f.exception_expired);

  const lines = [];

  // ── Count per severity ───────────────────────────────────────────────────
  const counts = {};
  for (const f of [...active, ...exposures]) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  // Count low-confidence findings per severity for annotation
  const lowConfCounts = {};
  for (const f of [...active, ...exposures]) {
    if (f.confidence === 'LOW') {
      lowConfCounts[f.severity] = (lowConfCounts[f.severity] ?? 0) + 1;
    }
  }

  const summaryParts = Object.entries(counts)
    .sort((a, b) => sevOrder(a[0]) - sevOrder(b[0]))
    .map(([sev, n]) => {
      const { color } = sevConfig(sev);
      const lowN  = lowConfCounts[sev] ?? 0;
      const note  = lowN > 0 ? `${DIM} (${lowN} low confidence)${RESET}` : '';
      return `${color}${BOLD}${n} ${sev.trim()}${RESET}${note}`;
    });

  if (excepted.length > 0) {
    summaryParts.push(`${DIM}✓ ${excepted.length} excepted${RESET}`);
  }
  if (rejected.length > 0) {
    summaryParts.push(`${YELLOW}⛔ ${rejected.length} rejected${RESET}`);
  }

  const skipped         = meta.skipped         ?? [];
  const timedOut        = meta.timedOut        ?? [];
  const scopeExclusions = meta.scopeExclusions  ?? null;

  const modeLabel = hookType === 'manual'     ? 'Manual scan'
                  : hookType === 'pre-commit'  ? 'Pre-commit (secrets)'
                  : 'Pre-push (OWASP)';

  const scanMode   = `  ${DIM}· scan: ${config?.scan_mode   || 'full'}${RESET}`;
  const trustLevel = `  ${DIM}· trust: ${config?.trust_level || 'balanced'}${RESET}`;

  const skippedTotal = skipped.length + timedOut.length;
  const skippedNote  = skippedTotal > 0 ? `  ${YELLOW}· ${skippedTotal} file(s) skipped/timeout${RESET}` : '';
  const taintCount   = unique.filter(f => f.taintSource).length;
  const taintNote    = taintCount > 0 ? `  ${DIM}· ${taintCount} taint-tracked${RESET}` : '';

  lines.push('');
  lines.push(`${BOLD}─── Summary ${'─'.repeat(60)}${RESET}`);
  lines.push(`  ${summaryParts.join('   ')}`);
  lines.push(`  ${DIM}${modeLabel}  ·  ${unique.length} findings total${taintNote}${skippedNote}${scanMode}${trustLevel}${RESET}`);
  lines.push(`${BOLD}${'─'.repeat(72)}${RESET}`);

  lines.push('');

  // ── Skipped / timed-out files ────────────────────────────────────────────
  if (skipped.length > 0 || timedOut.length > 0) {
    for (const s of skipped) {
      if (s.reason === 'too_large') {
        lines.push(`  ${DIM}⊘ ${fileLink(s.filePath)}  ${s.sizeKb} KB – skipped (too large)${RESET}`);
      } else {
        lines.push(`  ${DIM}⊘ ${fileLink(s.filePath)}  ${s.error}${RESET}`);
      }
    }
    for (const t of timedOut) {
      lines.push(`  ${YELLOW}⏱ ${fileLink(t.filePath)}  ${t.sizeKb} KB – timeout${RESET}`);
    }
    lines.push('');
  }

  // ── Active scope exclusions ─────────────────────────────────────────────
  if (scopeExclusions) {
    const fileExcludes = scopeExclusions.file_excludes || [];
    const ruleExcludes = scopeExclusions.rule_excludes || [];
    if (fileExcludes.length > 0 || ruleExcludes.length > 0) {
      lines.push(`${YELLOW}${BOLD} ⚠ Active scope exclusions:${RESET}`);
      for (const e of fileExcludes) {
        const reason = e.reason ? ` — "${e.reason}"` : '';
        const meta_  = [e.added_by, formatLocalTime(e.added_at)].filter(Boolean).join(', ');
        const src    = e._source ? ` [${e._source}]` : '';
        lines.push(`  ${YELLOW}Files : ${e.pattern}${reason} (${meta_})${src}${RESET}`);
      }
      for (const e of ruleExcludes) {
        const scope_ = e.files && e.files.length ? e.files.join(', ') : 'all files';
        const reason = e.reason ? ` — "${e.reason}"` : '';
        const meta_  = [e.added_by, formatLocalTime(e.added_at)].filter(Boolean).join(', ');
        const src    = e._source ? ` [${e._source}]` : '';
        const excl   = e.findings_excluded > 0 ? `, ${e.findings_excluded} finding(s) excluded` : '';
        lines.push(`  ${YELLOW}Rules : ${e.rule} (${scope_})${reason} (${meta_}${excl})${src}${RESET}`);
      }
      lines.push('');
    }
  }

  if (verbose) {
    // ════════════════════════════════════════════════════════════════════════
    // VERBOSE MODE – full file-grouped list + rule details (original format)
    // ════════════════════════════════════════════════════════════════════════

    const byFile = {};
    for (const f of [...active, ...exposures]) {
      if (!byFile[f.filePath]) byFile[f.filePath] = [];
      byFile[f.filePath].push(f);
    }

    if (Object.keys(byFile).length > 0) {
      lines.push(`${BOLD}Findings per file:${RESET}`);
      lines.push('');
      for (const [filePath, filefindings] of Object.entries(byFile)) {
        lines.push(`  ${BOLD}${fileLink(filePath)}${RESET}`);
        for (const f of filefindings) {
          const { color, tag } = sevConfig(f.severity);
          const lineRef  = f.line ? `${DIM}${fileLink(f.filePath, f.line, 'line ' + f.line)}${RESET}` : '';
          const isWarn   = f.action === 'warn';
          const rejected = f.exception_rejected ? `  ${YELLOW}⛔ rejected – fix required${RESET}` : '';
          const fid = f.findingId ? `  ${DIM}${f.findingId}${RESET}` : '';
          lines.push(
            `    ${color}${BOLD}${tag.padEnd(4)}${RESET}  ${color}${f.name}${RESET}` +
            `${isWarn ? ` ${DIM}(warning)${RESET}` : ''}` +
            `  ${lineRef}  ${DIM}[${f.ruleId}]${RESET}${fid}${rejected}`
          );
        }
        lines.push('');
      }
    }

    if (excepted.length > 0) {
      lines.push(`  ${DIM}Excepted findings:${RESET}`);
      for (const f of excepted) {
        const expired = f.exception_expired;
        const icon    = expired ? `${YELLOW}⚠ ${RESET}` : `${DIM}✓${RESET} `;
        lines.push(`    ${icon} ${DIM}${f.ruleId} – ${f.name}  (${fileLink(f.filePath, f.line)})${RESET}` +
          (expired ? ` ${YELLOW}– exception expired!${RESET}` : ''));
      }
      lines.push('');
    }

    // Rule details with explanation
    const allDetailed = [...active, ...exposures];
    if (allDetailed.length > 0) {
      lines.push('');
      lines.push(`${DIM}${'─'.repeat(60)}${RESET}`);
      lines.push(`${DIM}  ↓  Details grouped by rule  ↓${RESET}`);
      lines.push(`${DIM}${'─'.repeat(60)}${RESET}`);

      const byRule = {};
      for (const f of allDetailed) {
        if (!byRule[f.ruleId]) byRule[f.ruleId] = [];
        byRule[f.ruleId].push(f);
      }

      const sortedRules = Object.entries(byRule).sort(([, a], [, b]) =>
        sevOrder(a[0].severity) - sevOrder(b[0].severity)
      );

      for (const [ruleId, ruleFindings] of sortedRules) {
        const rep    = ruleFindings[0];
        const { color, tag } = sevConfig(rep.severity);
        const isWarn = rep.action === 'warn';
        const count  = ruleFindings.length;
        lines.push('');
        lines.push(
          `${color}${BOLD}${tag} ${rep.name}${RESET}` +
          `${isWarn ? ` ${DIM}(warning – does not block)${RESET}` : ''}` +
          `${count > 1 ? ` ${DIM}· ${count} occurrences${RESET}` : ''}` +
          `  ${DIM}[${ruleId}]${RESET}`
        );
        for (const f of ruleFindings) {
          const snippet = f.snippet ? `  ${DIM}→ ${f.snippet.trim().slice(0, 60)}${f.snippet.trim().length > 60 ? '…' : ''}${RESET}` : '';
          // Show confidence badge for LOW/MEDIUM findings
          const confBadge = f.confidence === 'LOW'    ? ` ${DIM}[low confidence]${RESET}`
                          : f.confidence === 'MEDIUM'  ? ` ${DIM}[medium confidence]${RESET}`
                          : '';
          lines.push(`  ${DIM}${fileLink(f.filePath, f.line)}${RESET}${snippet}${confBadge}`);
          if (f.taintSource) {
            lines.push(`  ${DIM}   ↳ \$${f.taintSource.variable} assigned from ${f.taintSource.source} on line ${f.taintSource.line}${RESET}`);
          }
          if (f.exception_rejected) {
            lines.push(`  ${YELLOW}   ⛔ exception rejected – fix required${RESET}`);
          }
        }
        if (rep.why || rep.scenario || rep.fix) {
          lines.push('');
          if (rep.why)      lines.push(`  ${BOLD}Problem:${RESET}  ${rep.why}`);
          if (rep.scenario) lines.push(`  ${BOLD}Scenario:${RESET} ${CYAN}${rep.scenario}${RESET}`);
          if (rep.fix)      lines.push(`  ${BOLD}Fix:${RESET}      ${GREEN}${rep.fix}${RESET}`);
        }
        if (rep.severity === 'EXPOSURE' && rep.checklist) {
          lines.push('');
          lines.push(`  ${BOLD}Verify:${RESET}`);
          rep.checklist.forEach(item => lines.push(`  ${YELLOW}☐${RESET} ${item}`));
          for (const f of ruleFindings) {
            lines.push(`  ${DIM}→ scd ignore ${f.findingId || f.ruleId} --reason "..."   or   scd accept ${f.findingId || f.ruleId} --reason "..."${RESET}`);
          }
        }
      }
    }

  } else {
    // ════════════════════════════════════════════════════════════════════════
    // COMPACT MODE (default) – top issues + most affected files
    // ════════════════════════════════════════════════════════════════════════

    // ── Top issues by rule ──────────────────────────────────────────────────
    const byRule = {};
    for (const f of [...active, ...exposures]) {
      if (!byRule[f.ruleId]) byRule[f.ruleId] = { rep: f, count: 0 };
      byRule[f.ruleId].count++;
    }

    const sortedRules = Object.values(byRule)
      .sort((a, b) => {
        const sevDiff = sevOrder(a.rep.severity) - sevOrder(b.rep.severity);
        return sevDiff !== 0 ? sevDiff : b.count - a.count;
      });

    const TOP_N = 8;
    lines.push(`${BOLD}Top issues:${RESET}`);
    for (const { rep, count } of sortedRules.slice(0, TOP_N)) {
      const { color, tag } = sevConfig(rep.severity);
      const isWarn = rep.action === 'warn';
      const cnt    = String(count).padStart(3);
      lines.push(
        `   ${color}${BOLD}${tag.padEnd(4)}${RESET} ${color}${cnt}${RESET}  ${DIM}${rep.ruleId.padEnd(20)}${RESET}  ${rep.name}` +
        `${isWarn ? ` ${DIM}(warning)${RESET}` : ''}`
      );
    }
    if (sortedRules.length > TOP_N) {
      lines.push(`   ${DIM}+ ${sortedRules.length - TOP_N} more rule(s)${RESET}`);
    }
    lines.push('');

    // ── Most affected files ─────────────────────────────────────────────────
    const byFile = {};
    for (const f of [...active, ...exposures]) {
      if (!byFile[f.filePath]) byFile[f.filePath] = { count: 0, maxSev: 9, lines: [] };
      byFile[f.filePath].count++;
      if (f.line) byFile[f.filePath].lines.push(f.line);
      const sev = sevOrder(f.severity);
      if (sev < byFile[f.filePath].maxSev) byFile[f.filePath].maxSev = sev;
    }

    const sortedFiles = Object.entries(byFile)
      .sort(([, a], [, b]) => a.maxSev !== b.maxSev ? a.maxSev - b.maxSev : b.count - a.count);

    const TOP_FILES = 5;
    if (sortedFiles.length > 0) {
      lines.push(`${BOLD}Most affected files:${RESET}`);
      for (const [filePath, info] of sortedFiles.slice(0, TOP_FILES)) {
        const sevKey = ['CRITICAL','HIGH','MEDIUM','EXPOSURE','INFO'][info.maxSev] ?? 'INFO';
        const { color, tag } = sevConfig(sevKey);
        const cnt  = String(info.count).padStart(3);
        const name = filePath.length > 45 ? '…' + filePath.slice(-44) : filePath;
        // Show up to 8 line numbers, sorted, comma-separated
        const lineNums = [...new Set(info.lines)].sort((a, b) => a - b);
        const lineStr  = lineNums.length > 0
          ? `  ${DIM}(Lines: ${lineNums.slice(0, 8).join(', ')}${lineNums.length > 8 ? ', …' : ''})${RESET}`
          : '';
        lines.push(`   ${color}${BOLD}${tag.padEnd(4)}${RESET} ${DIM}${cnt}${RESET}  ${fileLink(filePath, null, name)}${lineStr}`);
      }
      if (sortedFiles.length > TOP_FILES) {
        lines.push(`   ${DIM}+ ${sortedFiles.length - TOP_FILES} more file(s)${RESET}`);
      }
      lines.push('');
    }

    // ── Excepted summary ────────────────────────────────────────────────────
    if (excepted.length > 0) {
      const expired = excepted.filter(f => f.exception_expired);
      lines.push(`  ${DIM}✓ ${excepted.length} finding(s) excepted${RESET}` +
        (expired.length > 0 ? `  ${YELLOW}⚠  ${expired.length} exception(s) expired — re-approval needed${RESET}` : ''));
      lines.push('');
    }

    // ── Rejected exceptions ─────────────────────────────────────────────────
    if (rejected.length > 0) {
      lines.push(`  ${YELLOW}⛔ ${rejected.length} rejected exception(s) — fix required:${RESET}`);
      for (const f of rejected) {
        const excId = f.exception?.id ? `  ${DIM}[${f.exception.id}]${RESET}` : '';
        lines.push(`  ${DIM}   ${f.ruleId}  ${f.filePath}${f.line ? ':' + f.line : ''}${RESET}${excId}`);
      }
      lines.push(`  ${DIM}   Run scd exceptions --list rejected to see details${RESET}`);
      lines.push('');
    }

    // ── Next steps ──────────────────────────────────────────────────────────
    lines.push(`${DIM}${'─'.repeat(62)}${RESET}`);
    lines.push(`${DIM}  Full details:${RESET}  ${BOLD}scd report open${RESET}   ${DIM}or${RESET}   ${BOLD}scd report serve${RESET}  ${DIM}(Linux/Firefox)${RESET}`);
    lines.push(`${DIM}  All findings: ${RESET}  ${BOLD}scd scan --verbose${RESET}   ${DIM}or${RESET}   ${BOLD}scd export-findings${RESET}`);
  }

  lines.push('');

  // ── Block/pass status ─────────────────────────────────────────────────────
  if (shouldBlock) {
    if (hookType === 'manual') {
      lines.push(`${RED}${BOLD} ⚠  Critical vulnerabilities found – fix before pushing.${RESET}`);
      lines.push(`${DIM}    Manual scan does not block. Git push will block on CRITICAL/HIGH.${RESET}`);
    } else if (hookType === 'pre-commit') {
      lines.push(`${RED}${BOLD} 🚫 Commit blocked – secrets must never reach git history.${RESET}`);
      lines.push(`${DIM}    Fix the above and try again.${RESET}`);
    } else {
      lines.push(`${RED}${BOLD} 🚫 Push blocked – critical vulnerabilities must be fixed.${RESET}`);
      lines.push(`${DIM}    Run git push again after fixing the above.${RESET}`);
    }
  } else {
    if (hookType === 'manual') {
      lines.push(`${GREEN}${BOLD} ✓ No blocking vulnerabilities.${RESET} ${DIM}Review HIGH/EXPOSURE findings above.${RESET}`);
    } else {
      lines.push(`${GREEN}${BOLD} ✓ Push allowed${RESET} ${DIM}– review HIGH findings above.${RESET}`);
    }
  }

  lines.push('');

  return {
    output: lines.join('\n'),
    exitCode: shouldBlock ? 1 : 0,
  };
}

module.exports = { formatTerminal };
