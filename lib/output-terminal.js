/**
 * output-terminal.js
 * Two-part terminal output:
 *   1. Summary + file-grouped overview  ← visible without scrolling
 *   2. Full details per finding          ← scroll down for explanations
 */

const SEVERITY_CONFIG = {
  CRITICAL: { color: '\x1b[31m', icon: '🔴', label: 'CRITICAL' },
  HIGH:     { color: '\x1b[33m', icon: '🟠', label: 'HIGH    ' },
  MEDIUM:   { color: '\x1b[33m', icon: '🟡', label: 'MEDIUM  ' },
  EXPOSURE: { color: '\x1b[34m', icon: '🔷', label: 'EXPOSURE' },
  INFO:     { color: '\x1b[36m', icon: '🔵', label: 'INFO    ' },
};

const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[90m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const CYAN   = '\x1b[36m';
const YELLOW = '\x1b[33m';
const BLUE   = '\x1b[34m';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, INFO: 4 };

// ── OSC 8 hyperlink support detection ────────────────────────────────────────
// Only emit hyperlink sequences in terminals known to support OSC 8.
// Unsupported terminals (Terminal.app, basic xterm etc.) receive plain text.
const OSC8_SUPPORTED = (() => {
  const prog    = process.env.TERM_PROGRAM   ?? '';
  const emul    = process.env.TERM_EMULATOR  ?? '';
  const vte     = process.env.VTE_VERSION    ?? '';
  const color   = process.env.COLORTERM      ?? '';
  return (
    prog  === 'iTerm.app'          ||  // iTerm2
    prog  === 'vscode'             ||  // VS Code integrated terminal
    prog  === 'WarpTerminal'       ||  // Warp
    prog  === 'ghostty'            ||  // Ghostty
    emul  === 'JetBrains-JediTerm' ||  // JetBrains IDEs (IntelliJ, WebStorm, …)
    (color === 'truecolor' && vte !== '') // VTE-based: GNOME Terminal, Tilix, …
  );
})();

function fileLink(relativePath, lineNum = null, displayText = null) {
  const display = displayText ?? (lineNum ? `${relativePath}:${lineNum}` : relativePath);

  // Plain text fallback for terminals that don't support OSC 8
  if (!OSC8_SUPPORTED) return display;

  const abs = require('path').resolve(process.cwd(), relativePath);
  // file:// URI never includes line number – macOS can't open 'file.js:12'
  const uri = `file://${abs}`;
  const ESC = '\x1b';
  return `${ESC}]8;;${uri}${ESC}\\${display}${ESC}]8;;${ESC}\\`;
}

function formatTerminal(findings, hookType, config = null, meta = {}) {
  if (findings.length === 0) {
    return {
      output: `\n${GREEN}${BOLD} ✅ No security issues found.${RESET}\n`,
      exitCode: 0,
    };
  }

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
    return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
  });

  const active    = unique.filter(f => !f.excepted && !f.resolved && f.severity !== 'EXPOSURE');
  const exposures = unique.filter(f => !f.excepted && !f.resolved && f.severity === 'EXPOSURE');
  const excepted  = unique.filter(f => f.excepted);

  let shouldBlock = active.some(f => f.blocks) ||
                    excepted.some(f => f.exception_expired);

  const lines = [];

  // ══════════════════════════════════════════════════════════════════════════
  // PART 1 – SUMMARY + FILE-GROUPED OVERVIEW
  // ══════════════════════════════════════════════════════════════════════════

  // ── Count per severity ──────────────────────────────────────────────────
  const counts = {};
  for (const f of [...active, ...exposures]) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const summaryParts = Object.entries(counts)
    .sort((a, b) => (SEV_ORDER[a[0]] ?? 9) - (SEV_ORDER[b[0]] ?? 9))
    .map(([sev, n]) => {
      const cfg = SEVERITY_CONFIG[sev];
      const color = sev === 'CRITICAL' ? RED : sev === 'EXPOSURE' ? BLUE : YELLOW;
      return `${color}${BOLD}${cfg.icon} ${n} ${sev.trim()}${RESET}`;
    });

  if (excepted.length > 0) {
    summaryParts.push(`${DIM}✓ ${excepted.length} excepted${RESET}`);
  }

  const skipped  = meta.skipped  ?? [];
  const timedOut = meta.timedOut ?? [];

  lines.push('');
  lines.push(`${BOLD}┌─ Summary ${'─'.repeat(52)}┐${RESET}`);
  lines.push(`${BOLD}│${RESET}  ${summaryParts.join('   ')}  ${BOLD}│${RESET}`);

  // Hook/mode label on same header block
  const modeLabel = hookType === 'manual'  ? 'Manual scan'
                  : hookType === 'pre-commit' ? 'Pre-commit (secrets)'
                  : 'Pre-push (OWASP)';
  const skippedTotal = skipped.length + timedOut.length;
  const skippedNote = skippedTotal > 0 ? `  ${YELLOW}· ${skippedTotal} file(s) skipped/timeout${RESET}` : '';
  lines.push(`${BOLD}│${RESET}  ${DIM}${modeLabel}  ·  ${unique.length} findings total${RESET}${skippedNote}  ${BOLD}│${RESET}`);
  lines.push(`${BOLD}└${'─'.repeat(62)}┘${RESET}`);
  lines.push('');

  // Skipped + timed-out files – shown just below header
  if (skipped.length > 0 || timedOut.length > 0) {
    lines.push(`${DIM}Skipped (not included in scan):${RESET}`);
    for (const s of skipped) {
      if (s.reason === 'too_large') {
        lines.push(`  ${DIM}⊘ ${fileLink(s.filePath)}  ${s.sizeKb} KB > gräns ${s.limitKb} KB  ${RESET}${DIM}(troligen genererad/minifierad – justera scan.max_file_size_kb i .securityagent.yml)${RESET}`);
      } else {
        lines.push(`  ${DIM}⊘ ${fileLink(s.filePath)}  ${s.error}${RESET}`);
      }
    }
    for (const t of timedOut) {
      lines.push(`  ${YELLOW}⏱ ${fileLink(t.filePath)}  ${t.sizeKb} KB  ${RESET}${DIM}– scan took >30s and was aborted. Try --no-limit or exclude the file.${RESET}`);
    }
    lines.push('');
  }

  // ── File-grouped overview ───────────────────────────────────────────────
  const byFile = {};
  for (const f of [...active, ...exposures]) {
    const fp = f.filePath;
    if (!byFile[fp]) byFile[fp] = [];
    byFile[fp].push(f);
  }

  if (Object.keys(byFile).length > 0) {
    lines.push(`${BOLD}Findings per fil:${RESET}`);
    lines.push('');

    for (const [filePath, filefindings] of Object.entries(byFile)) {
      // File header
      lines.push(`  ${BOLD}${fileLink(filePath)}${RESET}`);

      for (const f of filefindings) {
        const cfg      = SEVERITY_CONFIG[f.severity] ?? SEVERITY_CONFIG.INFO;
        const color    = f.severity === 'CRITICAL' ? RED
                       : f.severity === 'EXPOSURE'  ? BLUE : YELLOW;
        const lineRef  = f.line ? `${DIM}${fileLink(f.filePath, f.line, 'rad ' + f.line)}${RESET}` : '';
        const ruleId   = `${DIM}[${f.ruleId}]${RESET}`;
        const isWarn   = f.action === 'warn';
        const warnNote = isWarn ? ` ${DIM}(warning)${RESET}` : '';

        lines.push(
          `    ${color}${cfg.icon}${RESET}  ${color}${f.name}${RESET}${warnNote}`
          + `  ${lineRef}  ${ruleId}`
        );
      }
      lines.push('');
    }
  }

  // ── Excepted overview (compact) ─────────────────────────────────────────
  if (excepted.length > 0) {
    lines.push(`  ${DIM}Undantagna (visas ej i detaljer):${RESET}`);
    for (const f of excepted) {
      const expired  = f.exception_expired;
      const icon     = expired ? `${YELLOW}⚠️ ${RESET}` : `${DIM}✓${RESET} `;
      const expNote  = expired ? ` ${YELLOW}– undantag utgånget!${RESET}` : '';
      lines.push(`    ${icon} ${DIM}${f.ruleId} – ${f.name}  (${fileLink(f.filePath, f.line)})${RESET}${expNote}`);
    }
    lines.push('');
  }

  // ── Block/pass status ───────────────────────────────────────────────────
  if (shouldBlock) {
    if (hookType === 'manual') {
      lines.push(`${RED}${BOLD} ⚠️  Critical vulnerabilities found – fix before pushing.${RESET}`);
      lines.push(`${DIM}    Manual scan does not block. Git push will block on CRITICAL/HIGH.${RESET}`);
    } else if (hookType === 'pre-commit') {
      lines.push(`${RED}${BOLD} 🚫 Commit blockerad – secrets får aldrig hamna i git-historiken.${RESET}`);
      lines.push(`${DIM}    Åtgärda ovanstående och försök igen.${RESET}`);
    } else {
      lines.push(`${RED}${BOLD} 🚫 Push blocked – critical vulnerabilities must be fixed.${RESET}`);
      lines.push(`${DIM}    Run git push again after fixing the above.${RESET}`);
    }
  } else {
    if (hookType === 'manual') {
      lines.push(`${GREEN}${BOLD} ✅ Inga blockerande sårbarheter.${RESET} ${DIM}Granska HIGH/EXPOSURE ovan.${RESET}`);
    } else {
      lines.push(`${GREEN}${BOLD} ✅ Push tillåten${RESET} ${DIM}– granska HIGH-findings ovan.${RESET}`);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PART 2 – DETAILS GROUPED BY RULE (one explanation per rule type)
  // ══════════════════════════════════════════════════════════════════════════

  const allDetailed = [...active, ...exposures];

  if (allDetailed.length > 0) {
    lines.push('');
    lines.push(`${DIM}${'─'.repeat(60)}${RESET}`);
    lines.push(`${DIM}  ↓  Detaljer (grupperade per regeltyp)  ↓${RESET}`);
    lines.push(`${DIM}${'─'.repeat(60)}${RESET}`);

    // Group by ruleId – explanation shown once, all occurrences listed under it
    const byRule = {};
    for (const f of allDetailed) {
      if (!byRule[f.ruleId]) byRule[f.ruleId] = [];
      byRule[f.ruleId].push(f);
    }

    // Sort rule groups by severity order, then ruleId
    const sortedRules = Object.entries(byRule).sort(([, a], [, b]) => {
      return (SEV_ORDER[a[0].severity] ?? 9) - (SEV_ORDER[b[0].severity] ?? 9);
    });

    for (const [ruleId, ruleFindings] of sortedRules) {
      const rep   = ruleFindings[0]; // representative finding for explanation
      const cfg   = SEVERITY_CONFIG[rep.severity] ?? SEVERITY_CONFIG.INFO;
      const color = rep.severity === 'CRITICAL' ? RED
                  : rep.severity === 'EXPOSURE'  ? BLUE : YELLOW;
      const isWarn   = rep.action === 'warn';
      const warnNote = isWarn ? ` ${DIM}(warning – does not block)${RESET}` : '';
      const count    = ruleFindings.length;
      const countNote = count > 1 ? ` ${DIM}· ${count} förekomster${RESET}` : '';

      lines.push('');
      // Rule header – name + id
      lines.push(
        `${color}${BOLD}${cfg.icon} ${rep.name}${RESET}${warnNote}${countNote}` +
        `  ${DIM}[${ruleId}]${RESET}`
      );

      // All file:line occurrences – compact, one per line
      for (const f of ruleFindings) {
        const snippet = f.snippet ? `  ${DIM}→ ${f.snippet.trim().slice(0, 60)}${f.snippet.trim().length > 60 ? '…' : ''}${RESET}` : '';
        lines.push(`  ${DIM}${fileLink(f.filePath, f.line)}${RESET}${snippet}`);
      }

      // Explanation once per rule
      if (rep.why || rep.scenario || rep.fix) {
        lines.push('');
        if (rep.why)      lines.push(`  ${BOLD}Problem:${RESET}  ${rep.why}`);
        if (rep.scenario) lines.push(`  ${BOLD}Scenario:${RESET} ${CYAN}${rep.scenario}${RESET}`);
        if (rep.fix)      lines.push(`  ${BOLD}Åtgärd:${RESET}   ${GREEN}${rep.fix}${RESET}`);
      }

      // EXPOSURE checklist (per finding since resolve cmd is file-specific)
      if (rep.severity === 'EXPOSURE' && rep.checklist) {
        lines.push('');
        lines.push(`  ${BOLD}Verifiera:${RESET}`);
        rep.checklist.forEach(item => lines.push(`  ${YELLOW}☐${RESET} ${item}`));
        for (const f of ruleFindings) {
          lines.push(`  ${DIM}→ scd resolve --rule ${f.ruleId} --file ${f.filePath} --line ${f.line}${RESET}`);
        }
      }
    }
  }

  lines.push('');

  return {
    output: lines.join('\n'),
    exitCode: shouldBlock ? 1 : 0,
  };
}

module.exports = { formatTerminal };
