/**
 * insights-output.js
 * Terminal-rendering av beteendeanalys från sc insights.
 */

'use strict';

const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[90m';
const RED    = '\x1b[31m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const BLUE   = '\x1b[34m';

function bar(value, max, width = 20, color = CYAN) {
  const filled = max > 0 ? Math.round((value / max) * width) : 0;
  return color + '█'.repeat(filled) + DIM + '░'.repeat(width - filled) + RESET;
}

function pad(str, len) {
  return String(str).slice(0, len).padEnd(len);
}

function renderInsights(analysis) {
  if (analysis.empty) {
    console.log(`\n${DIM} ℹ️  ${analysis.reason || 'No audit data found. Run sc scan to start collecting data.'}${RESET}\n`);
    return;
  }

  const { meta, recurringRules, avoidance, timePatterns,
          knowledgeGaps, fileHotspots, trend, developers, signals, deepInsight, deepInsightError } = analysis;

  // ── Header ──────────────────────────────────────────────────────────────
  console.log(`\n${CYAN}${BOLD}╔═══════════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}${BOLD}║     Security Co-Pilot – Behavior Insights     ║${RESET}`);
  console.log(`${CYAN}${BOLD}╚═══════════════════════════════════════════════╝${RESET}`);
  console.log(`  ${DIM}Period: ${meta.firstFinding} → ${meta.lastFinding}  ·  ${meta.periodDays} days${RESET}`);
  console.log(`  ${DIM}Scans: ${meta.totalScans}  ·  Findings: ${meta.totalFindings}  ·  Developers: ${meta.uniqueDevelopers}${RESET}\n`);

  // ── Signaler (viktigast överst) ──────────────────────────────────────────
  if (signals && signals.length > 0) {
    console.log(`${BOLD}Detected patterns${RESET}`);
    console.log('─'.repeat(52));
    for (const s of signals) {
      console.log(`\n  ${s.level}  ${BOLD}${s.title}${RESET}`);
      console.log(`     ${DIM}${s.detail}${RESET}`);
      console.log(`     ${GREEN}→ ${s.action}${RESET}`);
    }
    console.log();
  }

  // ── Trend ────────────────────────────────────────────────────────────────
  if (trend.signal !== 'INSUFFICIENT_DATA' && trend.weeks?.length > 2) {
    console.log(`${BOLD}Findings per week (trend)${RESET}`);
    console.log('─'.repeat(52));
    const maxVal = Math.max(...trend.weeks.map(w => w.total), 1);
    for (const w of trend.weeks.slice(-8)) {  // visa max 8 veckor
      const critStr = w.critical > 0 ? ` ${RED}(${w.critical} CRIT)${RESET}` : '';
      console.log(`  ${DIM}${w.week}${RESET}  ${bar(w.total, maxVal, 24)}  ${String(w.total).padStart(3)}${critStr}`);
    }
    const trendSymbol = trend.signal === 'IMPROVING' ? `${GREEN}↓ Improving${RESET}`
                      : trend.signal === 'WORSENING' ? `${RED}↑ Worsening${RESET}`
                      : `${DIM}→ Stable${RESET}`;
    console.log(`\n  Trend: ${trendSymbol}${trend.trendPct ? ` ${DIM}(${trend.trendPct > 0 ? '+' : ''}${trend.trendPct}%)${RESET}` : ''}\n`);
  }

  // ── Kunskapsgap ──────────────────────────────────────────────────────────
  if (knowledgeGaps.gaps.length > 0) {
    console.log(`${BOLD}Knowledge gaps – OWASP categories${RESET}`);
    console.log('─'.repeat(52));
    const maxCat = Math.max(...knowledgeGaps.gaps.map(g => g.count), 1);
    for (const g of knowledgeGaps.gaps) {
      const critStr = g.breakdown?.CRITICAL > 0 ? ` ${RED}${g.breakdown.CRITICAL}C${RESET}` : '';
      const highStr = g.breakdown?.HIGH > 0      ? ` ${YELLOW}${g.breakdown.HIGH}H${RESET}` : '';
      // Förkorta kategorinamn för terminalen
      const shortCat = g.category.replace(' (OWASP A0\\d+)', '').replace(/\(OWASP .+?\)/, '').trim();
      console.log(`  ${pad(shortCat, 38)} ${bar(g.count, maxCat, 12)}  ${String(g.count).padStart(3)} ${DIM}(${g.percent}%)${RESET}${critStr}${highStr}`);
    }
    console.log();
  }

  // ── Recurring rules ───────────────────────────────────────────────────
  if (recurringRules.length > 0) {
    console.log(`${BOLD}Recurring rules${RESET}`);
    console.log('─'.repeat(52));
    const maxR = Math.max(...recurringRules.map(r => r.count), 1);
    for (const r of recurringRules.slice(0, 6)) {
      const sevColor = r.severity === 'CRITICAL' ? RED : r.severity === 'HIGH' ? YELLOW : DIM;
      const span = r.spanDays > 0 ? ` ${DIM}(${r.spanDays} days)${RESET}` : '';
      console.log(`  ${sevColor}${pad(r.ruleId, 16)}${RESET}  ${bar(r.count, maxR, 14)}  ${String(r.count).padStart(3)} findings${span}`);
    }
    console.log();
  }

  // ── File hotspots ──────────────────────────────────────────────────────────
  if (fileHotspots.hotspots.length > 0) {
    console.log(`${BOLD}File hotspots${RESET}`);
    console.log('─'.repeat(52));
    const maxH = Math.max(...fileHotspots.hotspots.map(h => h.count), 1);
    for (const h of fileHotspots.hotspots) {
      const critStr = h.critical > 0 ? ` ${RED}${h.critical} CRIT${RESET}` : '';
      // Visa bara filnamnet + en nivå upp för läsbarhet
      const parts   = h.file.replace(/\\/g, '/').split('/');
      const shortFile = parts.length > 2 ? '…/' + parts.slice(-2).join('/') : h.file;
      console.log(`  ${pad(shortFile, 36)} ${bar(h.count, maxH, 10)}  ${String(h.count).padStart(3)}${critStr}`);
    }
    console.log();
  }

  // ── Tidsmönster ───────────────────────────────────────────────────────────
  if (timePatterns.byHour) {
    console.log(`${BOLD}Time patterns – findings per hour${RESET}`);
    console.log('─'.repeat(52));
    const maxHour = Math.max(...timePatterns.byHour, 1);
    // Visa 4-timmarsbuckets för kompakt output
    for (let h = 0; h < 24; h += 4) {
      const bucket  = timePatterns.byHour.slice(h, h + 4).reduce((a, b) => a + b, 0);
      const isLate  = h >= 20 || h < 4;
      const label   = `${String(h).padStart(2, '0')}–${String(h + 4).padStart(2, '0')}`;
      const color   = isLate && bucket > 0 ? YELLOW : DIM;
      console.log(`  ${color}${label}${RESET}  ${bar(bucket, maxHour * 4, 20)}  ${String(bucket).padStart(3)}`);
    }
    if (timePatterns.lateRate > 0) {
      const lateColor = timePatterns.lateRate >= 20 ? YELLOW : DIM;
      console.log(`\n  Late-night findings: ${lateColor}${timePatterns.lateRate}%${RESET}  ${DIM}(peak: ${timePatterns.peakHour}:00, ${timePatterns.peakWeekday})${RESET}`);
    }
    console.log();
  }

  // ── Per-developer ─────────────────────────────────────────────────────────
  if (developers.isTeam) {
    console.log(`${BOLD}Per developer${RESET}`);
    console.log('─'.repeat(52));
    console.log(`  ${DIM}${'Name'.padEnd(20)} ${'Findings'.padEnd(10)} ${'CRITICAL%'.padEnd(11)} Top category${RESET}`);
    console.log(`  ${'─'.repeat(20)} ${'─'.repeat(9)} ${'─'.repeat(10)} ${'─'.repeat(18)}`);
    for (const d of developers.developers) {
      const critColor = d.criticalRate >= 50 ? RED : d.criticalRate >= 25 ? YELLOW : GREEN;
      const shortCat  = (d.topCategory || '–').replace(/\s*\(OWASP.+?\)/, '').slice(0, 28);
      console.log(`  ${pad(d.name, 20)} ${String(d.total).padStart(8)}   ${critColor}${String(d.criticalRate).padStart(6)}%${RESET}    ${DIM}${shortCat}${RESET}`);
    }
    console.log();
  }

  // ── Undvikandebeteende ────────────────────────────────────────────────────
  if (avoidance.totalFindings > 0) {
    console.log(`${BOLD}Exception handling${RESET}`);
    console.log('─'.repeat(52));
    const excColor = avoidance.signal === 'HIGH' ? RED : avoidance.signal === 'MEDIUM' ? YELLOW : GREEN;
    console.log(`  Excepted:    ${excColor}${avoidance.excepted}${RESET} of ${avoidance.totalFindings} findings ${DIM}(${avoidance.exceptRate}%)${RESET}`);
    if (avoidance.expiredExceptions > 0) {
      console.log(`  Expired:      ${RED}${avoidance.expiredExceptions} exceptions have expired – action required${RESET}`);
    }
    if (avoidance.topApprovers.length > 0) {
      const approvers = avoidance.topApprovers.map(a => `${a.key} (${a.count})`).join(', ');
      console.log(`  Approvers:    ${DIM}${approvers}${RESET}`);
    }
    console.log();
  }

  // ── Claude deep insight ───────────────────────────────────────────────────
  if (deepInsight) {
    console.log(`${CYAN}${BOLD}╔═══════════════════════════════════════════════╗${RESET}`);
    console.log(`${CYAN}${BOLD}║     Claude – Deep Analysis                    ║${RESET}`);
    console.log(`${CYAN}${BOLD}╚═══════════════════════════════════════════════╝${RESET}\n`);
    // Wrap långa rader
    const wrapped = deepInsight.split('\n').map(line => {
      if (line.length <= 76) return '  ' + line;
      const words = line.split(' ');
      const lines2 = [];
      let cur = '  ';
      for (const w of words) {
        if (cur.length + w.length > 76) { lines2.push(cur); cur = '  ' + w + ' '; }
        else cur += w + ' ';
      }
      if (cur.trim()) lines2.push(cur);
      return lines2.join('\n');
    });
    console.log(wrapped.join('\n'));
    console.log();
  }

  if (deepInsightError) {
    console.log(`  ${YELLOW}⚠️  Deep-analys misslyckades: ${deepInsightError}${RESET}\n`);
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  console.log(`${DIM}${'─'.repeat(52)}${RESET}`);
  if (!deepInsight && !deepInsightError) {
    console.log(`${DIM}  Run 'sc insights --deep' for Claude analysis of patterns${RESET}`);
  }
  console.log(`${DIM}  Run 'sc audit' for event log  ·  'sc report' for full report${RESET}\n`);
}

module.exports = { renderInsights };
