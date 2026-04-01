/**
 * insights-analyzer.js
 * Analyserar beteendemönster i audit-loggen.
 *
 * Två lägen:
 *   Lokalt  – statistik och mönsterdetektering utan externa anrop
 *   --deep  – skickar ENBART statistik (aldrig kod/filinnehåll) till Claude API
 *             för djupare tolkning och konkreta rekommendationer
 *
 * Detekterade mönster:
 *   1. Återkommande regler     – samma regel triggar upprepade gånger
 *   2. Undvikandebeteende      – hög andel exceptions vs findings
 *   3. Tidsmönster             – fler findings sent/slutet av sprint
 *   4. Kunskapsgap per kategori – dominanta OWASP-kategorier
 *   5. Filhotspots             – filer som återkommer i findings
 *   6. Trend                   – förbättras eller försämras det?
 *   7. Per-developer (om team) – individuella mönster
 */

'use strict';

const { readAuditLog, EVENTS } = require('./audit');

// ── Helpers ────────────────────────────────────────────────────────────────

function topN(map, n = 5) {
  return Object.entries(map)
    .sort(([, a], [, b]) => b - a)
    .slice(0, n)
    .map(([k, v]) => ({ key: k, count: v }));
}

function weekOf(isoTs) {
  const d = new Date(isoTs);
  // ISO week: Monday-based
  const day = d.getDay() || 7;
  d.setDate(d.getDate() + 4 - day);
  const yearStart = new Date(d.getFullYear(), 0, 1);
  return `${d.getFullYear()}-W${String(Math.ceil(((d - yearStart) / 86400000 + 1) / 7)).padStart(2, '0')}`;
}

function hourOf(isoTs) {
  return new Date(isoTs).getHours();
}

function dayOfWeek(isoTs) {
  return new Date(isoTs).getDay(); // 0=sön, 5=fre, 6=lör
}

function percent(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}

// ── Extrahera findings-events ─────────────────────────────────────────────

const FINDING_EVENTS = new Set([
  EVENTS.FINDING_BLOCKED,
  EVENTS.FINDING_WARNED,
  EVENTS.FINDING_EXCEPTED,
  EVENTS.FINDING_EXCEPTION_EXPIRED,
]);

// ── Analysmoduler ──────────────────────────────────────────────────────────

function analyzeRecurringRules(findings) {
  const ruleCount = {};
  const ruleFirst = {};
  const ruleLast  = {};
  for (const f of findings) {
    ruleCount[f.rule_id] = (ruleCount[f.rule_id] || 0) + 1;
    if (!ruleFirst[f.rule_id] || f.timestamp < ruleFirst[f.rule_id]) ruleFirst[f.rule_id] = f.timestamp;
    if (!ruleLast[f.rule_id]  || f.timestamp > ruleLast[f.rule_id])  ruleLast[f.rule_id]  = f.timestamp;
  }

  const recurring = Object.entries(ruleCount)
    .filter(([, count]) => count >= 3)
    .sort(([, a], [, b]) => b - a)
    .map(([ruleId, count]) => ({
      ruleId,
      count,
      severity: findings.find(f => f.rule_id === ruleId)?.severity,
      category: findings.find(f => f.rule_id === ruleId)?.category,
      firstSeen: ruleFirst[ruleId]?.slice(0, 10),
      lastSeen:  ruleLast[ruleId]?.slice(0, 10),
      spanDays:  Math.round((new Date(ruleLast[ruleId]) - new Date(ruleFirst[ruleId])) / 86400000),
    }));

  return recurring;
}

function analyzeAvoidanceBehavior(events, findings) {
  const totalFindings  = findings.length;
  const excepted       = findings.filter(f => f.event === EVENTS.FINDING_EXCEPTED).length;
  const expiredExc     = findings.filter(f => f.event === EVENTS.FINDING_EXCEPTION_EXPIRED).length;
  const exceptRate     = percent(excepted, totalFindings);

  // Vem godkänner undantag?
  const approverCount = {};
  for (const f of findings.filter(f => f.exception_by)) {
    approverCount[f.exception_by] = (approverCount[f.exception_by] || 0) + 1;
  }

  // Filer som undantas upprepade gånger
  const exceptedFileCount = {};
  for (const f of findings.filter(f => f.event === EVENTS.FINDING_EXCEPTED)) {
    if (f.file) exceptedFileCount[f.file] = (exceptedFileCount[f.file] || 0) + 1;
  }

  const scanBlocked = events.filter(e => e.event === EVENTS.SCAN_BLOCKED).length;
  const scanTotal   = events.filter(e => e.event === EVENTS.SCAN_STARTED).length;
  const blockRate   = percent(scanBlocked, scanTotal);

  return {
    totalFindings,
    excepted,
    expiredExceptions: expiredExc,
    exceptRate,
    blockRate,
    topApprovers:     topN(approverCount, 3),
    topExceptedFiles: topN(exceptedFileCount, 3),
    signal: exceptRate >= 25 ? 'HIGH'
           : exceptRate >= 10 ? 'MEDIUM'
           : 'LOW',
  };
}

function analyzeTimePatterns(findings) {
  const byHour    = Array(24).fill(0);
  const byWeekday = Array(7).fill(0);  // 0=sön

  for (const f of findings) {
    byHour[hourOf(f.timestamp)]++;
    byWeekday[dayOfWeek(f.timestamp)]++;
  }

  const lateNightFindings = byHour.slice(20).reduce((a, b) => a + b, 0)
                          + byHour.slice(0, 5).reduce((a, b) => a + b, 0);
  const businessHourFindings = byHour.slice(8, 18).reduce((a, b) => a + b, 0);
  const lateRate = percent(lateNightFindings, findings.length);

  const DAYS = ['Sön', 'Mån', 'Tis', 'Ons', 'Tor', 'Fre', 'Lör'];
  const peakHour    = byHour.indexOf(Math.max(...byHour));
  const peakWeekday = byWeekday.indexOf(Math.max(...byWeekday));

  // Fredag + helg
  const weekendFindings = byWeekday[0] + byWeekday[6] + byWeekday[5];
  const weekendRate     = percent(weekendFindings, findings.length);

  return {
    byHour,
    byWeekday,
    peakHour,
    peakWeekday: DAYS[peakWeekday],
    lateNightFindings,
    lateRate,
    weekendRate,
    businessHourFindings,
    signal: lateRate >= 25 ? 'HIGH' : lateRate >= 10 ? 'MEDIUM' : 'LOW',
  };
}

function analyzeKnowledgeGaps(findings) {
  const catCount = {};
  const catSev   = {};

  for (const f of findings) {
    const cat = f.category || 'Unknown';
    catCount[cat] = (catCount[cat] || 0) + 1;
    if (!catSev[cat]) catSev[cat] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, EXPOSURE: 0 };
    if (catSev[cat][f.severity] !== undefined) catSev[cat][f.severity]++;
  }

  const total = findings.length;
  const gaps = Object.entries(catCount)
    .sort(([, a], [, b]) => b - a)
    .map(([cat, count]) => ({
      category: cat,
      count,
      percent: percent(count, total),
      breakdown: catSev[cat] || {},
    }));

  // Dominant gap = top category om den är >30% av alla findings
  const dominantGap = gaps[0]?.percent >= 30 ? gaps[0] : null;

  return { gaps: gaps.slice(0, 6), dominantGap };
}

function analyzeFileHotspots(findings) {
  const fileCount  = {};
  const fileSev    = {};

  for (const f of findings) {
    const fp = f.file || 'okänd';
    fileCount[fp] = (fileCount[fp] || 0) + 1;
    if (!fileSev[fp]) fileSev[fp] = { CRITICAL: 0, HIGH: 0 };
    if (f.severity === 'CRITICAL') fileSev[fp].CRITICAL++;
    if (f.severity === 'HIGH')     fileSev[fp].HIGH++;
  }

  const hotspots = Object.entries(fileCount)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8)
    .map(([file, count]) => ({
      file,
      count,
      critical: fileSev[file]?.CRITICAL || 0,
      high:     fileSev[file]?.HIGH || 0,
    }));

  return { hotspots };
}

function analyzeTrend(findings) {
  if (findings.length < 10) return { signal: 'INSUFFICIENT_DATA', weeks: [] };

  const byWeek = {};
  for (const f of findings) {
    const w = weekOf(f.timestamp);
    if (!byWeek[w]) byWeek[w] = { total: 0, critical: 0 };
    byWeek[w].total++;
    if (f.severity === 'CRITICAL') byWeek[w].critical++;
  }

  const weeks = Object.entries(byWeek)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([week, data]) => ({ week, ...data }));

  if (weeks.length < 3) return { signal: 'INSUFFICIENT_DATA', weeks };

  // Jämför sista 2 veckorna med föregående 2
  const recent  = weeks.slice(-2).reduce((s, w) => s + w.total, 0);
  const earlier = weeks.slice(-4, -2).reduce((s, w) => s + w.total, 0);

  let signal = 'STABLE';
  let trendPct = 0;
  if (earlier > 0) {
    trendPct = Math.round(((recent - earlier) / earlier) * 100);
    if (trendPct >=  20) signal = 'WORSENING';
    if (trendPct <= -20) signal = 'IMPROVING';
  }

  return { signal, trendPct, weeks, recentAvg: Math.round(recent / 2), earlierAvg: Math.round(earlier / 2) };
}

function analyzeDevelopers(findings) {
  if (findings.length === 0) return { developers: [], isTeam: false };

  const devMap = {};
  for (const f of findings) {
    const dev = f.git_user || 'unknown';
    if (!devMap[dev]) {
      devMap[dev] = {
        email: dev,
        name:  f.git_name || dev,
        total: 0, critical: 0, high: 0, excepted: 0,
        topRules: {}, topCategories: {},
      };
    }
    const d = devMap[dev];
    d.total++;
    if (f.severity === 'CRITICAL') d.critical++;
    if (f.severity === 'HIGH')     d.high++;
    if (f.event === EVENTS.FINDING_EXCEPTED) d.excepted++;
    d.topRules[f.rule_id] = (d.topRules[f.rule_id] || 0) + 1;
    if (f.category) d.topCategories[f.category] = (d.topCategories[f.category] || 0) + 1;
  }

  const developers = Object.values(devMap)
    .sort((a, b) => b.total - a.total)
    .map(d => ({
      ...d,
      criticalRate: percent(d.critical, d.total),
      exceptRate:   percent(d.excepted, d.total),
      topRule:      topN(d.topRules, 1)[0]?.key,
      topCategory:  topN(d.topCategories, 1)[0]?.key,
    }));

  return { developers, isTeam: developers.length > 1 };
}

// ── Lokal signaltolkning ───────────────────────────────────────────────────

function interpretSignals(analysis) {
  const signals = [];

  // Återkommande regler
  const top = analysis.recurringRules[0];
  if (top && top.count >= 5) {
    signals.push({
      type:    'RECURRING_RULE',
      level:   top.severity === 'CRITICAL' ? '🔴' : '🟠',
      title:   `${top.ruleId} triggered ${top.count} times over ${top.spanDays} days`,
      detail:  top.category
        ? `Kategori: ${top.category}. Problemet återkommer utan att grundorsaken åtgärdas.`
        : 'The issue recurs without addressing the root cause.',
      action:  'Schedule a code review focused on this rule. Consider adding a concrete code example to onboarding.',
    });
  }

  // Undvikandebeteende
  if (analysis.avoidance.signal === 'HIGH') {
    signals.push({
      type:    'AVOIDANCE',
      level:   '🟠',
      title:   `${analysis.avoidance.exceptRate}% of findings are excepted instead of fixed`,
      detail:  'A high exception rate suggests the tool is being silenced rather than code being improved.',
      action:  'Review all exceptions – which are legitimate? Define a formal exception policy.',
    });
  }

  // Tidsmönster
  if (analysis.timePatterns.signal === 'HIGH') {
    signals.push({
      type:    'TIME_PRESSURE',
      level:   '🟡',
      title:   `${analysis.timePatterns.lateRate}% of findings occur late at night`,
      detail:  `Peak: ${analysis.timePatterns.peakHour}:00. Code written under time pressure or fatigue tends to have more security issues.`,
      action:  'Investigate whether sprint pressure is driving late-night coding. Findings during these periods should be extra-reviewed.',
    });
  }

  // Kunskapsgap
  if (analysis.knowledgeGaps.dominantGap) {
    const gap = analysis.knowledgeGaps.dominantGap;
    signals.push({
      type:    'KNOWLEDGE_GAP',
      level:   '🟠',
      title:   `${gap.percent}% of all findings belong to "${gap.category}"`,
      detail:  `${gap.count} findings in the same category indicates a systematic knowledge gap, not isolated mistakes.`,
      action:  `Plan targeted training on ${gap.category}. A half-day hands-on workshop yields the greatest impact.`,
    });
  }

  // Trend
  if (analysis.trend.signal === 'WORSENING') {
    signals.push({
      type:    'TREND',
      level:   '🔴',
      title:   `Findings increasing – +${analysis.trend.trendPct}% over the last 2 weeks`,
      detail:  `Average last 2 weeks: ${analysis.trend.recentAvg}/week vs ${analysis.trend.earlierAvg}/week previously.`,
      action:  'Investigate whether new code was added, a new developer joined, or AI-assisted coding intensified without security review.',
    });
  } else if (analysis.trend.signal === 'IMPROVING') {
    signals.push({
      type:    'TREND',
      level:   '🟢',
      title:   `Findings decreasing – ${analysis.trend.trendPct}% over the last 2 weeks`,
      detail:  `Positive trend – security work is paying off.`,
      action:  'Keep up the momentum. Share what is working with the team.',
    });
  }

  // Hotspot-fil
  const topFile = analysis.fileHotspots.hotspots[0];
  if (topFile && topFile.count >= 5) {
    signals.push({
      type:    'HOTSPOT',
      level:   topFile.critical >= 3 ? '🔴' : '🟡',
      title:   `${topFile.file} is a hotspot (${topFile.count} findings, ${topFile.critical} CRITICAL)`,
      detail:  'A file with many recurring findings needs structural refactoring, not just point fixes.',
      action:  'Prioritize a security-focused code review of the entire file.',
    });
  }

  return signals;
}

// ── Huvud-analysör ─────────────────────────────────────────────────────────

async function analyzeInsights(repoRoot, opts = {}) {
  const { days = 90 } = opts;

  const allEvents = readAuditLog(repoRoot, 5000);

  if (allEvents.length === 0) {
    return { empty: true };
  }

  // Filtrera på period
  const cutoff   = new Date(Date.now() - days * 86400000).toISOString();
  const events   = allEvents.filter(e => e.timestamp >= cutoff);
  const findings = events.filter(e => FINDING_EVENTS.has(e.event));

  if (findings.length === 0) {
    return { empty: true, reason: `No findings in the last ${days} days.` };
  }

  const scans = events.filter(e => e.event === EVENTS.SCAN_STARTED);
  const dates = findings.map(f => f.timestamp).sort();

  const analysis = {
    meta: {
      periodDays:       days,
      totalScans:       scans.length,
      totalFindings:    findings.length,
      uniqueDevelopers: new Set(findings.map(f => f.git_user).filter(Boolean)).size,
      firstFinding:     dates[0]?.slice(0, 10),
      lastFinding:      dates[dates.length - 1]?.slice(0, 10),
    },
    recurringRules:  analyzeRecurringRules(findings),
    avoidance:       analyzeAvoidanceBehavior(events, findings),
    timePatterns:    analyzeTimePatterns(findings),
    knowledgeGaps:   analyzeKnowledgeGaps(findings),
    fileHotspots:    analyzeFileHotspots(findings),
    trend:           analyzeTrend(findings),
    developers:      analyzeDevelopers(findings),
  };

  const signals = interpretSignals(analysis);
  analysis.signals = signals;

  return analysis;
}

module.exports = { analyzeInsights };
