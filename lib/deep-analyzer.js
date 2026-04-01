/**
 * deep-analyzer.js
 * Routes --deep analysis to scd-server. All AI logic lives server-side.
 *
 * If scd-server is not configured, prints a teaser message and returns an
 * empty Map (non-fatal). The CLI scan completes normally without deep results.
 *
 * Request:  POST /api/v1/deep/analyze  (Bearer token)
 * Response: { results: [...], analyzed_at }
 *
 * Returns the same Map<filePath, analyses[]> structure as before so all
 * callers remain unchanged.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const CONTEXT_LINES = 8;

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractContext(filePath, lineNum, lines = CONTEXT_LINES) {
  try {
    const abs     = path.resolve(process.cwd(), filePath);
    const content = fs.readFileSync(abs, 'utf8').split('\n');
    const start   = Math.max(0, lineNum - lines - 1);
    const end     = Math.min(content.length, lineNum + lines);
    return content
      .slice(start, end)
      .map((l, i) => `${start + i + 1}: ${l}`)
      .join('\n');
  } catch {
    return '(source not available)';
  }
}

// ── Teaser ────────────────────────────────────────────────────────────────────

function printTeaser() {
  const DIM   = '\x1b[90m';
  const CYAN  = '\x1b[36m';
  const RESET = '\x1b[0m';
  console.log('');
  console.log(`  ${CYAN}ℹ  Deep analysis requires scd-server with the Deep Analysis Pack.${RESET}`);
  console.log(`  ${DIM}   See https://securecodebydesign.com for subscription options.${RESET}`);
  console.log('');
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Run deep analysis via scd-server.
 *
 * @param {Array}  findings  - CRITICAL/HIGH findings from scanFull()
 * @param {Object} opts      - { centralUrl, token, repoId, scanId, trustLevel, verbose }
 * @returns {Map}  filePath → [analysis results]
 */
async function deepAnalyze(findings, opts = {}) {
  const { centralUrl, token, repoId, scanId, trustLevel = 'balanced', verbose = false } = opts;

  if (!centralUrl) {
    printTeaser();
    return new Map();
  }

  if (!token) {
    console.log('\n\x1b[31m❌ --deep requires an scd-server API token.\x1b[0m');
    console.log('\x1b[90m   Run: scd configure --token <token>\x1b[0m\n');
    return new Map();
  }

  const eligible = Array.from(findings).filter(f =>
    f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );

  if (eligible.length === 0) return new Map();

  if (verbose) {
    console.log(`\x1b[90m 🔍 Sending ${eligible.length} findings to scd-server for deep analysis...\x1b[0m`);
  }

  const payload = eligible.map(f => ({
    ruleId:   f.ruleId,
    name:     f.name     || f.ruleId,
    severity: f.severity,
    file:     f.filePath,
    line:     f.line,
    snippet:  f.snippet  || null,
    context:  extractContext(f.filePath, f.line),
    problem:  f.description || null,
  }));

  try {
    const res = await fetch(centralUrl + '/api/v1/deep/analyze', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': 'Bearer ' + token,
      },
      body: JSON.stringify({ repoId, scanId, trust_level: trustLevel, findings: payload }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      // 503 = deep analysis not available (no scd-ai entitlement)
      // 404 = endpoint not yet deployed (scd-ai not merged to main)
      if (res.status === 503 || res.status === 404) {
        printTeaser();
        return new Map();
      }
      throw new Error(body.error || `HTTP ${res.status}`);
    }

    const data = await res.json();

    // Re-group flat results by file → Map<filePath, analyses[]>
    const results = new Map();
    for (const result of (data.results || [])) {
      const fp = result.file || result.filePath;
      if (!fp) continue;
      if (!results.has(fp)) results.set(fp, []);
      results.get(fp).push(result);
    }
    return results;

  } catch (err) {
    console.log(`\n\x1b[33m⚠️  Deep analysis unavailable: ${err.message}\x1b[0m`);
    console.log('\x1b[90m   Scan completed. Run again with --deep when scd-server is reachable.\x1b[0m\n');
    return new Map();
  }
}

// ── Output formatting ─────────────────────────────────────────────────────────

const SEV_COLORS = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m' };

/**
 * Format the deep analysis section for terminal output.
 * Interface unchanged — all callers remain the same.
 */
function formatDeepSection(findings, deepResults) {
  if (!deepResults || deepResults.size === 0) return '';

  const RESET  = '\x1b[0m';
  const BOLD   = '\x1b[1m';
  const DIM    = '\x1b[90m';
  const GREEN  = '\x1b[32m';
  const RED    = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const CYAN   = '\x1b[36m';

  const lines = [];
  lines.push('');
  lines.push('─'.repeat(60));
  lines.push(`  ${CYAN}${BOLD}↓  Deep analysis (--deep)  ↓${RESET}`);
  lines.push('─'.repeat(60));

  for (const [filePath, analyses] of deepResults) {
    if (!Array.isArray(analyses) || analyses.length === 0) continue;

    if (analyses[0]?._error) {
      lines.push(`\n  ${RED}❌ ${filePath}${RESET}`);
      lines.push(`     ${DIM}Error: ${analyses[0]._error}${RESET}`);
      continue;
    }

    for (const analysis of analyses) {
      const original = findings.find(f =>
        f.ruleId === analysis.ruleId && f.line === analysis.line &&
        (f.filePath === filePath || f.filePath.endsWith(filePath) || filePath.endsWith(f.filePath))
      );
      const sev     = original?.severity ?? 'HIGH';
      const color   = SEV_COLORS[sev] ?? YELLOW;
      const sevIcon = sev === 'CRITICAL' ? '🔴' : '🟠';

      lines.push('');
      lines.push(`  ${color}${BOLD}${sevIcon} ${analysis.ruleId} · ${filePath}:${analysis.line}${RESET}`);

      if (analysis.confirmed === false) {
        lines.push(`     ${GREEN}${BOLD}✓ Likely false positive${RESET}  ${DIM}(confidence: ${analysis.confidence})${RESET}`);
        if (analysis.false_positive_reason) lines.push(`     ${DIM}${analysis.false_positive_reason}${RESET}`);
        continue;
      }

      const confColor = analysis.confidence === 'HIGH' ? RED : analysis.confidence === 'MEDIUM' ? YELLOW : DIM;
      lines.push(`     ${BOLD}Assessment:${RESET} ${RED}✗ Confirmed${RESET}  ${DIM}confidence: ${confColor}${analysis.confidence}${RESET}`);

      if (analysis.attack_scenario) {
        lines.push('');
        lines.push(`     ${BOLD}Attack:${RESET}`);
        const words = analysis.attack_scenario.split(' ');
        let cur = '     ';
        for (const w of words) {
          if (cur.length + w.length > 82) { lines.push(`${DIM}${cur}${RESET}`); cur = '     ' + w + ' '; }
          else cur += w + ' ';
        }
        if (cur.trim()) lines.push(`${DIM}${cur}${RESET}`);
      }

      if (analysis.fix_code) {
        lines.push('');
        lines.push(`     ${BOLD}Fix:${RESET}`);
        for (const fl of analysis.fix_code.split('\n')) lines.push(`     ${GREEN}${fl}${RESET}`);
      }

      if (analysis.fix_explanation) lines.push(`     ${DIM}↳ ${analysis.fix_explanation}${RESET}`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

module.exports = { deepAnalyze, formatDeepSection };
