/**
 * deep-analyzer.js
 * Routes --deep analysis to scd-server. All AI logic lives server-side.
 * Uses http.request instead of fetch to avoid Node.js fetch socket timeout issues.
 */

'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('./output-constants');

const fs   = require('fs');
const path = require('path');
const http  = require('http');
const https = require('https');
const url   = require('url');

const CONTEXT_LINES  = 8;

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

function printTeaser() {
  console.log('');
  console.log(`  ${CYAN}ℹ  Deep analysis requires scd-server with the Deep Analysis Pack.${RESET}`);
  console.log(`  ${DIM}   See https://securecodebydesign.com for subscription options.${RESET}`);
  console.log('');
}

/**
 * Simple HTTP POST using http.request — avoids fetch socket timeout issues.
 */
function httpPost(targetUrl, body, token, timeoutMs) {
  return new Promise((resolve, reject) => {
    const parsed   = new url.URL(targetUrl);
    const isHttps  = parsed.protocol === 'https:';
    const lib      = isHttps ? https : http;
    const bodyStr  = typeof body === 'string' ? body : JSON.stringify(body);

    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (isHttps ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Authorization':  'Bearer ' + token,
        'Content-Length': Buffer.byteLength(bodyStr),
      },
      timeout: timeoutMs,
    };

    const req = lib.request(options, (res) => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, body: raw });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function deepAnalyze(findings, opts = {}) {
  const { centralUrl, token, repoId, scanId, trustLevel = 'balanced', verbose = false } = opts;

  if (!centralUrl) { printTeaser(); return new Map(); }

  if (!token) {
    console.log('\nRED❌ --deep requires an scd-server API token.' + RESET);
    console.log(DIM + '   Run: scd configure --token <token>' + RESET + '\n');
    return new Map();
  }

  const eligible = Array.from(findings).filter(f =>
    f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );

  if (eligible.length === 0) return new Map();

  if (verbose) {
    process.stdout.write(`${DIM} 🔍 Sending ${eligible.length} findings to scd-server for deep analysis...${RESET}\n`);
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
    const { getDeepTimeout } = require('./global-config');
    const response = await httpPost(
      centralUrl + '/api/v1/deep/analyze',
      { repoId, scanId, trust_level: trustLevel, findings: payload },
      token,
      getDeepTimeout()
    );

    if (response.status === 503 || response.status === 404) {
      printTeaser();
      return new Map();
    }

    if (response.status !== 200) {
      let errMsg = `HTTP ${response.status}`;
      try { errMsg = JSON.parse(response.body).error || errMsg; } catch {}
      throw new Error(errMsg);
    }

    const data = JSON.parse(response.body);

    const results = new Map();
    for (const result of (data.results || [])) {
      const fp = result.file || result.filePath;
      if (!fp) continue;
      if (!results.has(fp)) results.set(fp, []);
      results.get(fp).push(result);
    }
    return results;

  } catch (err) {
    console.log(`\nYELLOW⚠️  Deep analysis unavailable: ${err.message}${RESET}`);
    console.log(DIM + '   Scan completed. Run again with --deep when scd-server is reachable.' + RESET + '\n');
    return new Map();
  }
}

const SEV_COLORS = { CRITICAL: RED, HIGH: YELLOW };

function formatDeepSection(findings, deepResults) {
  if (!deepResults || deepResults.size === 0) return '';


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

      // Normalise confidence — 7b model may return numeric (0-1) instead of string
      const rawConf = analysis.confidence;
      const conf = typeof rawConf === 'number'
        ? (rawConf >= 0.8 ? 'HIGH' : rawConf >= 0.5 ? 'MEDIUM' : 'LOW')
        : (rawConf || 'LOW');
      const confColor = conf === 'HIGH' ? RED : conf === 'MEDIUM' ? YELLOW : DIM;
      lines.push(`     ${BOLD}Assessment:${RESET} ${RED}✗ Confirmed${RESET}  ${DIM}confidence: ${confColor}${conf}${RESET}`);

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
