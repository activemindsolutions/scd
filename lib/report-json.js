/**
 * report-json.js
 * Generates a structured JSON security report from scan findings.
 *
 * Designed for:
 *   - CI/CD pipeline integration (fail build on CRITICAL count threshold)
 *   - Import into dashboards, ticketing systems, or SIEMs
 *   - Diffing findings between scans
 *
 * Structure:
 *   {
 *     meta:      { scanDate, target, totalFiles, generatedBy, version }
 *     summary:   { riskScore, riskLabel, totalFindings, bySeverity, byCategory }
 *     findings:  [ { ruleId, severity, name, category, filePath, line, match, why, fix } ]
 *     checklist: [ { ruleId, severity, name, occurrences } ]
 *   }
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Risk scoring ───────────────────────────────────────────────────────────

const SEV_WEIGHT = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, EXPOSURE: 1, INFO: 0 };
const SEV_ORDER  = ['CRITICAL', 'HIGH', 'MEDIUM', 'EXPOSURE', 'INFO'];

function computeRiskScore(findings) {
  if (!findings.length) return 0;
  const raw = findings.reduce((sum, f) => sum + (SEV_WEIGHT[f.severity] || 0), 0);
  return Math.min(100, Math.round(raw / Math.max(findings.length, 1) * 5));
}

function riskLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 55) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  if (score >= 10) return 'LOW';
  return 'MINIMAL';
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, EXPOSURE: 0, INFO: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  return counts;
}

function countByCategory(findings) {
  const counts = {};
  findings.forEach(f => {
    const cat = f.category || 'Unknown';
    counts[cat] = (counts[cat] || 0) + 1;
  });
  // Sort by count descending
  return Object.fromEntries(
    Object.entries(counts).sort(([, a], [, b]) => b - a)
  );
}

function buildChecklist(findings) {
  const seen  = new Set();
  const items = [];
  for (const sev of SEV_ORDER) {
    for (const f of findings.filter(x => x.severity === sev)) {
      if (seen.has(f.ruleId)) continue;
      seen.add(f.ruleId);
      items.push({
        ruleId:      f.ruleId,
        severity:    f.severity,
        name:        f.name,
        category:    f.category || null,
        occurrences: findings.filter(x => x.ruleId === f.ruleId).length,
        resolved:    false,   // placeholder for tooling integration
      });
    }
  }
  return items;
}

// ── Main generator ─────────────────────────────────────────────────────────

function generateJson(findings, opts = {}) {
  const {
    target     = '.',
    scanDate   = new Date(),
    totalFiles = 0,
    skipped    = [],
    repoRoot   = process.cwd(),
  } = opts;

  const score  = computeRiskScore(findings);

  const report = {
    meta: {
      generatedBy:  'Secure Code by Design',
      version:      require('../package.json').version,
      scanDate:     new Date(scanDate).toISOString(),
      target,
      totalFiles,
      skippedFiles: skipped.length,
    },
    summary: {
      riskScore:     score,
      riskLabel:     riskLabel(score),
      totalFindings: findings.length,
      bySeverity:    countBySeverity(findings),
      byCategory:    countByCategory(findings),
    },
    findings: findings.map(f => ({
      findingId: f.findingId  || null,
      ruleId:    f.ruleId,
      severity:  f.severity,
      name:      f.name       || null,
      category:  f.category   || null,
      filePath:  f.filePath,
      line:      f.line,
      match:     f.match      || null,
      why:       f.why        || null,
      scenario:  f.scenario   || null,
      fix:       f.fix        || null,
      excepted:  f.excepted   || false,
      codeHash:  f.codeHash   || null,
    })),
    checklist: buildChecklist(findings),
  };

  return JSON.stringify(report, null, 2);
}

function writeJson(json, outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, json, { encoding: 'utf8', mode: 0o644 });
}

module.exports = { generateJson, writeJson };
