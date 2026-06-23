/**
 * report-markdown.js
 * Generates a Markdown security report from scan findings.
 *
 * Designed for two use cases:
 *   1. Pasting into GitHub Issues, Confluence, Notion, Jira, etc.
 *   2. Committing as SECURITY.md or including in PR descriptions.
 *
 * Sections:
 *   - Executive summary (risk score, severity counts)
 *   - Findings by severity (CRITICAL → EXPOSURE)
 *   - Per-finding detail: file, line, why, fix
 *   - Remediation checklist
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { formatLocalTime } = require('./format-time');
const { SEVERITY } = require('./severity');

// ── Risk scoring (same weights as report-html) ─────────────────────────────

const SEV_WEIGHT = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, EXPOSURE: 1, INFO: 0 };
// Severity order comes from the central severity module. A Markdown document has no
// ANSI colour, so severity shows as a plain text label — no emoji circles.
const SEV_ORDER  = Object.keys(SEVERITY);

function computeRiskScore(findings) {
  if (!findings.length) return 0;
  const raw = findings.reduce((sum, f) => sum + (SEV_WEIGHT[f.severity] || 0), 0);
  return Math.min(100, Math.round(raw / Math.max(findings.length, 1) * 5));
}

function riskLabel(score) {
  if (score >= 80) return 'CRITICAL RISK';
  if (score >= 55) return 'HIGH RISK';
  if (score >= 30) return 'MEDIUM RISK';
  if (score >= 10) return 'LOW RISK';
  return 'MINIMAL RISK';
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, EXPOSURE: 0, INFO: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  return counts;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function escMd(str) {
  // Escape markdown special chars in inline text
  return String(str || '').replace(/([`*_\[\]<>|\\])/g, '\\$1');
}

function shortPath(filePath, repoRoot) {
  if (repoRoot && filePath.startsWith(repoRoot)) {
    return filePath.slice(repoRoot.length).replace(/^[\\/]/, '');
  }
  return filePath;
}

function severityBar(counts) {
  const parts = SEV_ORDER
    .filter(s => counts[s] > 0)
    .map(s => `**${counts[s]} ${s}**`);
  return parts.join('  ·  ');
}

function groupBy(arr, key) {
  return arr.reduce((acc, item) => {
    const k = item[key] || 'Unknown';
    (acc[k] = acc[k] || []).push(item);
    return acc;
  }, {});
}

// ── Remediation checklist ──────────────────────────────────────────────────

function buildChecklist(findings) {
  // Deduplicate by ruleId – one checklist item per unique rule
  const seen   = new Set();
  const items  = [];
  for (const sev of SEV_ORDER) {
    const bySev = findings.filter(f => f.severity === sev);
    for (const f of bySev) {
      if (seen.has(f.ruleId)) continue;
      seen.add(f.ruleId);
      const count = findings.filter(x => x.ruleId === f.ruleId).length;
      items.push({ sev, ruleId: f.ruleId, name: f.name, count });
    }
  }
  return items;
}

// ── Main generator ─────────────────────────────────────────────────────────

function generateMarkdown(findings, opts = {}) {
  const {
    target    = '.',
    scanDate  = new Date(),
    totalFiles = 0,
    skipped   = [],
    repoRoot  = process.cwd(),
  } = opts;

  const counts   = countBySeverity(findings);
  const score    = computeRiskScore(findings);
  const risk     = riskLabel(score);
  const dateStr  = formatLocalTime(scanDate);   // local wall clock, English, consistent

  const lines = [];

  // ── Header ────────────────────────────────────────────────────────────────
  lines.push(`# {scd} Secure Code by Design – Security Report`);
  lines.push('');
  lines.push(`> Generated: **${dateStr}**  ·  Target: \`${escMd(target)}\`  ·  Files: **${totalFiles}**`);
  lines.push('');

  // ── Executive summary ─────────────────────────────────────────────────────
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Property | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Risk assessment | ${risk} (${score}/100) |`);
  lines.push(`| Total findings | **${findings.length}** |`);
  lines.push(`| Files scanned | ${totalFiles} |`);
  if (skipped.length > 0) {
    lines.push(`| Skipped files | ${skipped.length} (too large) |`);
  }
  lines.push('');

  // Severity breakdown
  lines.push('### Findings by severity');
  lines.push('');
  lines.push('| Severity | Count | Description |');
  lines.push('|---|---|---|');
  const sevDesc = {
    CRITICAL: 'Directly exploitable – fix immediately',
    HIGH:     'High risk – fix within sprint',
    MEDIUM:   'Medium risk – schedule remediation',
    EXPOSURE: 'Configuration risk – may leak information',
    INFO:     'Informational',
  };
  for (const sev of SEV_ORDER) {
    if (counts[sev] === 0) continue;
    lines.push(`| ${sev} | **${counts[sev]}** | ${sevDesc[sev]} |`);
  }
  lines.push('');

  // ── Findings per severity ─────────────────────────────────────────────────
  lines.push('---');
  lines.push('');
  lines.push('## Findings');
  lines.push('');

  for (const sev of SEV_ORDER) {
    const sevFindings = findings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    lines.push(`### ${sev} (${sevFindings.length})`);
    lines.push('');

    // Group by rule for compact output
    const byRule = groupBy(sevFindings, 'ruleId');

    for (const [ruleId, ruleFindings] of Object.entries(byRule)) {
      const first = ruleFindings[0];
      lines.push(`#### ${escMd(ruleId)} – ${escMd(first.name)}`);
      lines.push('');

      if (first.category) {
        lines.push(`**Category:** ${escMd(first.category)}`);
        lines.push('');
      }

      // Affected locations
      lines.push('**Occurrences:**');
      lines.push('');
      for (const f of ruleFindings) {
        const fp = shortPath(f.filePath, repoRoot);
        const matchSnippet = (f.snippet && f.snippet !== '[REDACTED]') ? `  \`${escMd(f.snippet.slice(0, 80).trim())}\`` : '';
        lines.push(`- \`${escMd(fp)}\` line **${f.line}**${matchSnippet}`);
      }
      lines.push('');

      // Why
      if (first.why) {
        lines.push('<details>');
        lines.push('<summary>Why is this a problem?</summary>');
        lines.push('');
        lines.push(first.why);
        lines.push('');
        lines.push('</details>');
        lines.push('');
      }

      // Scenario
      if (first.scenario) {
        lines.push('<details>');
        lines.push('<summary>Attack scenario</summary>');
        lines.push('');
        lines.push(`> ${first.scenario}`);
        lines.push('');
        lines.push('</details>');
        lines.push('');
      }

      // Fix
      if (first.fix) {
        lines.push('**Fix:**');
        lines.push('');
        lines.push(`> ${first.fix}`);
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    }
  }

  // ── Remediation checklist ─────────────────────────────────────────────────
  lines.push('## Remediation checklist');
  lines.push('');
  lines.push('Check off each finding when resolved:');
  lines.push('');

  const checklist = buildChecklist(findings);
  for (const item of checklist) {
    const plural = item.count > 1 ? ` _(${item.count} occurrences)_` : '';
    lines.push(`- [ ] \`${item.sev}\` **${item.ruleId}** – ${escMd(item.name)}${plural}`);
  }
  lines.push('');

  // ── Footer ────────────────────────────────────────────────────────────────
  lines.push('---');
  lines.push('');
  lines.push(`_Report generated by **Secure Code by Design** · ${dateStr}_`);
  lines.push('');

  return lines.join('\n');
}

function writeMarkdown(md, outPath) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, md, { encoding: 'utf8', mode: 0o644 });
}

module.exports = { generateMarkdown, writeMarkdown };
