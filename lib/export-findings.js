/**
 * export-findings.js
 * Core export logic for sc export-findings and sc review-rules.
 *
 * Both commands produce a structured JSON file capturing findings and
 * rule metadata from a completed scan — suitable for analysis in a
 * separate session or for sharing with Activemind for rule quality review.
 *
 * sc export-findings : customer-facing, omits rule pattern/antipattern
 * sc review-rules    : Activemind-internal, includes pattern/antipattern
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const { loadCache, loadScan }  = require('./scan-cache');
const { storeDir }             = require('./store');
const { queryRules, RULES_VERSION } = require('./rule-registry');
const pkg = require('../package.json');

// ── ANSI helpers ───────────────────────────────────────────────────────────

const GREEN = '\x1b[32m';
const DIM   = '\x1b[90m';
const RED   = '\x1b[31m';
const RESET = '\x1b[0m';

// ── Language mapping ───────────────────────────────────────────────────────

const EXT_TO_LANG = {
  js:   'javascript',
  ts:   'typescript',
  jsx:  'javascript',
  tsx:  'typescript',
  py:   'python',
  php:  'php',
  cs:   'csharp',
  aspx: 'aspnet',
  ascx: 'aspnet',
};

// ── Context reader ─────────────────────────────────────────────────────────

const CONTEXT_LINES = 5;

/**
 * Read lines of source context around a finding.
 * Returns an array of "lineN: content" strings, or null if the file
 * cannot be read (it may have changed or been deleted since the scan).
 */
function readContext(repoRoot, filePath, lineNum) {
  try {
    const abs     = path.resolve(repoRoot, filePath);
    const content = fs.readFileSync(abs, 'utf8').split('\n');
    const start   = Math.max(0, lineNum - CONTEXT_LINES - 1);
    const end     = Math.min(content.length, lineNum + CONTEXT_LINES);
    return content
      .slice(start, end)
      .map((l, i) => `${start + i + 1}: ${l}`);
  } catch {
    return null;
  }
}

// ── Raw rule lookup for pattern / antipattern ──────────────────────────────

/**
 * Search all rule source arrays for a rule by ID.
 * Returns { pattern: string|null, antipattern: string|null } (RegExp → source string).
 * Only used by sc review-rules (includeRuleInternals = true).
 */
function getRulePatterns(ruleId) {
  const sources = [
    require('./rules/rules-js').ALL_RULES,
    require('./rules/rules-js').ALL_EXPOSURE_RULES,
    require('./rules/rules-ts').ALL_RULES,
    require('./rules/rules-python').ALL_RULES,
    require('./rules/rules-python').ALL_EXPOSURE_RULES,
    require('./rules/rules-php').ALL_RULES,
    require('./rules/rules-php').ALL_EXPOSURE_RULES,
    require('./rules/rules-aspx').ALL_RULES,
    require('./rules/rules-aspx-cs').ALL_RULES,
    require('./rules/rules-sensitive-files').CONTENT_RULES,
    require('./rules/rules-sensitive-files').FILENAME_RULES,
    require('./rules/rules-infra-leakage').ALL_INFRA_RULES,
  ];

  for (const rules of sources) {
    if (!Array.isArray(rules)) continue;
    const rule = rules.find(r => r.id === ruleId);
    if (rule) {
      return {
        pattern:     rule.pattern     instanceof RegExp ? rule.pattern.source     : null,
        antipattern: rule.antipattern instanceof RegExp ? rule.antipattern.source : null,
      };
    }
  }
  return { pattern: null, antipattern: null };
}

// ── Deep result lookup ─────────────────────────────────────────────────────

/**
 * Find the deep analysis object for a finding from the deep results map.
 * The map key is filePath, which may not exactly match finding.filePath.
 * We do a best-effort match on path suffix equality.
 *
 * @param {Map}    deepMap  - filePath → [analysisObjects]
 * @param {object} finding
 * @returns {object|null}
 */
function findDeepResult(deepMap, finding) {
  for (const [fp, analyses] of deepMap) {
    if (!Array.isArray(analyses)) continue;
    // Accept if paths are identical or one is a suffix of the other
    if (fp !== finding.filePath &&
        !fp.endsWith(finding.filePath) &&
        !finding.filePath.endsWith(fp)) continue;

    const match = analyses.find(a =>
      !a._error &&
      a.ruleId === finding.ruleId &&
      a.line   === finding.line
    );
    if (match) return match;
  }
  return null;
}

// ── Main export function ───────────────────────────────────────────────────

/**
 * Export findings from a scan to a structured JSON file.
 *
 * @param {object}      options
 * @param {string}      options.repoRoot             Path to the repo being analysed
 * @param {string|null} options.scanId               Specific scan ID, or null for latest
 * @param {string|null} options.severity             Severity filter, or null for all
 * @param {string|null} options.rule                 Rule ID filter, or null for all
 * @param {boolean}     options.all                  Include findings without deep analysis
 * @param {string}      options.outputPath           Full path to write the JSON file
 * @param {boolean}     options.includeRuleInternals true for review-rules, false for export-findings
 * @param {string}      options.command              'export-findings' or 'review-rules'
 */
async function exportFindings(options) {
  const {
    repoRoot,
    scanId,
    severity,
    rule: ruleFilter,
    all: includeAll,
    outputPath,
    includeRuleInternals,
    command,
  } = options;

  // ── Load scan ────────────────────────────────────────────────────────────

  let cache;
  if (scanId) {
    cache = loadScan(repoRoot, scanId);
    if (!cache) {
      console.error('\n' + RED + '✗ Scan not found: ' + scanId + RESET);
      console.error('  Run \x1b[36msc store --scans\x1b[0m to list available scans.\n');
      process.exit(1);
    }
  } else {
    cache = loadCache(repoRoot);
    if (!cache) {
      console.error('\n' + RED + '✗ No saved scan found.' + RESET);
      console.error("  Run 'sc scan' first to generate findings to export from.\n");
      process.exit(1);
    }
  }

  const { findings: allFindings, scanDate, deepResults: deepResultsRaw } = cache;
  const actualScanId = cache.scanId || 'unknown';

  // ── Rebuild deep results map ─────────────────────────────────────────────

  // Stored as [[filePath, analysesArray], ...] — restore to Map
  const deepMap = deepResultsRaw instanceof Array
    ? new Map(deepResultsRaw)
    : new Map();

  // ── Derive languages from all findings (before any filter) ───────────────

  const langsSet = new Set();
  for (const f of allFindings) {
    const ext = path.extname(f.filePath || '').replace('.', '').toLowerCase();
    if (EXT_TO_LANG[ext]) langsSet.add(EXT_TO_LANG[ext]);
  }
  const languagesScanned = Array.from(langsSet).sort();

  // ── Apply severity / rule filters ────────────────────────────────────────

  let filtered = allFindings;
  if (severity) {
    filtered = filtered.filter(f => f.severity === severity.toUpperCase());
  }
  if (ruleFilter) {
    filtered = filtered.filter(f => f.ruleId === ruleFilter);
  }

  // ── Apply deep-only filter and pair each finding with its deep result ─────

  const paired = [];
  for (const f of filtered) {
    const deepAnalysis = findDeepResult(deepMap, f);
    if (!includeAll && !deepAnalysis) continue;
    paired.push({ finding: f, deepAnalysis });
  }

  // ── Repo name (from meta.json or basename) ───────────────────────────────

  let repoName = path.basename(path.resolve(repoRoot));
  try {
    const metaPath = path.join(storeDir(repoRoot), 'meta.json');
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (meta.name) repoName = meta.name;
  } catch { /* meta may not exist yet */ }

  // ── Per-rule statistics ──────────────────────────────────────────────────

  const ruleStats = {};   // ruleId → { name, severity, category, triggered, confirmed, fp, no_verdict }

  for (const { finding: f, deepAnalysis } of paired) {
    if (!ruleStats[f.ruleId]) {
      ruleStats[f.ruleId] = {
        name:           f.name,
        severity:       f.severity,
        category:       f.category || 'Uncategorised',
        triggered:      0,
        confirmed:      0,
        false_positives: 0,
        no_verdict:     0,
      };
    }
    const rs = ruleStats[f.ruleId];
    rs.triggered++;
    if (deepAnalysis) {
      if (deepAnalysis.confirmed) rs.confirmed++;
      else rs.false_positives++;
    } else {
      rs.no_verdict++;
    }
  }

  // ── Summary totals ───────────────────────────────────────────────────────

  let totalConfirmed = 0, totalFP = 0, totalNoVerdict = 0;
  for (const rs of Object.values(ruleStats)) {
    totalConfirmed  += rs.confirmed;
    totalFP         += rs.false_positives;
    totalNoVerdict  += rs.no_verdict;
  }

  // High FP rules: fp_rate >= 0.5 and sample_size >= 3, sorted descending
  const highFpRules = Object.entries(ruleStats)
    .map(([ruleId, rs]) => {
      const sampleSize = rs.confirmed + rs.false_positives;
      const fpRate     = sampleSize > 0 ? rs.false_positives / sampleSize : 0;
      return { rule_id: ruleId, fp_rate: fpRate, sample_size: sampleSize };
    })
    .filter(r => r.fp_rate >= 0.5 && r.sample_size >= 3)
    .sort((a, b) => b.fp_rate - a.fp_rate);

  // ── Build findings array ─────────────────────────────────────────────────

  const findingsOutput = paired.map(({ finding: f, deepAnalysis }, i) => {
    const contextLines = readContext(repoRoot, f.filePath, f.line);
    const entry = {
      id:        'f-' + String(i + 1).padStart(3, '0'),
      rule_id:   f.ruleId,
      rule_name: f.name,
      severity:  f.severity,
      category:  f.category || 'Uncategorised',
      file:      f.filePath,
      line:      f.line,
      code_line: f.snippet,
      context:   contextLines || [f.snippet],
    };

    if (deepAnalysis) {
      entry.deep = {
        verdict:         deepAnalysis.confirmed ? 'confirmed' : 'false_positive',
        confidence:      deepAnalysis.confidence || null,
        attack_scenario: deepAnalysis.attack_scenario || null,
        fix:             deepAnalysis.fix_code || deepAnalysis.fix_explanation || null,
        analyst_notes:   null,
      };
    } else {
      entry.deep = null;
    }

    return entry;
  });

  // ── Build rule_analysis map ──────────────────────────────────────────────

  const ruleAnalysis = {};

  for (const [ruleId, rs] of Object.entries(ruleStats)) {
    const sampleSize = rs.confirmed + rs.false_positives;
    const fpRate     = sampleSize > 0
      ? Math.round((rs.false_positives / sampleSize) * 100) / 100
      : 0;

    // Rule metadata from the registry (why, fix)
    const regMatches = queryRules({ id: ruleId });
    const regEntry   = regMatches[0] || {};

    const ruleEntry = {
      name:     rs.name,
      severity: rs.severity,
      category: rs.category,
      why:      regEntry.why  || null,
      fix:      regEntry.fix  || null,
      stats: {
        triggered:       rs.triggered,
        confirmed:       rs.confirmed,
        false_positives: rs.false_positives,
        no_verdict:      rs.no_verdict,
        fp_rate:         fpRate,
      },
    };

    // pattern / antipattern only for review-rules
    if (includeRuleInternals) {
      const patterns = getRulePatterns(ruleId);
      ruleEntry.pattern     = patterns.pattern;
      ruleEntry.antipattern = patterns.antipattern;
    }

    ruleAnalysis[ruleId] = ruleEntry;
  }

  // ── Assemble output JSON ─────────────────────────────────────────────────

  const output = {
    meta: {
      sc_version:        pkg.version,
      rules_version:     RULES_VERSION,
      scan_id:           actualScanId,
      scan_date:         scanDate,
      repo_name:         repoName,
      languages_scanned: languagesScanned,
      export_type:       includeAll ? 'all_findings' : 'deep_only',
      generated_at:      new Date().toISOString(),
      command,
    },
    summary: {
      total_findings_in_scan: allFindings.length,
      findings_exported:      paired.length,
      confirmed:              totalConfirmed,
      false_positives:        totalFP,
      no_verdict:             totalNoVerdict,
      rules_triggered:        Object.keys(ruleStats).length,
      high_fp_rules:          highFpRules,
    },
    findings:      findingsOutput,
    rule_analysis: ruleAnalysis,
  };

  // ── Ensure output directory exists ──────────────────────────────────────

  const outDir = path.dirname(outputPath);
  fs.mkdirSync(outDir, { recursive: true });

  // ── Write file ───────────────────────────────────────────────────────────

  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2), 'utf8');

  // ── Terminal summary ─────────────────────────────────────────────────────

  const fpSummary = highFpRules
    .map(r => r.rule_id + ' (' + Math.round(r.fp_rate * 100) + '%)')
    .join(', ');

  console.log('\n' + GREEN + '✓ Export complete: ' + outputPath + RESET);
  console.log(DIM + '  Findings exported : ' + paired.length + RESET);
  console.log(DIM + '  Confirmed         : ' + totalConfirmed + RESET);
  console.log(DIM + '  False positives   : ' + totalFP + RESET);
  if (fpSummary) {
    console.log(DIM + '  High FP rules     : ' + fpSummary + RESET);
  }
  console.log('');
}

module.exports = { exportFindings };
