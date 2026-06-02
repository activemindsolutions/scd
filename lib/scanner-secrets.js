/**
 * scanner-secrets.js
 * Fast secrets detection for pre-commit hook.
 * Now config-aware and audit-logged.
 *
 * Rules are loaded from rules/rules-secrets.json via rule-loader.js,
 * consistent with all other rule packs.
 */

const crypto = require('crypto');
const { isExcepted, getRuleAction } = require('./config');
const { loadPack } = require('../rules/rule-loader');

// Load and compile rules from JSON — patterns and antipatterns are RegExp objects
const _secretsPack = require('../rules/rules-secrets.json');
const RULES = loadPack(_secretsPack);

async function scanSecrets(files, config = null) {
  const findings = [];

  for (const { filePath, content } of files) {
    const lines = content.split('\n');

    for (const rule of RULES) {
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        const matches = [...line.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags))];

        for (const match of matches) {
          // Antipattern-check: if the rule has an antipattern, check match line + lookahead
          if (rule.antipattern) {
            const lookahead  = rule.lookahead || 80;
            const windowEnd  = Math.min(lines.length, lineIndex + Math.ceil(lookahead / 80) + 1);
            const window     = lines.slice(lineIndex, windowEnd).join('\n');
            if (rule.antipattern.test(window)) continue; // likely false positive — skip
          }

          const lineNum = lineIndex + 1;
          // Secrets rules use position-based deterministic ID
          const findingId = 'f-' + crypto.createHash('sha256')
            .update((rule.id || '') + '|' + filePath + '|' + String(lineNum))
            .digest('hex').slice(0, 10);

          // code_hash is content-based: sha256 of the raw line only — IDENTICAL algorithm to
          // scanner-full.js. It must never include filePath or line number (see CLAUDE.md:
          // "code_hash design rule"). Content-based so a finding survives a line shift without
          // becoming a new finding; filePath is already part of finding_id and the server identity
          // tuple, so file-scoping the hash too would be redundant and break line-movement survival.
          // (codeHash was previously null under redaction; redaction now lives at the output layer.)
          const codeHash = crypto.createHash('sha256')
            .update(line)
            .digest('hex').slice(0, 32);

          const finding = {
            ruleId:    rule.id,
            name:      rule.name,
            severity:  rule.severity,
            category:  rule.category,
            filePath,
            line:      lineNum,
            snippet:   line.trim(),
            codeHash,
            findingId,
            why:       rule.why,
            scenario:  rule.scenario,
            fix:       rule.fix,
            hook:      'pre-commit',
          };

          if (config) {
            const excResult = isExcepted(config, finding, line);
            finding.excepted          = excResult.excepted;
            finding.exception_expired = excResult.expired;
            finding.exception         = excResult.exception;
            const action = getRuleAction(config, rule.id, rule.severity);
            finding.action = action;
            finding.blocks = !excResult.excepted && action === 'block';
          } else {
            finding.excepted = false;
            finding.action   = rule.severity === 'CRITICAL' ? 'block' : 'warn';
            finding.blocks   = rule.severity === 'CRITICAL';
          }

          findings.push(finding);
        }
      }
    }
  }

  // ── Coverage contract (OQ-B) ──────────────────────────────────────────────
  // The secrets scanner runs secrets rules on every file it is given, so proven
  // coverage is the full input list. ruleDomain is 'secrets' — a pre-commit scan
  // must never resolve non-secret (e.g. OWASP) findings. INVARIANT: files here
  // are exactly the files secrets rules ran on. (See scanner-full.js for the
  // matching contract — both scanners expose the same shape, design §11.11.)
  findings._coverage = {
    files:      files.map(f => f.filePath),
    ruleDomain: 'secrets',
  };

  return findings;
}

module.exports = { scanSecrets, RULES };
