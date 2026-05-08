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

          const redacted = line.trim().replace(match[0], '[REDACTED]');

          const lineNum = lineIndex + 1;
          // Secrets rules redact lineRaw — use position-based deterministic ID
          const findingId = 'f-' + crypto.createHash('sha256')
            .update((rule.id || '') + '|' + filePath + '|' + String(lineNum))
            .digest('hex').slice(0, 8);

          const finding = {
            ruleId:    rule.id,
            name:      rule.name,
            severity:  rule.severity,
            category:  rule.category,
            filePath,
            line:      lineNum,
            snippet:   redacted,
            codeHash:  null,   // redacted — cannot hash secret content
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

  return findings;
}

module.exports = { scanSecrets, RULES };
