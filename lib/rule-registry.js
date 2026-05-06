/**
 * rule-registry.js
 * Central catalogue of all Secure Code by Design rules.
 *
 * Normalises every rule into a consistent shape:
 *   { id, name, severity, category, languages, matchMode, why, scenario, fix }
 *
 * Used by: scd rules (list/search/detail)
 *          scd report (rule metadata in reports)
 *          scd insights (category grouping)
 */

'use strict';

// Rules bundle version – bump on rule additions/fixes (minor) or ID changes (major)
// Independent of CLI version: scd 0.2.0 can ship with rules 1.3.0
const RULES_VERSION = '1.2.0';

const { ALL_RULES: JS_RULES, ALL_EXPOSURE_RULES: JS_EXPOSURE }   = require('./rules/rules-js');
const { ALL_RULES: TS_RULES }                                     = require('./rules/rules-ts');
const { loadRule }                                                = require('./rules/rule-loader');
const _pyPack                                                     = require('./rules/rules-python.json');
const _phpPack                                                    = require('./rules/rules-php.json');
const PY_RULES                                                    = _pyPack.rules.map(r => loadRule(r, 'builtin'));
const PHP_RULES                                                   = _phpPack.rules.map(r => loadRule(r, 'builtin'));
const PY_EXPOSURE                                                 = PY_RULES.filter(r => r.severity === 'EXPOSURE');
const PHP_EXPOSURE                                                = PHP_RULES.filter(r => r.severity === 'EXPOSURE');
const _aspxPack                                                   = require('./rules/rules-aspx.json');
const _aspxCsPack                                                 = require('./rules/rules-aspx-cs.json');
const ASPX_RULES                                                  = _aspxPack.rules.map(r => loadRule(r, 'builtin'));
const ASPX_CS_RULES                                               = _aspxCsPack.rules.map(r => loadRule(r, 'builtin'));
const _sensitivePack                                              = require('./rules/rules-sensitive-files.json');
const _sensitiveRules                                             = _sensitivePack.rules.map(r => loadRule(r, 'builtin'));
const SF_CONTENT                                                  = _sensitiveRules.filter(r => r.matchMode !== 'filename');
const SF_FILENAME                                                 = _sensitiveRules.filter(r => r.matchMode === 'filename');
const _infraPack                                                  = require('./rules/rules-infra-leakage.json');
const ALL_INFRA_RULES                                             = _infraPack.rules.map(r => loadRule(r, 'builtin'));

// ── Language tags per rule source ──────────────────────────────────────────

const SOURCES = [
  { rules: JS_RULES,     languages: ['js', 'ts', 'mjs', 'cjs', 'jsx', 'tsx'] },
  { rules: JS_EXPOSURE,  languages: ['js', 'ts', 'mjs', 'cjs', 'jsx', 'tsx', 'html', 'php', 'py'] },
  { rules: TS_RULES,     languages: ['ts', 'tsx'] },
  { rules: PY_RULES,     languages: ['py'] },
  { rules: PY_EXPOSURE,  languages: ['py'] },
  { rules: PHP_RULES,    languages: ['php'] },
  { rules: PHP_EXPOSURE, languages: ['php'] },
  { rules: ASPX_RULES,   languages: ['aspx', 'ascx', 'cs'] },
  { rules: ASPX_CS_RULES,languages: ['cs'] },
  { rules: SF_CONTENT,   languages: null },   // fileTypes on each rule
  { rules: SF_FILENAME,  languages: null },   // filename-match rules
  { rules: ALL_INFRA_RULES, languages: ['all'] },
];

// ── Severity sort order ────────────────────────────────────────────────────

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, LOW: 4 };

// ── Build normalised registry ──────────────────────────────────────────────

function buildRegistry() {
  const seen = new Set();
  const registry = [];

  for (const { rules, languages } of SOURCES) {
    if (!rules) continue;
    for (const rule of rules) {
      if (seen.has(rule.id)) continue;   // dedup (e.g. EXPOSURE rules appear in multiple sets)
      seen.add(rule.id);

      // Determine languages for this rule
      let langs;
      if (languages) {
        langs = languages;
      } else if (rule.fileTypes) {
        langs = rule.fileTypes;
      } else {
        langs = ['all'];
      }

      registry.push({
        id:        rule.id,
        name:      rule.name,
        severity:  rule.severity,
        category:  rule.category  || 'Uncategorised',
        languages: langs,
        matchMode: rule.matchMode === 'filename' || rule.filenamePattern ? 'filename' : 'content',
        why:       rule.why       || null,
        scenario:  rule.scenario  || null,
        fix:       rule.fix       || null,
        checklist: rule.checklist || null,
      });
    }
  }

  // Sort: severity → id prefix → numeric suffix
  registry.sort((a, b) => {
    const sevDiff = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    return a.id.localeCompare(b.id, undefined, { numeric: true });
  });

  return registry;
}

// Lazy singleton
let _registry = null;
function getRegistry() {
  if (!_registry) _registry = buildRegistry();
  return _registry;
}

// ── Query helpers ──────────────────────────────────────────────────────────

/**
 * Filter registry by options.
 * @param {{ lang, severity, id, search }} opts
 */
function queryRules({ lang, severity, id, search } = {}) {
  let rules = getRegistry();

  if (id) {
    return rules.filter(r => r.id.toLowerCase() === id.toLowerCase());
  }

  if (lang) {
    const langs = lang.split(',').map(l => l.trim().toLowerCase());
    rules = rules.filter(r =>
      r.languages.includes('all') ||
      r.languages.some(l => langs.includes(l.toLowerCase()))
    );
  }

  if (severity) {
    const sev = severity.toUpperCase();
    rules = rules.filter(r => r.severity === sev);
  }

  if (search) {
    const q = search.toLowerCase();
    rules = rules.filter(r =>
      r.id.toLowerCase().includes(q) ||
      r.name.toLowerCase().includes(q) ||
      r.category.toLowerCase().includes(q) ||
      (r.why      && r.why.toLowerCase().includes(q)) ||
      (r.fix      && r.fix.toLowerCase().includes(q))
    );
  }

  return rules;
}

/**
 * Stats summary across all (or filtered) rules.
 */
function getStats(rules) {
  rules = rules || getRegistry();
  const bySeverity = {};
  const byLanguage = {};
  const byCategory = {};

  for (const r of rules) {
    bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;
    for (const l of r.languages) {
      byLanguage[l] = (byLanguage[l] || 0) + 1;
    }
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
  }

  return { total: rules.length, bySeverity, byLanguage, byCategory };
}

module.exports = { getRegistry, queryRules, getStats, SEV_ORDER, RULES_VERSION };
