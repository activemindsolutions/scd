/**
 * config.js
 * Loads and validates .securityagent.yml
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const CONFIG_FILENAME = 'config.yml'; // lives in global store, not in repo

const DEFAULTS = {
  trust_level:      'balanced',
  ai_coding_tool:   'none',
  block_on_critical: true,
  block_on_high:    false,
  report_all:       true,
  locked_rules: [
    'SECRET-001', 'SECRET-002', 'SECRET-003',
    'SECRET-006', 'SECRET-007', 'JWT-001',
  ],
};

// ── YAML parser ────────────────────────────────────────────────────────────
// Hand-rolled subset parser – avoids external deps.
// Supports: top-level scalars, top-level sections (objects), lists of objects,
// nested object properties (rule_overrides: { RULE: { action, reason } })
function parseSimpleYaml(content) {
  const result  = {};
  const lines   = content.split('\n');

  let currentSection  = null;   // top-level key
  let currentItem     = null;   // current list item object
  let currentSubKey   = null;   // e.g. "SECRET-005" inside rule_overrides
  let inList          = false;

  for (const raw of lines) {
    const line    = raw.replace(/\r$/, '');
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = line.match(/^(\s*)/)[1].length;

    // ── Top-level key: value  (indent 0, has colon, not ending with ':')
    if (indent === 0 && trimmed.includes(':') && !trimmed.endsWith(':')) {
      const [k, ...vParts] = trimmed.split(':');
      result[k.trim()] = parseValue(vParts.join(':').trim());
      currentSection = null; inList = false; currentItem = null; currentSubKey = null;
      continue;
    }

    // ── Top-level section header  (indent 0, ends with ':')
    if (indent === 0 && trimmed.endsWith(':')) {
      currentSection = trimmed.slice(0, -1);
      result[currentSection] = {};
      inList = false; currentItem = null; currentSubKey = null;
      continue;
    }

    if (!currentSection) continue;

    // ── List item start  (indent 2, starts with '- ')
    if (indent === 2 && trimmed.startsWith('- ')) {
      if (!inList) {
        result[currentSection] = [];
        inList = true;
      }
      currentItem = {};
      currentSubKey = null;
      const rest = trimmed.slice(2).trim();
      if (rest.includes(':')) {
        const [k, ...vParts] = rest.split(':');
        currentItem[k.trim()] = parseValue(vParts.join(':').trim());
      }
      result[currentSection].push(currentItem);
      continue;
    }

    // ── List item property  (indent 4, inside a list item)
    if (indent === 4 && inList && currentItem && trimmed.includes(':')) {
      const [k, ...vParts] = trimmed.split(':');
      const key = k.trim();
      const val = vParts.join(':').trim();
      currentItem[key] = parseLineRangeOrValue(key, val);
      continue;
    }

    // ── Sub-key in a section object (e.g. rule_overrides: SECRET-005:)
    if (indent === 2 && !inList && trimmed.endsWith(':')) {
      currentSubKey = trimmed.slice(0, -1);
      result[currentSection][currentSubKey] = {};
      continue;
    }

    // ── Property of sub-key  (indent 4, inside rule_overrides.SECRET-005)
    if (indent === 4 && !inList && currentSubKey && trimmed.includes(':')) {
      const [k, ...vParts] = trimmed.split(':');
      result[currentSection][currentSubKey][k.trim()] = parseValue(vParts.join(':').trim());
      continue;
    }

    // ── Section scalar  (indent 2, section is plain object, no subkey)
    if (indent === 2 && !inList && !trimmed.endsWith(':') && trimmed.includes(':')) {
      const [k, ...vParts] = trimmed.split(':');
      if (typeof result[currentSection] === 'object' && !Array.isArray(result[currentSection])) {
        result[currentSection][k.trim()] = parseValue(vParts.join(':').trim());
      }
      continue;
    }
  }

  return result;
}

function parseValue(v) {
  if (v === 'true')  return true;
  if (v === 'false') return false;
  if (v === '' || v === null || v === undefined) return null;
  if (!isNaN(v) && v !== '') return Number(v);
  return v.replace(/^['"]|['"]$/g, '');
}

// Parse line_range: [3, 3] as an actual array
function parseLineRangeOrValue(key, val) {
  if (key === 'line_range') {
    const m = val.match(/\[\s*(\d+)\s*,\s*(\d+)\s*\]/);
    if (m) return [parseInt(m[1]), parseInt(m[2])];
  }
  return parseValue(val);
}

// ── Hash a line for exception matching ────────────────────────────────────
function hashLine(rawLine) {
  const normalized = rawLine
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/"/g, "'");
  return 'sha256:' + crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

// ── Load config ────────────────────────────────────────────────────────────
function loadConfig(repoRoot) {
  const store      = require('./store');
  const configPath = store.configPath(repoRoot);
  let parsed = {};

  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, 'utf8');
      parsed = parseSimpleYaml(content);
    } catch (err) {
      console.error(`\x1b[33m[Security Copilot] Kunde inte läsa config: ${err.message}\x1b[0m`);
    }
  }

  return {
    ...DEFAULTS,
    ...parsed,
    locked_rules: [
      ...DEFAULTS.locked_rules,
      ...(parsed.locked_rules || []),
    ],
    exceptions:    Array.isArray(parsed.exceptions)   ? parsed.exceptions   : [],
    resolutions:   Array.isArray(parsed.resolutions)  ? parsed.resolutions  : [],
    rule_overrides: parsed.rule_overrides && typeof parsed.rule_overrides === 'object'
      ? parsed.rule_overrides : {},
  };
}

// ── Check if a finding is excepted ────────────────────────────────────────
function isExcepted(config, finding, lineContent) {
  const lineHash = lineContent ? hashLine(lineContent) : null;

  for (const exc of config.exceptions) {
    if (exc.rule !== finding.ruleId) continue;

    // Check expiry first
    if (exc.expires) {
      const expiry = new Date(exc.expires);
      if (expiry < new Date()) {
        return { excepted: false, expired: true, exception: exc };
      }
    }

    // Normalise file paths for comparison
    const ne = exc.file      ? exc.file.replace(/\\/g,      '/').replace(/^\.\//, '') : null;
    const nf = finding.filePath ? finding.filePath.replace(/\\/g, '/').replace(/^\.\//, '') : null;
    const fileMatches = ne && nf && (nf === ne || nf.endsWith('/' + ne));

    // Hash match requires BOTH correct hash AND correct file
    if (exc.line_hash && lineHash && exc.line_hash === lineHash && fileMatches) {
      return { excepted: true, expired: false, exception: exc };
    }

    // File + line_range match (no hash)
    if (!exc.line_hash && fileMatches) {
      if (Array.isArray(exc.line_range) && finding.line != null) {
        const [from, to] = exc.line_range;
        if (finding.line >= from && finding.line <= to) {
          return { excepted: true, expired: false, exception: exc };
        }
        continue; // file matched but line range didn't
      }
      return { excepted: true, expired: false, exception: exc };
    }
  }

  return { excepted: false, expired: false, exception: null };
}

// ── Get effective action for a rule ───────────────────────────────────────
function getRuleAction(config, ruleId, defaultSeverity) {
  if (config.locked_rules.includes(ruleId)) return 'block';

  const override = config.rule_overrides?.[ruleId];
  if (override && override.action) return override.action;

  if (defaultSeverity === 'CRITICAL') return config.block_on_critical ? 'block' : 'warn';
  if (defaultSeverity === 'HIGH')     return config.block_on_high     ? 'block' : 'warn';
  return 'warn';
}

// ── Get repo root ──────────────────────────────────────────────────────────
function getRepoRoot() {
  try {
    const { execSync } = require('child_process');
    return execSync('git rev-parse --show-toplevel', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'], // suppress stderr – avoids "fatal: not a git repo" leaking to terminal
    }).trim();
  } catch {
    return process.cwd();
  }
}


// ── Check if an EXPOSURE finding has been resolved ────────────────────────
function isResolved(config, finding) {
  const resolutions = config.resolutions || [];
  for (const res of resolutions) {
    if (res.rule !== finding.ruleId) continue;
    if (res.file) {
      const ne = res.file.replace(/\\/g, '/').replace(/^\.\//, '');
      const nf = finding.filePath ? finding.filePath.replace(/\\/g, '/').replace(/^\.\//, '') : null;
      if (nf !== ne && !nf?.endsWith('/' + ne)) continue;
    }
    // Check review date
    if (res.review_date) {
      const review = new Date(res.review_date);
      if (review < new Date()) {
        return { resolved: false, expired: true, record: res };
      }
    }
    return { resolved: true, expired: false, record: res };
  }
  return { resolved: false, expired: false, record: null };
}

module.exports = { loadConfig, isExcepted, isResolved, getRuleAction, hashLine, getRepoRoot, CONFIG_FILENAME };
