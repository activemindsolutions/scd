const { RESET, YELLOW } = require('./output-constants');
/**
 * config.js
 * Loads per-repo configuration from ~/.scd/repos/{repoId}/config.yml
 * Never reads from the customer repository — zero repo footprint.
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const CONFIG_FILENAME = 'config.yml'; // lives in global store, not in repo

const DEFAULTS = {
  trust_level:       'balanced',  // maximum_privacy | balanced | maximum_analysis
  block_on_critical: true,        // always blocks (cannot be disabled by rule_overrides)
  block_on_high:     true,        // set to false to warn only
  scan_mode:         'full',      // 'full' (default) | 'fast' (skips taint analysis)
  locked_rules: [
    'SECRET-001', 'SECRET-002', 'SECRET-003',
    'SECRET-006', 'SECRET-007', 'JWT-001',
  ],
  deep_delay_ms:     0,           // ms pause between API calls in scd scan --deep (0 = no delay)
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

// ── Global config keys that can serve as per-repo fallbacks ──────────────
// These keys in ~/.scd/config (KEY=VALUE format) override code defaults
// but are overridden by per-repo config.yml values.
const GLOBAL_FALLBACK_KEYS = [
  'trust_level', 'block_on_critical', 'block_on_high', 'scan_mode', 'deep_delay_ms',
];

function parseGlobalBool(val) {
  if (val === 'true')  return true;
  if (val === 'false') return false;
  return undefined;
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
      console.error(`${YELLOW}[scd] Could not read config: ${err.message}${RESET}`);
    }
  }

  // Read global fallback settings from ~/.scd/config
  // Priority: repo config.yml > global config > code defaults
  const globalFallback = {};
  try {
    const gc = require('./global-config');
    for (const key of GLOBAL_FALLBACK_KEYS) {
      const raw = gc.get('REPO_' + key.toUpperCase());
      if (raw === undefined) continue;
      if (key === 'block_on_critical' || key === 'block_on_high') {
        const v = parseGlobalBool(raw);
        if (v !== undefined) globalFallback[key] = v;
      } else if (key === 'deep_delay_ms') {
        const n = parseInt(raw, 10);
        if (!isNaN(n)) globalFallback[key] = n;
      } else {
        globalFallback[key] = raw;
      }
    }
  } catch { /* global-config not available — skip */ }

  return {
    ...DEFAULTS,
    ...globalFallback,
    ...parsed,
    locked_rules: [
      ...DEFAULTS.locked_rules,
      ...(parsed.locked_rules || []),
    ],
    exceptions:    Array.isArray(parsed.exceptions)   ? parsed.exceptions   : [],
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
        return { excepted: false, expired: true, rejected: false, exception: exc };
      }
    }

    // Normalise file paths for comparison
    const ne = exc.file      ? exc.file.replace(/\\/g,      '/').replace(/^\.\//, '') : null;
    const nf = finding.filePath ? finding.filePath.replace(/\\/g, '/').replace(/^\.\//, '') : null;
    const fileMatches = ne && nf && (nf === ne || nf.endsWith('/' + ne));

    // Hash match — three formats supported:
    // 1. codeHash (32-char hex): stored by addExceptionById — exact match against finding.codeHash
    // 2. Legacy 16-char hex: old addException computed sha256.slice(0,16) from file content.
    //    These are a prefix of finding.codeHash (which is sha256.slice(0,32) of the same content).
    // 3. hashLine() format "sha256:{16hex}": stored by legacy addException path
    const codeHashMatches = exc.line_hash && finding.codeHash && (
      exc.line_hash === finding.codeHash ||                              // format 1: exact 32-char
      (exc.line_hash.length === 16 && finding.codeHash.startsWith(exc.line_hash))  // format 2: legacy 16-char prefix
    );
    const lineHashMatches = exc.line_hash && lineHash &&
      exc.line_hash === lineHash;

    if ((codeHashMatches || lineHashMatches) && fileMatches) {
      if (exc.status === 'rejected') {
        return { excepted: false, expired: false, rejected: true, exception: exc };
      }
      return { excepted: true, expired: false, rejected: false, exception: exc };
    }

    // Fallback: line_hash exists in config but lineContent was empty (e.g. secrets rules
    // that redact lineRaw). Match on rule + file + line instead — the hash cannot be verified
    // but the finding is specific enough to match safely.
    if (exc.line_hash && !lineHash && fileMatches && exc.line != null && finding.line === exc.line) {
      if (exc.status === 'rejected') {
        return { excepted: false, expired: false, rejected: true, exception: exc };
      }
      return { excepted: true, expired: false, rejected: false, exception: exc };
    }

    // File + line_range match (no hash)
    if (!exc.line_hash && fileMatches) {
      if (Array.isArray(exc.line_range) && finding.line != null) {
        const [from, to] = exc.line_range;
        if (finding.line >= from && finding.line <= to) {
          if (exc.status === 'rejected') {
            return { excepted: false, expired: false, rejected: true, exception: exc };
          }
          return { excepted: true, expired: false, rejected: false, exception: exc };
        }
        continue;
      }
      if (exc.status === 'rejected') {
        return { excepted: false, expired: false, rejected: true, exception: exc };
      }
      return { excepted: true, expired: false, rejected: false, exception: exc };
    }
  }

  return { excepted: false, expired: false, rejected: false, exception: null };
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
  // Walk up from CWD looking for .git using fs.existsSync — avoids spawning
  // git against slow filesystems (iCloud Drive, network mounts) where
  // `git rev-parse --show-toplevel` without an explicit cwd can hang.
  const root = path.parse(process.cwd()).root;
  let dir = process.cwd();
  while (dir !== root) {
    if (fs.existsSync(path.join(dir, '.git'))) {
      try {
        const { execSync } = require('child_process');
        return execSync('git rev-parse --show-toplevel', {
          cwd: dir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
        }).trim();
      } catch {
        return dir;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}


module.exports = { loadConfig, isExcepted, getRuleAction, hashLine, getRepoRoot, CONFIG_FILENAME };
