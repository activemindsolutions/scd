/**
 * lib/scope.js
 * Loads and applies scan scope exclusions from scope.yml files.
 *
 * Scope decisions are explicit, documented choices about what scd scans.
 * They are distinct from operational config (config.yml) and are treated
 * as security decisions — every entry requires reason, added_by, added_at.
 *
 * Three sources, merged in priority order (last wins on conflict):
 *   1. ~/.scd/scope.yml              — global, user-owned
 *   2. ~/.scd/repos/{id}/scope.yml   — repo, user-owned
 *   3. ~/.scd/repos/{id}/scope-server.yml — server-owned, read-only
 *
 * Source 3 only applied when a server URL is configured (getCentralUrl()).
 * Standalone-first: missing scope files are not errors.
 */

'use strict';
const { RESET, DIM } = require('./output-constants');

const fs   = require('fs');
const path = require('path');
const store = require('./store');
const { formatLocalTime } = require('./format-time');

// ── YAML parser (hand-rolled, consistent with config.js) ─────────────────

/**
 * Minimal YAML parser for scope.yml structure.
 * Handles: top-level keys, list items (- key: value), nested keys under lists.
 * Does not support anchors, aliases, or multi-document streams.
 */
function parseScope(yamlText) {
  const lines = yamlText.split('\n');
  const result = { file_excludes: [], rule_excludes: [] };

  let section = null;   // 'file_excludes' | 'rule_excludes'
  let current = null;   // current list entry being built

  function finalise() {
    if (!current) return;
    if (section === 'file_excludes' && current.pattern) {
      result.file_excludes.push(current);
    } else if (section === 'rule_excludes' && current.rule) {
      result.rule_excludes.push(current);
    }
    current = null;
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line || line.trimStart().startsWith('#')) continue;

    // Top-level section headers
    if (/^file_excludes\s*:/.test(line)) { finalise(); section = 'file_excludes'; continue; }
    if (/^rule_excludes\s*:/.test(line)) { finalise(); section = 'rule_excludes'; continue; }

    // List item start: "  - key: value"
    const listItemMatch = line.match(/^(\s+)-\s+(\w+)\s*:\s*(.*)/);
    if (listItemMatch) {
      finalise();
      current = {};
      const [, , key, val] = listItemMatch;
      current[key] = unquote(val.trim());
      if (section === 'rule_excludes' && key === 'rule' && !current.files) {
        current.files = null;
      }
      continue;
    }

    // Nested key under current list item: "    key: value"
    if (current) {
      const nestedKeyMatch = line.match(/^(\s+)(\w+)\s*:\s*(.*)/);
      if (nestedKeyMatch) {
        const [, , key, val] = nestedKeyMatch;
        const trimmedVal = val.trim();

        // files: is a list — initialise it if we see the key with no value
        if (key === 'files') {
          current.files = trimmedVal ? [unquote(trimmedVal)] : [];
          continue;
        }

        current[key] = unquote(trimmedVal);
        continue;
      }

      // List item under files: "      - pattern"
      const filesItemMatch = line.match(/^(\s+)-\s+(.*)/);
      if (filesItemMatch && Array.isArray(current.files)) {
        current.files.push(unquote(filesItemMatch[2].trim()));
        continue;
      }
    }
  }

  finalise();
  return result;
}

function unquote(str) {
  if (!str) return str;
  if ((str.startsWith('"') && str.endsWith('"')) ||
      (str.startsWith("'") && str.endsWith("'"))) {
    return str.slice(1, -1);
  }
  return str;
}

// ── Load a single scope file ──────────────────────────────────────────────

function loadScopeFile(filePath, source) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    const parsed = parseScope(text);
    // Tag each entry with its source
    for (const e of parsed.file_excludes) e._source = source;
    for (const e of parsed.rule_excludes) e._source = source;
    return parsed;
  } catch (err) {
    console.error(`${DIM}[scd] scope.yml warning (${source}): ${err.message}${RESET}`);
    return null;
  }
}

// ── Merge two scope objects (later wins on conflict) ──────────────────────

function mergeScope(base, override) {
  if (!override) return base;
  return {
    file_excludes: [...base.file_excludes, ...override.file_excludes],
    rule_excludes: [...base.rule_excludes, ...override.rule_excludes],
  };
}

// ── Load merged scope for a repo ──────────────────────────────────────────

/**
 * Load and merge scope from all three sources for a given repo root.
 * Returns a merged scope object: { file_excludes, rule_excludes }
 *
 * Source priority (last wins): global → repo → server
 *
 * @param {string} repoRoot  Absolute path to repo root
 * @returns {{ file_excludes: Array, rule_excludes: Array }}
 */
function loadScope(repoRoot) {
  let scope = { file_excludes: [], rule_excludes: [] };

  // 1. Global scope (~/.scd/scope.yml)
  const global = loadScopeFile(store.globalScopePath(), 'global');
  if (global) scope = mergeScope(scope, global);

  // Global-only mode (scd scope --show passes null): without a repo root there is
  // no per-repo or server scope to merge, and resolving a repo ID from a null root
  // throws (path.resolve(null)). Returning here also prevents the per-repo source
  // from silently resolving against whatever git repo the cwd happens to be.
  if (!repoRoot) return scope;

  // 2. Repo scope (~/.scd/repos/{id}/scope.yml)
  const repo = loadScopeFile(store.scopePath(repoRoot), 'repo');
  if (repo) scope = mergeScope(scope, repo);

  // 3. Server scope (~/.scd/repos/{id}/scope-server.yml)
  // Only applied when a central URL is configured
  try {
    const { getCentralUrl } = require('./global-config');
    if (getCentralUrl()) {
      const server = loadScopeFile(store.serverScopePath(repoRoot), 'server');
      if (server) scope = mergeScope(scope, server);
    }
  } catch { /* global-config unavailable — standalone mode */ }

  return scope;
}

// ── Pattern matching ───────────────────────────────────────────────────────

/**
 * Convert a scope pattern to a match function.
 * Supports:
 *   - Directory: "tests/fixtures/" or "tests/fixtures"  → prefix match
 *   - Glob:      "**\/*.test.js"                        → glob → regex
 *   - Exact:     "bin/scd.js"                           → equality
 */
function makePatternMatcher(pattern) {
  const norm = pattern.replace(/\\/g, '/').replace(/\/$/, '');

  // Directory pattern (trailing slash in original, or contains no extension and no glob chars)
  const isDir = pattern.endsWith('/');
  if (isDir) {
    return (rel) => rel === norm || rel.startsWith(norm + '/');
  }

  // Glob pattern
  if (pattern.includes('*') || pattern.includes('?')) {
    const regexStr = norm
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\\\*/g, '__STAR__')
      .replace(/\*\*/g, '__DOUBLESTAR__')
      .replace(/__STAR__/g, '[^/]*')
      .replace(/__DOUBLESTAR__/g, '.*')
      .replace(/\?/g, '[^/]');
    const re = new RegExp('^' + regexStr + '$');
    return (rel) => re.test(rel);
  }

  // Exact match (also matches as directory prefix)
  return (rel) => rel === norm || rel.startsWith(norm + '/');
}

// ── Public filter API ─────────────────────────────────────────────────────

/**
 * Check if a file should be excluded by scope.file_excludes.
 *
 * @param {{ file_excludes: Array }} scope  Merged scope object
 * @param {string} absPath                  Absolute file path
 * @param {string} repoRoot                 Repo root for relative path calculation
 * @returns {{ excluded: boolean, entry: object|null }}
 */
function isFileExcluded(scope, absPath, repoRoot) {
  if (!scope.file_excludes.length) return { excluded: false, entry: null };

  // Normalise to forward-slash relative path for matching
  const rel = path.relative(repoRoot, absPath).replace(/\\/g, '/');

  for (const entry of scope.file_excludes) {
    if (!entry.pattern) continue;
    const matches = makePatternMatcher(entry.pattern);
    if (matches(rel)) return { excluded: true, entry };
  }

  return { excluded: false, entry: null };
}

/**
 * Check if a finding should be excluded by scope.rule_excludes.
 *
 * @param {{ rule_excludes: Array }} scope  Merged scope object
 * @param {string} ruleId                   Finding rule ID
 * @param {string} filePath                 Finding file path (relative)
 * @returns {{ excluded: boolean, entry: object|null }}
 */
function isRuleExcluded(scope, ruleId, filePath) {
  if (!scope.rule_excludes.length) return { excluded: false, entry: null };

  for (const entry of scope.rule_excludes) {
    if (!entry.rule || entry.rule !== ruleId) continue;

    // No files list → exclude for all files
    if (!entry.files || !entry.files.length) {
      return { excluded: true, entry };
    }

    // Files list → check if filePath matches any pattern
    const normFile = (filePath || '').replace(/\\/g, '/');
    for (const pattern of entry.files) {
      const matches = makePatternMatcher(pattern);
      if (matches(normFile)) return { excluded: true, entry };
    }
  }

  return { excluded: false, entry: null };
}

// ── Validation ────────────────────────────────────────────────────────────

/**
 * Validate a parsed scope object. Returns an array of warning objects
 * for entries missing required fields (reason, added_by, added_at).
 * Never throws — validation is advisory only.
 *
 * @param {{ file_excludes: Array, rule_excludes: Array }} scope
 * @returns {Array<{ type: string, identifier: string, missing: string[] }>}
 */
function validateScope(scope) {
  const warnings = [];
  const REQUIRED = ['reason', 'added_by', 'added_at'];

  for (const entry of scope.file_excludes) {
    const missing = REQUIRED.filter(f => !entry[f]);
    if (missing.length) {
      warnings.push({ type: 'file_exclude', identifier: entry.pattern || '(unknown)', missing });
    }
  }

  for (const entry of scope.rule_excludes) {
    const missing = REQUIRED.filter(f => !entry[f]);
    if (missing.length) {
      warnings.push({ type: 'rule_exclude', identifier: entry.rule || '(unknown)', missing });
    }
  }

  return warnings;
}

// ── Scope summary for output ──────────────────────────────────────────────

/**
 * Build a human-readable summary of active scope exclusions.
 * Used in terminal output and audit log.
 *
 * @param {{ file_excludes: Array, rule_excludes: Array }} scope
 * @returns {{ hasExclusions: boolean, fileLines: string[], ruleLines: string[] }}
 */
function summariseScope(scope) {
  const fileLines = scope.file_excludes.map(e => {
    const reason = e.reason ? ` — "${e.reason}"` : ' — (no reason given)';
    const meta   = [e.added_by, formatLocalTime(e.added_at)].filter(Boolean).join(', ');
    const src    = e._source ? ` [${e._source}]` : '';
    return `  ${e.pattern}${reason} (${meta})${src}`;
  });

  const ruleLines = scope.rule_excludes.map(e => {
    const scope_  = e.files && e.files.length ? e.files.join(', ') : 'all files';
    const reason  = e.reason ? ` — "${e.reason}"` : ' — (no reason given)';
    const meta    = [e.added_by, formatLocalTime(e.added_at)].filter(Boolean).join(', ');
    const src     = e._source ? ` [${e._source}]` : '';
    return `  ${e.rule} (${scope_})${reason} (${meta})${src}`;
  });

  return {
    hasExclusions: fileLines.length > 0 || ruleLines.length > 0,
    fileLines,
    ruleLines,
  };
}

module.exports = {
  loadScope,
  isFileExcluded,
  isRuleExcluded,
  validateScope,
  summariseScope,
  parseScope,     // exported for testing
};
