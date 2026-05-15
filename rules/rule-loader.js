'use strict';

/**
 * rule-loader.js
 * Compiles a raw rule definition (from JSON) into a runtime rule object
 * compatible with scanner-full.js.
 *
 * JSON rules cannot contain RegExp literals or functions — rule-loader
 * bridges that gap by compiling patterns and normalising confidence at
 * load time.
 *
 * ── Schema version ──────────────────────────────────────────────────────────
 * schema_version: 1
 *
 * ── Full field reference ────────────────────────────────────────────────────
 *
 * Required:
 *   id           {string}   Stable rule ID, e.g. "INFRA-001". Plugin rules
 *                           must use a prefix matching their pack_id to avoid
 *                           collisions with built-in rules.
 *   name         {string}   Human-readable rule name
 *   severity     {string}   "CRITICAL" | "HIGH" | "MEDIUM" | "EXPOSURE"
 *   category     {string}   OWASP category or custom grouping
 *   pattern      {string}   Regex pattern string (compiled to RegExp at load time)
 *
 * Optional:
 *   flags        {string}   Regex flags for pattern (default: "gi")
 *   antipattern  {string}   Regex pattern string — if matched near the finding,
 *                           the finding is suppressed. Compiled with antipattern_flags.
 *   antipattern_flags {string}  Flags for antipattern regex (default: "i")
 *   antipattern_preset {string} Named preset expanding to a standard antipattern.
 *                           Applied in addition to antipattern if both are set.
 *                           Available presets: "DEV_CONTEXT", "ADDR_AS_DATA",
 *                           "LINK_EXAMPLE", "ENV_VAR_REF"
 *   lookahead    {number}   Chars to scan ahead of match for antipattern (default: 300)
 *   lookbehind   {number}   Chars to scan behind match for antipattern (default: 120)
 *   exclude_file_types {string[]}  File extensions to skip entirely, e.g. ["md","txt"]
 *   file_types   {string[]}  File extensions this rule applies to (sensitive-file rules)
 *   match_mode   {string}   "content" (default) | "filename"
 *   taint_aware  {boolean}  True if rule requires taint tracking
 *   taint_extract {string}  Taint extraction strategy: "concat" | "interpolation" | "func_concat"
 *   service      {string}   Service name for secrets rules
 *   resolve_hint {string}   Additional remediation hint
 *   why          {string}   Explanation of the vulnerability
 *   scenario     {string}   Attack scenario description
 *   fix          {string}   Remediation guidance
 *   checklist    {string[]} Step-by-step remediation checklist
 *   source       {string}   Set by loader — "builtin" | pack_id. Never set in JSON.
 *
 * ── Confidence ──────────────────────────────────────────────────────────────
 * Omit confidence_rules → defaults to "HIGH" (same as current JS rules).
 *
 * confidence_rules: array of condition objects, evaluated top-to-bottom.
 * First matching condition wins. Always include a { "default": "..." } last.
 *
 * Available conditions (evaluated top-to-bottom, first match wins):
 *   if_file_context      {string|string[]}  Matches classifyFileContext() result.
 *                        Values: "frontend" | "backend" | "config" | "doc" | "test"
 *   if_path_contains     {string[]}         filePath contains any term (case-insensitive)
 *   if_line_contains     {string[]}         lineRaw contains any term (case-insensitive)
 *   if_value_matches     {string}           Captured group 1 (or full match) tests against regex
 *   if_value_not_matches {string}           Captured group 1 does NOT test against regex
 *   if_value_shorter_than {number}          Captured group 1 length < threshold
 *   default              {string}           Fallback — always matches
 *
 * Example:
 *   "confidence_rules": [
 *     { "if_value_matches": "^(?:sk-|ghp_|AKIA)",   "then": "HIGH"   },
 *     { "if_value_not_matches": "\\d",              "then": "LOW"    },
 *     { "if_value_shorter_than": 12,                  "then": "LOW"    },
 *     { "if_file_context": ["test", "doc"],           "then": "LOW"    },
 *     { "if_path_contains": ["auth", "login"],        "then": "HIGH"   },
 *     { "default": "MEDIUM" }
 *   ]
 *
 * ── Plugin / pack rules ──────────────────────────────────────────────────────
 * Rule packs are JSON files placed in ~/.scd/plugins/rules/ (community/custom)
 * or delivered to ~/.scd/packs/ (commercial, via scd-server).
 *
 * Pack file format:
 *   {
 *     "schema_version": 1,
 *     "pack_id": "my-pack",
 *     "pack_name": "My Rule Pack",
 *     "pack_version": "1.0.0",
 *     "author": "...",
 *     "rules": [ { ... }, { ... } ]
 *   }
 *
 * Rule IDs in a pack must use a prefix matching pack_id to avoid collisions
 * with built-in rules (e.g. pack_id "fintech" → rule IDs "FINTECH-001" etc.)
 *
 * License enforcement is server-side: scd-server validates rule source against
 * the customer's license. The CLI runs offline (trust on install for plugins).
 */

// ── File context classifier ─────────────────────────────────────────────────
// Kept here (not imported from rules-infra-leakage.js) so rule-loader is
// self-contained and usable by scanner-full without creating a circular dep.

const FRONTEND_EXTS = new Set(['js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs', 'vue', 'svelte', 'html', 'htm']);
const DOC_EXTS      = new Set(['md', 'txt', 'log', 'rst', 'adoc']);
const CONFIG_EXTS   = new Set(['json', 'yml', 'yaml', 'toml', 'ini', 'env', 'conf', 'cfg', 'properties', 'xml']);

function classifyFileContext(filePath) {
  if (!filePath) return 'backend';
  const ext   = filePath.split('.').pop().toLowerCase();
  const lower = filePath.toLowerCase();
  // Test check first — matches path segments at any position including start,
  // and .test.js / .spec.js filename suffixes
  if (/(?:^|[/\\])(?:tests?|spec|__tests__|__mocks__|fixtures)(?:[/\\]|$)|\.(?:test|spec)\.[a-z]+$/.test(lower)) return 'test';
  if (FRONTEND_EXTS.has(ext)) return 'frontend';
  if (DOC_EXTS.has(ext))      return 'doc';
  if (CONFIG_EXTS.has(ext))   return 'config';
  return 'backend';
}

// ── Antipattern presets ─────────────────────────────────────────────────────
// Shared patterns used by multiple built-in rules. Plugin rules can reference
// these by name via antipattern_preset for convenience — but inline patterns
// are always preferred for transparency.

const ANTIPATTERN_PRESETS = {
  DEV_CONTEXT:  '(?:example|sample|placeholder|TODO|FIXME|NOTE|demo|mock|fake|dummy|test|spec|localhost_only|dev.only|development.only)',
  ADDR_AS_DATA: '(?:==\\s*[\'"`]|!=\\s*[\'"`]|\\.startswith\\s*\\(|netloc\\s*==|\\.host\\s*==|is_loopback|is_private|is_reserved|_has_ipv6|check.*local|local.*check|returns\\s+(?:True|False)\\s+if|e\\.g\\.|i\\.e\\.|for\\s+example|#.*if\\s+ip\\s*=|#.*ip\\s*=|log\\.(?:debug|info|warning|error|critical)\\s*\\()',
  LINK_EXAMPLE: '(?:example\\.com|example\\.org|example\\.net|your[-_]?(?:host|domain|server|url)|<host>|<server>|\\[host\\]|\\[server\\])',
  ENV_VAR_REF:  '(?:process\\.env|os\\.environ|getenv|System\\.getenv|\\$\\{|\\$[A-Z_]+\\b)',
};

// ── Confidence rule evaluator ───────────────────────────────────────────────

/**
 * Build a confidence function from a confidence_rules array.
 * Returns a function with the same signature as the existing JS confidence
 * functions: (matchObj, lineRaw, filePath) => 'HIGH' | 'MEDIUM' | 'LOW'
 *
 * @param {Array} rules  Array of condition objects from JSON
 * @returns {function}
 */
function buildConfidenceFunction(rules) {
  return function confidenceFromRules(matchObj, lineRaw, filePath) {
    const fileCtx  = classifyFileContext(filePath);
    const lineLow  = (lineRaw  || '').toLowerCase();
    const pathLow  = (filePath || '').toLowerCase();

    // Extract captured value from matchObj (capture group 1, or full match as fallback).
    // Used by if_value_matches / if_value_not_matches / if_value_shorter_than.
    // matchObj is the raw RegExp match array: match[0] = full match, match[1] = first group.
    const value = (matchObj && (matchObj[1] || matchObj[0])) || '';

    for (const rule of rules) {
      // { default: "MEDIUM" }
      if ('default' in rule) {
        return rule.default;
      }

      let matched = false;

      // { if_file_context: "frontend" } or { if_file_context: ["test","backend"] }
      if (rule.if_file_context !== undefined) {
        const targets = Array.isArray(rule.if_file_context)
          ? rule.if_file_context
          : [rule.if_file_context];
        if (targets.includes(fileCtx)) matched = true;
      }

      // { if_path_contains: ["auth","login"] }
      if (!matched && rule.if_path_contains !== undefined) {
        if (rule.if_path_contains.some(t => pathLow.includes(t.toLowerCase()))) matched = true;
      }

      // { if_line_contains: ["nonce","csrf"] }
      if (!matched && rule.if_line_contains !== undefined) {
        if (rule.if_line_contains.some(t => lineLow.includes(t.toLowerCase()))) matched = true;
      }

      // { if_value_matches: "^sk-" }
      // Matches if the captured value (match group 1, or full match) tests against the regex.
      if (!matched && rule.if_value_matches !== undefined) {
        try {
          if (new RegExp(rule.if_value_matches).test(value)) matched = true;
        } catch { /* invalid regex in rule — skip */ }
      }

      // { if_value_not_matches: "\\d" }
      // Matches if the value does NOT test against the regex.
      if (!matched && rule.if_value_not_matches !== undefined) {
        try {
          if (!new RegExp(rule.if_value_not_matches).test(value)) matched = true;
        } catch { /* invalid regex in rule — skip */ }
      }

      // { if_value_shorter_than: 12 }
      // Matches if the value length is strictly less than the threshold.
      if (!matched && rule.if_value_shorter_than !== undefined) {
        if (value.length < rule.if_value_shorter_than) matched = true;
      }

      if (matched) return rule.then;
    }

    // No rule matched and no default — fall back to HIGH
    return 'HIGH';
  };
}


// ── Core loader ─────────────────────────────────────────────────────────────

/**
 * Load and compile a single raw rule definition from JSON.
 * Returns a runtime rule object compatible with scanner-full.js.
 *
 * @param {object} raw     Parsed rule object from JSON
 * @param {string} source  "builtin" or pack_id — set by caller
 * @returns {object}       Compiled rule ready for use by scanner-full
 */
function loadRule(raw, source) {
  if (!raw.id)      throw new Error('Rule missing required field: id');
  if (!raw.pattern) throw new Error(`Rule ${raw.id} missing required field: pattern`);

  // ── Pattern ─────────────────────────────────────────────────────────────
  const compiled = {
    ...raw,
    // Rename snake_case JSON fields to camelCase for scanner-full compatibility
    id:               raw.id,
    name:             raw.name             || raw.id,
    severity:         raw.severity         || 'HIGH',
    category:         raw.category         || 'Uncategorised',
    pattern:          new RegExp(raw.pattern, raw.flags || 'gi'),
    lookahead:        raw.lookahead        ?? undefined,
    lookbehind:       raw.lookbehind       ?? undefined,
    fileTypes:        raw.file_types       ?? undefined,
    excludeFileTypes: raw.exclude_file_types ?? undefined,
    matchMode:        raw.match_mode       ?? undefined,
    taintAware:       raw.taint_aware      ?? undefined,
    taintExtract:     raw.taint_extract    ?? undefined,
    service:          raw.service          ?? undefined,
    resolve_hint:     raw.resolve_hint     ?? undefined,
    source:           source               || 'builtin',
    // scan_comments: true — rule intentionally matches comment line content.
    // Opts out of the global comment-line suppression in scanFileWithRules().
    // Use only for rules whose pattern explicitly targets comment syntax
    // (e.g. @ts-ignore, TODO/FIXME with sensitive data, commented-out secrets).
    scanComments:     raw.scan_comments    ?? false,
  };

  // ── Antipattern ─────────────────────────────────────────────────────────
  // Combine inline antipattern + optional preset into a single RegExp.
  const apFlags = raw.antipattern_flags || 'i';
  const parts   = [];

  if (raw.antipattern) {
    parts.push(raw.antipattern);
  }

  if (raw.antipattern_preset) {
    const preset = ANTIPATTERN_PRESETS[raw.antipattern_preset];
    if (!preset) {
      console.warn(`[scd] Unknown antipattern_preset "${raw.antipattern_preset}" in rule ${raw.id}`);
    } else {
      parts.push(preset);
    }
  }

  compiled.antipattern = parts.length > 0
    ? new RegExp(parts.join('|'), apFlags)
    : null;

  // Clean up JSON-only fields that scanner-full doesn't need
  delete compiled.flags;
  delete compiled.antipattern_flags;
  delete compiled.antipattern_preset;
  delete compiled.file_types;
  delete compiled.exclude_file_types;
  delete compiled.match_mode;
  delete compiled.taint_aware;
  delete compiled.taint_extract;
  delete compiled.schema_version;
  delete compiled.variant;  // variant is internal — scanner sees only id

  // ── Confidence ──────────────────────────────────────────────────────────
  // confidence_rules array → compiled function
  // Static string → kept as-is (scanner-full handles both)
  // Omitted → no confidence property, scanner-full defaults to HIGH
  if (Array.isArray(raw.confidence_rules)) {
    compiled.confidence = buildConfidenceFunction(raw.confidence_rules);
    delete compiled.confidence_rules;
  } else if (raw.confidence && typeof raw.confidence === 'string') {
    compiled.confidence = raw.confidence;
  } else {
    delete compiled.confidence;
    delete compiled.confidence_rules;
  }

  return compiled;
}

/**
 * Load all rules from a pack object (parsed pack JSON).
 * Returns an array of compiled rule objects.
 *
 * @param {object} pack   Parsed pack JSON with pack_id and rules array
 * @returns {object[]}    Array of compiled rules
 */
function loadPack(pack) {
  if (!Array.isArray(pack.rules)) {
    throw new Error(`Pack "${pack.pack_id || '?'}" has no rules array`);
  }
  return pack.rules.map(raw => loadRule(raw, pack.pack_id || 'unknown'));
}

module.exports = { loadRule, loadPack, classifyFileContext, ANTIPATTERN_PRESETS };
