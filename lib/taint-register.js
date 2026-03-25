/**
 * taint-register.js
 * Pre-scan single-file taint tracking.
 *
 * Builds a register of variables that are assigned from external/user-controlled
 * sources (HTTP input, CLI args, environment). Passed to the scanner so rules
 * can detect when a tainted variable reaches a dangerous sink.
 *
 * Scope: single-file, single-assignment. Does not track:
 *   - Cross-function taint propagation
 *   - Chained assignments ($a = $b; $b = $_GET['x'])
 *   - Conditional assignments
 *
 * These limitations are acceptable for the current regex-based engine.
 * Full taint analysis is on the roadmap as a future architectural improvement.
 *
 * Usage:
 *   const { buildTaintRegister } = require('./taint-register');
 *   const taint = buildTaintRegister(fileContent, 'php');
 *   // taint.has('id')   → true if $id was assigned from $_GET/$_POST etc.
 *   // taint.getLine('id') → line number of the assignment
 *   // taint.getSource('id') → '$_GET["id"]'
 */

'use strict';

// ── Source patterns per language ──────────────────────────────────────────
// Each pattern captures: group 1 = variable name

const SOURCE_PATTERNS = {
  php: [
    // $varname = $_GET['key'] / $_POST['key'] / $_REQUEST / $_COOKIE / $_SESSION
    /^\s*\$(\w+)\s*=\s*(\$_(?:GET|POST|REQUEST|COOKIE|SESSION)\s*\[['"][^'"]{0,60}['"]\])/,
    // $varname = $_SERVER['key'] (e.g. HTTP_HOST, REQUEST_URI)
    /^\s*\$(\w+)\s*=\s*(\$_SERVER\s*\[['"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PATH_INFO)['"]\])/,
    // $varname = htmlspecialchars_decode(...)  ← still tainted after decode
    /^\s*\$(\w+)\s*=\s*(htmlspecialchars_decode\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[)/,
    // $varname = trim/strip/addslashes of superglobal ← still tainted (insufficient sanitisation)
    /^\s*\$(\w+)\s*=\s*(?:trim|strip_tags|addslashes|stripslashes|htmlentities)\s*\(\s*(\$_(?:GET|POST|REQUEST|COOKIE)\s*\[)/,
  ],

  python: [
    // var = request.args.get('key') / request.args['key']
    /^\s*(\w+)\s*=\s*(request\.(?:args|form|values|files)(?:\.get\s*\(|(?:\[)))/,
    // var = request.json.get / request.json['key']
    /^\s*(\w+)\s*=\s*(request\.json(?:\.get\s*\(|\[))/,
    // var = flask.request. / g. shorthand
    /^\s*(\w+)\s*=\s*(flask\.request\.(?:args|form|json|values))/,
    // var = sys.argv[n]
    /^\s*(\w+)\s*=\s*(sys\.argv\s*\[(?:[1-9]|\w+)\])/,
  ],

  js: [
    // const/let/var name = req.query.x / req.body.x / req.params.x
    /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(req\.(?:query|body|params)(?:\.\w+|\[['"][^'"]{0,40}['"]\]))/,
    // const name = req.query['x']
    /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(request\.(?:query|body|params))/,
    // destructuring: const { id } = req.query  ← handled separately below
  ],

  ts: [
    // Same as JS
    /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(req\.(?:query|body|params)(?:\.\w+|\[['"][^'"]{0,40}['"]\]))/,
  ],
};

// ── TaintRegister class ───────────────────────────────────────────────────

class TaintRegister {
  constructor() {
    // Map: varName → { line, source }
    this._vars = new Map();
  }

  /**
   * Record a tainted variable.
   */
  add(varName, lineNumber, source) {
    if (!this._vars.has(varName)) {
      this._vars.set(varName, { line: lineNumber, source });
    }
  }

  /**
   * Returns true if varName is tainted.
   */
  has(varName) {
    return this._vars.has(varName);
  }

  /**
   * Returns the line number where varName was tainted, or null.
   */
  getLine(varName) {
    return this._vars.get(varName)?.line ?? null;
  }

  /**
   * Returns the source expression (e.g. '$_GET["id"]'), or null.
   */
  getSource(varName) {
    return this._vars.get(varName)?.source ?? null;
  }

  /**
   * Returns all tainted variable names.
   */
  all() {
    return [...this._vars.keys()];
  }

  /**
   * Returns true if the register has any entries.
   */
  isEmpty() {
    return this._vars.size === 0;
  }
}

// ── Builder ───────────────────────────────────────────────────────────────

/**
 * Build a TaintRegister from file content.
 *
 * @param {string} content     - Full file content
 * @param {string} language    - 'php' | 'python' | 'js' | 'ts'
 * @returns {TaintRegister}
 */
function buildTaintRegister(content, language) {
  const register = new TaintRegister();
  const patterns = SOURCE_PATTERNS[language] || [];

  if (patterns.length === 0) return register;

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line    = lines[i];
    const lineNum = i + 1;

    // Skip comments
    const trimmed = line.trim();
    if (
      trimmed.startsWith('//') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('/*')
    ) continue;

    for (const pattern of patterns) {
      const m = line.match(pattern);
      if (m) {
        register.add(m[1], lineNum, m[2]);
        break; // one pattern match per line is enough
      }
    }

    // PHP: handle destructuring-style list() / extract()
    if (language === 'php') {
      // extract($_GET) / extract($_POST) — all vars in scope become tainted
      // We can't know the keys, mark a wildcard
      if (/extract\s*\(\s*\$_(?:GET|POST|REQUEST)/.test(line)) {
        register.add('*', lineNum, 'extract()');
      }
    }

    // JS/TS: destructuring  const { id, name } = req.query
    if (language === 'js' || language === 'ts') {
      const destructure = line.match(/^\s*(?:const|let|var)\s*\{([^}]{1,200})\}\s*=\s*(req\.(?:query|body|params))/);
      if (destructure) {
        const source = destructure[2];
        const vars   = destructure[1].split(',').map(v => v.trim().split(/\s*:\s*/)[0].trim());
        for (const v of vars) {
          if (/^\w+$/.test(v)) register.add(v, lineNum, source);
        }
      }
    }
  }

  return register;
}

/**
 * Map file extension to language key.
 */
function extToLanguage(ext) {
  const map = {
    php: 'php', php5: 'php', phtml: 'php',
    py:  'python',
    js:  'js', mjs: 'js', cjs: 'js',
    ts:  'ts', tsx: 'ts',
  };
  return map[ext.toLowerCase()] || null;
}

module.exports = { buildTaintRegister, extToLanguage, TaintRegister };
