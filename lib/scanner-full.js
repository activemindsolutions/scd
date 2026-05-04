/**
 * scanner-full.js
 * Full security scan for pre-push hook.
 * Language-aware: selects rules based on file extension.
 * Antipattern-aware: skips findings where a safe pattern appears nearby.
 */

const path   = require('path');
const crypto = require('crypto');
const { buildTaintRegister, extToLanguage } = require('./taint-register');
const { scanSecrets }                            = require('./scanner-secrets');
const { isExcepted, getRuleAction, isResolved }  = require('./config');
const { ALL_RULES: JS_RULES, ALL_EXPOSURE_RULES: JS_EXPOSURE }  = require('./rules/rules-js');
const { ALL_EXPOSURE_RULES: PY_EXPOSURE }                        = require('./rules/rules-python');
const { ALL_EXPOSURE_RULES: PHP_EXPOSURE }                       = require('./rules/rules-php');

// Merge all EXPOSURE rules into one set — applied to all supported source files
const ALL_EXPOSURE_RULES = [
  ...(JS_EXPOSURE  || []),
  ...(PY_EXPOSURE  || []),
  ...(PHP_EXPOSURE || []),
];
const { ALL_RULES: TS_RULES }                    = require('./rules/rules-ts');
const { ALL_RULES: PY_RULES }                    = require('./rules/rules-python');
const { ALL_RULES: PHP_RULES }                   = require('./rules/rules-php');
const { ALL_RULES: ASPX_RULES }                  = require('./rules/rules-aspx');
const { ALL_RULES: ASPX_CS_RULES }               = require('./rules/rules-aspx-cs');
const { loadRule }                               = require('./rules/rule-loader');
const _sensitivePack                             = require('./rules/rules-sensitive-files.json');
const _sensitiveRules                            = _sensitivePack.rules.map(r => loadRule(r, 'builtin'));
const SENSITIVE_CONTENT_RULES                    = _sensitiveRules.filter(r => r.matchMode !== 'filename');
const SENSITIVE_FILENAME_RULES                   = _sensitiveRules.filter(r => r.matchMode === 'filename');
const _infraPack                                 = require('./rules/rules-infra-leakage.json');
const INFRA_RULES                                = _infraPack.rules.map(r => loadRule(r, 'builtin'));

// Separate filename-match rules (e.g. log files in web root)
const ASPX_FILENAME_RULES = ASPX_RULES.filter(r => r.matchMode === 'filename');
const ASPX_CONTENT_RULES  = ASPX_RULES.filter(r => r.matchMode !== 'filename');

// ── File extension → rule sets ─────────────────────────────────────────────
const RULES_BY_EXT = {
  js:  JS_RULES,  mjs: JS_RULES,  cjs: JS_RULES,
  ts:  [...JS_RULES, ...TS_RULES],   // TypeScript: JS rules + TS-specific rules
  jsx: JS_RULES,
  tsx: [...JS_RULES, ...TS_RULES],   // TSX same as TS
  py:  PY_RULES,
  php: PHP_RULES,
  aspx:   ASPX_CONTENT_RULES,
  ascx:   ASPX_CONTENT_RULES,
  master: ASPX_CONTENT_RULES,
  config: ASPX_CONTENT_RULES,
  cs:     ASPX_CS_RULES,        // C# code-behind and class files
  txt:    SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('txt')),
  log:    SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('log')),
  // Sensitive file types — content rules
  env:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('env')),
  sql:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('sql')),
  yml:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('yml')),
  yaml:       SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('yaml')),
  json:       [...SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('json')),
               ...TS_RULES.filter(r => r.id === 'TS-SUPPRESS-002')],  // tsconfig.json strict checks
  xml:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('xml')),
  properties: SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('properties')),
  ini:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('ini')),
  cfg:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('cfg')),
  conf:       SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('conf')),
  sh:         SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('sh')),
  bash:       SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('bash')),
  ps1:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('ps1')),
  bat:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('bat')),
  cmd:        SENSITIVE_CONTENT_RULES.filter(r => r.fileTypes.includes('cmd')),
  bak:        [],   // filename-only rule, no content scan
};

const EXPOSURE_EXTS = new Set(['js', 'ts', 'mjs', 'jsx', 'tsx', 'html', 'php', 'py']);

// Extensions where infra-leakage rules are meaningful (i.e. files that get deployed)
// Excludes binary, lock-files, and pure asset files.
const INFRA_SKIP_EXTS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot',
  'mp4', 'mp3', 'pdf', 'zip', 'gz', 'tar', 'lock', 'sum',
]);

// Filename patterns that indicate test/example context — skip infra rules
const INFRA_TEST_FILE_RE = /(?:\.(?:test|spec|mock)\.|__tests__|__mocks__|\.env\.(?:example|template)|README|CHANGELOG|fixtures|examples|webpack\.config|vite\.config|rollup\.config|babel\.config|jest\.config|karma\.conf|postcss\.config|tailwind\.config|next\.config|nuxt\.config|vitest\.config)/i;

// ── Antipattern check ──────────────────────────────────────────────────────
function isAntipatternPresent(rule, content, matchIndex) {
  if (!rule.antipattern) return false;
  const lookahead  = rule.lookahead  ?? 300;
  const lookbehind = rule.lookbehind ?? 120;  // check same line backwards too
  const start  = Math.max(0, matchIndex - lookbehind);
  const window = content.slice(start, matchIndex + lookahead);
  return rule.antipattern.test(window);
}

// ── Build a finding object ─────────────────────────────────────────────────
function buildFinding(rule, filePath, lineNumber, snippet, lineRaw, config, taintInfo = null, matchObj = null) {
  // ── Confidence ──────────────────────────────────────────────────────────
  // Rules may declare confidence as:
  //   'HIGH' | 'MEDIUM' | 'LOW'  (static string)
  //   function(matchObj, lineRaw, filePath) → 'HIGH' | 'MEDIUM' | 'LOW'  (dynamic)
  // Default is 'HIGH' for backward compatibility.
  let confidence = 'HIGH';
  if (typeof rule.confidence === 'function') {
    try { confidence = rule.confidence(matchObj, lineRaw, filePath) || 'HIGH'; }
    catch { confidence = 'HIGH'; }
  } else if (rule.confidence) {
    confidence = rule.confidence;
  }

  const finding = {
    ruleId:       rule.id,
    name:         rule.name,
    severity:     rule.severity,
    confidence,
    category:     rule.category,
    filePath,
    line:         lineNumber,
    snippet,
    codeHash:     lineRaw ? crypto.createHash('sha256').update(lineRaw).digest('hex').slice(0, 32) : null,
    // findingId: prefer codeHash-based (stable, content-aware), fall back to
    // ruleId+filePath+line for findings where lineRaw is redacted (e.g. secrets rules).
    // Fallback ID is still deterministic and unique enough for exception targeting.
    findingId:    lineRaw
      ? 'f-' + crypto.createHash('sha256').update(lineRaw).digest('hex').slice(0, 8)
      : 'f-' + crypto.createHash('sha256').update((rule.id || '') + '|' + filePath + '|' + String(lineNumber)).digest('hex').slice(0, 8),
    why:          rule.why,
    scenario:     rule.scenario,
    fix:          rule.fix           || null,
    checklist:    rule.checklist     || null,
    service:      rule.service       || null,
    resolve_hint: rule.resolve_hint  || null,
    hook:         'pre-push',
    deepAnalysis: null,
    taintSource:  taintInfo || null,
  };

  if (config) {
    const excResult           = isExcepted(config, finding, lineRaw);
    finding.excepted          = excResult.excepted;
    finding.exception_expired = excResult.expired;
    finding.exception_rejected = excResult.rejected;
    finding.exception         = excResult.exception;

    if (finding.severity === 'EXPOSURE') {
      const res              = isResolved(config, finding);
      finding.resolved       = res.resolved;
      finding.resolve_record = res.record || null;
    } else {
      finding.resolved       = false;
      finding.resolve_record = null;
    }

    const action   = getRuleAction(config, rule.id, rule.severity);
    finding.action = action;
    finding.blocks = !excResult.excepted && !finding.resolved && action === 'block';
  } else {
    finding.excepted       = false;
    finding.resolved       = false;
    finding.resolve_record = null;
    finding.action  = rule.severity === 'CRITICAL' ? 'block'
                    : rule.severity === 'EXPOSURE'  ? 'educate'
                    : 'warn';
    finding.blocks  = rule.severity === 'CRITICAL';
  }

  return finding;
}

// ── Scan a single file with a set of rules ─────────────────────────────────
function scanFileWithRules(filePath, content, rules, config, taintReg = null) {
  const findings = [];
  const lines    = content.split('\n');
  const fileExt  = filePath.split('.').pop().toLowerCase();

  // Pre-build line start offsets once per file — avoids repeated substring+split
  // for every match when computing line numbers.
  const lineOffsets = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') lineOffsets.push(i + 1);
  }

  // Filter out rules that explicitly exclude this file type
  const applicableRules = rules.filter(rule =>
    !rule.excludeFileTypes || !rule.excludeFileTypes.includes(fileExt)
  );

  // Binary search: find 1-based line number for a character offset
  function offsetToLine(offset) {
    let lo = 0, hi = lineOffsets.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineOffsets[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1; // 1-based
  }

  // Whether the taint register has any entries — used for early-exit below
  const hasTaint = taintReg && !taintReg.isEmpty();

  for (const rule of applicableRules) {
    // Early exit: taintAware rules are only useful if the file has tainted variables.
    // Skip matchAll entirely if the register is empty — avoids expensive regex scan.
    if (rule.taintAware && !hasTaint) continue;

    const re      = new RegExp(rule.pattern.source, rule.pattern.flags);
    const matches = [...content.matchAll(re)];

    for (const match of matches) {
      const matchIndex = match.index;
      const lineNumber = offsetToLine(matchIndex);
      const lineRaw    = lines[lineNumber - 1] || '';
      const snippet    = lineRaw.trim();

      if (isAntipatternPresent(rule, content, matchIndex)) continue;

      // ── Taint-aware check ──────────────────────────────────────────────
      // If rule is taintAware, extract the variable name from the match line
      // using the appropriate extraction strategy (concat, interpolation, or
      // func_concat). Check if that variable was assigned from external input
      // earlier in the file. If not found in register, skip the finding.
      let taintInfo = null;
       if (rule.taintAware && taintReg) {
         const strategy = rule.taintExtract || 'concat';
         let varName = null;

         // PHP vars have $ prefix; Python/JS/TS use plain identifiers
         const phpVarRe   = /\$(?!_GET|_POST|_REQUEST|_COOKIE|_SESSION|stmt|pdo|conn|db)([a-zA-Z_]\w*)/;
         const jsKeywords = /^(?:function|return|const|let|var|if|else|for|while|true|false|null|undefined|new|this|class|import|export|require|async|await|typeof|instanceof)$/;

         if (strategy === 'interpolation') {
           // PHP: extract $var from inside the SQL string
           const strContent = lineRaw.match(/"([^"]+)"/);
           const m = strContent
             ? strContent[1].match(phpVarRe)
             : lineRaw.match(phpVarRe);
           varName = m ? m[1] : null;

         } else if (strategy === 'func_concat') {
           // PHP: ($var  or  . $var
           const mPhp1 = lineRaw.match(/\(\s*\$(?!_GET|_POST|_REQUEST|_COOKIE|_SESSION|stmt|pdo|conn|db)([a-zA-Z_]\w*)/);
           const mPhp2 = lineRaw.match(/\.\s*\$(?!_GET|_POST|_REQUEST|_COOKIE|_SESSION|stmt|pdo|conn|db)([a-zA-Z_]\w*)\s*[;)"'.\\]]/);
           if (mPhp1 || mPhp2) {
             varName = mPhp1 ? mPhp1[1] : mPhp2[1];
           } else {
             // Python/JS: extract tainted variable from concatenation or first arg.
             // mPlus: picks up  + varname  followed by anything (string, +, ,, ))
             // mPlain: picks up first arg of function call, but only when it's a plain
             //         identifier not immediately followed by + (avoid matching base in base+doc)
             const mPlus  = lineRaw.match(/[+]\s*([a-zA-Z_]\w{1,40})\s*[+,);'"` + '`' + r`]/);
             const mPlain = lineRaw.match(/\(\s*([a-zA-Z_]\w{1,40})\s*[,)]/);
             // Also catch template literals: ${varname}
             const mTmplF = lineRaw.match(/\$\{([a-zA-Z_]\w{1,40})\}/);
             const cand   = mTmplF ? mTmplF[1] : (mPlus ? mPlus[1] : (mPlain ? mPlain[1] : null));
             if (cand && !jsKeywords.test(cand)) varName = cand;
           }

         } else {
           // default: concat
           const mPhp = lineRaw.match(/\.\s*\$(?!_GET|_POST|_REQUEST|_COOKIE|_SESSION|stmt|pdo|conn|db)([a-zA-Z_]\w*)\s*[;,"'\)\]]/);
           if (mPhp) {
             varName = mPhp[1];
           } else {
             // JS/Python: template literal ${var}, or + var at end of expression
             const mTmpl = lineRaw.match(/\$\{([a-zA-Z_]\w{1,40})\}/);
             const mPlus = lineRaw.match(/[+]\s*([a-zA-Z_]\w{1,40})\s*[+,;)"'\]` + '`' + r`]/);
             const cand  = mTmpl ? mTmpl[1] : (mPlus ? mPlus[1] : null);
             if (cand && !jsKeywords.test(cand)) varName = cand;
           }
         }

        if (varName) {
          if (taintReg.has(varName)) {
            taintInfo = {
              variable: varName,
              line:     taintReg.getLine(varName),
              source:   taintReg.getSource(varName),
            };
          } else if (taintReg.has('*')) {
            // extract($_GET) used — all vars in scope potentially tainted
            taintInfo = { variable: varName, line: taintReg.getLine('*'), source: 'extract()' };
          } else {
            // Variable not found in taint register — skip finding
            continue;
          }
        }
        // If no variable could be extracted from a taintAware rule, skip the finding.
        // taintAware rules are only meaningful when a specific tainted variable can be
        // identified — without one we cannot confirm the taint path.
        if (!varName) continue;
      }

      findings.push(buildFinding(rule, filePath, lineNumber, snippet, lineRaw, config, taintInfo, match));
    }
  }

  return findings;
}

// ── Full scan ──────────────────────────────────────────────────────────────
const { NO_LIMIT_TIMEOUT_MS } = require('./scanner-manual');

/**
 * Scan a single file with timeout guard (used for large files in --no-limit mode).
 * Returns { findings, timedOut }.
 */
function scanFileWithTimeout(filePath, content, rules, exposureRules, config, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ findings: [], timedOut: true });
    }, timeoutMs);

    try {
      const findings = [];
      if (rules) findings.push(...scanFileWithRules(filePath, content, rules, config));
      if (exposureRules) findings.push(...scanFileWithRules(filePath, content, exposureRules, config));
      clearTimeout(timer);
      resolve({ findings, timedOut: false });
    } catch (err) {
      clearTimeout(timer);
      resolve({ findings: [], timedOut: false }); // scan error – skip silently
    }
  });
}

async function scanFull(files, config = null) {
  const findings = await scanSecrets(files, config);
  const timedOut = []; // files that exceeded timeout

  const total    = files.length;
  const showProg = total > 20 && process.stderr.isTTY;  // only in interactive terminals
  let   scanned  = 0;
  const progInterval = Math.max(1, Math.floor(total / 40)); // update ~40 times

  // Count by extension for progress display
  const extCounts = {};

  for (const file of files) {
    const { filePath, content, isLarge, noLimit } = file;
    const ext = path.extname(filePath).replace('.', '').toLowerCase();
    const rules         = RULES_BY_EXT[ext];
    const exposureRules = EXPOSURE_EXTS.has(ext) ? ALL_EXPOSURE_RULES : null;

    // ── Filename-based rules (e.g. log/debug files in web root) ────────────
    const basename = path.basename(filePath);
    for (const rule of ASPX_FILENAME_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(basename)) {
        findings.push(buildFinding(rule, filePath, 0, basename, basename, config));
      }
    }
    for (const rule of SENSITIVE_FILENAME_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(basename)) {
        findings.push(buildFinding(rule, filePath, 0, basename, basename, config));
      }
    }

    // ── Build taint register for this file ─────────────────────────────
    // Pre-scan pass: identify variables assigned from user-controlled sources
    // (e.g. $id = $_GET['id']). Passed to taintAware rules so they can detect
    // when a tainted variable reaches a dangerous sink on a different line.
    // Skipped in 'fast' scan_mode for performance on large codebases.
    const taintLang = extToLanguage(ext);
    const taintReg  = (taintLang && config?.scan_mode !== 'fast')
      ? buildTaintRegister(content, taintLang)
      : null;

    if (isLarge && noLimit) {
      // Large file in --no-limit mode: wrap in timeout
      const { findings: f, timedOut: didTimeout } = await scanFileWithTimeout(
        filePath, content, rules, exposureRules, config, NO_LIMIT_TIMEOUT_MS
      );
      if (didTimeout) {
        timedOut.push({ filePath, sizeKb: file.sizeKb });
      } else {
        findings.push(...f);
      }
    } else {
      // Normal path – synchronous
      if (rules)         findings.push(...scanFileWithRules(filePath, content, rules, config, taintReg));
      if (exposureRules) findings.push(...scanFileWithRules(filePath, content, exposureRules, config, taintReg));
    }

    // ── Infra leakage rules – runs on ALL file types, skips test/example/minified files
    const isMinified = content.length > 500 && (content.indexOf('\n') === -1 || content.length / (content.split('\n').length || 1) > 500);
    const isVendor   = /(?:[/\\]vendor[/\\]|[/\\]node_modules[/\\]|[/\\]bower_components[/\\]|\.min\.(?:js|css)$|flot_|jquery[-.]|bootstrap[-.])/i.test(filePath);
    if (!INFRA_SKIP_EXTS.has(ext) && !INFRA_TEST_FILE_RE.test(filePath) && !isMinified && !isVendor) {
      findings.push(...scanFileWithRules(filePath, content, INFRA_RULES, config));
    }

    // ── Progress indicator ──────────────────────────────────────────────────
    scanned++;
    if (showProg && (scanned % progInterval === 0 || scanned === total)) {
      extCounts[ext] = (extCounts[ext] ?? 0) + 1;
      const pct      = Math.round((scanned / total) * 100);
      const bar      = '█'.repeat(Math.floor(pct / 5)) + '░'.repeat(20 - Math.floor(pct / 5));
      const topExts  = Object.entries(extCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 3)
        .map(([e, n]) => `.${e}:${n}`)
        .join('  ');
      process.stderr.write(`\r\x1b[90m Scanning  ${bar}  ${String(scanned).padStart(String(total).length)}/${total}  ${topExts}\x1b[0m`);
    }
  }

  // Clear progress line
  if (showProg) process.stderr.write('\r\x1b[K');

  // Attach timed-out list so CLI can surface it
  findings._timedOut = timedOut;

  // Deduplicate findings.
  //
  // Pass 1: same ruleId + file + line — prefer taintAware (with taintSource).
  // Pass 2: same file + line across different rules — prefer higher severity.
  //         This prevents e.g. PY-INJ-006 (HIGH) duplicating PY-INJ-001 (CRITICAL)
  //         on the same line when both patterns match the same construct.
  const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, INFO: 4 };

  const seen = new Set();
  const locationBest = new Map(); // 'file:line' → best severity rank so far

  // Sort: taintSource first, then by severity
  const sorted = findings.sort((a, b) => {
    const taintDiff = (b.taintSource ? 1 : 0) - (a.taintSource ? 1 : 0);
    if (taintDiff !== 0) return taintDiff;
    return (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9);
  });

  return sorted.filter(f => {
    // Pass 1: exact ruleId + file + line dedup
    const exactKey = `${f.ruleId}:${f.filePath}:${f.line}`;
    if (seen.has(exactKey)) return false;
    seen.add(exactKey);

    // Pass 2: if a higher-severity finding already occupies this file:line, drop this one
    const locKey  = `${f.filePath}:${f.line}`;
    const myRank  = SEV_RANK[f.severity] ?? 9;
    const bestRank = locationBest.get(locKey) ?? 99;
    if (myRank > bestRank) return false; // lower priority — already covered
    locationBest.set(locKey, Math.min(myRank, bestRank));
    return true;
  });
}

module.exports = { scanFull, EXPOSURE_RULES: ALL_EXPOSURE_RULES };
