const { RESET } = require('./output-constants');
/**
 * scanner-full.js
 * Full security scan for pre-push hook.
 * Language-aware: selects rules based on file extension.
 * Antipattern-aware: skips findings where a safe pattern appears nearby.
 */

const path   = require('path');
const crypto = require('crypto');
const { makeFindingId }  = require('./finding-identity');
const { isRuleExcluded } = require('./scope');
const { buildTaintRegister, extToLanguage } = require('./taint-register');
const { scanSecrets }                            = require('./scanner-secrets');
const { getRuleAction }  = require('./config');
const { reconcileException } = require('./exception-gatekeeper');
const { loadRule }                               = require('../rules/rule-loader');
const { buildFileContext }                       = require('./file-context');
const { applyContextModifiers }                  = require('./context-modifiers');
const { buildCommentMap }                        = require('./comment-map');
const { buildFileManifest, formatManifestSummary } = require('./file-manifest');
const { getScanTrace }                             = require('./global-config');
const _jsPack                                    = require('../rules/rules-js.json');
const JS_RULES                                   = _jsPack.rules.filter(r => r.severity !== 'EXPOSURE').map(r => loadRule(r, 'builtin'));
const JS_EXPOSURE                                = _jsPack.rules.filter(r => r.severity === 'EXPOSURE').map(r => loadRule(r, 'builtin'));
const _pyPack                                    = require('../rules/rules-python.json');
const _phpPack                                   = require('../rules/rules-php.json');
const PY_RULES                                   = _pyPack.rules.map(r => loadRule(r, 'builtin'));
const PHP_RULES                                  = _phpPack.rules.map(r => loadRule(r, 'builtin'));
const PY_EXPOSURE                                = PY_RULES.filter(r => r.severity === 'EXPOSURE');
const PHP_EXPOSURE                               = PHP_RULES.filter(r => r.severity === 'EXPOSURE');

// Merge all EXPOSURE rules into one set — applied to all supported source files
const ALL_EXPOSURE_RULES = [
  ...(JS_EXPOSURE  || []),
  ...(PY_EXPOSURE  || []),
  ...(PHP_EXPOSURE || []),
];
const _tsPack                                    = require('../rules/rules-ts.json');
const TS_RULES                                   = _tsPack.rules.map(r => loadRule(r, 'builtin'));
const _aspxPack                                  = require('../rules/rules-aspx.json');
const _aspxCsPack                                = require('../rules/rules-aspx-cs.json');
const ASPX_RULES                                 = _aspxPack.rules.map(r => loadRule(r, 'builtin'));
const ASPX_CS_RULES                              = _aspxCsPack.rules.map(r => loadRule(r, 'builtin'));
const _sensitivePack                             = require('../rules/rules-sensitive-files.json');
const _sensitiveRules                            = _sensitivePack.rules.map(r => loadRule(r, 'builtin'));
const SENSITIVE_CONTENT_RULES                    = _sensitiveRules.filter(r => r.matchMode !== 'filename');
const SENSITIVE_FILENAME_RULES                   = _sensitiveRules.filter(r => r.matchMode === 'filename');
const _infraPack                                 = require('../rules/rules-infra-leakage.json');
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
    // codeHash is content-based — see lib/finding-identity.js for the canonical
    // algorithm. The `: null` fallback when lineRaw is empty is a relic from
    // the redaction era; the findings-store [WARN]-gate on null code_hash keeps
    // degenerate findings out of persistence and push payloads.
    codeHash:     lineRaw ? crypto.createHash('sha256').update(lineRaw).digest('hex').slice(0, 32) : null,
    // findingId: content-based via lib/finding-identity.js.
    // Line numbers MUST NEVER enter identity — a finding has to survive a line
    // shift without fragmenting its history. Degenerate empty-lineRaw input
    // produces a deterministic but degenerate id; the codeHash:null gate above
    // keeps such findings out of findings.jsonl regardless.
    findingId:    makeFindingId(rule.id, filePath, lineRaw),
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
    const excResult           = reconcileException(finding, config.exceptions);
    finding.excepted          = excResult.excepted;
    finding.exception_expired = excResult.expired;
    finding.exception_rejected = excResult.rejected;
    finding.exception         = excResult.exception;

    finding.resolved       = false;
    finding.resolve_record = null;

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
function scanFileWithRules(filePath, content, rules, config, taintReg = null, commentMap = null) {
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

      // ── Comment line check ─────────────────────────────────────────────
      // Skip findings on lines that are entirely comments — comment lines
      // cannot produce runtime behaviour regardless of their content.
      // Rules that intentionally target comment content can set
      // `scanComments: true` to opt out of this filter.
      // MIXED lines (code + inline comment) are always scanned — the match
      // may be in the code portion. Inline-comment suppression for MIXED
      // lines is a separate optional feature (config: scan.comment_scanning).
      if (commentMap && !rule.scanComments && commentMap.isComment(lineNumber)) continue;

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
function scanFileWithTimeout(filePath, content, rules, exposureRules, config, timeoutMs, commentMap = null) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ findings: [], timedOut: true });
    }, timeoutMs);

    try {
      const findings = [];
      if (rules) findings.push(...scanFileWithRules(filePath, content, rules, config, null, commentMap));
      if (exposureRules) findings.push(...scanFileWithRules(filePath, content, exposureRules, config, null, commentMap));
      clearTimeout(timer);
      resolve({ findings, timedOut: false });
    } catch (err) {
      clearTimeout(timer);
      resolve({ findings: [], timedOut: false }); // scan error – skip silently
    }
  });
}

/**
 * Route a finding through file context modifiers and push to the correct bucket.
 *
 * @param {Object}   finding          - Raw finding from buildFinding().
 * @param {Object}   fileContext      - Context from buildFileContext() for this file.
 * @param {Object[]} findings         - Active findings array (mutated in place).
 * @param {Object[]} suppressedFindings - Suppressed findings array (mutated in place).
 * @param {Object}   [traceOpts]      - Optional trace injection.
 * @param {boolean}  [traceOpts.enabled]         - Whether to keep _trace on findings.
 * @param {string}   [traceOpts.manifestContext]  - Scan context from file manifest.
 * @param {string}   [traceOpts.commentLineType]  - Line type from comment-map (CODE/COMMENT/MIXED).
 */
function routeFinding(finding, fileContext, findings, suppressedFindings, traceOpts = {}) {
  const modified = applyContextModifiers(finding, fileContext);

  // ── Inject pipeline context into _trace ──────────────────────────────────
  // manifest_context and comment_line_type are only known at call site, not
  // inside applyContextModifiers(), so they are injected here.
  if (modified._trace) {
    modified._trace.manifest_context  = traceOpts.manifestContext  ?? 'source';
    modified._trace.comment_line_type = traceOpts.commentLineType  ?? null;
  }

  // Strip _trace unless scan.trace is enabled in config.
  // Keeps scan-JSON files lean in normal operation.
  if (!traceOpts.enabled) {
    delete modified._trace;
  }

  if (modified.suppressed) {
    suppressedFindings.push(modified);
  } else {
    findings.push(modified);
  }
}

async function scanFull(files, config = null, scope = null) {
  const rawSecrets = await scanSecrets(files, config);
  const timedOut = []; // files that exceeded timeout

  // ── Findings buckets ───────────────────────────────────────────────────
  // Active findings and suppressed findings are kept separate throughout the
  // scan. Deduplication runs on active findings only — suppressed findings
  // are already context-adjusted and need no further dedup.
  const findings          = [];
  const suppressedFindings = [];

  // ── Pre-scan: build file manifest ─────────────────────────────────────
  // Classifies every file into a scan context BEFORE any rules run.
  // This is the correct architectural layer for this decision — routing
  // happens here, not as post-scan severity compensation.
  //
  //   source   → scanned with full rule set (production code + config + docs)
  //   test     → scanned with test rule set (currently empty — defined later)
  //   excluded → vendor/generated, not scanned, documented in output
  //
  // Classification uses buildFileContext() internally: two-layer detection
  // (path/filename signal + content confirmation). Tentative-only signals
  // (path without content confirmation) fall back to source — conservative.
  const manifest = buildFileManifest(files);

  // ── Trace config ─────────────────────────────────────────────────────────
  // When SCAN_TRACE=true in ~/.scd/config, _trace is preserved on every finding
  // (active and suppressed) in all scan-JSON files. Never shown in terminal.
  // Set manually — not exposed via scd configure. Internal debug tool only.
  const traceEnabled = getScanTrace();

  // Show manifest summary early — before scanning begins.
  // Design rule: important information must be shown as early as possible.
  if (process.stderr.isTTY && files.length > 0) {
    process.stderr.write(`  ${formatManifestSummary(manifest.summary)}\n`);
  }

  // Apply file context to secrets findings.
  // Secrets scanner returns findings with filePath already set — use manifest
  // context map to determine the file's scan context.
  // Config/env files are almost always source context, but manifest is
  // authoritative.
  //
  // Secrets are NEVER silently dropped, regardless of context. A leaked
  // credential in a test or vendor file is still a leaked credential. Every
  // secret finding is routed through routeFinding() like any other finding,
  // so context modifiers degrade severity in proportion to how strongly the
  // file is confirmed as test/vendor code (fileType + path + framework signals
  // stack). The result:
  //   - vendor/generated → modifiers typically push effective score <= 0 →
  //     suppressed (lands in suppressedFindings[] with full context_modifiers
  //     audit trail, never discarded).
  //   - test → degraded but usually still active. A well-signalled test
  //     (fileType:test + /test/ path + known framework) lands at EXPOSURE; a
  //     weakly-signalled file (e.g. fileType:test only) stays higher (HIGH) —
  //     low confidence that it is really test code → treated closer to source.
  // This intentionally surfaces secrets that previous logic discarded via
  // `continue`. A future secrets-specific policy (e.g. an EXPOSURE floor, or
  // tolerating known throwaway test passwords) can be layered on later; for
  // now secrets follow the same path as everything else.
  for (const f of rawSecrets) {
    const scanCtx = manifest.contexts.get(f.filePath) ?? 'source';

    // Reuse the manifest fileContext — never call buildFileContext() without
    // content here. buildFileContext(filePath) with no content commits a
    // tentative classification as-is, which causes test files to be reported
    // as file_type:test while manifest_context remains source — a mismatch
    // that produces incorrect _trace data and incorrect severity modifiers.
    const fileContext = manifest.fileContexts.get(f.filePath)
                     ?? buildFileContext(f.filePath);

    routeFinding(f, fileContext, findings, suppressedFindings, {
      enabled:         traceEnabled,
      manifestContext: scanCtx,
      commentLineType: null,  // secrets scanner has no line-level comment context
    });
  }

  const total    = manifest.source.length; // progress tracks source files only
  const showProg = total > 20 && process.stderr.isTTY;
  let   scanned  = 0;
  const progInterval = Math.max(1, Math.floor(total / 40)); // update ~40 times

  // Count by extension for progress display
  const extCounts = {};

  // ── Scan source context — full rule set ───────────────────────────────
  // manifest.source already has fileContext attached from buildFileManifest().
  // We reuse it directly — no second buildFileContext() call per file.
  for (const file of manifest.source) {
    const { filePath, content, isLarge, noLimit, fileContext } = file;
    const ext = path.extname(filePath).replace('.', '').toLowerCase();
    const rules         = RULES_BY_EXT[ext];
    const exposureRules = EXPOSURE_EXTS.has(ext) ? ALL_EXPOSURE_RULES : null;

    // ── Build comment map once per file ───────────────────────────────────
    // Classifies each line as CODE, COMMENT, or MIXED before the rule loop.
    // COMMENT lines are skipped in scanFileWithRules — comment content cannot
    // produce runtime behaviour. inline option reads from config (default: off).
    const commentInline = config?.scan?.comment_scanning === 'inline';
    const commentMap    = buildCommentMap(content, ext, { inline: commentInline });

    // ── Filename-based rules (e.g. log/debug files in web root) ────────────
    const basename = path.basename(filePath);
    for (const rule of ASPX_FILENAME_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(basename)) {
        const f = buildFinding(rule, filePath, 0, basename, basename, config);
        routeFinding(f, fileContext, findings, suppressedFindings, {
          enabled: traceEnabled, manifestContext: 'source', commentLineType: null,
        });
      }
    }
    for (const rule of SENSITIVE_FILENAME_RULES) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(basename)) {
        const f = buildFinding(rule, filePath, 0, basename, basename, config);
        routeFinding(f, fileContext, findings, suppressedFindings, {
          enabled: traceEnabled, manifestContext: 'source', commentLineType: null,
        });
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
        filePath, content, rules, exposureRules, config, NO_LIMIT_TIMEOUT_MS, commentMap
      );
      if (didTimeout) {
        timedOut.push({ filePath, sizeKb: file.sizeKb });
      } else {
        for (const finding of f) {
          routeFinding(finding, fileContext, findings, suppressedFindings, {
            enabled:         traceEnabled,
            manifestContext: 'source',
            commentLineType: commentMap?.lineType?.(finding.line) ?? null,
          });
        }
      }
    } else {
      // Normal path – synchronous
      if (rules) {
        for (const f of scanFileWithRules(filePath, content, rules, config, taintReg, commentMap)) {
          routeFinding(f, fileContext, findings, suppressedFindings, {
            enabled:         traceEnabled,
            manifestContext: 'source',
            commentLineType: commentMap?.lineType?.(f.line) ?? null,
          });
        }
      }
      if (exposureRules) {
        for (const f of scanFileWithRules(filePath, content, exposureRules, config, taintReg, commentMap)) {
          routeFinding(f, fileContext, findings, suppressedFindings, {
            enabled:         traceEnabled,
            manifestContext: 'source',
            commentLineType: commentMap?.lineType?.(f.line) ?? null,
          });
        }
      }
    }

    // ── Infra leakage rules — source context only ─────────────────────────
    // Runs on all source-context file types, skips minified and vendor files.
    // Test files are now excluded at the manifest level — INFRA_TEST_FILE_RE
    // is kept as a secondary guard for edge cases not caught by file-manifest.
    const isMinified = content.length > 500 && (content.indexOf('\n') === -1 || content.length / (content.split('\n').length || 1) > 500);
    const isVendor   = /(?:[/\\]vendor[/\\]|[/\\]node_modules[/\\]|[/\\]bower_components[/\\]|\.min\.(?:js|css)$|flot_|jquery[-.]|bootstrap[-.])/i.test(filePath);
    if (!INFRA_SKIP_EXTS.has(ext) && !INFRA_TEST_FILE_RE.test(filePath) && !isMinified && !isVendor) {
      // Filter INFRA rules per file: extension allowlist and fileType skip list.
      // Rules with `extensions` only fire on listed extensions.
      // Rules with `skipForFileTypes` skip files whose fileContext.fileType matches.
      const applicableInfraRules = INFRA_RULES.filter(rule => {
        if (rule.extensions && !rule.extensions.includes(ext)) return false;
        if (rule.skipForFileTypes?.includes(fileContext?.fileType)) return false;
        return true;
      });
      if (applicableInfraRules.length > 0) {
        for (const f of scanFileWithRules(filePath, content, applicableInfraRules, config, null, commentMap)) {
          routeFinding(f, fileContext, findings, suppressedFindings, {
            enabled:         traceEnabled,
            manifestContext: 'source',
            commentLineType: commentMap?.lineType?.(f.line) ?? null,
          });
        }
      }
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
      process.stderr.write(`\rDIM Scanning  ${bar}  ${String(scanned).padStart(String(total).length)}/${total}  ${topExts}${RESET}`);
    }
  }

  // Clear progress line
  if (showProg) process.stderr.write('\r\x1b[K');

  // ── Scan test context — test rule set (stub) ───────────────────────────
  // Test files are classified and routed here but the test rule set is not
  // yet defined. This stub documents the intended architecture and ensures
  // the flow is correct for when test rules are added.
  //
  // Future: load rules/rules-test.json and scanFileWithRules() here.
  // The test rule set will focus on:
  //   - Credentials committed in test files (CI/CD leak risk)
  //   - Test bypasses that could reach production (skipAuth, verifySSL=False)
  //   - Test files importing production secrets
  //
  // for (const file of manifest.test) { ... }

  // _timedOut attached to final result below (after rule_excludes filter)

  // Deduplicate active findings only.
  //
  // Pass 1: same ruleId + file + line — prefer taintAware (with taintSource).
  // Pass 2: same file + line across different rules — prefer higher severity.
  //         This prevents e.g. PY-INJ-006 (HIGH) duplicating PY-INJ-001 (CRITICAL)
  //         on the same line when both patterns match the same construct.
  //
  // Note: dedup uses effective severity (post-modifier) so the best surviving
  // finding already reflects file context. Suppressed findings skip dedup —
  // they are context-adjusted and kept as full audit records.
  const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, EXPOSURE: 3, INFO: 4 };

  const seen = new Set();
  const locationBest = new Map(); // 'file:line' → best severity rank so far

  // Sort: taintSource first, then by effective severity
  const sorted = findings.sort((a, b) => {
    const taintDiff = (b.taintSource ? 1 : 0) - (a.taintSource ? 1 : 0);
    if (taintDiff !== 0) return taintDiff;
    return (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9);
  });

  const deduped = sorted.filter(f => {
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

  // ── Deduplicate suppressed findings ──────────────────────────────────────
  // Same EXPOSURE rules can fire from two separate scanFileWithRules() calls
  // on the same file (once via rules[], once via exposureRules[]). Dedup on
  // ruleId + filePath + line — first occurrence wins, no severity comparison
  // needed (all suppressed findings have the same effective score ≤ 0).
  const suppressedSeen = new Set();
  const dedupedSuppressed = suppressedFindings.filter(f => {
    const key = `${f.ruleId}:${f.filePath}:${f.line}`;
    if (suppressedSeen.has(key)) return false;
    suppressedSeen.add(key);
    return true;
  });

  // ── Apply rule_excludes from scope ────────────────────────────────────────
  // Post-dedup filter — scope exclusions are applied last so dedup counts
  // are not affected by exclusions. Excluded findings are tracked for audit.
  // Suppressed findings are not subject to scope rule_excludes — they are
  // already below the severity threshold and excluded from active analysis.
  // ── Coverage contract (OQ-B) ──────────────────────────────────────────────
  // Proven coverage for reconciliation: files that actually had rules run, plus
  // the rule domain that ran. DECISION A: source bucket only. The test bucket is
  // a stub (no test rule set yet) — test files have NO rules run on them, so they
  // are NOT proven coverage and must be excluded. INVARIANT: a file is in
  // _coverage.files iff the rules of _coverage.ruleDomain ran on it. When a test
  // rule set is added, manifest.test joins coveredFiles AT THE SAME TIME — never
  // before. Adding uncovered files here would allow resolving findings in files
  // that were never examined (violates the evidence axiom).
  const _coverage = {
    files:      manifest.source.map(f => f.filePath),
    ruleDomain: 'all',
  };

  if (!scope || !scope.rule_excludes || scope.rule_excludes.length === 0) {
    deduped._timedOut           = timedOut;
    deduped._suppressedFindings = dedupedSuppressed;
    deduped._manifest           = manifest;
    deduped._coverage           = _coverage;
    return deduped;
  }

  const ruleExclusionCounts = {}; // ruleId → count of excluded findings
  const result = deduped.filter(f => {
    const { excluded } = isRuleExcluded(scope, f.ruleId, f.filePath);
    if (!excluded) return true;
    // Track count per rule for audit metadata
    ruleExclusionCounts[f.ruleId] = (ruleExclusionCounts[f.ruleId] || 0) + 1;
    return false;
  });

  // Attach metadata for audit.js and scan-cache.js
  result._timedOut             = timedOut;
  result._ruleExclusionCounts  = ruleExclusionCounts;
  result._suppressedFindings   = dedupedSuppressed;
  result._manifest             = manifest;
  result._coverage             = _coverage;
  return result;
}

module.exports = { scanFull, EXPOSURE_RULES: ALL_EXPOSURE_RULES };
