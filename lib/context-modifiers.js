/**
 * context-modifiers.js
 * Applies file context modifiers to a finding after a rule match.
 *
 * Modifiers are cumulative and additive — multiple signals stack.
 * The effective severity is derived from: base_score + total_modifier.
 * If effective_score <= SUPPRESS_THRESHOLD, the finding is flagged suppressed.
 *
 * This module never touches rule logic. Rules produce findings exactly as before.
 * File context confirms or adjusts — never replaces rule output.
 */

'use strict';

// ── Severity score mapping ─────────────────────────────────────────────────
// Higher score = higher severity. Scores are integers for clean arithmetic.
const SEVERITY_TO_SCORE = {
  CRITICAL:  4,
  HIGH:      3,
  MEDIUM:    2,
  EXPOSURE:  1,
  INFO:      0,
};

const SCORE_TO_SEVERITY = {
  4: 'CRITICAL',
  3: 'HIGH',
  2: 'MEDIUM',
  1: 'EXPOSURE',
  0: 'INFO',
};

// ── Suppress threshold ─────────────────────────────────────────────────────
// Fixed at 0 for v1.0.0. Configurable in v1.1.0 via config.yml.
const SUPPRESS_THRESHOLD = 0;

// ── Modifier table ─────────────────────────────────────────────────────────
// Values are additive. A file matching multiple signals accumulates all modifiers.
// Validated against scd-research data after Phase 3 — values may be tuned.
//
// Specificity rationale:
//   fixture  -2 : data intended to trigger rule patterns by design
//   vendor   -3 : third-party code — never the customer's responsibility
//   generated -2 : machine-generated — findings are not actionable
//   test     -1 : test code — lower risk but still customer-owned
//   docs     -1 : documentation — informational, not deployed
//   config    0 : config files are production risk — no modifier (may boost post-release)
//
// Path segment modifiers stack with fileType modifiers for cumulative effect.
// Example: Jest test in /fixtures/ → fileType(-2) + path(-1) + framework(-1) = -4

const MODIFIERS = {
  // ── File type modifiers ──────────────────────────────────────────────────
  fileType: {
    fixture:   -2,
    vendor:    -3,
    generated: -2,
    test:      -1,
    docs:      -1,
    config:     0,
    source:     0,
  },

  // ── Path segment modifiers ───────────────────────────────────────────────
  // Applied independently of fileType — stacks on top.
  // Only matched against the normalised filePath (lowercase, forward slashes).
  pathSegment: [
    { segment: '/test/',        modifier: -1 },
    { segment: '/tests/',       modifier: -1 },
    { segment: '/spec/',        modifier: -1 },
    { segment: '/specs/',       modifier: -1 },
    { segment: '/__tests__/',   modifier: -1 },
    { segment: '/fixtures/',    modifier: -1 },
    { segment: '/fixture/',     modifier: -1 },
    { segment: '/__fixtures__/',modifier: -1 },
    { segment: '/mocks/',       modifier: -1 },
    { segment: '/__mocks__/',   modifier: -1 },
    { segment: '/vendor/',      modifier: -2 },
    { segment: '/node_modules/',modifier: -2 },
  ],

  // ── Test framework modifiers ─────────────────────────────────────────────
  // Applied when a specific test framework is detected.
  // Rationale: confirmed test framework = high confidence it is test code.
  testFramework: {
    jest:    -1,
    vitest:  -1,
    mocha:   -1,
    pytest:  -1,
    phpunit: -1,
    rspec:   -1,
  },
};

// ── Helpers ────────────────────────────────────────────────────────────────

function normalisePath(filePath) {
  const n = filePath.replace(/\\/g, '/').toLowerCase();
  return n.startsWith('/') ? n : '/' + n;
}

/**
 * Derive effective severity string from a numeric score.
 * Score is clamped to [0, 4] — never goes negative or above CRITICAL.
 */
function scoreToSeverity(score) {
  const clamped = Math.max(0, Math.min(4, score));
  return SCORE_TO_SEVERITY[clamped];
}

// ── Main export ────────────────────────────────────────────────────────────

/**
 * Apply file context modifiers to a finding.
 *
 * Mutates a shallow copy of the finding — never the original object.
 * Adds: base_severity, context_modifiers[], file_context, suppressed, suppress_reason.
 * Updates: severity (becomes effective_severity when modifiers apply).
 *
 * @param {Object}      finding     - Finding object from buildFinding().
 * @param {FileContext} fileContext - Context object from buildFileContext().
 * @returns {Object} Modified finding (new object).
 */
function applyContextModifiers(finding, fileContext) {
  const baseSeverity = finding.severity;
  const baseScore    = SEVERITY_TO_SCORE[baseSeverity] ?? 0;

  const appliedModifiers = []; // { signal, modifier }
  let totalModifier = 0;

  // ── 1. File type modifier ────────────────────────────────────────────────
  const ftMod = MODIFIERS.fileType[fileContext.fileType] ?? 0;
  if (ftMod !== 0) {
    appliedModifiers.push({ signal: `fileType: ${fileContext.fileType}`, modifier: ftMod });
    totalModifier += ftMod;
  }

  // ── 2. Path segment modifiers ────────────────────────────────────────────
  const normPath = normalisePath(fileContext.filePath);
  for (const { segment, modifier } of MODIFIERS.pathSegment) {
    if (normPath.includes(segment)) {
      appliedModifiers.push({ signal: `path: ${segment}`, modifier });
      totalModifier += modifier;
    }
  }

  // ── 3. Test framework modifier ───────────────────────────────────────────
  if (fileContext.testFramework) {
    const fwMod = MODIFIERS.testFramework[fileContext.testFramework] ?? 0;
    if (fwMod !== 0) {
      appliedModifiers.push({ signal: `framework: ${fileContext.testFramework}`, modifier: fwMod });
      totalModifier += fwMod;
    }
  }

  // ── Compute effective score and severity ─────────────────────────────────
  const effectiveScore    = baseScore + totalModifier;
  const effectiveSeverity = scoreToSeverity(effectiveScore);
  const suppressed        = effectiveScore <= SUPPRESS_THRESHOLD;

  // ── Build modified finding ───────────────────────────────────────────────
  const modified = {
    ...finding,
    // Preserve original severity as base_severity for audit trail
    base_severity:     baseSeverity,
    // severity reflects effective severity (may be unchanged if no modifiers)
    severity:          effectiveSeverity,
    // context_modifiers is always present — empty array when nothing applied
    context_modifiers: appliedModifiers,
    // file_context always present — consumers can use it for display/filtering
    file_context: {
      file_type:      fileContext.fileType,
      test_framework: fileContext.testFramework,
      language:       fileContext.language,
    },
    suppressed:      suppressed,
    suppress_reason: suppressed
      ? 'Effective score below threshold after context modifiers'
      : null,
    // ── Internal trace (written when scan.trace: true in config.yml) ────────
    // Never shown in terminal output or reports. Available in scan-JSON files
    // and scd-research snapshots for FP analysis and rule refinement.
    // Structure mirrors the scan pipeline steps in order:
    //   manifest → file-context → modifiers → suppress-check
    // comment_line_type is injected by routeFinding() after comment-map lookup.
    _trace: {
      manifest_context:  null,       // injected by routeFinding()
      file_type:         fileContext.fileType,
      file_signals:      fileContext.signals      ?? [],
      tentative:         fileContext.tentative     ?? false,
      test_framework:    fileContext.testFramework ?? null,
      comment_line_type: null,       // injected by routeFinding()
      base_severity:     baseSeverity,
      base_score:        baseScore,
      modifiers:         appliedModifiers.map(m => ({
        step:    m.signal,
        delta:   m.modifier,
        reason:  m.signal,
      })),
      total_modifier:    totalModifier,
      effective_score:   effectiveScore,
      final_severity:    effectiveSeverity,
      suppressed,
      suppress_reason:   suppressed ? 'effective_score <= suppress_threshold' : null,
    },
  };

  return modified;
}

module.exports = { applyContextModifiers, MODIFIERS, SEVERITY_TO_SCORE, SUPPRESS_THRESHOLD };
