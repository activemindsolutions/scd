'use strict';
/**
 * severity.js
 * Single source of truth for severity presentation across all terminal output.
 *
 * The uppercase `tag` carries the meaning (readable without colour — colour-blind
 * safe, and disambiguates HIGH vs MEDIUM which shared a colour before); `color`
 * reinforces it. This replaces the round-emoji severity icons that had drifted out
 * of sync across scanner, findings, scan-overview, deep-analysis and insights output.
 *
 * Reports rendered in another medium (Markdown/HTML) source `label`/`order` from
 * here but keep their medium-appropriate badges — ANSI tags do not translate there.
 */

const { BRIGHT_RED, YELLOW, CYAN, BLUE, DIM } = require('./output-constants');

// order: 0 = most severe (drives sorting; lower sorts first)
const SEVERITY = {
  CRITICAL: { color: BRIGHT_RED, tag: 'CRIT', label: 'CRITICAL', order: 0 },
  HIGH:     { color: YELLOW,     tag: 'HIGH', label: 'HIGH',     order: 1 },
  MEDIUM:   { color: CYAN,       tag: 'MED',  label: 'MEDIUM',   order: 2 },
  EXPOSURE: { color: BLUE,       tag: 'EXPO', label: 'EXPOSURE', order: 3 },
  INFO:     { color: DIM,        tag: 'INFO', label: 'INFO',     order: 4 },
};

// Fallback for an unknown/missing severity — never throws, never colours loudly.
const UNKNOWN = { color: DIM, tag: '?', label: 'UNKNOWN', order: 9 };

function sevConfig(severity) {
  return SEVERITY[severity] || UNKNOWN;
}

function sevOrder(severity) {
  return (SEVERITY[severity] || UNKNOWN).order;
}

module.exports = { SEVERITY, sevConfig, sevOrder };
