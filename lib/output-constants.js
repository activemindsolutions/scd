'use strict';
/**
 * output-constants.js
 * Terminal presentation constants — colours and symbols.
 *
 * Single source of truth for all ANSI styling used in scd CLI output.
 * Import in command and lib files:
 *   const { CYAN, GREEN, DIM, RESET, OK, WARN, FAIL } = require('../output-constants');
 *   (from lib/commands/: ../output-constants)
 *   (from lib/:          ./output-constants)
 *
 * DIM uses \x1b[90m (bright black) — more widely supported than \x1b[2m.
 */

// ── Colours ────────────────────────────────────────────────────────────────
const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[90m';
const RED    = '\x1b[31m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE   = '\x1b[34m';
const CYAN   = '\x1b[36m';
const BRIGHT_RED = '\x1b[91m';   // critical — stands out above plain red (high)

// ── Symbols ────────────────────────────────────────────────────────────────
const OK   = '✓';   // success
const FAIL = '✗';   // hard failure / error
const WARN = '⚠';   // warning
const INFO = 'ℹ';   // informational
const DASH = '–';   // en dash — used for empty/none values
const SEP  = '─';   // horizontal separator (repeat as needed: SEP.repeat(52))

module.exports = { RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN, BRIGHT_RED, OK, FAIL, WARN, INFO, DASH, SEP };
