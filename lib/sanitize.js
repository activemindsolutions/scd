'use strict';
/**
 * sanitize.js
 * Neutralise terminal control sequences in externally-derived strings — scanned code
 * lines, file names, git author identity — before they reach the developer's terminal,
 * an OSC 8 hyperlink, or a report.
 *
 * scd processes untrusted, possibly hostile repositories. A scanned file line or a file
 * name that embeds terminal escapes (OSC 52 clipboard writes, OSC 2 title rewrites,
 * cursor/erase sequences to spoof a clean result) must not be able to drive the terminal
 * of the developer running scd. Strings that originate from the repo are display-only and
 * single-line at every sink, so we drop every C0 control except tab, plus ESC, DEL and the
 * C1 range. Identity (code_hash / finding_id) is computed from the raw line elsewhere and
 * is unaffected — this touches presentation only.
 */

// Keep \t (\x09); drop \x00–\x08, \x0a–\x1f (incl. CR, LF and ESC \x1b), \x7f (DEL), \x80–\x9f (C1).
const CONTROL_RE = /[\x00-\x08\x0a-\x1f\x7f-\x9f]/g;

function stripControl(str) {
  if (str === null || str === undefined) return str;
  return String(str).replace(CONTROL_RE, '');
}

module.exports = { stripControl };
