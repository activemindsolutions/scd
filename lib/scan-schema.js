'use strict';

/**
 * scan-schema.js
 * Canonical shape of a scan object persisted by scan-cache.js.
 *
 * Written by:
 *   scan-cache.js  → saveCache()
 *
 * Read by:
 *   bin/scd.js           → scd findings, scd report, scd repo scans, scd export-findings
 *   lib/exception-manager.js → addExceptionById() (reads findings[].findingId, codeHash)
 *   lib/report-html.js   → generateReport() (reads: findings, target, scanDate, totalFiles, skipped, repoRoot)
 *   lib/report-json.js   → generateReport() (reads: findings, target, scanDate, totalFiles)
 *   lib/report-markdown.js → (reads: findings, target, scanDate, totalFiles, skipped)
 *   lib/export-findings.js → exportFindings() (reads: findings, scanId, repoRoot)
 *   lib/audit.js         → logScan() (receives scan data as arguments, not from cache directly)
 *
 * Field inventory:
 *
 *   scanId      {string}   "s-{8hex}"  — random, unique per scan run
 *   scanDate    {string}   ISO 8601    — timestamp of scan
 *   target      {string}   CLI target argument, e.g. "." or "src/app.js"
 *   totalFiles  {number}   Number of files scanned
 *   skipped     {Array}    Files skipped: [{ filePath, reason, error? }]
 *   findings    {Array}    Finding objects from scanner-full.js / scanner-secrets.js
 *   deepResults {Array|null} Deep analysis results, or null if --deep not used
 *   hasDeep     {boolean}  True if deepResults is non-empty
 *   repoRoot    {string}   Absolute path to the repo root at scan time
 *   scanMode    {string}   "full" | "fast" — from config.scan_mode
 *   exclusions  {null}     Reserved for future .scdignore + rule_excludes (Phase 4)
 *
 * Note: repoRoot and scanMode were previously only sent to logScan(), not persisted
 * in the scan file. They are now included in the payload so all consumers have
 * full context without needing to re-resolve the repo root from disk.
 */

const REQUIRED_FIELDS = [
  'scanId',
  'scanDate',
  'target',
  'totalFiles',
  'skipped',
  'findings',
  'repoRoot',
  'scanMode',
];

/**
 * Validate a scan object and warn on missing required fields.
 * Never throws — always returns the object as-is.
 *
 * @param {object} obj     The scan object to validate
 * @param {string} context Optional label for the warning (e.g. 'saveCache')
 * @returns {object}       The same object, unmodified
 */
function validateScan(obj, context) {
  for (const field of REQUIRED_FIELDS) {
    if (obj[field] === undefined) {
      const label = context ? ' (' + context + ')' : '';
      console.warn('[scd] scan object missing field: ' + field + label);
    }
  }
  return obj;
}

module.exports = { validateScan, REQUIRED_FIELDS };
