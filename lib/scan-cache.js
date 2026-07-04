/**
 * scan-cache.js
 * Saves and loads scan data.
 *
 * Each scan is saved as an individual file in:
 *   ~/.scd/repos/{repoId}/scans/{scanId}.json
 *
 * last-scan.json is kept as a copy of the latest scan for backwards
 * compatibility with scd report (no flags needed for the common case).
 *
 * Scan files are never overwritten — a new scanId is generated per run.
 * Deep analysis results are stored alongside findings in the same file.
 */

'use strict';
const { RESET, DIM } = require('./output-constants');

const fs           = require('fs');
const store        = require('./store');
const { validateScan } = require('./scan-schema');

// ── Scan ID ────────────────────────────────────────────────────────────────

/**
 * Generate a short random scan ID.
 * Format: s-{8 hex chars}  e.g. s-a3f9b2c1
 *
 * Deliberately not date/time-based — avoids timezone confusion.
 * The actual scan timestamp lives in the file's scanDate field.
 * Same ID is used as session_id on the server for full traceability.
 */
function makeScanId() {
  const crypto = require('crypto');
  return 's-' + crypto.randomBytes(4).toString('hex');
}


// ── Build exclusions summary for scan JSON ─────────────────────────────────

/**
 * Build the exclusions field for the scan JSON payload.
 * Combines file exclusion metadata (from scanner-manual) with rule exclusion
 * counts (from scanner-full._ruleExclusionCounts).
 *
 * Returns null if no exclusions were active.
 */
function buildExclusionsSummary(scopeExclusions, findings) {
  if (!scopeExclusions) return null;

  const ruleExclusionCounts = findings?._ruleExclusionCounts || {};

  const ruleExcludes = (scopeExclusions.rule_excludes || []).map(e => ({
    rule:              e.rule,
    files:             e.files || null,
    findings_excluded: ruleExclusionCounts[e.rule] || 0,
    source:            e._source || 'repo',
    reason:            e.reason  || null,
    added_by:          e.added_by || null,
    added_at:          e.added_at || null,
  }));

  const fileExcludes = (scopeExclusions.file_excludes || []).map(e => ({
    pattern:        e.pattern,
    files_excluded: scopeExclusions.files_excluded || 0,
    source:         e._source || 'repo',
    reason:         e.reason  || null,
    added_by:       e.added_by || null,
    added_at:       e.added_at || null,
  }));

  return {
    files_excluded: scopeExclusions.files_excluded || 0,
    file_excludes:  fileExcludes,
    rule_excludes:  ruleExcludes,
  };
}

// ── Save ───────────────────────────────────────────────────────────────────

/**
 * Save scan results to the per-repo scans directory.
 * Accepts an optional scanId — if not provided, generates a new one.
 * Always returns the scanId used (pass it to logScan for consistency).
 */
function saveCache(repoRoot, data, scanId) {
  try {
    const id       = scanId || makeScanId();
    const scanDate = data.scanDate || new Date();

    store.updateMeta(repoRoot, {
      findingCount:  (data.findings || []).length,
      criticalCount: (data.findings || []).filter(f => f.severity === 'CRITICAL').length,
    });

    const { getMachineFingerprint } = require('./store');
    const os = require('os');

    const payload = {
      scanId:          id,
      scanDate:        scanDate instanceof Date ? scanDate.toISOString() : scanDate,
      installation_id: getMachineFingerprint(),
      hostname:        os.hostname(),
      target:          data.target      || '.',
      totalFiles:      data.totalFiles  || 0,
      skipped:         data.skipped     || [],
      findings:            (data.findings            || []).filter(f => f.ruleId),
      suppressed_findings: (data.suppressed_findings || []).filter(f => f.ruleId),
      deepResults:     data.deepResults || null,
      hasDeep:         !!(data.deepResults && data.deepResults.length > 0),
      repoRoot:        data.repoRoot    || null,
      scanMode:        data.scanMode    || 'full',
      hook:            data.hook        || null,   // 'pre-commit' | 'pre-push' | null (manual) — self-describing scan file
      exclusions:      buildExclusionsSummary(data.scopeExclusions, data.findings),
    };

    validateScan(payload, 'saveCache');

    const json = JSON.stringify(payload, null, 2);

    // Save as individual scan file (never overwritten)
    fs.writeFileSync(store.scanPath(repoRoot, id), json, { encoding: 'utf8', mode: 0o600 });

    // Keep last-scan.json as a copy for backwards compatibility
    fs.writeFileSync(store.scanCachePath(repoRoot), json, { encoding: 'utf8', mode: 0o600 });

    return id;
  } catch (err) {
    console.error(`${DIM}[sc] Scan save warning: ${err.message}${RESET}`);
    return null;
  }
}

// ── Load ───────────────────────────────────────────────────────────────────

function loadCache(repoRoot) {
  const cachePath = store.scanCachePath(repoRoot);
  if (!fs.existsSync(cachePath)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
    if (!Array.isArray(data.findings)) return null;
    return data;
  } catch {
    return null;
  }
}

function loadScan(repoRoot, scanId) {
  const scanFile = store.scanPath(repoRoot, scanId);
  if (!fs.existsSync(scanFile)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(scanFile, 'utf8'));
    if (!Array.isArray(data.findings)) return null;
    return data;
  } catch {
    return null;
  }
}

// ── Human-readable age ─────────────────────────────────────────────────────

function cacheAge(isoDate) {
  const diff  = Date.now() - new Date(isoDate).getTime();
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(mins  / 60);
  const days  = Math.floor(hours / 24);
  if (days  > 0) return `${days} day${days   > 1 ? 's' : ''} ago`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (mins  > 0) return `${mins} minute${mins > 1 ? 's' : ''} ago`;
  return 'just now';
}

module.exports = { saveCache, loadCache, loadScan, cacheAge, makeScanId };
