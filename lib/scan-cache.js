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

    const payload = {
      scanId:      id,
      scanDate:    scanDate instanceof Date ? scanDate.toISOString() : scanDate,
      target:      data.target      || '.',
      totalFiles:  data.totalFiles  || 0,
      skipped:     data.skipped     || [],
      findings:    (data.findings   || []).filter(f => f.ruleId),
      deepResults: data.deepResults || null,
      hasDeep:     !!(data.deepResults && data.deepResults.length > 0),
      repoRoot:    data.repoRoot    || null,
      scanMode:    data.scanMode    || 'full',
      exclusions:  null,  // reserved for .scdignore + rule_excludes (Phase 4)
    };

    validateScan(payload, 'saveCache');

    const json = JSON.stringify(payload, null, 2);

    // Save as individual scan file (never overwritten)
    fs.writeFileSync(store.scanPath(repoRoot, id), json, { encoding: 'utf8', mode: 0o600 });

    // Keep last-scan.json as a copy for backwards compatibility
    fs.writeFileSync(store.scanCachePath(repoRoot), json, { encoding: 'utf8', mode: 0o600 });

    return id;
  } catch (err) {
    console.error(`\x1b[90m[sc] Scan save warning: ${err.message}\x1b[0m`);
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
