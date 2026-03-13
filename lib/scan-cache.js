/**
 * scan-cache.js
 * Saves and loads the most recent scan findings.
 * Data lives in ~/.security-copilot/repos/{repoId}/last-scan.json
 * Nothing is written inside the user's git repository.
 */

'use strict';

const fs    = require('fs');
const store = require('./store');

function saveCache(repoRoot, data) {
  try {
    store.updateMeta(repoRoot);
    const payload = {
      scanDate:   (data.scanDate || new Date()).toISOString(),
      target:     data.target     || '.',
      totalFiles: data.totalFiles || 0,
      skipped:    data.skipped    || [],
      findings:   (data.findings  || []).filter(f => f.ruleId),
    };
    fs.writeFileSync(store.scanCachePath(repoRoot), JSON.stringify(payload, null, 2), 'utf8');
  } catch {
    // Cache write failure is non-fatal
  }
}

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

module.exports = { saveCache, loadCache, cacheAge };
