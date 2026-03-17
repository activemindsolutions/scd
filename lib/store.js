/**
 * store.js
 * Central path management for the Security Co-Pilot global store.
 *
 * All per-repo data lives in ~/.security-copilot/repos/{repoId}/
 * Nothing is ever written inside the user's git repository.
 *
 * repoId = first 16 chars of SHA-256( git remote origin URL )
 *          Falls back to SHA-256( absolute repo root path ) if no remote.
 *          This makes the ID stable across re-clones of the same repo.
 *
 * Directory layout:
 *   ~/.security-copilot/
 *   ├── config                  ← global settings (API key etc.)
 *   └── repos/
 *       └── {repoId}/
 *           ├── meta.json       ← human-readable: remote URL, last seen path, name
 *           ├── config.yml      ← per-repo security config (exceptions, rules)
 *           ├── audit.log       ← full findings history (JSONL)
 *           ├── audit-summary.log ← anonymised statistics (JSONL)
 *           ├── last-scan.json  ← symlink to latest scan (backwards compat)
 *           ├── scans/             ← one JSON per scan, never overwritten
 *           └── reports/           ← generated reports (html, md, json)
 *
 * If no git remote exists, repoId is based on absolute path.
 * meta.json records type: "remote" | "path-based" so sc list can flag instability.
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const GLOBAL_DIR  = path.join(os.homedir(), '.security-copilot');
const REPOS_DIR   = path.join(GLOBAL_DIR, 'repos');

// ── Repo identification ────────────────────────────────────────────────────

/**
 * Derive a stable repo ID from git remote origin URL.
 * Falls back to absolute path if no remote is configured.
 */
function getRepoIdentity(repoRoot) {
  try {
    const { execSync } = require('child_process');
    // Check it's a git repo first
    execSync('git rev-parse --git-dir', {
      cwd: repoRoot, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    });
    const remote = execSync('git remote get-url origin', {
      cwd: repoRoot, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    return { identifier: remote, type: 'remote' };
  } catch {
    // Not a git repo, or no remote – fall back to absolute path
    return { identifier: path.resolve(repoRoot), type: 'path-based' };
  }
}

function getRepoId(repoRoot) {
  const { identifier } = getRepoIdentity(repoRoot);
  return crypto.createHash('sha256').update(identifier).digest('hex').slice(0, 16);
}

// ── Directory helpers ──────────────────────────────────────────────────────

function getRepoStoreDir(repoRoot) {
  const id  = getRepoId(repoRoot);
  const dir = path.join(REPOS_DIR, id);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function getFilePath(repoRoot, filename) {
  return path.join(getRepoStoreDir(repoRoot), filename);
}

// ── Meta (human-readable index of what repo each ID belongs to) ───────────

function updateMeta(repoRoot, scanData = null) {
  const dir      = getRepoStoreDir(repoRoot);
  const metaPath = path.join(dir, 'meta.json');
  const identity = getRepoIdentity(repoRoot);

  // Preserve existing meta fields (e.g. lastScan) if file exists
  let existing = {};
  try { existing = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch {}

  const meta = {
    ...existing,
    repoId:    path.basename(dir),
    type:      identity.type,                    // 'remote' | 'path-based'
    remote:    identity.type === 'remote' ? identity.identifier : null,
    localPath: path.resolve(repoRoot),
    name:      path.basename(path.resolve(repoRoot)),
    lastSeen:  new Date().toISOString(),
  };

  if (scanData) {
    meta.lastScan         = new Date().toISOString();
    meta.lastScanFindings = scanData.findingCount  ?? null;
    meta.lastScanCritical = scanData.criticalCount ?? null;
  }

  fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf8');
  return meta;
}

// ── Public path accessors ──────────────────────────────────────────────────

const FILES = {
  CONFIG:        'config.yml',
  AUDIT:         'audit.log',
  AUDIT_SUMMARY: 'audit-summary.log',
  SCAN_CACHE:    'last-scan.json',
};

function configPath(repoRoot)       { return getFilePath(repoRoot, FILES.CONFIG);        }
function auditPath(repoRoot)        { return getFilePath(repoRoot, FILES.AUDIT);         }
function auditSummaryPath(repoRoot) { return getFilePath(repoRoot, FILES.AUDIT_SUMMARY); }
function scanCachePath(repoRoot)    { return getFilePath(repoRoot, FILES.SCAN_CACHE);    }
function storeDir(repoRoot)         { return getRepoStoreDir(repoRoot);                  }

function reportsDir(repoRoot) {
  const dir = path.join(getRepoStoreDir(repoRoot), 'reports');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function reportPath(repoRoot, filename) {
  return path.join(reportsDir(repoRoot), filename);
}

function scansDir(repoRoot) {
  const dir = path.join(getRepoStoreDir(repoRoot), 'scans');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function scanPath(repoRoot, scanId) {
  return path.join(scansDir(repoRoot), scanId + '.json');
}

/**
 * List all saved scans for a repo, newest first.
 */
function listScans(repoRoot) {
  const dir = scansDir(repoRoot);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      const full = path.join(dir, f);
      const stat = fs.statSync(full);
      const scanId = f.replace('.json', '');
      let meta = { scanId, scanDate: null, totalFiles: 0, hasDeep: false, findingCount: 0 };
      try {
        const d = JSON.parse(fs.readFileSync(full, 'utf8'));
        meta = {
          scanId,
          scanDate:    d.scanDate    || null,
          totalFiles:  d.totalFiles  || 0,
          findingCount: (d.findings  || []).length,
          hasDeep:     !!(d.deepResults && d.deepResults.length > 0),
          size:        stat.size,
        };
      } catch {}
      return meta;
    })
    .sort((a, b) => (b.scanDate || '').localeCompare(a.scanDate || ''));
}

function listReports(repoRoot) {
  const dir = path.join(getRepoStoreDir(repoRoot), 'reports');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => /\.(html|md|json)$/.test(f))
    .map(f => {
      const full = path.join(dir, f);
      const stat = fs.statSync(full);
      return { filename: f, path: full, size: stat.size, mtime: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.mtime.localeCompare(a.mtime));
}

/**
 * List all known repos in the global store.
 * Used by sc doctor and future sc export.
 */
function listRepos() {
  if (!fs.existsSync(REPOS_DIR)) return [];
  return fs.readdirSync(REPOS_DIR)
    .filter(id => {
      // Only process directories – ignore .DS_Store and other stray files
      try { return fs.statSync(path.join(REPOS_DIR, id)).isDirectory(); }
      catch { return false; }
    })
    .map(id => {
      const metaFile = path.join(REPOS_DIR, id, 'meta.json');
      try {
        return JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      } catch {
        return { repoId: id, remote: null, localPath: null, name: id };
      }
    });
}

module.exports = {
  getRepoId,
  getRepoIdentity,
  updateMeta,
  configPath,
  auditPath,
  auditSummaryPath,
  scanCachePath,
  storeDir,
  scansDir,
  scanPath,
  listScans,
  reportsDir,
  reportPath,
  listReports,
  listRepos,
  GLOBAL_DIR,
  REPOS_DIR,
  FILES,
};
