/**
 * store.js
 * Central path management for the Secure Code by Design global store.
 *
 * All per-repo data lives in ~/.scd/repos/{repoId}/
 * Nothing is ever written inside the user's git repository.
 *
 * repoId = first 16 chars of SHA-256( git remote origin URL )
 *          Falls back to SHA-256( absolute repo root path ) if no remote.
 *          This makes the ID stable across re-clones of the same repo.
 *
 * Directory layout:
 *   ~/.scd/
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
 * meta.json records type: "remote" | "path-based" so scd list can flag instability.
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');
const { DIM, RESET } = require('./output-constants');

const GLOBAL_DIR  = path.join(os.homedir(), '.scd');
const REPOS_DIR   = path.join(GLOBAL_DIR, 'repos');
const PUSH_QUEUE  = path.join(GLOBAL_DIR, 'push-queue.jsonl');

function sha16(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);
}

// ── Repo identification ────────────────────────────────────────────────────

/**
 * Canonicalise a git remote URL so the same repository yields the same identifier
 * regardless of transport: SSH (`git@github.com:owner/repo.git`), HTTPS
 * (`https://github.com/owner/repo`), an embedded user, a port, a `.git` suffix, or
 * a trailing slash all reduce to `host/owner/repo` (host lower-cased).
 *
 * A URL we don't recognise as host/path (e.g. a local filesystem remote) is
 * returned trimmed-but-unchanged — it's already a stable identifier, and inventing
 * a normal form for it risks collapsing distinct repos.
 */
function canonicalizeRemote(remote) {
  const raw = String(remote || '').trim();

  const normalize = (host, repoPath) =>
    host.toLowerCase() + '/' + repoPath.replace(/\/+$/, '').replace(/\.git$/i, '').replace(/^\/+/, '');

  // URL form: scheme://[user@]host[:port]/path
  let m = raw.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?\/(.+)$/i);
  if (m) return normalize(m[1], m[2]);

  // scp-like SSH: [user@]host:path — only when there is no scheme:// prefix.
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    m = raw.match(/^(?:[^@/]+@)?([^/:]+):(.+)$/);
    if (m) return normalize(m[1], m[2]);
  }

  return raw;
}

/**
 * Derive a stable repo ID from git remote origin URL.
 * Falls back to absolute path if no remote is configured.
 *
 * `identifier` is the raw remote (for display / legacy id); `canonical` is the
 * transport-independent form the current id is derived from.
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
    return { identifier: remote, canonical: canonicalizeRemote(remote), type: 'remote' };
  } catch {
    // Not a git repo, or no remote – fall back to absolute path
    const abs = path.resolve(repoRoot);
    return { identifier: abs, canonical: abs, type: 'path-based' };
  }
}

function getRepoId(repoRoot) {
  return sha16(getRepoIdentity(repoRoot).canonical);
}

// The id this repo's store was keyed under before remote canonicalisation
// (hash of the raw remote). Equal to getRepoId() for path-based repos and for
// remotes already in canonical form — those never migrate.
function getLegacyRepoId(repoRoot) {
  return sha16(getRepoIdentity(repoRoot).identifier);
}

// ── repoId canonicalisation migration ──────────────────────────────────────
//
// Remote canonicalisation changes a repo's id (e.g. an SSH clone that used to key
// under hash(raw git@...) now keys under hash(host/owner/repo)). Move the existing
// store from the legacy id to the canonical id in place, so local history and
// approved exceptions survive the upgrade. The id value lives in exactly three
// places: the store directory name, meta.json's `repoId` field, and each
// push-queue.jsonl entry's `repoId` — everything else keys off the directory or a
// path. Idempotent and memoised per resolved repo root (one check per process).

const _migrationChecked = new Set();

function ensureRepoIdMigrated(repoRoot) {
  const key = path.resolve(repoRoot);
  if (_migrationChecked.has(key)) return;
  _migrationChecked.add(key);
  try { migrateRepoIdDir(repoRoot); } catch { /* best-effort — never block store access */ }
}

function migrateRepoIdDir(repoRoot) {
  const identity = getRepoIdentity(repoRoot);
  if (identity.type !== 'remote') return;                 // path-based ids don't change
  if (identity.identifier === identity.canonical) return; // already canonical

  const oldId = sha16(identity.identifier);
  const newId = sha16(identity.canonical);
  if (oldId === newId) return;

  const oldDir = path.join(REPOS_DIR, oldId);
  const newDir = path.join(REPOS_DIR, newId);
  if (!fs.existsSync(oldDir)) return;                     // nothing under the legacy id

  if (fs.existsSync(newDir)) {
    // Two remotes canonicalise to the same id (e.g. the same repo cloned via both
    // SSH and HTTPS). Never overwrite — leave both and let the operator reconcile.
    process.stderr.write(
      `${DIM}Note: two repo remotes map to the same id — kept both stores ` +
      `(${oldId} and ${newId}); reconcile manually if this is one repo.${RESET}\n`,
    );
    return;
  }

  fs.renameSync(oldDir, newDir);

  // Patch meta.json's repoId to the new id (the field mirrors the directory name).
  const metaPath = path.join(newDir, 'meta.json');
  try {
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    meta.repoId = newId;
    fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch { /* meta missing/unreadable — directory name is the source of truth anyway */ }

  rewriteQueueRepoId(oldId, newId);
}

// Re-stamp queued events from the legacy id to the canonical id so they flush under
// the right repo. Done inline (not via push-queue.js) to avoid a load-time require
// cycle — store.js owns the ~/.scd layout. Malformed lines are preserved verbatim.
function rewriteQueueRepoId(oldId, newId) {
  let raw;
  try { raw = fs.readFileSync(PUSH_QUEUE, 'utf8'); } catch { return; }
  let changed = false;
  const out = raw.split('\n').map((line) => {
    if (!line.trim()) return line;
    try {
      const obj = JSON.parse(line);
      if (obj && obj.repoId === oldId) { obj.repoId = newId; changed = true; return JSON.stringify(obj); }
    } catch { /* keep unparseable line as-is */ }
    return line;
  });
  if (changed) fs.writeFileSync(PUSH_QUEUE, out.join('\n'), { encoding: 'utf8', mode: 0o600 });
}

// ── Directory helpers ──────────────────────────────────────────────────────

// Read-only: compute path without creating the directory.
// Used by read-path functions (configPath, scopePath, serverScopePath, readMeta).
// Does NOT call mkdirSync — will not create orphan store folders as a side effect.
function getRepoDirReadOnly(repoRoot) {
  ensureRepoIdMigrated(repoRoot);
  const id = getRepoId(repoRoot);
  return path.join(REPOS_DIR, id);
}

// Write-oriented: creates directory. Used by write-path functions only.
function getRepoStoreDir(repoRoot) {
  ensureRepoIdMigrated(repoRoot);
  const id  = getRepoId(repoRoot);
  const dir = path.join(REPOS_DIR, id);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

// Read-only path helper — no directory creation.
function getFilePathReadOnly(repoRoot, filename) {
  return path.join(getRepoDirReadOnly(repoRoot), filename);
}

// Write-oriented path helper — creates directory.
function getFilePath(repoRoot, filename) {
  return path.join(getRepoStoreDir(repoRoot), filename);
}

/**
 * Returns true if this repo has been registered in the store (has a meta.json).
 * Unlike getRepoStoreDir(), this never creates any directories.
 */
function isRepoKnown(repoRoot) {
  ensureRepoIdMigrated(repoRoot);
  const metaPath = path.join(REPOS_DIR, getRepoId(repoRoot), 'meta.json');
  return fs.existsSync(metaPath);
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
    // Preserve removed flag if set — cleared on re-init
    removed:   existing.removed || false,
    removedAt: existing.removedAt || null,
  };

  // Re-init clears the removed flag
  if (!scanData) {
    meta.removed   = false;
    meta.removedAt = null;
  }

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
  CONFIG:          'config.yml',
  SCOPE:           'scope.yml',
  SCOPE_SERVER:    'scope-server.yml',
  AUDIT:           'audit.log',
  AUDIT_SUMMARY:   'audit-summary.log',
  SCAN_CACHE:      'last-scan.json',
  FINDINGS:        'findings.jsonl',
  EXCEPTIONS:      'exceptions.jsonl',
  EXCEPTIONS_PUSH: 'exceptions-push.jsonl',
};

// Read-only paths — do not create the store directory:
function configPath(repoRoot)                 { return getFilePathReadOnly(repoRoot, FILES.CONFIG);          }
function scopePath(repoRoot)                  { return getFilePathReadOnly(repoRoot, FILES.SCOPE);           }
function serverScopePath(repoRoot)            { return getFilePathReadOnly(repoRoot, FILES.SCOPE_SERVER);    }
function findingsPathReadOnly(repoRoot)       { return getFilePathReadOnly(repoRoot, FILES.FINDINGS);        }
function exceptionsPathReadOnly(repoRoot)     { return getFilePathReadOnly(repoRoot, FILES.EXCEPTIONS);      }
function exceptionsPushPathReadOnly(repoRoot) { return getFilePathReadOnly(repoRoot, FILES.EXCEPTIONS_PUSH); }

// Write-oriented paths — create the store directory on first use:
function auditPath(repoRoot)         { return getFilePath(repoRoot, FILES.AUDIT);           }
function auditSummaryPath(repoRoot)  { return getFilePath(repoRoot, FILES.AUDIT_SUMMARY);   }
function scanCachePath(repoRoot)     { return getFilePath(repoRoot, FILES.SCAN_CACHE);      }
function findingsPath(repoRoot)      { return getFilePath(repoRoot, FILES.FINDINGS);        }
function exceptionsPath(repoRoot)    { return getFilePath(repoRoot, FILES.EXCEPTIONS);      }
function exceptionsPushPath(repoRoot){ return getFilePath(repoRoot, FILES.EXCEPTIONS_PUSH); }
function globalScopePath()           { return path.join(GLOBAL_DIR, FILES.SCOPE);           }
function storeDir(repoRoot)          { return getRepoStoreDir(repoRoot);                    }

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

function exportsDir(repoRoot) {
  const dir = path.join(getRepoStoreDir(repoRoot), 'exports');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function exportPath(repoRoot, filename) {
  return path.join(exportsDir(repoRoot), filename);
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
 * Used by scd doctor and future scd export.
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
        const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
        // repoId is the store directory name — it is NOT persisted in meta.json,
        // so inject it. Without this, every successfully-parsed record had
        // repoId: undefined, and a meta that also lacked `name` crashed callers
        // doing `r.name || r.repoId` (scd list).
        return { ...meta, repoId: id };
      } catch {
        return { repoId: id, remote: null, localPath: null, name: id };
      }
    });
}

function updateLastSynced(repoRoot, handledIds = []) {
  const metaPath = path.join(getRepoStoreDir(repoRoot), 'meta.json');
  let existing = {};
  try { existing = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch {}
  existing.lastSynced = new Date().toISOString();
  // Accumulate handled IDs so getSyncNotice can exclude them
  const prev = Array.isArray(existing.handledExceptionIds) ? existing.handledExceptionIds : [];
  existing.handledExceptionIds = [...new Set([...prev, ...handledIds])];
  fs.writeFileSync(metaPath, JSON.stringify(existing, null, 2), 'utf8');
}

function readMeta(repoRoot) {
  const metaPath = path.join(getRepoDirReadOnly(repoRoot), 'meta.json');
  try { return JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch { return {}; }
}

/**
 * Resolve a repo's working-directory path from its repoId, via the store's
 * meta.json (`localPath`). Returns null if the repo is unknown or has no recorded
 * path. Used by the push-queue flush to run the per-repo decision-pull / sync-ack
 * for a queued repo without standing in its directory.
 */
function getRepoRootById(repoId) {
  try {
    const metaPath = path.join(REPOS_DIR, repoId, 'meta.json');
    if (!fs.existsSync(metaPath)) return null;
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    return meta.localPath || null;
  } catch {
    return null;
  }
}

// ── sync_exceptions ack token (per-installation machine state) ──────────────
//
// The push-response delivery channel (POST /api/v1/events/batch → response
// `sync_exceptions`) is acked back to the server via an OPAQUE token: the
// highest `updated_at` string among the decision records the CLI has
// successfully applied. The server moves its per-(repo, installation) cursor
// ONLY when it receives this token — at-least-once delivery.
//
// Policy-vs-machine-state split (mirrors the Branch A push tracker): config.yml
// is user policy shared via git; this token is machine/installation state and
// must NEVER travel between checkouts or machines. It therefore lives in the
// global store's meta.json alongside `lastSynced` / `handledExceptionIds`
// (already per-installation sync state), not in the repo working tree.
//
// The token is opaque: stored and echoed VERBATIM. The CLI never parses,
// reformats, or generates it from its own clock.

function getSyncAckToken(repoRoot) {
  const meta = readMeta(repoRoot);
  return typeof meta.syncAckToken === 'string' && meta.syncAckToken
    ? meta.syncAckToken
    : null;
}

// Persist the ack token verbatim. Monotonic: a lower token never regresses a
// higher one (plain string comparison, matching the server's MAX() semantics).
// Returns the token actually stored (existing one if no advance happened).
function setSyncAckToken(repoRoot, token) {
  if (typeof token !== 'string' || !token) return getSyncAckToken(repoRoot);
  const metaPath = path.join(getRepoStoreDir(repoRoot), 'meta.json');
  let existing = {};
  try { existing = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch {}
  const current = typeof existing.syncAckToken === 'string' ? existing.syncAckToken : null;
  if (current && current >= token) return current;   // never regress
  existing.syncAckToken   = token;
  existing.syncAckTokenAt = new Date().toISOString();
  fs.writeFileSync(metaPath, JSON.stringify(existing, null, 2), 'utf8');
  return token;
}


// ── Machine fingerprint ────────────────────────────────────────────────────
// Stable installation identity derived from hardware characteristics.
// Mirrors the logic in scd-server/lib/auth.js getMachineFingerprint()
// so the server can correlate CLI events with its own fingerprint records.
// Also used as added_by identifier in scope.yml exclusion entries.

function getMachineFingerprint() {
  try {
    const hostname = os.hostname();
    const platform = os.platform();
    const cpus     = os.cpus();
    const cpuModel = cpus.length > 0 ? cpus[0].model : 'unknown';
    const cpuCount = String(cpus.length);
    const raw = `${hostname}|${platform}|${cpuModel}|${cpuCount}`;
    return 'fp-' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32);
  } catch {
    return 'fp-unknown';
  }
}

module.exports = {
  getRepoId,
  getLegacyRepoId,
  getRepoIdentity,
  canonicalizeRemote,
  isRepoKnown,
  getMachineFingerprint,
  updateMeta,
  updateLastSynced,
  readMeta,
  getRepoRootById,
  getSyncAckToken,
  setSyncAckToken,
  configPath,
  auditPath,
  auditSummaryPath,
  scanCachePath,
  findingsPath,
  findingsPathReadOnly,
  exceptionsPath,
  exceptionsPathReadOnly,
  exceptionsPushPath,
  exceptionsPushPathReadOnly,
  scopePath,
  serverScopePath,
  globalScopePath,
  storeDir,
  scansDir,
  scanPath,
  listScans,
  reportsDir,
  reportPath,
  listReports,
  exportsDir,
  exportPath,
  listRepos,
  GLOBAL_DIR,
  REPOS_DIR,
  FILES,
};
