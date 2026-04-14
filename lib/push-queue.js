/**
 * push-queue.js
 * Offline-first push queue for scd events → scd-server.
 *
 * Events are always written to audit.log first (existing behaviour).
 * When a central URL is configured, events are also queued here and
 * flushed to the server on every scd command (non-blocking).
 *
 * Queue file: ~/.scd/push-queue.jsonl  (one JSON object per line)
 *
 * Each entry:
 *   { id, ts, attempts, lastAttempt, event: { ...audit event } }
 *
 * Flush behaviour:
 *   - Sends all pending events as a single POST /api/v1/events/batch
 *   - On success: removes sent entries from queue
 *   - On failure: increments attempts, updates lastAttempt, keeps entry
 *   - Silent on network errors – never blocks the CLI
 *
 * Stale threshold: entries with attempts >= 10 are considered stale.
 * scd doctor reports stale count; scd repo --verify --clean can purge.
 * TODO: scd store/repo --verify --clean is currently per-repo but the push queue
 * lives globally at ~/.scd — consider a global scd verify --clean command.
 *
 * Grace period: if all events are older than 7 days the user is warned
 * by scd doctor (not by the push worker itself).
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const QUEUE_PATH      = path.join(os.homedir(), '.scd', 'push-queue.jsonl');
const STALE_ATTEMPTS  = 10;
const GRACE_DAYS      = 7;
const BATCH_ENDPOINT  = '/api/v1/events/batch';

// ── Machine fingerprint ──────────────────────────────────────────────────
// Mirrors the logic in scd-server/lib/auth.js getMachineFingerprint()
// so the server can correlate CLI events with its own fingerprint records.

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

/**
 * Build the meta object sent alongside events.
 * Includes installation identity and repo context.
 * repoRoot is optional — omitted when flush is called outside a repo context.
 */
function buildMeta(repoRoot) {
  const meta = {
    installationId: getMachineFingerprint(),
    hostname:       os.hostname(),
    platform:       os.platform(),
    scdVersion:     (() => {
      try { return require('../package.json').version; } catch { return null; }
    })(),
  };

  if (repoRoot) {
    try {
      const store = require('./store');
      meta.repoId     = store.getRepoId(repoRoot);
      meta.repoName   = path.basename(path.resolve(repoRoot));
      // Include remote URL if available
      const identity = store.getRepoIdentity ? store.getRepoIdentity(repoRoot) : null;
      if (identity && identity.type === 'remote') {
        meta.repoRemote = identity.identifier;
      }
    } catch { /* non-fatal */ }
  }

  return meta;
}

// ── Queue file helpers ────────────────────────────────────────────────────

function readQueue() {
  if (!fs.existsSync(QUEUE_PATH)) return [];
  try {
    return fs.readFileSync(QUEUE_PATH, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line));
  } catch {
    return [];
  }
}

function writeQueue(entries) {
  try {
    const dir = path.dirname(QUEUE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const content = entries.map(e => JSON.stringify(e)).join('\n');
    fs.writeFileSync(QUEUE_PATH, content ? content + '\n' : '', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Queue write failure is non-fatal — audit.log is the source of truth
  }
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Add an audit event to the push queue.
 * Called from audit.js whenever a scan completes.
 */
function enqueue(auditEvent) {
  try {
    const entry = {
      id:          `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ts:          new Date().toISOString(),
      attempts:    0,
      lastAttempt: null,
      event:       auditEvent,
    };
    const dir = path.dirname(QUEUE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.appendFileSync(QUEUE_PATH, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // Non-fatal
  }
}

/**
 * Flush pending events to scd-server.
 * Returns a status string for optional display: 'sent', 'unreachable', 'empty', 'error'.
 * Always resolves — never rejects.
 *
 * @param {string} centralUrl  e.g. 'https://security.company.internal:3000'
 * @param {object} opts
 * @param {boolean} opts.verbose  print result to terminal
 */
async function flush(centralUrl, opts = {}) {
  const entries = readQueue();
  const pending = entries.filter(e => e.attempts < STALE_ATTEMPTS);

  if (pending.length === 0) return 'empty';

  const url   = centralUrl.replace(/\/$/, '') + BATCH_ENDPOINT;
  const now   = new Date().toISOString();
  const token = opts.token || (() => {
    try { return require('./global-config').getCentralToken(); } catch { return null; }
  })();

  try {
    const http  = url.startsWith('https') ? require('https') : require('http');
    const meta  = buildMeta(opts.repoRoot || null);
    const body  = JSON.stringify({ events: pending.map(e => e.event), meta });

    const response = await httpPost(http, url, body, token);

    if (response.status >= 200 && response.status < 300) {
      // Remove successfully sent entries, keep stale ones
      const sentIds  = new Set(pending.map(e => e.id));
      const remaining = entries.filter(e => !sentIds.has(e.id));
      writeQueue(remaining);

      if (opts.verbose) {
        console.log(`\x1b[90m  ↑ Synced ${pending.length} queued event(s) to central\x1b[0m`);
      }
      return 'sent';
    } else if (response.status === 503) {
      // Server license invalid — do NOT bump attempts, keep events intact for retry
      // Data is safe in queue and will sync automatically when license is restored
      let isLicenseInvalid = false;
      try {
        const parsed = JSON.parse(response.body);
        isLicenseInvalid = parsed.error === 'License invalid';
      } catch { /* ignore parse error */ }

      if (isLicenseInvalid) {
        if (opts.verbose) {
          console.log(`\x1b[90m  ↑ Server license invalid – ${pending.length} event(s) held in queue\x1b[0m`);
        }
        return 'license_invalid';
      }
      // Other 503 — treat as transient, bump attempts
      bumpAttempts(entries, pending, now);
      if (opts.verbose) {
        console.log(`\x1b[90m  ↑ Central unavailable (503) – ${pending.length} event(s) queued for next sync\x1b[0m`);
      }
      return 'error';
    } else {
      // Server reachable but returned error — increment attempts
      bumpAttempts(entries, pending, now);
      if (opts.verbose) {
        console.log(`\x1b[90m  ↑ Central returned ${response.status} – ${pending.length} event(s) queued for next sync\x1b[0m`);
      }
      return 'error';
    }
  } catch {
    // Network error — server unreachable
    bumpAttempts(entries, pending, now);
    if (opts.verbose) {
      console.log(`\x1b[90m  ↑ Central unreachable – ${pending.length} event(s) queued for next sync\x1b[0m`);
    }
    return 'unreachable';
  }
}

function bumpAttempts(allEntries, pendingEntries, now) {
  const pendingIds = new Set(pendingEntries.map(e => e.id));
  const updated = allEntries.map(e => {
    if (!pendingIds.has(e.id)) return e;
    return { ...e, attempts: e.attempts + 1, lastAttempt: now };
  });
  writeQueue(updated);
}

/**
 * Number of events currently in queue (excluding stale).
 */
function queueSize() {
  return readQueue().filter(e => e.attempts < STALE_ATTEMPTS).length;
}

/**
 * Number of stale events (attempts >= STALE_ATTEMPTS).
 */
function staleCount() {
  return readQueue().filter(e => e.attempts >= STALE_ATTEMPTS).length;
}

/**
 * Whether all pending events are older than the grace period.
 * Returns false if queue is empty.
 */
function isPastGrace() {
  const pending = readQueue().filter(e => e.attempts < STALE_ATTEMPTS);
  if (pending.length === 0) return false;
  const oldest = pending.reduce((min, e) => e.ts < min ? e.ts : min, pending[0].ts);
  const ageMs  = Date.now() - new Date(oldest).getTime();
  return ageMs > GRACE_DAYS * 24 * 60 * 60 * 1000;
}

/**
 * Remove all stale entries from queue.
 * Returns number of entries removed.
 */
function purgeStale() {
  const entries = readQueue();
  const clean   = entries.filter(e => e.attempts < STALE_ATTEMPTS);
  writeQueue(clean);
  return entries.length - clean.length;
}

// ── HTTP helper (no external deps) ───────────────────────────────────────

function httpPost(http, urlStr, body, token = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const headers = {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body),
      'User-Agent':     'scd-cli/1',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const { getServerTimeout } = require('./global-config');
    const options = {
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname + u.search,
      method:   'POST',
      headers,
      timeout: getServerTimeout(),
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end',  () => resolve({ status: res.statusCode, body: data }));
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error',   reject);
    req.write(body);
    req.end();
  });
}

module.exports = {
  enqueue,
  flush,
  queueSize,
  staleCount,
  isPastGrace,
  purgeStale,
  getMachineFingerprint,
  buildMeta,
  QUEUE_PATH,
  STALE_ATTEMPTS,
  GRACE_DAYS,
};
