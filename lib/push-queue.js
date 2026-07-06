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
 *   { id, ts, attempts, lastAttempt, repoId, event: { ...audit event } }
 *
 * repoId is stamped at ENQUEUE time from the producing repo — the queue is a single
 * global file shared by every repo, so attribution must travel WITH the event. flush()
 * groups by repoId and sends one batch per repo; it must never stamp a batch-level id
 * from the flushing cwd (that misattributes one repo's events to another).
 *
 * Flush behaviour:
 *   - Sends all pending events as a single POST /api/v1/events/batch
 *   - On success: removes sent entries from queue
 *   - On failure: increments attempts, updates lastAttempt, keeps entry
 *   - Silent on network errors – never blocks the CLI
 *
 * Stale threshold: entries with attempts >= 10 are considered stale.
 * `scd doctor` reports the stale count; `scd queue reset` makes them
 * deliverable again.
 *
 * Grace period: if all events are older than 7 days the user is warned
 * by scd doctor (not by the push worker itself).
 */

'use strict';
const { DIM, RESET } = require('./output-constants');

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

const QUEUE_PATH      = path.join(os.homedir(), '.scd', 'push-queue.jsonl');
// Stale threshold (see isStale/staleReason): an entry is stale when it has
// reached STALE_ATTEMPTS permanent failures, OR when it is older than STALE_DAYS.
// The two causes are an independent logical OR — age alone makes an entry stale
// even with zero failed attempts. Transient failures (network down, server
// unreachable) do NOT increment attempts, so they can only ever go stale by age.
const STALE_DAYS      = 30;
const STALE_ATTEMPTS  = 10;  // kept for backwards compat with existing queue entries
const GRACE_DAYS      = 7;
const BATCH_ENDPOINT  = '/api/v1/events/batch';

// ── Machine fingerprint ──────────────────────────────────────────────────
const { getMachineFingerprint } = require('./store');

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
 * @param {object} auditEvent  the event payload
 * @param {string} repoId      the producing repo's id (attribution — see flush).
 *   Omitted/null marks the entry unattributed; flush drops such entries.
 */
function enqueue(auditEvent, repoId = null) {
  try {
    const entry = {
      id:          `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ts:          new Date().toISOString(),
      attempts:    0,
      lastAttempt: null,
      repoId:      repoId || null,
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
 * Apply a successful events/batch response: cache server version info and apply
 * any server decisions piggybacked on the sync_exceptions push channel. The
 * sync_exceptions KEY being present (an array, even empty) is positive evidence
 * the channel is live and nothing is pending — that, not a bare 2xx, refreshes
 * the staleness timestamp. An old server omits the key entirely, so the
 * stale-sync nag correctly survives. Non-throwing — best-effort.
 */
function applyBatchResponse(repoRoot, responseBody) {
  try {
    const parsed = JSON.parse(responseBody);
    if (parsed.server_version || parsed.min_cli_version) {
      require('./global-config').setServerVersionInfo(
        parsed.server_version || null,
        parsed.min_cli_version || null
      );
    }
    if (repoRoot && Array.isArray(parsed.sync_exceptions)) {
      if (parsed.sync_exceptions.length > 0) {
        // applyFlushDecisions is idempotent, silent on no-op, never throws.
        require('./exception-manager').applyFlushDecisions(repoRoot, parsed.sync_exceptions);
      }
      try { require('./store').updateLastSynced(repoRoot, []); }
      catch { /* non-fatal */ }
    }
  } catch { /* non-fatal */ }
}

// Aggregate the flush status across per-repo batches — surface the most actionable
// outcome (a rejected token beats a plain error beats an offline server, etc.).
const FLUSH_STATUS_RANK = { auth_failed: 5, license_invalid: 4, error: 3, unreachable: 2, sent: 1, empty: 0 };
function worseFlushStatus(a, b) {
  return (FLUSH_STATUS_RANK[b] || 0) > (FLUSH_STATUS_RANK[a] || 0) ? b : a;
}

// Notice when pre-attribution (no-repoId) entries are dropped — they predate the
// per-repo fix and cannot be safely routed, so they are removed rather than guessed.
function warnDroppedLegacy(count, opts) {
  if (opts.verbose) {
    console.log(`${DIM}  ↑ Dropped ${count} unattributed queued event(s) from before the per-repo fix — re-sync history if needed: scd sync --history${RESET}`);
  }
}

/**
 * Flush pending events to scd-server.
 * Returns a status string for optional display: 'sent', 'unreachable', 'empty',
 * 'error', 'auth_failed' (token rejected — permanent), 'license_invalid'.
 * Always resolves — never rejects.
 *
 * The queue is a single global file shared by all repos. Attribution is stamped per
 * event at enqueue (entry.repoId); flush GROUPS by repoId and sends one events/batch
 * per repo, each with its own meta.repoId — never a single batch-level id from the
 * flushing cwd (that misattributes one repo's findings to another). Entries with no
 * repoId predate the fix and are dropped (the per-repo audit.log is the source of
 * truth; a later `scd sync --history` re-pushes them under the correct repo).
 *
 * @param {string} centralUrl  e.g. 'https://security.company.internal:3000'
 * @param {object} opts
 * @param {boolean} opts.verbose       print result to terminal
 * @param {boolean} opts.pullDecisions (E1d) when the queue is empty, still POST an
 *   empty batch to pull server decisions (sync_exceptions ride the response) so
 *   approvals/rejections reach the CLI without `scd sync`. Requires opts.repoRoot.
 */
async function flush(centralUrl, opts = {}) {
  const store   = require('./store');
  const entries = readQueue();
  const fresh   = entries.filter(e => !isStale(e));

  // Legacy pre-attribution entries (no repoId) — DROP. The per-repo store/audit.log
  // is the source of truth; guessing an id from the flush cwd is exactly the
  // cross-repo misattribution this grouping removes.
  const legacyIds  = new Set(fresh.filter(e => !e.repoId).map(e => e.id));
  const attributed = fresh.filter(e => e.repoId);

  // Group attributed entries by their enqueue-time repoId.
  const groups = new Map();   // repoId -> entries[]
  for (const e of attributed) {
    if (!groups.has(e.repoId)) groups.set(e.repoId, []);
    groups.get(e.repoId).push(e);
  }

  // Resolve the flushing repo's id up front: a group matching it uses opts.repoRoot
  // directly for the token + decision-pull, avoiding a store lookup (and working even
  // when the repo has no meta.json yet — e.g. first contact).
  let flushRepoId = null;
  if (opts.repoRoot) {
    try { flushRepoId = store.getRepoId(opts.repoRoot); } catch { /* non-fatal */ }
  }
  // Decision-pull (E1d): guarantee the flushing repo still gets a contact even with
  // no events of its own, so approvals/rejections reach it.
  if (opts.pullDecisions && flushRepoId && !groups.has(flushRepoId)) groups.set(flushRepoId, []);

  if (groups.size === 0) {
    if (legacyIds.size) { writeQueue(entries.filter(e => !legacyIds.has(e.id))); warnDroppedLegacy(legacyIds.size, opts); }
    return 'empty';
  }

  const url   = centralUrl.replace(/\/$/, '') + BATCH_ENDPOINT;
  const now   = new Date().toISOString();
  const token = opts.token || (() => {
    try { return require('./global-config').getCentralToken(); } catch { return null; }
  })();
  const http  = url.startsWith('https') ? require('https') : require('http');

  const sentIds  = new Set();
  const bumpIds  = new Set();
  const authIds  = new Set();
  let   sentReal = 0;
  let   status   = 'empty';

  // One events/batch POST per repo — each stamped with ITS OWN repoId. Sequential;
  // a failure on one repo never blocks or misattributes another.
  for (const [repoId, groupEntries] of groups) {
    const groupEmpty = groupEntries.length === 0;
    // repoRoot for token + decision-pull: the flushing dir if it matches, else the
    // repo's recorded working dir. Attribution (meta.repoId) never depends on it.
    const repoRoot = (repoId === flushRepoId ? opts.repoRoot : null) || store.getRepoRootById(repoId);

    const meta = buildMeta(repoRoot);
    meta.repoId = repoId;   // authoritative — the id stamped at enqueue, never recomputed
    if (repoRoot) {
      try {
        const tok = store.getSyncAckToken(repoRoot);
        if (tok) meta.sync_exceptions_acked_through = tok;
      } catch { /* non-fatal — omit field */ }
    }
    const body = JSON.stringify({ events: groupEntries.map(e => e.event), meta });

    let response;
    try {
      response = await httpPost(http, url, body, token);
    } catch {
      // Network error — transient. Keep entries (no bump); retry next contact.
      status = worseFlushStatus(status, groupEmpty ? 'empty' : 'unreachable');
      continue;
    }

    if (response.status >= 200 && response.status < 300) {
      groupEntries.forEach(e => sentIds.add(e.id));
      if (!groupEmpty) sentReal += groupEntries.length;
      // Cache server version + apply piggybacked decisions for THIS repo.
      applyBatchResponse(repoRoot, response.body);
      status = worseFlushStatus(status, groupEmpty ? 'empty' : 'sent');
    } else if (response.status === 503) {
      // License invalid or server temporarily unavailable — do NOT bump; keep for retry.
      let isLicenseInvalid = false;
      try { isLicenseInvalid = JSON.parse(response.body).error === 'License invalid'; } catch { /* ignore */ }
      status = worseFlushStatus(status, groupEmpty ? 'empty' : (isLicenseInvalid ? 'license_invalid' : 'unreachable'));
    } else if (response.status === 401 || response.status === 403) {
      // Token rejected — PERMANENT until fixed. Flag (not bump), so delivery resumes
      // automatically once a valid token is set.
      groupEntries.forEach(e => authIds.add(e.id));
      status = worseFlushStatus(status, groupEmpty ? 'empty' : 'auth_failed');
    } else {
      // Reachable but errored — bump attempts.
      groupEntries.forEach(e => bumpIds.add(e.id));
      status = worseFlushStatus(status, groupEmpty ? 'empty' : 'error');
    }
  }

  // Rebuild the queue once: keep stale verbatim; drop legacy + delivered; apply
  // auth-block / attempt-bump; keep the rest (unreachable / license) for retry.
  const rebuilt = [];
  for (const e of entries) {
    if (isStale(e))          { rebuilt.push(e); continue; }
    if (legacyIds.has(e.id))  continue;
    if (sentIds.has(e.id))    continue;
    if (authIds.has(e.id))   { rebuilt.push({ ...e, lastError: 'auth' }); continue; }
    if (bumpIds.has(e.id))   { const { lastError, ...rest } = e; rebuilt.push({ ...rest, attempts: e.attempts + 1, lastAttempt: now }); continue; }
    rebuilt.push(e);
  }
  writeQueue(rebuilt);

  if (legacyIds.size) warnDroppedLegacy(legacyIds.size, opts);
  if (opts.verbose && sentReal > 0) {
    console.log(`${DIM}  ↑ Synced ${sentReal} queued event(s) to central${RESET}`);
  }
  return status;
}

/**
 * Flush the events queue for a repo when a central server is configured.
 * Events-only — does NOT touch the exception tracker, fetch version info, or
 * print anything. Silent, never throws, resolves to the flush status (or null
 * when no central URL / on error).
 *
 * Purpose: enforce the per-contact ordering "events first". The events flush
 * registers the repo (and findings context) on the server that an exception
 * push FK-references; pushing an exception before the repo exists yields a
 * first-contact 500 (FOREIGN KEY constraint failed). Call this immediately
 * before any exception tracker push that is not already preceded by a flush.
 */
async function flushEvents(repoRoot) {
  try {
    const centralUrl = require('./global-config').getCentralUrl();
    if (!centralUrl) return null;
    return await flush(centralUrl, { repoRoot: repoRoot || null });
  } catch {
    return null;
  }
}

// Per-entry disposition (attempt-bump on a reachable error, auth-block on a
// rejected token) is applied inline in flush's single queue rebuild — see there.

/**
 * Classify WHY an entry is stale, or null when it is deliverable. Single source
 * of truth for staleness — isStale(), the doctor counts, and `scd queue list`
 * (which shows the cause per entry) all read this, so the classification can
 * never diverge from the exclusion decision.
 *   'attempts' → STALE_ATTEMPTS permanent failures reached (e.g. a dead token
 *                returning 403 on every flush — the recoverable case)
 *   'age'      → older than STALE_DAYS, independent of attempts
 *   'both'     → both causes apply
 * `scd queue reset` zeroes attempts, so it clears 'attempts'/'both' down to at
 * most 'age'; it deliberately never rewrites ts, so age-staleness survives.
 * @param {object} entry
 * @returns {null|'attempts'|'age'|'both'}
 */
function staleReason(entry) {
  const byAttempts = entry.attempts >= STALE_ATTEMPTS;
  const ageMs      = Date.now() - new Date(entry.ts).getTime();
  const byAge      = ageMs > STALE_DAYS * 24 * 60 * 60 * 1000;
  if (byAttempts && byAge) return 'both';
  if (byAttempts) return 'attempts';
  if (byAge) return 'age';
  return null;
}

/**
 * Determine if a queue entry is stale (excluded from flush). Delegates to
 * staleReason so the two never diverge.
 */
function isStale(entry) {
  return staleReason(entry) !== null;
}

/**
 * Number of events currently in queue (excluding stale).
 */
function queueSize() {
  return readQueue().filter(e => !isStale(e)).length;
}

/**
 * Number of stale events (attempts >= STALE_ATTEMPTS).
 */
function staleCount() {
  return readQueue().filter(e => isStale(e)).length;
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
  const clean   = entries.filter(e => !isStale(e));
  writeQueue(clean);
  return entries.length - clean.length;
}

/**
 * Read the full queue annotated for display (`scd queue list`). Unlike
 * queueSize/staleCount this returns the entries themselves — INCLUDING stale
 * ones — each tagged with its staleness and the cause.
 * @returns {Array<{id,ts,attempts,lastAttempt,event,stale:boolean,reason:(string|null)}>}
 */
function listEntries() {
  return readQueue().map(e => {
    const reason = staleReason(e);
    return { ...e, stale: reason !== null, reason, authBlocked: e.lastError === 'auth' };
  });
}

/**
 * Recovery primitive for `scd queue reset`. Zeroes `attempts` and clears
 * lastAttempt on EVERY entry, so attempt-based stale exclusion no longer fires
 * on the next flush — making the queue deliverable again after an incident
 * (e.g. a dead token that drove every entry past STALE_ATTEMPTS with repeated
 * 403s, silently halting all delivery).
 *
 * The distinction "stale-only vs all" is operationally empty here: non-stale
 * entries are already deliverable, so zeroing them changes nothing. The command
 * therefore has a single semantic — "make the whole queue deliverable again".
 *
 * Deliberately does NOT rewrite `ts`: age-based staleness (age > STALE_DAYS) is
 * an independent, honest signal and must survive a reset. The caller surfaces
 * any entries that remain stale by age afterwards. Idempotent.
 *
 * @returns {{ total:number, wereStale:number, ageStaleRemaining:number }}
 */
function resetAttempts() {
  const entries   = readQueue();
  const total     = entries.length;
  const wereStale = entries.filter(e => staleReason(e) !== null).length;
  // Zero attempts + clear lastAttempt and any auth block — `reset` makes the
  // whole queue deliverable again (e.g. after fixing a rejected token).
  const cleared   = entries.map(({ lastError, ...e }) => ({ ...e, attempts: 0, lastAttempt: null }));
  writeQueue(cleared);
  // After zeroing attempts the only staleness cause that can remain is age.
  const ageStaleRemaining = cleared.filter(e => staleReason(e) !== null).length;
  return { total, wereStale, ageStaleRemaining };
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
  flushEvents,
  queueSize,
  staleCount,
  staleReason,
  isPastGrace,
  purgeStale,
  listEntries,
  resetAttempts,
  getMachineFingerprint,
  buildMeta,
  QUEUE_PATH,
  STALE_ATTEMPTS,
  STALE_DAYS,
  GRACE_DAYS,
};
