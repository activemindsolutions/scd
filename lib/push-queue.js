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

/**
 * Flush pending events to scd-server.
 * Returns a status string for optional display: 'sent', 'unreachable', 'empty',
 * 'error', 'auth_failed' (token rejected — permanent), 'license_invalid'.
 * Always resolves — never rejects.
 *
 * @param {string} centralUrl  e.g. 'https://security.company.internal:3000'
 * @param {object} opts
 * @param {boolean} opts.verbose       print result to terminal
 * @param {boolean} opts.pullDecisions (E1d) when the queue is empty, still POST an
 *   empty batch to pull server decisions (sync_exceptions ride the response) so
 *   approvals/rejections reach the CLI without `scd sync`. Requires opts.repoRoot.
 */
async function flush(centralUrl, opts = {}) {
  const entries = readQueue();
  const pending = entries.filter(e => !isStale(e));
  const isEmpty = pending.length === 0;

  // Empty queue: nothing to send. Unless the caller asked to pull decisions on an
  // empty contact (E1d) and there is a repo to pull for, there is nothing to do.
  // An empty queue has nothing to lose if the server is unreachable — the contact
  // is retried at the next command.
  if (isEmpty && !(opts.pullDecisions && opts.repoRoot)) return 'empty';

  const url   = centralUrl.replace(/\/$/, '') + BATCH_ENDPOINT;
  const now   = new Date().toISOString();
  const token = opts.token || (() => {
    try { return require('./global-config').getCentralToken(); } catch { return null; }
  })();

  try {
    const http  = url.startsWith('https') ? require('https') : require('http');
    const meta  = buildMeta(opts.repoRoot || null);

    // sync_exceptions ack: echo the persisted opaque token VERBATIM so the
    // server advances its per-(repo, installation) cursor. No token persisted
    // yet → omit the field entirely (server treats absence as the old-CLI
    // path). Standalone (no repoRoot) → no token concept at all.
    if (opts.repoRoot) {
      try {
        const tok = require('./store').getSyncAckToken(opts.repoRoot);
        if (tok) meta.sync_exceptions_acked_through = tok;
      } catch { /* non-fatal — omit field */ }
    }

    // events:[] on an empty pull-decisions contact (E1d) — the POST exists only
    // to receive the sync_exceptions response.
    const body  = JSON.stringify({ events: pending.map(e => e.event), meta });

    const response = await httpPost(http, url, body, token);

    if (response.status >= 200 && response.status < 300) {
      if (!isEmpty) {
        // Remove successfully sent entries, keep stale ones
        const sentIds   = new Set(pending.map(e => e.id));
        const remaining = entries.filter(e => !sentIds.has(e.id));
        writeQueue(remaining);
      }

      // Cache server version + apply piggybacked decisions (both empty and
      // non-empty contacts) — the decision-pull is the point of an empty contact.
      applyBatchResponse(opts.repoRoot, response.body);

      if (opts.verbose && !isEmpty) {
        console.log(`${DIM}  ↑ Synced ${pending.length} queued event(s) to central${RESET}`);
      }
      // An empty pull-decisions contact reports 'empty' (the queue state), not
      // 'sent' — callers key on 'empty'/'sent' for display; the decision-pull is
      // a side effect, not a queued-event send.
      return isEmpty ? 'empty' : 'sent';
    } else if (response.status === 503) {
      // Server license invalid — do NOT bump attempts, keep events intact for retry
      // Data is safe in queue and will sync automatically when license is restored
      let isLicenseInvalid = false;
      try {
        const parsed = JSON.parse(response.body);
        isLicenseInvalid = parsed.error === 'License invalid';
      } catch { /* ignore parse error */ }

      if (isLicenseInvalid) {
        if (opts.verbose && !isEmpty) {
          console.log(`${DIM}  ↑ Server license invalid – ${pending.length} event(s) held in queue${RESET}`);
        }
        return isEmpty ? 'empty' : 'license_invalid';
      }
      // Other 503 — server temporarily unavailable, do NOT bump attempts
      if (opts.verbose && !isEmpty) {
        console.log(`${DIM}  ↑ Central unavailable (503) – ${pending.length} event(s) held in queue${RESET}`);
      }
      return isEmpty ? 'empty' : 'unreachable';
    } else if (response.status === 401 || response.status === 403) {
      // Token rejected — PERMANENT until the user fixes it. Do NOT bump attempts
      // (that would silently age the queue out, halting all delivery); flag the
      // entries so `scd queue` shows "delivery blocked" and the caller surfaces
      // it at command time. Events stay and deliver once a valid token is set.
      if (!isEmpty) markAuthBlocked(entries, pending);
      if (opts.verbose && !isEmpty) {
        console.log(`${DIM}  ↑ Server rejected the token (${response.status}) – delivery blocked${RESET}`);
      }
      return isEmpty ? 'empty' : 'auth_failed';
    } else {
      // Server reachable but returned error — increment attempts (nothing to bump
      // on an empty contact).
      if (!isEmpty) {
        bumpAttempts(entries, pending, now);
        if (opts.verbose) {
          console.log(`${DIM}  ↑ Central returned ${response.status} – ${pending.length} event(s) queued for next sync${RESET}`);
        }
      }
      return isEmpty ? 'empty' : 'error';
    }
  } catch {
    // Network error — server unreachable (connection refused, DNS failure, timeout)
    // Do NOT bump attempts — this is a transient failure, not a permanent error.
    // Events stay in queue and will sync when server comes back online. An empty
    // contact has nothing queued to lose; it retries at the next command.
    if (opts.verbose && !isEmpty) {
      console.log(`${DIM}  ↑ Central unreachable – ${pending.length} event(s) held in queue${RESET}`);
    }
    return isEmpty ? 'empty' : 'unreachable';
  }
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

function bumpAttempts(allEntries, pendingEntries, now) {
  const pendingIds = new Set(pendingEntries.map(e => e.id));
  const updated = allEntries.map(e => {
    if (!pendingIds.has(e.id)) return e;
    // A reachable-but-errored response is transient and supersedes any prior
    // auth block — clear lastError so the queue no longer shows "token rejected".
    const { lastError, ...rest } = e;
    return { ...rest, attempts: e.attempts + 1, lastAttempt: now };
  });
  writeQueue(updated);
}

// Flag pending entries as auth-blocked (server rejected the token, 401/403).
// PERMANENT until the user fixes the token — so, unlike bumpAttempts, this does
// NOT increment attempts (which would age the queue out and halt delivery). The
// entries stay deliverable and recover automatically once a valid token is set.
function markAuthBlocked(allEntries, pendingEntries) {
  const pendingIds = new Set(pendingEntries.map(e => e.id));
  const updated = allEntries.map(e =>
    pendingIds.has(e.id) ? { ...e, lastError: 'auth' } : e);
  writeQueue(updated);
}

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
