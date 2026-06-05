/**
 * exceptions-push-tracker.js
 * Persistent record of exceptions awaiting acknowledged delivery to scd-server.
 *
 * State of delivery is held HERE, not on the config.yml record itself:
 *
 *   id in tracker  ⟺  exception not yet acked by server
 *   id absent      ⟺  delivered (or never queued — standalone mode)
 *
 * This avoids in-place YAML mutation in config.yml (no symmetric YAML writer
 * exists; see config.js:parseSimpleYaml). It also mirrors push-queue.jsonl's
 * "list of things to retry until ack" pattern.
 *
 * Format: JSONL, one record per line, schema:
 *     { exception_id: "exc-...", queued_at: "2026-06-05T12:34:56.789Z" }
 *
 * - `queued_at` is preserved across retries — `scd doctor` uses it for the
 *   "oldest: <age>" annotation. NEVER rewrite it on retry.
 * - File mode 0o600, atomic write (tmp → fsync → rename), mode 0o700 dir.
 *
 * Edge cases (decided 2026-06-05):
 *  - **Standalone mode** (no centralUrl): writes are no-ops; `markPending`
 *    must never be called. The guard is at the call site (exception-manager).
 *  - **Orphan entries**: an id may remain in the tracker after its exception
 *    was deleted from config.yml (manual edit or future remove-command). The
 *    push path drops orphan ids silently — nothing to deliver, nothing to
 *    report. Without this, a deleted exception would retry-loop forever.
 *  - **Corrupt lines**: skip with a single [WARN] summary on load, same as
 *    findings-store. One bad line must not block other deliveries.
 *  - **Concurrent writers** (two processes doing markPending/clearIds at the
 *    same time): same read-modify-write race as findings-store. Covered by
 *    the documented dubbelbatch lock-fix (see PROGRESS.md "Dubbelbatch —
 *    push-queue race"), not addressed here. The atomic rename ensures one
 *    writer wins cleanly without corruption — at worst an entry is lost and
 *    will be re-marked on the next operation.
 */

'use strict';

const fs = require('fs');

const { exceptionsPushPath, exceptionsPushPathReadOnly } = require('./store');

const YELLOW = '\x1b[33m';
const RESET  = '\x1b[0m';

function loadPending(repoRoot) {
  const target = exceptionsPushPathReadOnly(repoRoot);
  if (!fs.existsSync(target)) return [];

  let content;
  try { content = fs.readFileSync(target, 'utf8'); }
  catch { return []; }

  const lines = content.split('\n').filter(l => l.length > 0);
  const records = [];
  let corrupt = 0;
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj && typeof obj.exception_id === 'string') {
        records.push(obj);
      } else {
        corrupt++;
      }
    } catch { corrupt++; }
  }
  if (corrupt > 0) {
    process.stderr.write(
      `${YELLOW}[WARN]${RESET} exceptions-push.jsonl: ${corrupt} corrupt line(s) skipped\n`
    );
  }
  return records;
}

function writePendingAtomic(repoRoot, records) {
  const target = exceptionsPushPath(repoRoot);
  const tmp    = target + '.tmp';

  const body    = records.map(r => JSON.stringify(r)).join('\n');
  const content = records.length > 0 ? body + '\n' : '';

  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    if (content.length > 0) fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, target);
  try { fs.chmodSync(target, 0o600); } catch { /* best-effort */ }
}

/**
 * Mark an exception as awaiting server delivery. No-op if the id is already
 * pending (idempotent). Caller MUST guard with getCentralUrl() — this module
 * does not know about that — standalone mode never reaches here.
 */
function markPending(repoRoot, exceptionId) {
  if (!exceptionId) return;
  const existing = loadPending(repoRoot);
  if (existing.some(e => e.exception_id === exceptionId)) return;
  existing.push({ exception_id: exceptionId, queued_at: new Date().toISOString() });
  writePendingAtomic(repoRoot, existing);
}

/**
 * Remove ids from the tracker (called both on confirmed delivery and on
 * orphan-detection — the caller decides the meaning, the tracker just drops).
 */
function clearIds(repoRoot, ids) {
  if (!Array.isArray(ids) || ids.length === 0) return;
  const set = new Set(ids);
  const existing = loadPending(repoRoot);
  const remaining = existing.filter(e => !set.has(e.exception_id));
  if (remaining.length === existing.length) return;   // nothing to drop
  writePendingAtomic(repoRoot, remaining);
}

function pendingCount(repoRoot) {
  return loadPending(repoRoot).length;
}

/**
 * Return the oldest queued_at ISO string from the tracker, or null if empty.
 * Used by `scd doctor` to annotate pending-count with age.
 */
function oldestQueuedAt(repoRoot) {
  const list = loadPending(repoRoot);
  if (list.length === 0) return null;
  // ISO 8601 strings compare lexicographically as time
  return list.reduce((min, e) => (e.queued_at < min ? e.queued_at : min), list[0].queued_at);
}

module.exports = {
  loadPending,
  markPending,
  clearIds,
  pendingCount,
  oldestQueuedAt,
};
