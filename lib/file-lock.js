/**
 * file-lock.js
 * Shared advisory file lock for read-modify-write cycles on ~/.scd state files.
 *
 * Problem it solves (lost update): two writers each load a state file, modify
 * their in-memory copy, then atomically rename a fresh file into place. The
 * rename is crash-safe (jsonl-atomic.js), but the LAST rename wins — the earlier
 * writer's diff is silently lost. `withFileLock` serialises the whole
 * load→modify→write cycle so the read sees the other writer's committed state.
 *
 * Format-agnostic on purpose: it guards a critical section around a path and
 * does not care whether the target is JSONL (findings/exceptions stores) or
 * YAML (global-config.yml). Keep the read INSIDE fn — a lock that only wraps the
 * write does not prevent the lost update.
 *
 * Mechanism:
 *   - Acquire by creating `<target>.lock` with O_EXCL (`wx`) — an atomic
 *     create-if-absent that is the primary mutual-exclusion guarantee.
 *   - The lock carries a unique nonce (`<pid>.<rand>`) + a timestamp.
 *   - A held lock is STALE when its holder pid is dead (`process.kill(pid, 0)`),
 *     or as a backstop when it is older than `staleMs` (covers pid reuse). A
 *     stale lock is stolen (unlinked) and acquisition retried.
 *   - A LIVE holder is never stolen from (decision: no silent steal of a live
 *     writer — that would re-introduce the lost update). We wait, bounded by
 *     `maxWaitMs`, then throw `ELOCKED` rather than risk data loss or deadlock.
 *
 * Assumptions: local `~/.scd` (pid liveness is only meaningful on one machine).
 * A network-shared store has other problems and is out of scope.
 *
 * The CLI is synchronous, so this primitive is synchronous (backoff via
 * Atomics.wait — the only sync sleep in Node).
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DEFAULTS = {
  staleMs:   30000,  // backstop: a lock older than this is stealable even if pid looks alive (pid reuse)
  maxWaitMs: 10000,  // total time to wait for a LIVE holder before throwing ELOCKED
  backoffMs: 50,     // sync poll interval while waiting
};

// Synchronous sleep — the CLI has no event loop to yield to here.
function sleepSync(ms) {
  if (ms <= 0) return;
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// EPERM = process exists but is not ours (still alive); ESRCH = no such process.
function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (err) { return err.code === 'EPERM'; }
}

// Inspect a lock file. Distinguishes three states that the stale logic treats
// very differently:
//   { gone:true }                     — file absent (ENOENT)
//   { unparsed:true, mtimeMs }        — file present but empty/partial. This is
//                                       the create→write window: openSync('wx')
//                                       makes the file visible BEFORE writeSync
//                                       fills it. A concurrent reader here must
//                                       NOT treat it as stealable, or it would
//                                       evict a live lock mid-creation (lost update).
//   { nonce, pid, ts, mtimeMs }       — fully written, parseable.
function readLock(lockPath) {
  let stat;
  try { stat = fs.statSync(lockPath); }
  catch { return { gone: true }; }              // ENOENT → already gone
  let raw = '';
  try { raw = fs.readFileSync(lockPath, 'utf8'); } catch { /* partial/locked — unparsed */ }
  const [nonce, tsStr] = raw.split('\n');
  if (!nonce) return { unparsed: true, mtimeMs: stat.mtimeMs };
  const pid = Number(nonce.split('.')[0]);
  const ts  = Number(tsStr);
  return { nonce, pid, ts: Number.isFinite(ts) ? ts : 0, mtimeMs: stat.mtimeMs };
}

// A lock is stale (stealable) when:
//   - the file is gone (acquire can proceed), or
//   - its holder pid is dead (crashed holder — the main recovery case), or
//   - (backstop) it is older than staleMs: covers pid reuse for a written lock,
//     and a genuinely orphaned EMPTY lock. A young empty lock is NOT stale — it
//     is a live writer mid-creation, judged by file mtime, not content.
function isStale(lock, staleMs, now) {
  if (lock.gone) return true;
  if (lock.unparsed) return (now - lock.mtimeMs) > staleMs;
  if (!isProcessAlive(lock.pid)) return true;
  return (now - lock.ts) > staleMs;
}

/**
 * Run `fn` while holding an exclusive lock on `targetPath`.
 *
 * @param {string}   targetPath  the state file being guarded (the lock is `<targetPath>.lock`)
 * @param {Function} fn          the read-modify-write cycle to run under the lock
 * @param {object}   [opts]      { staleMs, maxWaitMs, backoffMs }
 * @returns {*} whatever `fn` returns
 * @throws  Error with `.code === 'ELOCKED'` if a live holder does not release within maxWaitMs
 */
function withFileLock(targetPath, fn, opts = {}) {
  const staleMs   = opts.staleMs   ?? DEFAULTS.staleMs;
  const maxWaitMs = opts.maxWaitMs ?? DEFAULTS.maxWaitMs;
  const backoffMs = opts.backoffMs ?? DEFAULTS.backoffMs;

  const lockPath = targetPath + '.lock';
  const nonce    = `${process.pid}.${crypto.randomBytes(6).toString('hex')}`;
  const start    = Date.now();

  // ── Acquire ──────────────────────────────────────────────────────────────
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);   // O_EXCL — atomic create-if-absent
      try { fs.writeSync(fd, `${nonce}\n${Date.now()}\n`); }
      finally { fs.closeSync(fd); }
      break;                                            // acquired
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;             // unexpected fs error — surface it

      const lock = readLock(lockPath);
      if (isStale(lock, staleMs, Date.now())) {
        if (lock.gone) continue;                         // vanished → just retry the O_EXCL create
        // Steal: re-verify it is still the SAME lock we judged stale before
        // unlinking, so we never evict a fresh lock a peer created in between
        // (matched on nonce for a written lock, on identity+mtime for an empty one).
        const cur = readLock(lockPath);
        const same = (lock.nonce && cur.nonce === lock.nonce)
          || (lock.unparsed && cur.unparsed && cur.mtimeMs === lock.mtimeMs);
        if (same) {
          try { fs.unlinkSync(lockPath); } catch { /* already gone */ }
        }
        continue;                                        // retry acquisition immediately
      }

      // Live holder — bounded wait, then refuse rather than steal or deadlock.
      if (Date.now() - start >= maxWaitMs) {
        const e = new Error(
          `Could not acquire lock on ${path.basename(targetPath)} within ${maxWaitMs}ms — ` +
          `another scd process is writing it. Retry in a moment.`
        );
        e.code = 'ELOCKED';
        throw e;
      }
      sleepSync(backoffMs);
    }
  }

  // ── Critical section ─────────────────────────────────────────────────────
  try {
    return fn();
  } finally {
    // Release only if the lock still bears OUR nonce. If we overran staleMs and a
    // peer reclaimed it, the lock is now theirs — never unlink someone else's lock.
    const held = readLock(lockPath);
    if (held && held.nonce === nonce) {
      try { fs.unlinkSync(lockPath); } catch { /* already gone */ }
    }
  }
}

module.exports = { withFileLock, DEFAULTS };
