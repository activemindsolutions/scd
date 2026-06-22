/**
 * jsonl-atomic.js
 * Shared atomic JSONL writer for the per-repo stores under ~/.scd/repos/{id}/.
 *
 * One routine, two callers (findings-store.js, exceptions-store.js): one storage
 * philosophy for one state model, not two. Extracted verbatim from the original
 * findings-store writer — same crash-safety (tmp → fsync → rename) and the same
 * 0o600 file mode.
 *
 * Contract:
 *   - The target directory MUST already exist. Callers resolve `targetPath` via the
 *     store's write-oriented path helpers (findingsPath / exceptionsPath), which
 *     create the repo store dir at 0o700 as a side effect of path resolution.
 *   - An empty record set still writes an empty file — keeps the invariant that the
 *     store exists after any successful write.
 */

'use strict';

const fs     = require('fs');
const crypto = require('crypto');

function writeJsonlAtomic(targetPath, records) {
  // Per-writer unique tmp name: a fixed `.tmp` lets two concurrent writers
  // (e.g. two same-repo scans) clobber each other's tmp before rename. Unique
  // tmp + atomic rename keeps each write self-consistent. (The remaining
  // read-modify-write lost-update is the separate write-lock round.)
  const tmp = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;

  const body    = records.map(r => JSON.stringify(r)).join('\n');
  const content = records.length > 0 ? body + '\n' : '';

  // Open tmp with mode 0o600 (file creation only — chmod after rename is defensive)
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    if (content.length > 0) fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tmp, targetPath);
  // Defensive: rename preserves source mode; chmod ensures invariant on edge platforms.
  try { fs.chmodSync(targetPath, 0o600); } catch { /* best-effort */ }
}

module.exports = { writeJsonlAtomic };
