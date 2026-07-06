/**
 * sync-exceptions-reception.test.js
 * Unit tests for Branch C — sync_exceptions reception via the events/batch
 * push-response channel (feature/sync-exceptions-reception).
 *
 * Run: npm test  (or: node --test tests/unit/sync-exceptions-reception.test.js)
 *
 * Two levels:
 *   - applyServerDecisions / applyFlushDecisions: classification, idempotence,
 *     high-water-mark, quiet UX (no network).
 *   - flush(): end-to-end against a local mock server — asserts the opaque ack
 *     token is echoed VERBATIM, decisions land in config.yml, and the staleness
 *     timestamp moves.
 *
 * Isolation mirrors exceptions-push.test.js: unique temp repo per test, the
 * scd global store (~/.scd/repos/{id}/) cleaned afterwards, and central-url +
 * the global push queue snapshotted/restored so the user's setup is untouched.
 */

'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const http   = require('http');
const crypto = require('crypto');

const root = path.resolve(__dirname, '../..');
const em        = require(path.join(root, 'lib/exception-manager'));
const store     = require(path.join(root, 'lib/store'));
const pushQueue = require(path.join(root, 'lib/push-queue'));
const tracker   = require(path.join(root, 'lib/exceptions-push-tracker'));
const gconfig   = require(path.join(root, 'lib/global-config'));
const config    = require(path.join(root, 'lib/config'));
const { storeDir, getSyncAckToken, readMeta, exceptionsPathReadOnly } = store;
const { loadExceptions, writeExceptions, buildExceptionRecord } = require(path.join(root, 'lib/exceptions-store'));

// The Branch C reception tests pass the central URL/token into flush() via
// arguments, never via ~/.scd/config. The delivery-order + sync-notice tests at
// the bottom DO patch the global-config/config module exports, but in-process
// (never touching ~/.scd/config), so there is no filesystem contention with
// exceptions-push.test.js (node runs test FILES in parallel).
//
// All flush()-driving tests live in THIS one file on purpose: flush() reads a
// single global queue (~/.scd/push-queue.jsonl). Splitting them across files
// would race two parallel processes on that one file; keeping them together
// runs them sequentially within one process.

// ── HTTP mock ──────────────────────────────────────────────────────────────

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        let json = {};
        try { json = body ? JSON.parse(body) : {}; } catch {}
        handler(req, res, json);
      });
    });
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise(r => srv.close(r)) });
    });
  });
}

// ── Repo + config helpers ────────────────────────────────────────────────────

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-syncrecv-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(repoRoot) {
  try { fs.rmSync(storeDir(repoRoot), { recursive: true, force: true }); } catch {}
  try { fs.rmSync(repoRoot, { recursive: true, force: true }); } catch {}
}

// Seed the machine-local store (Run 2 re-home) with one pending exception. The
// hash field is `line_hash` (the store's on-disk name); the decision record's
// code_hash matches it.
function seedException(repoRoot, ex) {
  writeExceptions(repoRoot, [buildExceptionRecord({
    id:         ex.id,
    type:       ex.type || 'exception',
    status:     ex.status || 'pending',
    rule:       ex.rule,
    file:       ex.file,
    line:       ex.line,
    line_hash:  ex.code_hash || undefined,
    reason:     ex.reason || 'because',
    created_at: '2026-06-06T00:00:00.000Z',
  })]);
}

// Seed the store with an explicit record array (multi-record / malformed cases).
function seedStore(repoRoot, records) {
  writeExceptions(repoRoot, records);
}

// Raw exceptions.jsonl text (for byte-identical assertions); '' if absent.
function readStoreRaw(repoRoot) {
  const p = exceptionsPathReadOnly(repoRoot);
  return fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
}

// A store record by id (or the first record when id omitted).
function storeRec(repoRoot, id) {
  const recs = loadExceptions(repoRoot);
  return id ? recs.find(r => r.id === id) : recs[0];
}

// A server decision record as delivered in the events/batch response.
function decision(over = {}) {
  return {
    rule_id:        'RULE-1',
    file_path:      'src/a.js',
    line:           5,
    code_hash:      'abcdef0123456789abcdef0123456789',
    type:           'exception',
    reason:         'because',
    status:         'approved',
    requested_by:   'dev',
    reviewed_by:    'lead',
    review_comment: null,
    created_at:     '2026-06-06T10:00:00.000Z',
    updated_at:     '2026-06-06T10:00:00.000Z',
    source:         'cli',
    finding_id:     null,
    ...over,
  };
}

// Capture stdout/stderr around a callback.
function capture(fn) {
  const out = [], err = [];
  const so = process.stdout.write.bind(process.stdout);
  const se = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c) => { out.push(String(c)); return true; };
  process.stderr.write = (c) => { err.push(String(c)); return true; };
  try { return { ret: fn(), out: out.join(''), err: err.join('') }; }
  finally { process.stdout.write = so; process.stderr.write = se; }
}

// ── global push-queue snapshot ───────────────────────────────────────────────
// flush() reads/writes the single global queue at ~/.scd/push-queue.jsonl.
// Snapshot and restore it so the user's real queue is untouched. (This file is
// the only writer of that queue in the suite, so within-file serial execution
// makes this safe.)

let originalQueue;
let restoreSetVer;
before(() => {
  try { originalQueue = fs.existsSync(pushQueue.QUEUE_PATH)
    ? fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8') : null; } catch { originalQueue = null; }
  // flush()/doctor() cache the server version via global-config.setServerVersionInfo,
  // which read-modify-writes the single global ~/.scd/config.yml. That races
  // (lost update) with exceptions-push.test.js's central_url writes when node
  // runs the two files in parallel. No test here asserts on version caching, so
  // neutralise the writer for this whole file — keeping ~/.scd/config.yml a file
  // that only exceptions-push.test.js ever writes (sole writer → no race).
  restoreSetVer = patch(gconfig, 'setServerVersionInfo', () => {});
});
after(() => {
  if (restoreSetVer) restoreSetVer();
  try {
    if (originalQueue === null) { try { fs.unlinkSync(pushQueue.QUEUE_PATH); } catch {} }
    else fs.writeFileSync(pushQueue.QUEUE_PATH, originalQueue, 'utf8');
  } catch {}
});

// Write a controlled single-event queue (so flush has exactly one event to send).
// repoId is stamped from the repo the test flushes for — flush groups by it and
// drops unattributed entries, so a seeded event must carry its repo's id.
function seedQueue(repoRoot) {
  const store = require(path.join(root, 'lib/store'));
  const entry = {
    id:          `t-${Date.now()}-${counter++}`,
    ts:          new Date().toISOString(),
    attempts:    0,
    lastAttempt: null,
    repoId:      repoRoot ? store.getRepoId(repoRoot) : null,
    event:       { type: 'scan_completed', ts: new Date().toISOString() },
  };
  fs.mkdirSync(path.dirname(pushQueue.QUEUE_PATH), { recursive: true });
  fs.writeFileSync(pushQueue.QUEUE_PATH, JSON.stringify(entry) + '\n', 'utf8');
}

// ── applyServerDecisions / applyFlushDecisions (no network) ──────────────────

describe('applyServerDecisions classification', () => {

  test('1. applied then redelivered → no-op, config byte-identical, token unchanged', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });

      // First delivery → applied
      const t1 = em.applyFlushDecisions(r, [decision()]);
      assert.equal(t1, '2026-06-06T10:00:00.000Z', 'token = record updated_at');
      assert.equal(getSyncAckToken(r), '2026-06-06T10:00:00.000Z');
      const storeAfterApply = readStoreRaw(r);
      assert.equal(storeRec(r, 'exc-1').status, 'approved');
      assert.equal(storeRec(r, 'exc-1').reviewed_by, 'lead');

      // Second identical delivery → no-op, silent, store unchanged
      const cap = capture(() => em.applyFlushDecisions(r, [decision()]));
      assert.equal(cap.out, '', 'no output on redelivery');
      assert.equal(cap.err, '', 'no warning on redelivery');
      assert.equal(readStoreRaw(r), storeAfterApply, 'exceptions.jsonl byte-identical');
      assert.equal(getSyncAckToken(r), '2026-06-06T10:00:00.000Z', 'token unchanged (same max)');
    } finally { cleanup(r); }
  });

  test('2. rejected → rejected notice rendered; redelivered rejected → silent', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-2', rule: 'RULE-2', file: 'src/b.js', line: 9,
        code_hash: '1111222233334444' + '1111222233334444' });

      const rej = decision({ rule_id: 'RULE-2', file_path: 'src/b.js', line: 9,
        code_hash: '11112222333344441111222233334444', status: 'rejected',
        review_comment: 'fix this', updated_at: '2026-06-06T11:00:00.000Z' });

      const cap1 = capture(() => em.applyFlushDecisions(r, [rej]));
      assert.match(cap1.out, /rejected exception/i, 'rejected notice shown on first apply');
      assert.match(cap1.out, /fix this/, 'review comment shown');
      assert.equal(storeRec(r, 'exc-2').status, 'rejected');

      const cap2 = capture(() => em.applyFlushDecisions(r, [rej]));
      assert.equal(cap2.out, '', 'redelivered rejected is silent');
    } finally { cleanup(r); }
  });

  test('4. unknown identity → skipped quietly, counted, high-water mark advances past it', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-known', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });

      const known   = decision({ updated_at: '2026-06-06T10:00:00.000Z' });
      const unknown = decision({ rule_id: 'RULE-NOPE', file_path: 'src/ghost.js', line: 1,
        updated_at: '2026-06-06T12:00:00.000Z' });

      const res = em.applyServerDecisions(r, [known, unknown]);
      assert.equal(res.applied, 1);
      assert.equal(res.unknown, 1);

      const cap = capture(() => em.applyFlushDecisions(r, [known, unknown]));
      // Mark must advance past the unknown (newest) record.
      assert.equal(getSyncAckToken(r), '2026-06-06T12:00:00.000Z', 'mark advances past unknown');
      assert.doesNotMatch(cap.out, /RULE-NOPE/, 'unknown stays silent');
    } finally { cleanup(r); }
  });

  test('5. malformed payload → one [WARN], token not advanced, no throw', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      // Pre-seed a valid token so we can prove it is NOT advanced.
      store.setSyncAckToken(r, '2026-06-06T09:00:00.000Z');

      // A garbage record has no usable updated_at: applyServerDecisions classifies
      // it as 'skipped' (unsupported status — see the unknown-status guard), but the
      // flush mark loop still parks because it cannot name an unusable updated_at.
      // Either way the token does not advance.
      const cap = capture(() => em.applyFlushDecisions(r, [{ garbage: true }]));
      assert.equal(getSyncAckToken(r), '2026-06-06T09:00:00.000Z', 'token not advanced');
      // Unusable updated_at parks the mark → no token, and the record is never thrown.
      assert.doesNotThrow(() => em.applyFlushDecisions(r, [{ garbage: true }]));
    } finally { cleanup(r); }
  });

  test('7. unsupported status (e.g. resolved) mid-batch → skipped, mark advances past it (no ack jam)', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });

      const rec1 = decision({ updated_at: '2026-06-06T10:00:00.000Z' });               // applies
      const rec2 = decision({ status: 'resolved', updated_at: '2026-06-06T10:30:00.000Z' }); // unsupported → skipped
      const rec3 = decision({ updated_at: '2026-06-06T11:00:00.000Z' });               // applies

      // Classification: the unsupported status is benign 'skipped', NOT 'failed'.
      const res = em.applyServerDecisions(r, [rec1, rec2, rec3]);
      assert.equal(res.skipped, 1, 'unsupported status counted as skipped');
      assert.equal(res.failed, 0, 'unsupported status must not be a failure');
      assert.equal(res.records[1].outcome, 'skipped');

      // The mark advances PAST the skipped record to the last applied one — the
      // skipped record (and everything after it) is NOT jammed/redelivered forever.
      const token = em.applyFlushDecisions(r, [rec1, rec2, rec3]);
      assert.equal(token, '2026-06-06T11:00:00.000Z', 'mark advances past the skipped record');
      assert.equal(getSyncAckToken(r), '2026-06-06T11:00:00.000Z');
    } finally { cleanup(r); }
  });

  test('7b. genuine apply failure mid-batch → mark parks at the prior success', () => {
    const r = mkTempRepo();
    try {
      // exc-1 (well-formed) matches rec1/rec3; exc-bad has NO status field, so a
      // decision targeting it by id is a genuine apply failure (not a skip).
      seedStore(r, [
        buildExceptionRecord({ id: 'exc-1', type: 'exception', status: 'pending',
          rule: 'RULE-1', file: 'src/a.js', line: 5,
          line_hash: 'abcdef0123456789abcdef0123456789', reason: 'ok',
          created_at: '2026-06-06T00:00:00.000Z' }),
        // Raw record with NO status field (malformed local state).
        { id: 'exc-bad', type: 'exception', rule: 'RULE-2', file: 'src/b.js', line: 9,
          line_hash: '00000000000000000000000000000000', reason: 'malformed - no status',
          created_at: '2026-06-06T00:00:00.000Z' },
      ]);

      const rec1 = decision({ updated_at: '2026-06-06T10:00:00.000Z' });               // applies (exc-1)
      const rec2 = decision({ status: 'approved', id: 'exc-bad', rule_id: 'RULE-2',     // genuine failure
        file_path: 'src/b.js', line: 9, code_hash: '00000000000000000000000000000000',
        updated_at: '2026-06-06T10:30:00.000Z' });
      const rec3 = decision({ updated_at: '2026-06-06T11:00:00.000Z' });               // would apply (exc-1)

      const res = em.applyServerDecisions(r, [rec1, rec2, rec3]);
      assert.equal(res.failed, 1, 'matched-but-malformed entry is a genuine failure');
      assert.equal(res.records[1].outcome, 'failed');

      const token = em.applyFlushDecisions(r, [rec1, rec2, rec3]);
      assert.equal(token, '2026-06-06T10:00:00.000Z', 'stopped before the failing record');
      assert.equal(getSyncAckToken(r), '2026-06-06T10:00:00.000Z');
    } finally { cleanup(r); }
  });

  test('8. opaque echo — token persisted byte-identical to server updated_at', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      // A value that is NOT what new Date().toISOString() would produce for now —
      // proves no clock round-trip happened.
      const weird = '2024-01-02T03:04:05.678Z';
      em.applyFlushDecisions(r, [decision({ updated_at: weird })]);
      assert.equal(getSyncAckToken(r), weird, 'stored verbatim, no Date round-trip');
    } finally { cleanup(r); }
  });

  test('11. canonical identity — decision hash H1 vs local hash H2 (same rule/file/line) → unknown', () => {
    const r = mkTempRepo();
    try {
      // Local entry carries H2 (the live code's hash after an edit).
      seedException(r, { id: 'exc-h2', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: '22222222222222222222222222222222' });
      // A decision for the OLD exception on the same rule/file/line (hash H1).
      const d = decision({ code_hash: '11111111111111111111111111111111' });

      const res = em.applyServerDecisions(r, [d]);
      assert.equal(res.unknown, 1, 'hash mismatch is unknown, NOT a loose match');
      assert.equal(res.applied, 0, 'the wrong record is never updated');
      assert.equal(storeRec(r, 'exc-h2').status, 'pending', 'local H2 entry untouched');

      // Unknown still advances the mark — redelivery can never make it applicable.
      const token = em.applyFlushDecisions(r, [d]);
      assert.equal(token, d.updated_at, 'unknown advances the high-water mark');
    } finally { cleanup(r); }
  });

  test('12. legacy fallback — hashless local entry matches on rule+file+line', () => {
    const r = mkTempRepo();
    try {
      // Pre-hash exception: no line_hash field at all.
      seedStore(r, [buildExceptionRecord({ id: 'exc-nohash', type: 'exception',
        status: 'pending', rule: 'RULE-1', file: 'src/a.js', line: 5, reason: 'legacy',
        created_at: '2026-06-06T00:00:00.000Z' })]);

      const res = em.applyServerDecisions(r, [decision()]);
      assert.equal(res.applied, 1, 'hashless entry matches via the legacy rule+file+line fallback');
      assert.equal(storeRec(r, 'exc-nohash').status, 'approved');
    } finally { cleanup(r); }
  });

});

// ── flush() end-to-end ───────────────────────────────────────────────────────

describe('flush() push-response channel', () => {

  test('decisions in flush response → applied; staleness timestamp set', async () => {
    let captured = null;
    const mock = await startMockServer((req, res, body) => {
      captured = body;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        received: 1, inserted: 1, skipped: 0,
        server_version: '1.5.0', min_cli_version: '1.0.0',
        sync_exceptions: [decision()],
      }));
    });
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      seedQueue(r);

      const status = await pushQueue.flush(mock.url, { repoRoot: r, token: 'test-token' });
      assert.equal(status, 'sent');
      assert.equal(storeRec(r, 'exc-1').status, 'approved', 'decision applied to store');
      assert.equal(getSyncAckToken(r), '2026-06-06T10:00:00.000Z', 'token persisted');
      assert.ok(readMeta(r).lastSynced, 'staleness timestamp set by flush');
    } finally { await mock.close(); cleanup(r); }
  });

  test('3. sync_exceptions absent (old server) → no-op, no warning', async () => {
    const mock = await startMockServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, server_version: '1.4.0' }));
    });
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      seedQueue(r);

      const status = await pushQueue.flush(mock.url, { repoRoot: r, token: 'test-token' });
      assert.equal(status, 'sent');
      assert.equal(storeRec(r, 'exc-1').status, 'pending', 'no decision applied');
      assert.equal(getSyncAckToken(r), null, 'no token written');
      assert.ok(!readMeta(r).lastSynced, 'no channel evidence → no staleness bump, nag survives');
    } finally { await mock.close(); cleanup(r); }
  });

  test('empty sync_exceptions array → staleness bumped (evidence), nothing applied, no token', async () => {
    const mock = await startMockServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, sync_exceptions: [] }));
    });
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      seedQueue(r);

      await pushQueue.flush(mock.url, { repoRoot: r, token: 'test-token' });
      assert.ok(readMeta(r).lastSynced, 'empty array IS evidence → staleness bumped');
      assert.equal(getSyncAckToken(r), null, 'nothing applied → no token');
      assert.equal(storeRec(r, 'exc-1').status, 'pending', 'store untouched');
    } finally { await mock.close(); cleanup(r); }
  });

  test('9. fresh repo (no token) → request omits sync_exceptions_acked_through', async () => {
    let captured = null;
    const mock = await startMockServer((req, res, body) => {
      captured = body;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, sync_exceptions: [] }));
    });
    const r = mkTempRepo();
    try {
      seedQueue(r);

      await pushQueue.flush(mock.url, { repoRoot: r, token: 'test-token' });
      assert.ok(captured && captured.meta, 'meta present');
      assert.equal('sync_exceptions_acked_through' in captured.meta, false,
        'field omitted when no token persisted');
    } finally { await mock.close(); cleanup(r); }
  });

  test('8b. token round-trips: persisted token echoed verbatim on next flush', async () => {
    let captured = null;
    const mock = await startMockServer((req, res, body) => {
      captured = body;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, sync_exceptions: [] }));
    });
    const r = mkTempRepo();
    try {
      store.setSyncAckToken(r, '2026-06-06T10:00:00.000Z');
      seedQueue(r);

      await pushQueue.flush(mock.url, { repoRoot: r, token: 'test-token' });
      assert.equal(captured.meta.sync_exceptions_acked_through, '2026-06-06T10:00:00.000Z',
        'token sent byte-identical');
    } finally { await mock.close(); cleanup(r); }
  });

  test('10. standalone (no central_url) → no token file, flush untouched', async () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      // No flush is triggered without a central URL in real usage; assert the
      // ack-token state simply never materialises.
      assert.equal(getSyncAckToken(r), null, 'no token for standalone repo');
      assert.equal('syncAckToken' in readMeta(r), false, 'meta carries no token field');
    } finally { cleanup(r); }
  });

});

// ── E1d: empty-queue contact still pulls decisions (always-POST) ─────────────

describe('flush() empty-queue pull (E1d)', () => {

  function emptyQueue() { fs.writeFileSync(pushQueue.QUEUE_PATH, '', 'utf8'); }

  test('empty queue + pullDecisions → POSTs empty batch and applies decisions; returns "empty"', async () => {
    let captured = null;
    const mock = await startMockServer((req, res, body) => {
      captured = body;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 0, inserted: 0, sync_exceptions: [decision()] }));
    });
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      emptyQueue();

      const status = await pushQueue.flush(mock.url, { repoRoot: r, pullDecisions: true });
      assert.equal(status, 'empty', 'queue state is empty even though a contact was made');
      assert.ok(captured && Array.isArray(captured.events) && captured.events.length === 0,
        'POSTed an empty events batch');
      assert.equal(storeRec(r, 'exc-1').status, 'approved', 'piggybacked decision applied');
    } finally { await mock.close(); cleanup(r); }
  });

  test('empty queue WITHOUT pullDecisions → no POST (unchanged)', async () => {
    let contacted = false;
    const mock = await startMockServer((req, res) => {
      contacted = true;
      res.statusCode = 200; res.end('{}');
    });
    const r = mkTempRepo();
    try {
      emptyQueue();
      const status = await pushQueue.flush(mock.url, { repoRoot: r });
      assert.equal(status, 'empty');
      assert.equal(contacted, false, 'no server contact without pullDecisions');
    } finally { await mock.close(); cleanup(r); }
  });

  test('unreachable on empty pull contact → "empty", no throw, nothing lost', async () => {
    const r = mkTempRepo();
    try {
      emptyQueue();
      let status;
      await assert.doesNotReject(async () => {
        status = await pushQueue.flush('http://127.0.0.1:1', { repoRoot: r, pullDecisions: true });
      });
      assert.equal(status, 'empty');
      assert.equal(fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8').trim(), '', 'queue still empty');
    } finally { cleanup(r); }
  });
});

// ── #67: a rejected token is surfaced, not silently retried into staleness ────

describe('flush() token rejection (#67)', () => {

  function seedOneEvent(repoRoot, attempts = 3) {
    fs.writeFileSync(pushQueue.QUEUE_PATH, JSON.stringify({
      id: 't-67', ts: new Date().toISOString(), attempts, lastAttempt: null,
      repoId: require(path.join(root, 'lib/store')).getRepoId(repoRoot),
      event: { type: 'scan_completed', ts: new Date().toISOString() },
    }) + '\n', 'utf8');
  }

  test('401/403 → "auth_failed", attempts NOT bumped, entry flagged + recovers on a valid token', async () => {
    let code = 403;
    const mock = await startMockServer((req, res) => {
      res.statusCode = code;
      res.end(code === 403 ? JSON.stringify({ error: 'Invalid token' })
                           : JSON.stringify({ received: 1, inserted: 1, sync_exceptions: [] }));
    });
    const r = mkTempRepo();
    try {
      seedOneEvent(r, 3);
      const status = await pushQueue.flush(mock.url, { repoRoot: r });
      assert.equal(status, 'auth_failed');

      const entry = JSON.parse(fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8').trim());
      assert.equal(entry.attempts, 3, 'a permanent auth failure must NOT bump attempts toward staleness');
      assert.equal(entry.lastError, 'auth');
      assert.equal(pushQueue.listEntries()[0].authBlocked, true, 'surfaced to scd queue');

      // Token fixed → the queue recovers (it was never aged out).
      code = 200;
      const status2 = await pushQueue.flush(mock.url, { repoRoot: r });
      assert.equal(status2, 'sent');
      assert.equal(fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8').trim(), '', 'delivered once token is valid');
    } finally { await mock.close(); cleanup(r); }
  });
});

// ── per-repo attribution (#237) ──────────────────────────────────────────────
// The global queue is shared by every repo. flush() must group by each event's
// enqueue-time repoId and send one batch per repo — never stamp one id from the
// flushing cwd. These live in THIS file (the queue's sole writer) so they never
// race the global queue with a second parallel test process.

describe('flush() per-repo attribution', () => {
  const store = require(path.join(root, 'lib/store'));

  // Write a multi-repo queue directly. Each spec: { repoId, type }. null repoId
  // models a legacy (pre-fix) entry with no attribution.
  function seedMulti(specs) {
    const lines = specs.map((s, i) => JSON.stringify({
      id:          `attr-${process.pid}-${counter++}-${i}`,
      ts:          new Date().toISOString(),
      attempts:    0,
      lastAttempt: null,
      repoId:      s.repoId || null,
      event:       { type: s.type || 'scan_completed', ts: new Date().toISOString() },
    }));
    fs.mkdirSync(path.dirname(pushQueue.QUEUE_PATH), { recursive: true });
    fs.writeFileSync(pushQueue.QUEUE_PATH, lines.length ? lines.join('\n') + '\n' : '', 'utf8');
  }

  test('each repo delivered under its OWN id, even when flushed from another repo', async () => {
    const batches = [];
    const mock = await startMockServer((req, res, json) => {
      batches.push(json);
      res.statusCode = 200; res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, sync_exceptions: [] }));
    });
    const repoA = mkTempRepo(), repoB = mkTempRepo(), repoC = mkTempRepo();
    const idA = store.getRepoId(repoA), idB = store.getRepoId(repoB), idC = store.getRepoId(repoC);
    try {
      seedMulti([
        { repoId: idA, type: 'findings_batch' },
        { repoId: idA, type: 'scan_completed' },
        { repoId: idB, type: 'findings_batch' },
      ]);
      // Flush from repo C — the pre-fix bug would have stamped C on everything.
      const status = await pushQueue.flush(mock.url, { repoRoot: repoC, token: 't' });
      assert.equal(status, 'sent');

      const byId = {};
      for (const b of batches) byId[b.meta.repoId] = (byId[b.meta.repoId] || []).concat(b.events.map(e => e.type));
      assert.deepEqual((byId[idA] || []).sort(), ['findings_batch', 'scan_completed'], "A's events under A");
      assert.deepEqual(byId[idB], ['findings_batch'], "B's events under B");
      assert.ok(!byId[idC], 'nothing delivered under the flushing repo C');
      assert.equal(fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8').trim(), '', 'queue drained after delivery');
    } finally { await mock.close(); cleanup(repoA); cleanup(repoB); cleanup(repoC); }
  });

  test('unattributed (legacy) entries are dropped, never misrouted', async () => {
    const batches = [];
    const mock = await startMockServer((req, res, json) => {
      batches.push(json);
      res.statusCode = 200; res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 1, sync_exceptions: [] }));
    });
    const repoA = mkTempRepo();
    const idA = store.getRepoId(repoA);
    try {
      seedMulti([
        { repoId: null, type: 'scan_completed' },   // legacy — must NOT be delivered
        { repoId: idA,  type: 'findings_batch' },
      ]);
      await pushQueue.flush(mock.url, { repoRoot: repoA, token: 't' });
      assert.equal(batches.length, 1, 'only the attributed repo is contacted');
      assert.equal(batches[0].meta.repoId, idA);
      assert.equal(batches[0].events.length, 1, 'legacy event never smuggled into another batch');
      assert.equal(fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8').trim(), '', 'legacy dropped + attributed sent');
    } finally { await mock.close(); cleanup(repoA); }
  });
});

// ── flush status notices (surface push failures at explicit commands) ────────

describe('flushStatusNotice', () => {
  test('server-side failures warn; success is quiet; unreachable is soft info', () => {
    // Quiet outcomes — never nag on a healthy or empty sync.
    for (const s of ['sent', 'empty', null, undefined, 'weird']) {
      assert.equal(pushQueue.flushStatusNotice(s), null, `${s} → quiet`);
    }
    // Server-side failures the user must see (the silent-500 gap).
    for (const s of ['error', 'auth_failed', 'license_invalid']) {
      const n = pushQueue.flushStatusNotice(s);
      assert.equal(n.level, 'warn', `${s} → warn`);
      assert.ok(n.message && typeof n.message === 'string', `${s} has a message`);
    }
    // Offline-first: an unreachable server is expected, surfaced softly.
    assert.equal(pushQueue.flushStatusNotice('unreachable').level, 'info');
  });
});

// ── pull path does not touch the ack token (Branch C contract) ───────────────

describe('pull/push channel separation', () => {

  test('6. applyServerDecisions (pull path) never writes the ack token', () => {
    const r = mkTempRepo();
    try {
      seedException(r, { id: 'exc-1', rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789' });
      // The pull command uses applyServerDecisions directly (no token side-effect).
      em.applyServerDecisions(r, [decision()]);
      assert.equal(getSyncAckToken(r), null, 'pull apply leaves the ack token untouched');
    } finally { cleanup(r); }
  });

});

// ── delivery order + sync-notice helpers ──────────────────────────────────────

// Silence command output. IMPORTANT: suppress console.* (what the commands print
// through), NOT process.stdout.write — node:test's TAP reporter writes results
// via process.stdout.write, and muting it across an async boundary swallows other
// tests' results (only the last survives). stderr is safe to mute (TAP is stdout).
async function captureAsync(fn) {
  const methods = ['log', 'error', 'warn', 'info', 'debug'];
  const orig = {};
  for (const m of methods) { orig[m] = console[m]; console[m] = () => {}; }
  const se = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  try { return await fn(); }
  finally { for (const m of methods) console[m] = orig[m]; process.stderr.write = se; }
}

// Record console.* output (returns it joined) WITHOUT touching process.stdout.write.
async function recordConsole(fn) {
  const out = [];
  const orig = { log: console.log, error: console.error, warn: console.warn };
  console.log   = (...a) => out.push(a.join(' '));
  console.error = (...a) => out.push(a.join(' '));
  console.warn  = (...a) => out.push(a.join(' '));
  try { await fn(); return out.join('\n'); }
  finally { Object.assign(console, orig); }
}

// Monkeypatch a module export for the duration of a test. Restored in finally.
function patch(mod, name, fn) {
  const orig = mod[name];
  mod[name] = fn;
  return () => { mod[name] = orig; };
}

// Mock handling both batch endpoints + the pull GETs, recording request order.
// opts.eventsFail → /events/batch 500; opts.approve → /events/batch carries an
// approval for the seeded exception in sync_exceptions.
async function startOrderMock(opts = {}) {
  const order = [];
  const mock = await startMockServer((req, res) => {
    const u = req.url || '';
    order.push(u);
    res.setHeader('Content-Type', 'application/json');
    if (u.includes('/events/batch')) {
      if (opts.eventsFail) { res.statusCode = 500; res.end(JSON.stringify({ error: 'boom' })); return; }
      const sync = opts.approve ? [{
        rule_id: 'RULE-1', file_path: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789abcdef0123456789', status: 'approved',
        reviewed_by: 'lead', review_comment: null,
        updated_at: '2026-06-06T10:00:00.000Z', finding_id: null,
      }] : [];
      res.statusCode = 200;
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, sync_exceptions: sync }));
    } else if (u.includes('/exceptions/batch')) {
      res.statusCode = 200;
      res.end(JSON.stringify({ received: 1, inserted: 1, duplicate: 0, invalid: 0 }));
    } else if (u.includes('/exceptions/approved')) {
      res.statusCode = 200;
      res.end(JSON.stringify({ exceptions: [] }));
    } else {
      res.statusCode = 200;
      res.end('{}');  // health etc.
    }
  });
  mock.order = order;
  return mock;
}

function seedPendingExc(r, excId = 'exc-ord') {
  seedException(r, { id: excId, rule: 'RULE-1', file: 'src/a.js', line: 5,
    code_hash: 'abcdef0123456789abcdef0123456789' });
  tracker.markPending(r, excId);
}

function seedStaleMeta(r) {
  // lastSynced 2h ago so the pre-flush sync notice exists ("synced 2h ago").
  fs.writeFileSync(path.join(storeDir(r), 'meta.json'),
    JSON.stringify({ lastSynced: new Date(Date.now() - 2 * 3600 * 1000).toISOString() }), 'utf8');
}

function assertEventsBeforeExceptions(order, msg) {
  const ie = order.findIndex(u => u.includes('/events/batch'));
  const ix = order.findIndex(u => u.includes('/exceptions/batch'));
  assert.ok(ie >= 0, `${msg}: /events/batch was POSTed`);
  assert.ok(ix >= 0, `${msg}: /exceptions/batch was POSTed`);
  assert.ok(ie < ix, `${msg}: events flushed before exception push`);
}

// ── delivery order: events queue flush BEFORE exception push ──────────────────
// fix(delivery-order): events register the repo server-side that exceptions
// FK-reference; pushing an exception first yields a first-contact 500. Asserts
// the transport POSTs /events/batch before /exceptions/batch at every site where
// both happen in one contact. These drive real command paths that read the
// central URL / repo root from process-global modules (patched per-test).

describe('delivery order — events before exception push', () => {

  test('scan flush (tryFlush): events/batch precedes exceptions/batch', async () => {
    const mock = await startOrderMock();
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedQueue(r);
      await captureAsync(() => require(path.join(root, 'lib/cli-helpers')).tryFlush({}));
      assertEventsBeforeExceptions(mock.order, 'scan flush');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('scd sync: events/batch precedes exceptions/batch', async () => {
    const mock = await startOrderMock();
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedQueue(r);
      const { Command } = require('commander');
      const program = new Command();
      program.exitOverride();
      require(path.join(root, 'lib/commands/sync')).register(program);
      await captureAsync(() => program.parseAsync(['node', 'scd', 'sync']));
      assertEventsBeforeExceptions(mock.order, 'scd sync');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('scd doctor: events/batch precedes exceptions/batch', async () => {
    const mock = await startOrderMock();
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedQueue(r);
      await captureAsync(() => require(path.join(root, 'lib/doctor')).doctor());
      assertEventsBeforeExceptions(mock.order, 'scd doctor');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('accept-time (addException): events flush precedes the creation push', async () => {
    const mock = await startOrderMock();
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
    ];
    try {
      storeDir(r);  // create the global store dir (normally done by a prior scan)
      fs.mkdirSync(path.join(r, 'src'), { recursive: true });
      fs.writeFileSync(path.join(r, 'src', 'a.js'), 'a\nb\nc\nd\nconst x = bad;\n');
      seedQueue(r);
      await captureAsync(() => em.addException(r,
        { rule: 'RULE-1', file: 'src/a.js', line: '5', reason: 'ordering test' }, 'exception'));
      assertEventsBeforeExceptions(mock.order, 'accept-time');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('flush failure does not suppress the exception push (order preserved)', async () => {
    const mock = await startOrderMock({ eventsFail: true });
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedQueue(r);
      await captureAsync(() => require(path.join(root, 'lib/cli-helpers')).tryFlush({}));
      assertEventsBeforeExceptions(mock.order, 'flush failure');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

});

// ── sync notice reflects post-flush state ─────────────────────────────────────
// The scan output renders getSyncNotice AFTER tryFlush, recomputed from current
// state, so a decision applied during the flush (e.g. an approval) doesn't leave
// a "pending approval" notice contradicting the flush's own "✓ approved" line.

describe('sync notice reflects post-flush state', () => {

  test('approval in flush response → "✓ approved" shown and NO pending notice', async () => {
    const mock = await startOrderMock({ approve: true });
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedStaleMeta(r);
      seedQueue(r);

      // Pre-flush the notice would have been shown (1 pending).
      assert.ok(em.getSyncNotice(r), 'pending notice exists before the flush');

      // Scan-tail order: flush first, THEN recompute the notice.
      const out = await recordConsole(() => require(path.join(root, 'lib/cli-helpers')).tryFlush({}));
      assert.match(out, /approved by server/, 'flush printed the approval line');
      assert.equal(em.getSyncNotice(r), null, 'recomputed notice is gone — exception no longer pending');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('failed flush → pending notice still shown (state unchanged)', async () => {
    const mock = await startOrderMock({ eventsFail: true });
    const r = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      seedPendingExc(r);
      seedStaleMeta(r);
      seedQueue(r);

      await recordConsole(() => require(path.join(root, 'lib/cli-helpers')).tryFlush({}));
      assert.ok(em.getSyncNotice(r), 'offline flush leaves the pending notice intact');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

});

// ── scd queue list / reset (push-queue recovery tooling) ─────────────────────
// These tests write the single global queue at pushQueue.QUEUE_PATH, which the
// file-level before/after snapshot+restore protects. They live HERE (not in a
// new file) on purpose: that snapshot makes THIS file the queue's sole writer in
// the suite — a second writer file would race two parallel processes on that one
// global path (see the header note). None of these drive a flush across files.

describe('scd queue list/reset', () => {
  const queueCmd  = require(path.join(root, 'lib/commands/queue'));
  const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

  // Write a controlled multi-entry queue. Each spec: { type, attempts, ageDays }.
  function writeQueue(specs, repoRoot) {
    const rid = repoRoot ? require(path.join(root, 'lib/store')).getRepoId(repoRoot) : null;
    const lines = specs.map((s, i) => JSON.stringify({
      id:          `q-${process.pid}-${counter++}-${i}`,
      ts:          new Date(Date.now() - (s.ageDays || 0) * 86400000).toISOString(),
      attempts:    s.attempts || 0,
      lastAttempt: s.attempts ? new Date().toISOString() : null,
      repoId:      rid,
      event:       { type: s.type || 'scan_completed', ts: new Date().toISOString() },
    }));
    fs.mkdirSync(path.dirname(pushQueue.QUEUE_PATH), { recursive: true });
    fs.writeFileSync(pushQueue.QUEUE_PATH, lines.length ? lines.join('\n') + '\n' : '', 'utf8');
  }

  test('1. list shows fresh + stale events with correct counts and the exception line', async () => {
    const r  = mkTempRepo();
    const un = [
      patch(gconfig, 'getCentralUrl', () => 'https://central.example:3000'),
      patch(config,  'getRepoRoot',   () => r),
    ];
    try {
      seedStaleMeta(r);                  // writes meta.json → repo is "known"
      tracker.markPending(r, 'exc-q1');  // one exception awaiting delivery
      writeQueue([
        { type: 'scan_completed', attempts: 0 },    // fresh
        { type: 'findings_batch', attempts: 10 },   // stale by attempts
      ]);
      const out = stripAnsi(await recordConsole(() => queueCmd.renderList({})));
      assert.match(out, /Events: 2 total/);
      assert.match(out, /1 deliverable/);
      assert.match(out, /1 stale/);
      assert.match(out, /findings_batch.*stale: attempts/);
      assert.match(out, /Exceptions awaiting delivery: 1/);
    } finally { un.forEach(f => f()); cleanup(r); }
  });

  test('2. list --stale shows only stale entries; a healthy queue prints the OK message', async () => {
    const un = [ patch(gconfig, 'getCentralUrl', () => 'https://central.example:3000') ];
    try {
      writeQueue([
        { type: 'scan_completed',    attempts: 0 },
        { type: 'findings_resolved', ageDays: 40 },   // stale by age
      ]);
      let out = stripAnsi(await recordConsole(() => queueCmd.renderList({ stale: true })));
      assert.match(out, /findings_resolved.*stale: age/);
      assert.doesNotMatch(out, /scan_completed/, 'fresh entry omitted in --stale view');

      writeQueue([{ type: 'scan_completed', attempts: 0 }]);   // all healthy
      out = stripAnsi(await recordConsole(() => queueCmd.renderList({ stale: true })));
      assert.match(out, /No stale entries — queue is healthy/);
    } finally { un.forEach(f => f()); }
  });

  test('3. reset zeroes attempts on all entries and a subsequent flush POSTs them', async () => {
    let received = null;
    const mock = await startMockServer((req, res, json) => {
      received = json;
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 200;
      res.end(JSON.stringify({ sync_exceptions: [] }));
    });
    const r  = mkTempRepo();   // unknown repo → reset's flush runs with repoRoot=null
    const un = [
      patch(gconfig, 'getCentralUrl',   () => mock.url),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      writeQueue([
        { type: 'scan_completed', attempts: 10 },   // stale
        { type: 'findings_batch', attempts: 10 },   // stale
      ], r);
      const out = stripAnsi(await recordConsole(() => queueCmd.runReset()));
      assert.match(out, /Reset 2 events \(2 were stale\)/);
      assert.equal(pushQueue.listEntries().length, 0, 'queue drained after successful delivery');
      assert.ok(received && Array.isArray(received.events), 'server received an events batch');
      const types = received.events.map(e => e.type).sort();
      assert.deepEqual(types, ['findings_batch', 'scan_completed'], 'previously-stale events delivered');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

  test('4. reset with an unreachable server keeps entries with attempts reset (no re-stale)', async () => {
    const r  = mkTempRepo();
    const un = [
      // Closed port → connection refused → transient failure, never bumps attempts.
      patch(gconfig, 'getCentralUrl',   () => 'http://127.0.0.1:1'),
      patch(gconfig, 'getCentralToken', () => 'test-token'),
      patch(config,  'getRepoRoot',     () => r),
    ];
    try {
      writeQueue([{ type: 'scan_completed', attempts: 10 }], r);   // stale
      const out = stripAnsi(await recordConsole(() => queueCmd.runReset()));
      assert.match(out, /Reset 1 event \(1 was stale\)/);
      assert.match(out, /Server unreachable/);
      const entries = pushQueue.listEntries();
      assert.equal(entries.length, 1, 'entry kept (not delivered)');
      assert.equal(entries[0].attempts, 0, 'attempts stayed reset — unreachable does not bump');
      assert.equal(entries[0].stale, false, 'no longer stale after reset');
    } finally { un.forEach(f => f()); cleanup(r); }
  });

  test('5. no central URL → list and reset print the not-configured message and exit 0', async () => {
    const un = [ patch(gconfig, 'getCentralUrl', () => null) ];
    try {
      const l = stripAnsi(await recordConsole(() => queueCmd.renderList({})));
      assert.match(l, /No central server configured/);
      const rOut = stripAnsi(await recordConsole(() => queueCmd.runReset()));
      assert.match(rOut, /No central server configured/);
    } finally { un.forEach(f => f()); }
  });

});
