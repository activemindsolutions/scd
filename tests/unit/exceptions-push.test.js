/**
 * exceptions-push.test.js
 * Unit tests for the exceptions push tracker + pushPendingExceptions
 * acknowledged delivery path (fix/exception-push-ack).
 *
 * Run: npm test  (or: node --test tests/unit/exceptions-push.test.js)
 *
 * HTTP mocking: a real local http.Server on 127.0.0.1:0 returns a configurable
 * response per scenario. No new test dependencies — pure node:http.
 *
 * Config isolation: each test uses a unique repoRoot under os.tmpdir() and a
 * unique repoId fingerprint. The scd global store (~/.scd/repos/{id}/) is
 * cleaned up afterwards so test runs don't accumulate state.
 *
 * centralUrl + token are set via the global-config singleton; since the
 * configure-helper uses ~/.scd/config (a real file), each test snapshots and
 * restores any pre-existing values around the assertion window.
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
const tracker = require(path.join(root, 'lib/exceptions-push-tracker'));
const { pushPendingExceptions } = require(path.join(root, 'lib/exception-manager'));
const { exceptionsPushPathReadOnly, storeDir } = require(path.join(root, 'lib/store'));
const { writeExceptions, buildExceptionRecord } = require(path.join(root, 'lib/exceptions-store'));
const globalConfig = require(path.join(root, 'lib/global-config'));

// ── HTTP mock ──────────────────────────────────────────────────────────────

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const json = body ? JSON.parse(body) : {};
          handler(req, res, json);
        } catch (err) {
          res.statusCode = 500;
          res.end(String(err.message));
        }
      });
    });
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise(r => srv.close(r)) });
    });
  });
}

// ── Repo setup ─────────────────────────────────────────────────────────────

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-excpush-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(repoRoot) {
  try {
    const sd = storeDir(repoRoot);
    fs.rmSync(sd, { recursive: true, force: true });
  } catch {}
  try { fs.rmSync(repoRoot, { recursive: true, force: true }); } catch {}
}

// Seed the machine-local store (Run 2 re-home) — pushPendingExceptions resolves
// the delivery payload from exceptions.jsonl, not config.yml.
function seedConfigWithException(repoRoot, exception) {
  writeExceptions(repoRoot, [buildExceptionRecord({
    id:         exception.id,
    type:       exception.type,
    status:     exception.status,
    rule:       exception.rule,
    file:       exception.file,
    line:       exception.line,
    line_hash:  exception.code_hash || undefined,
    reason:     exception.reason,
    created_at: '2026-06-05T00:00:00.000Z',
  })]);
}

// ── central-url snapshot helpers ───────────────────────────────────────────
//
// global-config writes to ~/.scd/config (real file). Snapshot any existing
// central_url so we leave the user's setup unchanged after the tests run.

let originalCentralUrl, originalCentralToken;
before(() => {
  originalCentralUrl   = globalConfig.getCentralUrl();
  originalCentralToken = globalConfig.getCentralToken();
});
after(() => {
  if (originalCentralUrl)   globalConfig.setCentralUrl(originalCentralUrl);
  else                      globalConfig.removeCentralUrl();
  if (originalCentralToken) globalConfig.setCentralToken(originalCentralToken);
  else                      { try { globalConfig.remove('CENTRAL_TOKEN'); } catch {} }
});

// ── Test 1 — tracker write semantics by mode ───────────────────────────────

describe('exceptions push tracker', () => {

  test('1. markPending writes a record with exception_id + queued_at', () => {
    const r = mkTempRepo();
    try {
      tracker.markPending(r, 'exc-test-1');
      const list = tracker.loadPending(r);
      assert.equal(list.length, 1);
      assert.equal(list[0].exception_id, 'exc-test-1');
      assert.ok(list[0].queued_at);
      assert.match(list[0].queued_at, /^20\d\d-/);
    } finally { cleanup(r); }
  });

  test('1b. markPending is idempotent — same id never duplicates', () => {
    const r = mkTempRepo();
    try {
      tracker.markPending(r, 'exc-dup');
      tracker.markPending(r, 'exc-dup');
      assert.equal(tracker.pendingCount(r), 1);
    } finally { cleanup(r); }
  });

  test('1c. queued_at survives across retries — only set at first markPending', async () => {
    const r = mkTempRepo();
    try {
      tracker.markPending(r, 'exc-age');
      const first = tracker.loadPending(r)[0].queued_at;
      await new Promise(res => setTimeout(res, 10));
      tracker.markPending(r, 'exc-age');
      const second = tracker.loadPending(r)[0].queued_at;
      assert.equal(second, first, 'queued_at must NOT be rewritten on retry');
    } finally { cleanup(r); }
  });

  test('corrupt lines: load skips with single [WARN], valid lines preserved', () => {
    const r = mkTempRepo();
    try {
      // Seed: valid + corrupt + valid
      fs.mkdirSync(storeDir(r), { recursive: true });
      const target = exceptionsPushPathReadOnly(r);
      fs.writeFileSync(target,
        '{"exception_id":"exc-1","queued_at":"2026-06-05T10:00:00Z"}\n' +
        '{not valid json\n' +
        '{"exception_id":"exc-2","queued_at":"2026-06-05T11:00:00Z"}\n',
        { mode: 0o600 }
      );

      const originalWrite = process.stderr.write.bind(process.stderr);
      const captured = [];
      process.stderr.write = (chunk) => { captured.push(String(chunk)); return true; };

      let list;
      try { list = tracker.loadPending(r); }
      finally { process.stderr.write = originalWrite; }

      assert.equal(list.length, 2, 'valid lines preserved');
      const warnLines = captured.filter(c => c.includes('[WARN]') && c.includes('corrupt'));
      assert.ok(warnLines.length >= 1, 'one WARN line emitted');
    } finally { cleanup(r); }
  });

  test('oldestQueuedAt returns lexicographically earliest ISO timestamp', () => {
    const r = mkTempRepo();
    try {
      fs.mkdirSync(storeDir(r), { recursive: true });
      const target = exceptionsPushPathReadOnly(r);
      fs.writeFileSync(target,
        '{"exception_id":"exc-late","queued_at":"2026-06-05T20:00:00Z"}\n' +
        '{"exception_id":"exc-early","queued_at":"2026-06-05T08:00:00Z"}\n' +
        '{"exception_id":"exc-mid","queued_at":"2026-06-05T12:00:00Z"}\n',
        { mode: 0o600 }
      );
      assert.equal(tracker.oldestQueuedAt(r), '2026-06-05T08:00:00Z');
    } finally { cleanup(r); }
  });

});

// ── pushPendingExceptions integration tests ────────────────────────────────

describe('pushPendingExceptions', () => {

  test('2. response { inserted: 0, duplicate: 1 } → exception marked delivered', async () => {
    const mock = await startMockServer((req, res, body) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: body.exceptions.length, inserted: 0, duplicate: 1, invalid: 0 }));
    });
    const r = mkTempRepo();
    try {
      globalConfig.setCentralUrl(mock.url);
      globalConfig.setCentralToken('test-token');

      seedConfigWithException(r, {
        id: 'exc-dup-ok', type: 'exception', status: 'pending',
        rule: 'RULE-1', file: 'src/a.js', line: 5,
        code_hash: 'abcdef0123456789' + 'abcdef0123456789',
        reason: 'because',
      });
      tracker.markPending(r, 'exc-dup-ok');

      const result = await pushPendingExceptions(r);

      assert.equal(result.sent, 1);
      assert.equal(result.delivered, 1, 'duplicate counts as delivered');
      assert.equal(result.remaining, 0);
      assert.ok(result.deliveredIds.has('exc-dup-ok'), 'deliveredIds carries the id');
      assert.equal(tracker.pendingCount(r), 0);
    } finally { await mock.close(); cleanup(r); }
  });

  test('3. response missing duplicate/invalid → treated as 0 (old-server compat)', async () => {
    const mock = await startMockServer((req, res, body) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      // Old server: only { received, inserted }
      res.end(JSON.stringify({ received: body.exceptions.length, inserted: 1 }));
    });
    const r = mkTempRepo();
    try {
      globalConfig.setCentralUrl(mock.url);
      globalConfig.setCentralToken('test-token');

      seedConfigWithException(r, {
        id: 'exc-old', type: 'exception', status: 'pending',
        rule: 'RULE-OLD', file: 'src/old.js', line: 1,
        code_hash: '1111222233334444' + '1111222233334444',
        reason: 'old server compat',
      });
      tracker.markPending(r, 'exc-old');

      const result = await pushPendingExceptions(r);

      assert.equal(result.delivered, 1, 'inserted=1 alone reaches the threshold');
      assert.ok(result.deliveredIds.has('exc-old'));
      assert.equal(tracker.pendingCount(r), 0);
    } finally { await mock.close(); cleanup(r); }
  });

  test('4. network failure → tracker stays, no throw, deliveredIds empty', async () => {
    const r = mkTempRepo();
    try {
      // Point at a port nothing is listening on
      globalConfig.setCentralUrl('http://127.0.0.1:1');
      globalConfig.setCentralToken('test-token');

      seedConfigWithException(r, {
        id: 'exc-netfail', type: 'exception', status: 'pending',
        rule: 'RULE-X', file: 'src/n.js', line: 9,
        code_hash: 'deadbeefcafef00d' + 'deadbeefcafef00d',
        reason: 'expect failure',
      });
      tracker.markPending(r, 'exc-netfail');

      const result = await pushPendingExceptions(r);
      assert.ok(result.error, 'error field populated');
      assert.equal(result.deliveredIds.size, 0);
      assert.equal(tracker.pendingCount(r), 1, 'tracker preserved for next retry');
    } finally { cleanup(r); }
  });

  test('5. invalid > 0 → tracker stays + [WARN] emitted, deliveredIds empty', async () => {
    const mock = await startMockServer((req, res, body) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: body.exceptions.length, inserted: 0, duplicate: 0, invalid: 1 }));
    });
    const r = mkTempRepo();
    try {
      globalConfig.setCentralUrl(mock.url);
      globalConfig.setCentralToken('test-token');

      seedConfigWithException(r, {
        id: 'exc-invalid', type: 'exception', status: 'pending',
        rule: 'RULE-INV', file: 'src/i.js', line: 2,
        code_hash: 'feedbeeffeedbeef' + 'feedbeeffeedbeef',
        reason: 'should reject',
      });
      tracker.markPending(r, 'exc-invalid');

      const originalWrite = process.stderr.write.bind(process.stderr);
      const captured = [];
      process.stderr.write = (chunk) => { captured.push(String(chunk)); return true; };

      let result;
      try { result = await pushPendingExceptions(r); }
      finally { process.stderr.write = originalWrite; }

      assert.equal(result.deliveredIds.size, 0, 'nothing delivered when invalid > 0');
      assert.equal(tracker.pendingCount(r), 1, 'tracker preserved (contract bug, surface loudly)');
      const warns = captured.filter(c => c.includes('[WARN]') && c.includes('invalid'));
      assert.ok(warns.length >= 1, 'WARN emitted to surface contract mismatch');
    } finally { await mock.close(); cleanup(r); }
  });

  test('orphan in tracker (id not in store) → silently dropped', async () => {
    const mock = await startMockServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ received: 0, inserted: 0, duplicate: 0, invalid: 0 }));
    });
    const r = mkTempRepo();
    try {
      globalConfig.setCentralUrl(mock.url);
      globalConfig.setCentralToken('test-token');

      // Tracker has an id but the store does not (user deleted the exception)
      writeExceptions(r, []);
      tracker.markPending(r, 'exc-orphan');

      const result = await pushPendingExceptions(r);

      assert.equal(result.orphaned, 1, 'orphan was detected');
      assert.equal(result.sent, 0, 'nothing actually sent — batch was empty');
      assert.equal(tracker.pendingCount(r), 0, 'orphan dropped from tracker');
    } finally { await mock.close(); cleanup(r); }
  });

  test('no centralUrl → returns empty result without touching tracker', async () => {
    const r = mkTempRepo();
    try {
      globalConfig.removeCentralUrl();
      tracker.markPending(r, 'exc-standalone');
      // Standalone shouldn't have queued this, but defensive: the push path
      // must short-circuit on missing centralUrl regardless.
      const result = await pushPendingExceptions(r);
      assert.equal(result.sent, 0);
      assert.equal(result.delivered, 0);
      assert.equal(result.deliveredIds.size, 0);
      assert.equal(tracker.pendingCount(r), 1, 'tracker untouched');
    } finally { cleanup(r); }
  });

});
