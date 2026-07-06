'use strict';

/**
 * #235 Phase 1 (CLI) — reassertApprovedExceptions re-sends the exceptions the CLI
 * holds as APPROVED, tagged client_status:'approved', and reports the server's
 * `reconciled` outcomes. HTTP is mocked with a real local server that captures the
 * request body (mirrors exceptions-push.test.js — no new test dependencies).
 *
 * Run: node --test tests/unit/exception-reassert.test.js
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const http   = require('http');
const crypto = require('crypto');

const root = path.resolve(__dirname, '../..');
const { reassertApprovedExceptions } = require(path.join(root, 'lib/exception-manager'));
const { storeDir } = require(path.join(root, 'lib/store'));
const { writeExceptions, buildExceptionRecord } = require(path.join(root, 'lib/exceptions-store'));
const globalConfig = require(path.join(root, 'lib/global-config'));

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', c => { body += c; });
      req.on('end', () => {
        try { handler(req, res, body ? JSON.parse(body) : {}); }
        catch (err) { res.statusCode = 500; res.end(String(err.message)); }
      });
    });
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise(r => srv.close(r)) });
    });
  });
}

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-reassert-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function cleanup(repoRoot) {
  try { fs.rmSync(storeDir(repoRoot), { recursive: true, force: true }); } catch {}
  try { fs.rmSync(repoRoot, { recursive: true, force: true }); } catch {}
}
const approved = (over) => buildExceptionRecord({
  id: over.id, type: 'exception', status: over.status || 'approved',
  rule: over.rule, file: over.file, line: over.line, line_hash: over.line_hash,
  reason: 'fp', created_at: '2026-07-06T00:00:00.000Z',
});

let origUrl, origToken;
before(() => { origUrl = globalConfig.getCentralUrl(); origToken = globalConfig.getCentralToken(); });
after(() => {
  if (origUrl)   globalConfig.setCentralUrl(origUrl);   else globalConfig.removeCentralUrl();
  if (origToken) globalConfig.setCentralToken(origToken); else { try { globalConfig.remove('CENTRAL_TOKEN'); } catch {} }
});

test('re-asserts approved+hashed exceptions with client_status; aggregates reconciled', async () => {
  const r = mkTempRepo();
  let captured = null;
  const srv = await startMockServer((req, res, json) => {
    captured = json;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({
      received: json.exceptions.length, inserted: 0, duplicate: 0, invalid: 0,
      reconciled: { healed: 1, converged: 1, pending: 0, reapproval_required: 1, conflict_rejected: 0 },
    }));
  });
  try {
    globalConfig.setCentralUrl(srv.url);
    globalConfig.setCentralToken('scd-testtoken');
    writeExceptions(r, [
      approved({ id: 'exc-a', rule: 'INJ-001', file: 'a.js', line: 5, line_hash: 'a'.repeat(32) }),
      approved({ id: 'exc-b', rule: 'XSS-001', file: 'b.js', line: 9, line_hash: 'b'.repeat(32) }),
      approved({ id: 'exc-p', status: 'pending', rule: 'SEC-001', file: 'p.js', line: 1, line_hash: 'c'.repeat(32) }),
      approved({ id: 'exc-n', rule: 'RCE-001', file: 'n.js', line: 2 }),   // approved but no code_hash → skipped
    ]);

    const rc = await reassertApprovedExceptions(r);

    assert.equal(rc.sent, 2, 'only approved exceptions carrying a code_hash are re-asserted (pending + hashless skipped)');
    assert.ok(captured, 'server received a batch');
    assert.equal(captured.exceptions.length, 2);
    for (const e of captured.exceptions) {
      assert.equal(e.client_status, 'approved', 'each carries the approved hint the server keys the reconcile path on');
      assert.ok(e.code_hash, 'code_hash travels so the server matches line-independently');
    }
    assert.deepEqual(captured.exceptions.map(e => e.rule_id).sort(), ['INJ-001', 'XSS-001']);

    assert.equal(rc.healed, 1);
    assert.equal(rc.converged, 1);
    assert.equal(rc.reapproval_required, 1);
    assert.equal(rc.conflict_rejected, 0);
  } finally {
    await srv.close();
    cleanup(r);
  }
});

test('standalone (no central url) is a quiet no-op', async () => {
  const r = mkTempRepo();
  try {
    globalConfig.removeCentralUrl();
    const rc = await reassertApprovedExceptions(r);
    assert.equal(rc.sent, 0, 'nothing re-asserted without a server');
  } finally { cleanup(r); }
});

test('older server without a reconciled field → no crash, zero counts', async () => {
  const r = mkTempRepo();
  const srv = await startMockServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ received: 1, inserted: 0, duplicate: 1, invalid: 0 }));   // no `reconciled`
  });
  try {
    globalConfig.setCentralUrl(srv.url);
    globalConfig.setCentralToken('scd-testtoken');
    writeExceptions(r, [approved({ id: 'exc-a', rule: 'INJ-001', file: 'a.js', line: 5, line_hash: 'a'.repeat(32) })]);
    const rc = await reassertApprovedExceptions(r);
    assert.equal(rc.sent, 1);
    assert.equal(rc.healed, 0);
    assert.equal(rc.reapproval_required, 0);
  } finally {
    await srv.close();
    cleanup(r);
  }
});
