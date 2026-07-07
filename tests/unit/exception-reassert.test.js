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

// Isolate HOME so ~/.scd (global config INCLUDING the developer's personal token)
// is a throwaway temp dir — never read or clobber the real config. MUST be set
// before requiring store / global-config, which resolve ~/.scd at module load.
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-reassert-home-'));
process.env.HOME = HOME;

const root = path.resolve(__dirname, '../..');
const { reassertApprovedExceptions } = require(path.join(root, 'lib/exception-manager'));
const { storeDir, scopePath } = require(path.join(root, 'lib/store'));
const { writeExceptions, buildExceptionRecord } = require(path.join(root, 'lib/exceptions-store'));
const { appendToScope, buildFileEntry } = require(path.join(root, 'lib/commands/scope'));
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

// No snapshot/restore of the real config — HOME is isolated, so setCentralUrl /
// setCentralToken below write only into the throwaway temp ~/.scd.
after(() => { try { fs.rmSync(HOME, { recursive: true, force: true }); } catch {} });

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
    // The re-assert now only pushes LIVE, in-scope exceptions — the files must exist.
    fs.writeFileSync(path.join(r, 'a.js'), '// x\n');
    fs.writeFileSync(path.join(r, 'b.js'), '// x\n');
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

test('skips exceptions whose file is scoped-out or gone; pushes only live in-scope', async () => {
  const r = mkTempRepo();
  let captured = null;
  const srv = await startMockServer((req, res, json) => {
    captured = json;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ reconciled: {} }));
  });
  try {
    globalConfig.setCentralUrl(srv.url);
    globalConfig.setCentralToken('scd-testtoken');

    // A live, in-scope file; a file that exists but is scope-excluded; a gone file.
    fs.writeFileSync(path.join(r, 'live.js'), '// x\n');
    fs.mkdirSync(path.join(r, 'tests'), { recursive: true });
    fs.writeFileSync(path.join(r, 'tests', 'scoped.js'), '// x\n');
    appendToScope(scopePath(r), 'file_excludes', buildFileEntry('tests/', 'test dir', 'fp-test', '2026-07-06T00:00:00.000Z'));

    writeExceptions(r, [
      approved({ id: 'exc-live',   rule: 'INJ-001', file: 'live.js',         line: 1, line_hash: 'a'.repeat(32) }),
      approved({ id: 'exc-scoped', rule: 'XSS-001', file: 'tests/scoped.js',  line: 1, line_hash: 'b'.repeat(32) }),
      approved({ id: 'exc-gone',   rule: 'RCE-001', file: 'gone.js',          line: 1, line_hash: 'c'.repeat(32) }),
    ]);

    const rc = await reassertApprovedExceptions(r);

    assert.equal(rc.sent, 1, 'only the live, in-scope exception is re-asserted');
    assert.equal(rc.skipped, 2, 'the scoped-out and the gone exception are skipped');
    assert.ok(captured, 'a batch was sent');
    assert.equal(captured.exceptions.length, 1);
    assert.equal(captured.exceptions[0].rule_id, 'INJ-001', 'the live in-scope one');
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
    fs.writeFileSync(path.join(r, 'a.js'), '// x\n');   // live file so it is re-asserted
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
