'use strict';

/**
 * #239 (CLI) — scope-sync.pushScope sends the repo's scope RULES (not a resolved
 * file list) to the server and reports the reconcile counts. HTTP mocked with a
 * real local server that captures the request body.
 *
 * HOME is isolated to a temp dir so ~/.scd (global scope + central config) is clean
 * and the developer's real setup is never read or written.
 *
 * Run: node --test tests/unit/scope-sync.test.js
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const http   = require('http');

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-scopesync-home-'));
process.env.HOME = HOME;

const root = path.resolve(__dirname, '../..');
const { pushScope }   = require(path.join(root, 'lib/scope-sync'));
const store           = require(path.join(root, 'lib/store'));
const globalConfig    = require(path.join(root, 'lib/global-config'));
const { appendToScope, buildFileEntry, buildRuleEntry } = require(path.join(root, 'lib/commands/scope'));

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', c => { body += c; });
      req.on('end', () => { try { handler(req, res, body ? JSON.parse(body) : {}); } catch (e) { res.statusCode = 500; res.end(String(e.message)); } });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise(r => srv.close(r)) }));
  });
}

let counter = 0;
function mkTempRepo() {
  const dir = path.join(os.tmpdir(), `scd-scopesync-repo-${process.pid}-${counter++}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

after(() => { try { fs.rmSync(HOME, { recursive: true, force: true }); } catch {} });

test('pushScope sends scope rules with audit fields and reports reconcile counts', async () => {
  const repo = mkTempRepo();
  let captured = null;
  const srv = await startMockServer((req, res, json) => {
    captured = { path: req.url, body: json };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true, scoped: 2, unscoped: 1 }));
  });
  try {
    globalConfig.setCentralUrl(srv.url);
    globalConfig.setCentralToken('scd-testtoken');

    const scopeFile = store.scopePath(repo);
    appendToScope(scopeFile, 'file_excludes', buildFileEntry('docs/analysis/', 'sample vulns', 'fp-test', '2026-07-06T00:00:00.000Z'));
    appendToScope(scopeFile, 'rule_excludes', buildRuleEntry('INFRA-001', null, 'cloud-managed', 'fp-test', '2026-07-06T00:00:00.000Z'));

    const r = await pushScope(repo);

    assert.equal(r.sent, true);
    assert.equal(r.scoped, 2);
    assert.equal(r.unscoped, 1);
    assert.ok(captured, 'server received the push');
    assert.match(captured.path, /\/api\/v1\/repos\/.+\/scope$/, 'posted to the repo scope endpoint');
    assert.equal(captured.body.file_excludes[0].pattern, 'docs/analysis/');
    assert.equal(captured.body.file_excludes[0].reason, 'sample vulns', 'audit field carried');
    assert.equal(captured.body.file_excludes[0].added_by, 'fp-test');
    assert.equal(captured.body.rule_excludes[0].rule, 'INFRA-001');
  } finally {
    await srv.close();
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('standalone (no central url) is a quiet no-op', async () => {
  const repo = mkTempRepo();
  try {
    globalConfig.removeCentralUrl();
    const r = await pushScope(repo);
    assert.equal(r.sent, false);
    assert.equal(r.scoped, 0);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});
