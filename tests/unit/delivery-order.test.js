/**
 * delivery-order.test.js
 * fix(delivery-order): per server contact, the events queue flush completes
 * BEFORE the exception tracker push. Events register the repo (and findings
 * context) server-side that exceptions FK-reference; pushing an exception
 * first yields a first-contact 500 (FOREIGN KEY constraint failed).
 *
 * These tests assert the transport POSTs /events/batch before /exceptions/batch
 * at every site where both happen in one contact: scan flush (tryFlush),
 * scd sync, scd doctor, and accept-time (addException). They drive the real
 * code paths, which read the central URL / repo root from process-global
 * modules — so this lives in its OWN file (node runs each test file in a
 * separate process) to keep that global patching isolated from other suites.
 *
 * Run: npm test  (or: node --test tests/unit/delivery-order.test.js)
 */

'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const http   = require('http');
const crypto = require('crypto');

const root      = path.resolve(__dirname, '../..');
const em        = require(path.join(root, 'lib/exception-manager'));
const store     = require(path.join(root, 'lib/store'));
const pushQueue = require(path.join(root, 'lib/push-queue'));
const tracker   = require(path.join(root, 'lib/exceptions-push-tracker'));
const gconfig   = require(path.join(root, 'lib/global-config'));
const config    = require(path.join(root, 'lib/config'));
const { storeDir } = store;

// ── helpers ──────────────────────────────────────────────────────────────────

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-delorder-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(repoRoot) {
  try { fs.rmSync(storeDir(repoRoot), { recursive: true, force: true }); } catch {}
  try { fs.rmSync(repoRoot, { recursive: true, force: true }); } catch {}
}

function seedException(repoRoot, ex) {
  const yaml =
`# scd test config
trust_level: balanced

exceptions:
  - id: "${ex.id}"
    type: "exception"
    status: "pending"
    rule: "${ex.rule}"
    file: "${ex.file}"
    line: ${ex.line}
    line_hash: "${ex.code_hash}"
    reason: "because"
    created_date: "2026-06-06"
`;
  fs.mkdirSync(storeDir(repoRoot), { recursive: true });
  fs.writeFileSync(path.join(storeDir(repoRoot), 'config.yml'), yaml, 'utf8');
}

function seedPendingExc(r, excId = 'exc-ord') {
  seedException(r, { id: excId, rule: 'RULE-1', file: 'src/a.js', line: 5,
    code_hash: 'abcdef0123456789abcdef0123456789' });
  tracker.markPending(r, excId);
}

function seedQueue() {
  const entry = {
    id:          `t-${Date.now()}-${counter++}`,
    ts:          new Date().toISOString(),
    attempts:    0,
    lastAttempt: null,
    event:       { type: 'scan_completed', ts: new Date().toISOString() },
  };
  fs.mkdirSync(path.dirname(pushQueue.QUEUE_PATH), { recursive: true });
  fs.writeFileSync(pushQueue.QUEUE_PATH, JSON.stringify(entry) + '\n', 'utf8');
}

// Silence the command's noisy output. IMPORTANT: suppress the console.*
// methods (what the commands use), NOT process.stdout.write — node:test's TAP
// reporter writes results via process.stdout.write, and muting it across an
// async boundary swallows other tests' results (only the last survives).
// stderr is safe to mute (TAP is on stdout).
async function captureAsync(fn) {
  const methods = ['log', 'error', 'warn', 'info', 'debug'];
  const orig = {};
  for (const m of methods) { orig[m] = console[m]; console[m] = () => {}; }
  const se = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  try { return await fn(); }
  finally {
    for (const m of methods) console[m] = orig[m];
    process.stderr.write = se;
  }
}

function patch(mod, name, fn) {
  const orig = mod[name];
  mod[name] = fn;
  return () => { mod[name] = orig; };
}

function startMockServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => handler(req, res));
    });
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise(r => srv.close(r)) });
    });
  });
}

// Mock that handles both batch endpoints + the pull GETs, recording the order
// of request URLs. opts.eventsFail → /events/batch returns 500.
async function startOrderMock(opts = {}) {
  const order = [];
  const mock = await startMockServer((req, res) => {
    const u = req.url || '';
    order.push(u);
    res.setHeader('Content-Type', 'application/json');
    if (u.includes('/events/batch')) {
      if (opts.eventsFail) { res.statusCode = 500; res.end(JSON.stringify({ error: 'boom' })); return; }
      res.statusCode = 200;
      res.end(JSON.stringify({ received: 1, inserted: 1, skipped: 0, sync_exceptions: [] }));
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

function assertEventsBeforeExceptions(order, msg) {
  const ie = order.findIndex(u => u.includes('/events/batch'));
  const ix = order.findIndex(u => u.includes('/exceptions/batch'));
  assert.ok(ie >= 0, `${msg}: /events/batch was POSTed`);
  assert.ok(ix >= 0, `${msg}: /exceptions/batch was POSTed`);
  assert.ok(ie < ix, `${msg}: events flushed before exception push`);
}

// Snapshot/restore the global push queue so the user's real queue is untouched.
let originalQueue;
before(() => {
  try { originalQueue = fs.existsSync(pushQueue.QUEUE_PATH)
    ? fs.readFileSync(pushQueue.QUEUE_PATH, 'utf8') : null; } catch { originalQueue = null; }
});
after(() => {
  try {
    if (originalQueue === null) { try { fs.unlinkSync(pushQueue.QUEUE_PATH); } catch {} }
    else fs.writeFileSync(pushQueue.QUEUE_PATH, originalQueue, 'utf8');
  } catch {}
});

// ── tests ────────────────────────────────────────────────────────────────────

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
      seedQueue();
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
      seedQueue();
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
      seedQueue();
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
      seedQueue();
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
      seedQueue();
      await captureAsync(() => require(path.join(root, 'lib/cli-helpers')).tryFlush({}));
      assertEventsBeforeExceptions(mock.order, 'flush failure');
    } finally { un.forEach(f => f()); await mock.close(); cleanup(r); }
  });

});
