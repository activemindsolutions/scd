/**
 * findings-excepted-hint.test.js
 * E1g — `scd findings` surfaces excepted findings instead of hiding them silently:
 * a count hint in the default view (parity with the suppressed hint), and the
 * `--show-excepted` alias of `--excepted`.
 *
 * Run: node --test tests/unit/findings-excepted-hint.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const root = path.resolve(__dirname, '../..');
const config = require(path.join(root, 'lib/config'));
const store  = require(path.join(root, 'lib/store'));
const estore = require(path.join(root, 'lib/exceptions-store'));
const { makeCodeHash, makeFindingId } = require(path.join(root, 'lib/finding-identity'));
const { findingsAction } = require(path.join(root, 'lib/commands/findings'));

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-e1g-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function cleanup(r) {
  try { fs.rmSync(store.storeDir(r), { recursive: true, force: true }); } catch {}
  try { fs.rmSync(r, { recursive: true, force: true }); } catch {}
}

// One open finding that an exception will except, plus one plain open finding.
function seed(r) {
  store.storeDir(r);
  const snipA = 'const k = "AKIA_A";';
  const snipB = 'eval(x);';
  const rec = (rule, file, line, snip, sev) => ({
    finding_id: makeFindingId(rule, file, snip), rule_id: rule, file, line,
    code_hash: makeCodeHash(snip), status: 'open', severity: sev, base_severity: sev,
    snippet: snip, times_seen: 1,
    first_seen: '2026-06-20T00:00:00.000Z', last_seen: '2026-06-20T00:00:00.000Z',
  });
  fs.writeFileSync(store.findingsPath(r),
    JSON.stringify(rec('SECRET-008', 'src/a.js', 5, snipA, 'CRITICAL')) + '\n' +
    JSON.stringify(rec('GEN-1', 'src/b.js', 9, snipB, 'HIGH')) + '\n');
  estore.writeExceptions(r, [estore.buildExceptionRecord({
    id: 'exc-1', type: 'exception', status: 'approved', rule: 'SECRET-008',
    file: 'src/a.js', line: 5, line_hash: makeCodeHash(snipA), reason: 'ok',
    created_at: '2026-06-20T00:00:00.000Z',
  })]);
}

async function captureFindings(r, opts) {
  const out = [];
  const w = process.stdout.write.bind(process.stdout);
  const realRoot = config.getRepoRoot;
  config.getRepoRoot = () => r;
  process.stdout.write = (c) => { out.push(String(c)); return true; };
  try { await findingsAction(undefined, opts); }
  finally { process.stdout.write = w; config.getRepoRoot = realRoot; }
  return out.join('');
}

describe('E1g — excepted hint + --show-excepted', () => {

  test('default view: count hint shown, excepted finding hidden, open finding shown', async () => {
    const r = mkTempRepo();
    try {
      seed(r);
      const out = await captureFindings(r, {});
      assert.match(out, /1 finding\(s\) excepted/, 'count hint present');
      assert.match(out, /scd findings --excepted/, 'hint points at --excepted');
      assert.doesNotMatch(out, /SECRET-008/, 'excepted finding is hidden by default');
      assert.match(out, /GEN-1/, 'open finding is shown');
    } finally { cleanup(r); }
  });

  test('--excepted: shows only excepted, no "hidden" hint', async () => {
    const r = mkTempRepo();
    try {
      seed(r);
      const out = await captureFindings(r, { excepted: true });
      assert.match(out, /SECRET-008/, 'excepted finding shown');
      assert.doesNotMatch(out, /GEN-1/, 'open finding excluded in --excepted view');
      assert.doesNotMatch(out, /finding\(s\) excepted {2}·/, 'no hidden-count hint when already showing excepted');
    } finally { cleanup(r); }
  });

  test('--show-excepted is an alias of --excepted', async () => {
    const r = mkTempRepo();
    try {
      seed(r);
      const out = await captureFindings(r, { showExcepted: true });
      assert.match(out, /SECRET-008/, 'alias shows excepted finding');
      assert.doesNotMatch(out, /GEN-1/, 'alias excludes open findings');
    } finally { cleanup(r); }
  });

  test('no excepted findings → no hint', async () => {
    const r = mkTempRepo();
    try {
      store.storeDir(r);
      const snip = 'eval(x);';
      fs.writeFileSync(store.findingsPath(r), JSON.stringify({
        finding_id: makeFindingId('GEN-1', 'src/b.js', snip), rule_id: 'GEN-1',
        file: 'src/b.js', line: 9, code_hash: makeCodeHash(snip), status: 'open',
        severity: 'HIGH', base_severity: 'HIGH', snippet: snip, times_seen: 1,
        first_seen: '2026-06-20T00:00:00.000Z', last_seen: '2026-06-20T00:00:00.000Z',
      }) + '\n');
      const out = await captureFindings(r, {});
      assert.doesNotMatch(out, /finding\(s\) excepted/, 'no hint when nothing is excepted');
    } finally { cleanup(r); }
  });
});
