/**
 * exception-lifecycle.test.js
 * E1c.2 Phase A — archive-with-reason lifecycle (CLI-local).
 *   - archiveException / withdrawException (never deletes; idempotent)
 *   - gatekeeper: an archived exception never excepts (finding valid again)
 *   - archiveResolvedExceptions: finding resolved by evidence → archive its exception
 *   - listExceptions: archived hidden from active views, shown via --list archived
 *
 * Run: node --test tests/unit/exception-lifecycle.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const root = path.resolve(__dirname, '../..');
const em     = require(path.join(root, 'lib/exception-manager'));
const store  = require(path.join(root, 'lib/store'));
const estore = require(path.join(root, 'lib/exceptions-store'));
const { reconcileException } = require(path.join(root, 'lib/exception-gatekeeper'));
const { makeCodeHash } = require(path.join(root, 'lib/finding-identity'));

let counter = 0;
function mkTempRepo() {
  const id  = `${process.pid}-${Date.now()}-${counter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-lifecycle-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  store.storeDir(dir);
  return dir;
}
function cleanup(r) {
  try { fs.rmSync(store.storeDir(r), { recursive: true, force: true }); } catch {}
  try { fs.rmSync(r, { recursive: true, force: true }); } catch {}
}
function stripAnsi(s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }
function capture(fn) {
  const out = [];
  const w = console.log;
  console.log = (...a) => out.push(a.join(' '));
  try { fn(); } finally { console.log = w; }
  return stripAnsi(out.join('\n'));
}

const SNIP = 'const k = "AKIA";';
const HASH = makeCodeHash(SNIP);
const FINDING = { ruleId: 'SECRET-008', filePath: 'src/a.js', codeHash: HASH, line: 5, snippet: SNIP };
function mkExc(id, over = {}) {
  return estore.buildExceptionRecord({
    id, type: 'exception', status: 'approved', rule: 'SECRET-008', file: 'src/a.js',
    line: 5, line_hash: HASH, reason: 'ok', created_at: '2026-06-22T00:00:00.000Z', ...over,
  });
}

describe('E1c.2 archive lifecycle', () => {

  test('archiveException: sets archived_at + reason, never deletes, idempotent', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [mkExc('exc-1')]);
      const res = em.archiveException(r, 'exc-1', 'withdrawn');
      assert.deepEqual({ found: res.found, archived: res.archived }, { found: true, archived: true });

      const rec = estore.loadExceptions(r)[0];
      assert.ok(rec.archived_at, 'archived_at set');
      assert.equal(rec.archive_reason, 'withdrawn');
      assert.equal(estore.loadExceptions(r).length, 1, 'record retained, not deleted');

      const again = em.archiveException(r, 'exc-1', 'finding_resolved');
      assert.equal(again.already, true, 'already-archived is a no-op (first reason wins)');
      assert.equal(estore.loadExceptions(r)[0].archive_reason, 'withdrawn', 'reason unchanged');
    } finally { cleanup(r); }
  });

  test('archiveException: invalid reason rejected, unknown id reported', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [mkExc('exc-1')]);
      assert.match(em.archiveException(r, 'exc-1', 'bogus').error, /invalid archive reason/);
      assert.equal(estore.loadExceptions(r)[0].archived_at, undefined, 'invalid reason did not archive');
      assert.deepEqual(
        (({ found, archived }) => ({ found, archived }))(em.archiveException(r, 'nope', 'withdrawn')),
        { found: false, archived: false });
    } finally { cleanup(r); }
  });

  test('gatekeeper: archived exception never excepts', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [mkExc('exc-1')]);
      assert.equal(reconcileException(FINDING, estore.loadExceptions(r)).excepted, true, 'excepts while active');
      em.archiveException(r, 'exc-1', 'withdrawn');
      assert.equal(reconcileException(FINDING, estore.loadExceptions(r)).excepted, false, 'no longer excepts once archived');
    } finally { cleanup(r); }
  });

  test('archiveResolvedExceptions: a resolved finding archives its exception with finding_resolved', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [mkExc('exc-1')]);
      const resolved = [{ rule_id: 'SECRET-008', file: 'src/a.js', code_hash: HASH, line: 5, snippet: SNIP }];
      const res = em.archiveResolvedExceptions(r, resolved);
      assert.equal(res.archived, 1);
      const rec = estore.loadExceptions(r)[0];
      assert.equal(rec.archive_reason, 'finding_resolved');
      assert.ok(rec.archived_at);
    } finally { cleanup(r); }
  });

  test('archiveResolvedExceptions: no matching exception → nothing archived', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [mkExc('exc-1')]);
      const resolved = [{ rule_id: 'OTHER-1', file: 'src/z.js', code_hash: 'deadbeef', line: 9, snippet: 'x' }];
      assert.equal(em.archiveResolvedExceptions(r, resolved).archived, 0);
      assert.equal(estore.loadExceptions(r)[0].archived_at, undefined);
    } finally { cleanup(r); }
  });

  test('listExceptions: archived hidden from active views, shown via --list archived', () => {
    const r = mkTempRepo();
    try {
      estore.writeExceptions(r, [
        mkExc('exc-live'),
        mkExc('exc-arch', { archived_at: '2026-06-22T00:00:00.000Z', archive_reason: 'withdrawn' }),
      ]);
      const all = capture(() => em.listExceptions(r, 'all'));
      assert.match(all, /exc-live/);
      assert.doesNotMatch(all, /exc-arch/, 'archived hidden from --list all');

      const arch = capture(() => em.listExceptions(r, 'archived'));
      assert.match(arch, /exc-arch/);
      assert.doesNotMatch(arch, /exc-live/);
      assert.match(arch, /Archived: withdrawn/, 'archive reason badge shown');
    } finally { cleanup(r); }
  });
});
