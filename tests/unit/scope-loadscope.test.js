/**
 * scope-loadscope.test.js
 * Regression net for the scope crash: `scd scope --show` threw
 * ERR_INVALID_ARG_TYPE ("paths[0] ... Received null") when run outside a git
 * repo, because loadScope(null) still tried to resolve a per-repo store path
 * from a null repo root (store.scopePath(null) → path.resolve(null) throws).
 *
 * loadScope(null) is the documented "global only" mode used by `scd scope
 * --show`. It must never consult the per-repo / server scope sources (which
 * need a repo root) and must never throw — regardless of the current working
 * directory.
 *
 * Run: npm test  (or: node --test tests/unit/scope-loadscope.test.js)
 */

'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const repoRoot = path.resolve(__dirname, '../..');
const store    = require(path.join(repoRoot, 'lib/store'));
const scope    = require(path.join(repoRoot, 'lib/scope'));

// Snapshot the store functions we patch so we can restore them.
const ORIG = {
  globalScopePath: store.globalScopePath,
  scopePath:       store.scopePath,
  serverScopePath: store.serverScopePath,
};

let tmpGlobal;   // controlled global scope.yml
let repoCalls;   // records store.scopePath / serverScopePath invocations

beforeEach(() => {
  tmpGlobal = path.join(os.tmpdir(), `scd-scope-${process.pid}-${Math.random().toString(16).slice(2)}.yml`);
  fs.writeFileSync(tmpGlobal,
    'file_excludes:\n' +
    '  - pattern: tests/\n' +
    '    reason: "fixtures"\n' +
    '    added_by: fp-test\n' +
    '    added_at: "2026-06-12 00:00"\n' +
    'rule_excludes: []\n', 'utf8');

  repoCalls = [];
  store.globalScopePath = () => tmpGlobal;
  store.scopePath       = (r) => { repoCalls.push(['scopePath', r]);       return ORIG.scopePath(r); };
  store.serverScopePath = (r) => { repoCalls.push(['serverScopePath', r]); return ORIG.serverScopePath(r); };
});

afterEach(() => {
  store.globalScopePath = ORIG.globalScopePath;
  store.scopePath       = ORIG.scopePath;
  store.serverScopePath = ORIG.serverScopePath;
  try { fs.unlinkSync(tmpGlobal); } catch { /* already gone */ }
});

describe('loadScope — global-only mode (null repo root)', () => {

  test('loadScope(null) does not throw and never resolves a per-repo path', () => {
    let result;
    assert.doesNotThrow(() => { result = scope.loadScope(null); });

    // Global scope is loaded and returned ...
    assert.equal(result.file_excludes.length, 1);
    assert.equal(result.file_excludes[0].pattern, 'tests/');
    assert.deepEqual(result.rule_excludes, []);

    // ... and the per-repo / server sources are NOT consulted with a null root.
    assert.deepEqual(repoCalls, [], 'no per-repo path resolution in global-only mode');
  });

  test('loadScope(repoRoot) still consults the per-repo scope source', () => {
    // A non-existent, non-git path: getRepoIdentity falls back to a path-based
    // id, store.scopePath resolves to a file that does not exist, and
    // loadScopeFile returns null for the missing file — no crash, global merged.
    const fakeRepo = path.join(os.tmpdir(), `scd-test-repo-none-${process.pid}`);
    const result = scope.loadScope(fakeRepo);

    assert.ok(repoCalls.some(([fn]) => fn === 'scopePath'),
      'per-repo scope source consulted for a non-null repo root');
    assert.equal(result.file_excludes[0].pattern, 'tests/', 'global scope still merged');
  });
});
