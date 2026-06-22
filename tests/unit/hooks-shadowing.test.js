/**
 * hooks-shadowing.test.js
 * #72 — getHookStatus must reveal a foreign core.hooksPath as `shadowed`
 * (scd's hooks are silently bypassed) rather than reporting `enabled`.
 *
 * Run: node --test tests/unit/hooks-shadowing.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execSync } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

const root = path.resolve(__dirname, '../..');
const { getHookStatus } = require(root + '/lib/hooks-manager');

const SCD_HOOKS = path.join(os.homedir(), '.scd', 'hooks');

function mkGitRepo() {
  const dir = path.join(os.tmpdir(), `scd-hooks-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true });
  execSync('git init -q', { cwd: dir });
  execSync('git config user.email t@t.t && git config user.name t', { cwd: dir });
  return dir;
}
function setLocal(dir, v) { execSync(`git config --local core.hooksPath '${v}'`, { cwd: dir }); }
function cleanup(dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }

describe('#72 getHookStatus core.hooksPath shadowing', () => {

  test('a foreign local hooksPath → shadowed (not enabled)', () => {
    const r = mkGitRepo();
    try {
      setLocal(r, '../security-copilot-poc/hooks');   // relative, foreign
      assert.equal(getHookStatus(r).status, 'shadowed');
    } finally { cleanup(r); }
  });

  test('local hooksPath pointing at scd hooks → enabled', () => {
    const r = mkGitRepo();
    try {
      setLocal(r, SCD_HOOKS);
      assert.equal(getHookStatus(r).status, 'enabled');
    } finally { cleanup(r); }
  });

  test('local /dev/null → disabled (a deliberate scd disable)', () => {
    const r = mkGitRepo();
    try {
      setLocal(r, process.platform === 'win32' ? 'NUL' : '/dev/null');
      assert.equal(getHookStatus(r).status, 'disabled');
    } finally { cleanup(r); }
  });
});
