'use strict';

// Concurrency + recovery tests for lib/file-lock.js (withFileLock).
// The acceptance test (#170) uses REAL OS subprocesses — the only thing that
// reproduces cross-process lost-update; worker_threads share too much to count.

const test   = require('node:test');
const assert = require('node:assert');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const { withFileLock } = require('../../lib/file-lock');
const LOCK_MODULE = path.resolve(__dirname, '../../lib/file-lock.js');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'scd-flock-'));
}

// Worker: load JSON → (busy-wait to widen the race window) → add own key → write,
// all inside withFileLock. Concurrency-safe iff the lock serialises the cycle.
const WORKER = `
  const fs = require('fs');
  const { withFileLock } = require(${JSON.stringify(LOCK_MODULE)});
  const target = process.env.TARGET;
  const key    = process.env.KEY;
  // Retry on ELOCKED — decision (a) makes withFileLock throw rather than steal a
  // live holder, so a real caller retries. The test verifies the no-lost-update
  // INVARIANT, not contention timing.
  for (let tries = 0; ; tries++) {
    try {
      withFileLock(target, () => {
        let data = {};
        try { data = JSON.parse(fs.readFileSync(target, 'utf8')); } catch {}
        const t = Date.now(); while (Date.now() - t < 8) {}   // widen read→write window
        data[key] = true;
        fs.writeFileSync(target, JSON.stringify(data));
      });
      break;
    } catch (e) {
      if (e.code === 'ELOCKED' && tries < 500) { const s = Date.now(); while (Date.now() - s < 20) {} continue; }
      throw e;
    }
  }
`;

function runWorker(target, key) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', WORKER], {
      env: { ...process.env, TARGET: target, KEY: key },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let err = '';
    child.stderr.on('data', d => { err += d; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve() : reject(new Error(`worker ${key} exited ${code}: ${err}`)));
  });
}

test('concurrent same-file writers do not lose a diff (acceptance, #170)', async () => {
  const dir    = tmpDir();
  const target = path.join(dir, 'findings.jsonl');
  fs.writeFileSync(target, '{}');                    // start from an empty object

  const N    = 20;
  const keys = Array.from({ length: N }, (_, i) => `k${i}`);
  await Promise.all(keys.map(k => runWorker(target, k))); // all concurrent

  const final = JSON.parse(fs.readFileSync(target, 'utf8'));
  for (const k of keys) {
    assert.ok(final[k] === true, `lost update: ${k} missing — a writer's diff was clobbered`);
  }
  assert.strictEqual(Object.keys(final).length, N, 'exactly N keys expected');

  assert.ok(!fs.existsSync(target + '.lock'), 'lock file must be released after all writers finish');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('acquire/release leaves no lock file behind', () => {
  const dir    = tmpDir();
  const target = path.join(dir, 'state.json');
  const ret = withFileLock(target, () => {
    assert.ok(fs.existsSync(target + '.lock'), 'lock present inside the critical section');
    return 42;
  });
  assert.strictEqual(ret, 42, 'withFileLock returns fn() result');
  assert.ok(!fs.existsSync(target + '.lock'), 'lock removed after release');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a stale lock (dead holder) is stolen and acquisition proceeds', () => {
  const dir    = tmpDir();
  const target = path.join(dir, 'state.json');

  // A genuinely dead pid: spawnSync a no-op node; on return it has exited.
  const deadPid = spawnSync(process.execPath, ['-e', '']).pid;
  fs.writeFileSync(target + '.lock', `${deadPid}.deadbeef\n${Date.now()}\n`);

  let ran = false;
  withFileLock(target, () => { ran = true; }, { maxWaitMs: 500 });
  assert.ok(ran, 'fn ran — the dead-holder lock was recovered, not waited on');
  assert.ok(!fs.existsSync(target + '.lock'), 'stolen lock cleaned up after release');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a fresh live lock is refused with ELOCKED, never silently stolen', () => {
  const dir    = tmpDir();
  const target = path.join(dir, 'state.json');

  // A live holder: this very process's pid, fresh timestamp → not stale.
  fs.writeFileSync(target + '.lock', `${process.pid}.livelock\n${Date.now()}\n`);

  assert.throws(
    () => withFileLock(target, () => { assert.fail('must not enter critical section'); }, { maxWaitMs: 200, backoffMs: 20 }),
    err => err.code === 'ELOCKED',
    'a live holder must yield ELOCKED, not a steal',
  );
  // The live holder's lock must be left intact (we did not own it).
  assert.ok(fs.existsSync(target + '.lock'), 'live holder lock left untouched');
  fs.rmSync(dir, { recursive: true, force: true });
});
