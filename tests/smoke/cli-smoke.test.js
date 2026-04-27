'use strict';

/**
 * Smoke tests for scd CLI commands.
 *
 * Verifies that commands exit with the correct code and produce expected output.
 * These tests do NOT run actual scans against real code — they only test the
 * CLI surface (help text, flags, argument validation).
 *
 * Run: node --test tests/smoke/cli-smoke.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { execSync, spawnSync } = require('node:child_process');
const path = require('node:path');

const SCD = path.resolve(__dirname, '..', '..', 'bin', 'scd.js');
const run = (args, opts = {}) =>
  spawnSync(process.execPath, [SCD, ...args.split(' ')], {
    encoding: 'utf8',
    ...opts,
  });

// ---------------------------------------------------------------------------
// scd / scd --help
// ---------------------------------------------------------------------------

test('scd --help exits 0', () => {
  const r = run('--help');
  assert.strictEqual(r.status, 0, `Expected exit 0, got ${r.status}\n${r.stderr}`);
});

test('scd --help lists core commands', () => {
  const r = run('--help');
  const out = r.stdout + r.stderr;
  for (const cmd of ['scan', 'init', 'doctor', 'configure', 'repo', 'hooks', 'sync']) {
    assert.ok(out.includes(cmd), `--help output missing command: ${cmd}`);
  }
});

test('scd --version exits 0 and prints a version number', () => {
  const r = run('--version');
  assert.strictEqual(r.status, 0, `Expected exit 0, got ${r.status}`);
  const out = r.stdout + r.stderr;
  assert.match(out, /\d+\.\d+\.\d+/, 'Expected semver in --version output');
});

// ---------------------------------------------------------------------------
// scd scan --help
// ---------------------------------------------------------------------------

test('scd scan --help exits 0', () => {
  const r = run('scan --help');
  assert.strictEqual(r.status, 0);
});

test('scd scan --help mentions key flags', () => {
  const r = run('scan --help');
  const out = r.stdout + r.stderr;
  for (const flag of ['--deep', '--format', '--output', '--verbose', '--no-audit', '--no-sync', '--include-vendor']) {
    assert.ok(out.includes(flag), `scan --help missing flag: ${flag}`);
  }
});

// ---------------------------------------------------------------------------
// scd repo --help
// ---------------------------------------------------------------------------

test('scd repo --help exits 0', () => {
  const r = run('repo --help');
  assert.strictEqual(r.status, 0);
});

test('scd repo --help lists subcommands and key flags', () => {
  const r = run('repo --help');
  const out = r.stdout + r.stderr;
  for (const token of ['configure', 'hooks', '--verify', '--show', '--scans']) {
    assert.ok(out.includes(token), `repo --help missing token: ${token}`);
  }
});

test('scd repo configure --help exits 0', () => {
  const r = run('repo configure --help');
  assert.strictEqual(r.status, 0);
});

test('scd repo hooks --help exits 0', () => {
  const r = run('repo hooks --help');
  assert.strictEqual(r.status, 0);
});

// ---------------------------------------------------------------------------
// scd configure --help
// ---------------------------------------------------------------------------

test('scd configure --help exits 0', () => {
  const r = run('configure --help');
  assert.strictEqual(r.status, 0);
});

test('scd configure --help mentions timeout flags', () => {
  const r = run('configure --help');
  const out = r.stdout + r.stderr;
  for (const flag of ['--server-timeout', '--deep-timeout']) {
    assert.ok(out.includes(flag), `configure --help missing flag: ${flag}`);
  }
});

// ---------------------------------------------------------------------------
// scd hooks --help
// ---------------------------------------------------------------------------

test('scd hooks --help exits 0', () => {
  const r = run('hooks --help');
  assert.strictEqual(r.status, 0);
});

// ---------------------------------------------------------------------------
// scd doctor --help
// ---------------------------------------------------------------------------

test('scd doctor --help exits 0', () => {
  const r = run('doctor --help');
  assert.strictEqual(r.status, 0);
});

// ---------------------------------------------------------------------------
// scd sync --help
// ---------------------------------------------------------------------------

test('scd sync --help exits 0', () => {
  const r = run('sync --help');
  assert.strictEqual(r.status, 0);
});

// ---------------------------------------------------------------------------
// Unknown commands and bad flags
// ---------------------------------------------------------------------------

test('scd unknown-command exits non-zero', () => {
  const r = run('unknown-command-that-does-not-exist');
  assert.notStrictEqual(r.status, 0, 'Expected non-zero exit for unknown command');
});

test('scd scan --unknown-flag exits non-zero', () => {
  const r = run('scan --unknown-flag-xyz');
  assert.notStrictEqual(r.status, 0, 'Expected non-zero exit for unknown flag');
});
