'use strict';

/**
 * Smoke tests for scd CLI commands.
 *
 * Verifies that commands exit with the correct code and produce expected output.
 * These tests do NOT run actual scans against real code — they only test the
 * CLI surface (help text, flags, argument validation).
 *
 * Run: node --test tests/smoke/cli-smoke.test.js
 *
 * REGRESSION GUARDS:
 * Several tests below explicitly check that removed/renamed commands do NOT
 * appear in help output. Add a guard here whenever a command is renamed or
 * removed so it can never silently reappear in a future commit.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const SCD = path.resolve(__dirname, '..', '..', 'bin', 'scd.js');
const run = (args, opts = {}) =>
  spawnSync(process.execPath, [SCD, ...args.split(' ')], {
    encoding: 'utf8',
    ...opts,
  });

// Helper: get full help output
function help() {
  const r = run('--help');
  return r.stdout + r.stderr;
}

// ---------------------------------------------------------------------------
// scd --help — present commands
// ---------------------------------------------------------------------------

test('scd --help exits 0', () => {
  const r = run('--help');
  assert.strictEqual(r.status, 0, `Expected exit 0, got ${r.status}\n${r.stderr}`);
});

test('scd --help lists all expected commands', () => {
  const out = help();
  const expected = [
    'scan',
    'install',
    'uninstall',
    'init',
    'doctor',
    'configure',
    'repo',
    'hooks',
    'sync',
    'findings',
    'accept',
    'ignore',
    'exceptions',
    'resolve',
    'report',
    'audit',
    'insights',
    'rules',
    'list',
    'remove',
    'version',
  ];
  for (const cmd of expected) {
    assert.ok(out.includes(cmd), `--help output missing command: ${cmd}`);
  }
});

// ---------------------------------------------------------------------------
// REGRESSION GUARDS — commands that must NOT exist
// ---------------------------------------------------------------------------

test('REGRESSION: scd approve must not exist (renamed to scd accept)', () => {
  // Check it's not registered as a command (would appear as "  approve " at line start)
  const r = run('approve');
  const out = r.stdout + r.stderr;
  assert.ok(
    out.includes("unknown command 'approve'") || r.status !== 0 && !out.includes('approve ['),
    'approve appears to be a registered command — it was renamed to accept'
  );
  // Double-check: accept must exist
  const helpOut = help();
  assert.ok(helpOut.includes('accept'), 'accept command missing from --help');
});

test('REGRESSION: scd store must not exist (renamed to scd repo)', () => {
  // Verify running it fails with unknown command
  const r = run('store');
  const out = r.stdout + r.stderr;
  assert.ok(
    out.includes("unknown command 'store'") || r.status !== 0,
    'store appears to be a registered command — it was renamed to repo'
  );
  // Double-check: repo must exist
  const helpOut = help();
  assert.ok(helpOut.includes('repo'), 'repo command missing from --help');
});

// ---------------------------------------------------------------------------
// scd --version
// ---------------------------------------------------------------------------

test('scd --version exits 0 and prints a semver', () => {
  const r = run('--version');
  assert.strictEqual(r.status, 0);
  const out = r.stdout + r.stderr;
  assert.match(out, /\d+\.\d+\.\d+/, 'Expected semver in --version output');
});

// ---------------------------------------------------------------------------
// scd scan --help
// ---------------------------------------------------------------------------

test('scd scan --help exits 0', () => {
  assert.strictEqual(run('scan --help').status, 0);
});

test('scd scan --help mentions key flags', () => {
  const out = run('scan --help').stdout + run('scan --help').stderr;
  for (const flag of [
    '--deep', '--verbose', '--format', '--output',
    '--no-audit', '--no-sync', '--include-vendor', '--include-ignored',
  ]) {
    assert.ok(out.includes(flag), `scan --help missing flag: ${flag}`);
  }
});

// ---------------------------------------------------------------------------
// scd accept / scd ignore
// ---------------------------------------------------------------------------

test('scd accept --help exits 0', () => {
  assert.strictEqual(run('accept --help').status, 0);
});

test('scd accept --help mentions --reason and --tag', () => {
  const out = run('accept --help').stdout + run('accept --help').stderr;
  assert.ok(out.includes('--reason'), 'accept --help missing --reason');
  assert.ok(out.includes('--tag'), 'accept --help missing --tag');
});

test('scd accept without findingId exits non-zero', () => {
  const r = run('accept --reason test');
  assert.notStrictEqual(r.status, 0, 'accept without findingId should fail');
});

test('scd accept without --reason exits non-zero', () => {
  const r = run('accept f-abc12345');
  assert.notStrictEqual(r.status, 0, 'accept without --reason should fail');
});

test('scd ignore --help exits 0', () => {
  assert.strictEqual(run('ignore --help').status, 0);
});

test('scd ignore --help mentions --reason and --tag', () => {
  const out = run('ignore --help').stdout + run('ignore --help').stderr;
  assert.ok(out.includes('--reason'), 'ignore --help missing --reason');
  assert.ok(out.includes('--tag'), 'ignore --help missing --tag');
});

test('scd ignore without findingId exits non-zero', () => {
  const r = run('ignore --reason test');
  assert.notStrictEqual(r.status, 0, 'ignore without findingId should fail');
});

test('scd ignore without --reason exits non-zero', () => {
  const r = run('ignore f-abc12345');
  assert.notStrictEqual(r.status, 0, 'ignore without --reason should fail');
});

// ---------------------------------------------------------------------------
// scd findings --help
// ---------------------------------------------------------------------------

test('scd findings --help exits 0', () => {
  assert.strictEqual(run('findings --help').status, 0);
});

test('scd findings --help mentions key flags', () => {
  const out = run('findings --help').stdout + run('findings --help').stderr;
  for (const flag of ['--all', '--severity', '--rule', '--scan', '--excepted']) {
    assert.ok(out.includes(flag), `findings --help missing flag: ${flag}`);
  }
});

// ---------------------------------------------------------------------------
// scd install / scd uninstall
// ---------------------------------------------------------------------------

test('scd install --help exits 0', () => {
  assert.strictEqual(run('install --help').status, 0);
});

test('scd uninstall --help exits 0', () => {
  assert.strictEqual(run('uninstall --help').status, 0);
});

// ---------------------------------------------------------------------------
// scd init --help
// ---------------------------------------------------------------------------

test('scd init --help exits 0', () => {
  assert.strictEqual(run('init --help').status, 0);
});

// ---------------------------------------------------------------------------
// scd repo
// ---------------------------------------------------------------------------

test('scd repo --help exits 0', () => {
  assert.strictEqual(run('repo --help').status, 0);
});

test('scd repo --help lists key flags and subcommands', () => {
  const out = run('repo --help').stdout + run('repo --help').stderr;
  for (const token of ['configure', 'hooks', '--verify', '--show', '--scans']) {
    assert.ok(out.includes(token), `repo --help missing token: ${token}`);
  }
});

test('scd repo configure --help exits 0', () => {
  assert.strictEqual(run('repo configure --help').status, 0);
});

test('scd repo hooks --help exits 0', () => {
  assert.strictEqual(run('repo hooks --help').status, 0);
});

// ---------------------------------------------------------------------------
// scd configure --help
// ---------------------------------------------------------------------------

test('scd configure --help exits 0', () => {
  assert.strictEqual(run('configure --help').status, 0);
});

test('scd configure --help mentions key flags', () => {
  const out = run('configure --help').stdout + run('configure --help').stderr;
  for (const flag of ['--central-url', '--token', '--server-timeout', '--deep-timeout', '--scan-mode']) {
    assert.ok(out.includes(flag), `configure --help missing flag: ${flag}`);
  }
});

// ---------------------------------------------------------------------------
// scd hooks / scd doctor / scd sync / scd exceptions / scd resolve
// ---------------------------------------------------------------------------

test('scd hooks --help exits 0', () => {
  assert.strictEqual(run('hooks --help').status, 0);
});

test('scd doctor --help exits 0', () => {
  assert.strictEqual(run('doctor --help').status, 0);
});

test('scd sync --help exits 0', () => {
  assert.strictEqual(run('sync --help').status, 0);
});

test('scd exceptions --help exits 0', () => {
  assert.strictEqual(run('exceptions --help').status, 0);
});

test('scd resolve --help exits 0', () => {
  assert.strictEqual(run('resolve --help').status, 0);
});

// ---------------------------------------------------------------------------
// scd report / scd audit / scd insights / scd rules / scd list / scd remove
// ---------------------------------------------------------------------------

test('scd report --help exits 0', () => {
  assert.strictEqual(run('report --help').status, 0);
});

test('scd report --help mentions key flags', () => {
  const out = run('report --help').stdout + run('report --help').stderr;
  for (const flag of ['--serve', '--scan', '--open']) {
    assert.ok(out.includes(flag), `report --help missing flag: ${flag}`);
  }
});

test('scd audit --help exits 0', () => {
  assert.strictEqual(run('audit --help').status, 0);
});

test('scd insights --help exits 0', () => {
  assert.strictEqual(run('insights --help').status, 0);
});

test('scd rules --help exits 0', () => {
  assert.strictEqual(run('rules --help').status, 0);
});

test('scd rules --help mentions key flags', () => {
  const out = run('rules --help').stdout + run('rules --help').stderr;
  for (const flag of ['--lang', '--id', '--search', '--stats']) {
    assert.ok(out.includes(flag), `rules --help missing flag: ${flag}`);
  }
});

test('scd list --help exits 0', () => {
  assert.strictEqual(run('list --help').status, 0);
});

test('scd remove --help exits 0', () => {
  assert.strictEqual(run('remove --help').status, 0);
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
