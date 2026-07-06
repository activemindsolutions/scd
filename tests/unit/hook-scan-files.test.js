'use strict';

/**
 * Regression tests for hook scans writing scan files.
 *
 * Pre-commit/pre-push hook scans must write scans/{id}.json + last-scan.json
 * so `scd report`, `scd findings --scan`, and the scan history can reach them.
 * The scan-file artifact is written ON FINDINGS by default; empty hook scans
 * are written only when config write_empty_hook_scans is enabled. Each scan
 * file carries a `hook` field so its origin is self-describing.
 *
 * These are subprocess integration tests: they run the real CLI against an
 * isolated HOME (so ~/.scd points into a temp dir) and a throwaway git repo.
 *
 * Run: node --test tests/unit/hook-scan-files.test.js
 */

const { test }     = require('node:test');
const assert       = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');

const SCD = path.resolve(__dirname, '..', '..', 'bin', 'scd.js');

// A Stripe-style secret that triggers a CRITICAL secret rule in the pre-commit
// (secrets-only) scan. Assembled at runtime so this SOURCE file contains no literal
// secret — both GitHub push protection and our own SECRET-008 rule scan the temp
// file we WRITE below, not this test source. The written value still matches the rule.
const STRIPE_KEY  = 'sk_' + 'live_' + '51H8xQ2eZvKYlo2C0' + 'abcd1234efgh5678';
const SECRET_FILE = `const apiKey = "${STRIPE_KEY}";\nmodule.exports = { apiKey };\n`;
const CLEAN_FILE  = 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n';

// Build an isolated HOME + a throwaway git repo with the given files staged.
function setup(files) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-hook-'));
  const repo = path.join(home, 'proj');
  fs.mkdirSync(repo);
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(repo, name), content);
  }
  const git = (args) => spawnSync('git', args, { cwd: repo, encoding: 'utf8' });
  git(['init', '-q']);
  git(['config', 'user.email', 'test@example.com']);
  git(['config', 'user.name', 'test']);
  git(['remote', 'add', 'origin', 'https://example.com/' + path.basename(home) + '.git']);
  git(['add', '-A']);
  return { home, repo };
}

function runScd(args, home, repo) {
  return spawnSync(process.execPath, [SCD, ...args], {
    cwd: repo,
    encoding: 'utf8',
    env: { ...process.env, HOME: home },
  });
}

function repoStoreDir(home) {
  const reposDir = path.join(home, '.scd', 'repos');
  if (!fs.existsSync(reposDir)) return null;
  const id = fs.readdirSync(reposDir).find(d => fs.statSync(path.join(reposDir, d)).isDirectory());
  return id ? path.join(reposDir, id) : null;
}

function listScans(home) {
  const store = repoStoreDir(home);
  const dir = store && path.join(store, 'scans');
  if (!dir || !fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.json'));
}

function cleanup(home) {
  try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* best-effort */ }
}

test('hook scan with findings writes a scan file (hook=pre-commit) + last-scan.json', () => {
  const { home, repo } = setup({ 'secrets.js': SECRET_FILE });
  try {
    runScd(['init'], home, repo);
    runScd(['scan', '--hook', 'pre-commit'], home, repo);

    const scans = listScans(home);
    assert.strictEqual(scans.length, 1, 'expected exactly one scan file for a hook scan with findings');

    const store = repoStoreDir(home);
    const scanFile = JSON.parse(fs.readFileSync(path.join(store, 'scans', scans[0]), 'utf8'));
    assert.strictEqual(scanFile.hook, 'pre-commit', 'scan file must be self-describing (hook=pre-commit)');
    assert.ok(scanFile.findings.length > 0, 'scan file should record the secret finding');

    assert.ok(
      fs.existsSync(path.join(store, 'last-scan.json')),
      'hook scan must also update last-scan.json so `scd report` (no flags) reaches it',
    );

    // --scan lookup must resolve the hook scan.
    const scanId = scans[0].replace(/\.json$/, '');
    const r = runScd(['findings', '--scan', scanId], home, repo);
    assert.strictEqual(r.status, 0, 'scd findings --scan should resolve a hook scan');
  } finally {
    cleanup(home);
  }
});

test('empty hook scan writes no scan file by default', () => {
  const { home, repo } = setup({ 'clean.js': CLEAN_FILE });
  try {
    runScd(['init'], home, repo);
    runScd(['scan', '--hook', 'pre-commit'], home, repo);

    assert.strictEqual(listScans(home).length, 0, 'a clean hook scan must not write a scan file by default');
    const store = repoStoreDir(home);
    assert.ok(
      !store || !fs.existsSync(path.join(store, 'last-scan.json')),
      'a clean hook scan must not write last-scan.json by default',
    );
  } finally {
    cleanup(home);
  }
});

test('write_empty_hook_scans=true makes empty hook scans write a scan file', () => {
  const { home, repo } = setup({ 'clean.js': CLEAN_FILE });
  try {
    runScd(['init'], home, repo);

    const store = repoStoreDir(home);
    assert.ok(store, 'store should exist after init');
    fs.appendFileSync(path.join(store, 'config.yml'), '\nwrite_empty_hook_scans: true\n');

    runScd(['scan', '--hook', 'pre-commit'], home, repo);

    const scans = listScans(home);
    assert.strictEqual(scans.length, 1, 'with write_empty_hook_scans:true an empty hook scan writes a file');
    const scanFile = JSON.parse(fs.readFileSync(path.join(store, 'scans', scans[0]), 'utf8'));
    assert.strictEqual(scanFile.hook, 'pre-commit');
    assert.deepStrictEqual(scanFile.findings, [], 'empty hook scan file should have no findings');
  } finally {
    cleanup(home);
  }
});
