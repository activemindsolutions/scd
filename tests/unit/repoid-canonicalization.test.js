'use strict';

/**
 * repoId canonicalisation + legacy-store migration.
 *
 * A repo's id is derived from a transport-independent form of its git remote, so
 * an SSH clone and an HTTPS clone of the same repo share one id. Upgrading to the
 * canonicalising version moves an existing store from the legacy id (hash of the
 * raw remote) to the canonical id in place — preserving local findings, exceptions
 * and queued events. The id value lives in exactly three places: the store
 * directory name, meta.json's `repoId`, and each push-queue.jsonl entry's `repoId`.
 *
 * Run: node --test tests/unit/repoid-canonicalization.test.js
 */

const os     = require('node:os');
const path   = require('node:path');
const fs     = require('node:fs');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { test, before, after } = require('node:test');
const assert = require('node:assert');

// Isolate the global store into a temp HOME before store.js reads os.homedir().
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-repoid-home-'));
process.env.HOME = HOME;
const store = require('../../lib/store');

const REPOS = path.join(HOME, '.scd', 'repos');
const QUEUE = path.join(HOME, '.scd', 'push-queue.jsonl');
const sha16 = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
const repoDirs = [];

function makeRepo(remote) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-repoid-repo-'));
  repoDirs.push(dir);
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('remote', 'add', 'origin', remote);
  return dir;
}

function seedStore(id, extra = {}) {
  const dir = path.join(REPOS, id);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({ repoId: id, ...extra }, null, 2));
  fs.writeFileSync(path.join(dir, 'findings.jsonl'), '{"finding_id":"f-1"}\n');
  return dir;
}

after(() => {
  fs.rmSync(HOME, { recursive: true, force: true });
  for (const d of repoDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} }
});

test('canonicalize: SSH, HTTPS and .git collapse to one identifier', () => {
  assert.strictEqual(store.canonicalizeRemote('git@github.com:acme/widget.git'), 'github.com/acme/widget');
  assert.strictEqual(store.canonicalizeRemote('https://github.com/acme/widget'), 'github.com/acme/widget');
  assert.strictEqual(store.canonicalizeRemote('ssh://git@GitHub.com:22/acme/widget.git/'), 'github.com/acme/widget');
  // A local filesystem remote is left as-is (already a stable identifier).
  assert.strictEqual(store.canonicalizeRemote('/srv/git/widget.git'), '/srv/git/widget.git');
});

test('getRepoId is transport-independent; getLegacyRepoId follows the raw remote', () => {
  const ssh   = makeRepo('git@github.com:acme/thing.git');
  const https = makeRepo('https://github.com/acme/thing');
  assert.strictEqual(store.getRepoId(ssh), store.getRepoId(https), 'same repo, different transport → same id');
  assert.strictEqual(store.getLegacyRepoId(ssh), sha16('git@github.com:acme/thing.git'));
  assert.notStrictEqual(store.getLegacyRepoId(ssh), store.getRepoId(ssh), 'SSH remote migrates (raw ≠ canonical)');
});

test('migrate: legacy store dir renamed to canonical id; meta + queue re-stamped', () => {
  const remote = 'git@github.com:acme/migrate.git';
  const repo   = makeRepo(remote);
  const oldId  = sha16(remote);
  const newId  = sha16('github.com/acme/migrate');
  assert.notStrictEqual(oldId, newId);

  seedStore(oldId, { localPath: repo, remote });
  fs.mkdirSync(path.dirname(QUEUE), { recursive: true });
  fs.writeFileSync(QUEUE,
    JSON.stringify({ id: 'e1', repoId: oldId, event: {} }) + '\n' +
    JSON.stringify({ id: 'e2', repoId: 'unrelated', event: {} }) + '\n');

  const dir = store.storeDir(repo);   // write-path accessor → triggers the migration

  assert.strictEqual(path.basename(dir), newId, 'store dir is now the canonical id');
  assert.ok(!fs.existsSync(path.join(REPOS, oldId)), 'legacy dir is gone');
  assert.ok(fs.existsSync(path.join(REPOS, newId, 'findings.jsonl')), 'local data preserved through the rename');

  const meta = JSON.parse(fs.readFileSync(path.join(REPOS, newId, 'meta.json'), 'utf8'));
  assert.strictEqual(meta.repoId, newId, 'meta.json repoId updated to the canonical id');

  const q = fs.readFileSync(QUEUE, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.strictEqual(q[0].repoId, newId, 'queued event re-stamped to the canonical id');
  assert.strictEqual(q[1].repoId, 'unrelated', 'unrelated queue entry untouched');
});

test('collision: legacy and canonical stores both exist → both kept, no overwrite', () => {
  const remote = 'git@github.com:acme/collide.git';
  const repo   = makeRepo(remote);
  const oldId  = sha16(remote);
  const newId  = sha16('github.com/acme/collide');

  seedStore(oldId, { marker: 'legacy' });
  seedStore(newId, { marker: 'canonical' });

  store.readMeta(repo);   // read-path accessor → migration attempt (must not overwrite)

  assert.ok(fs.existsSync(path.join(REPOS, oldId)), 'legacy dir preserved on collision');
  const meta = JSON.parse(fs.readFileSync(path.join(REPOS, newId, 'meta.json'), 'utf8'));
  assert.strictEqual(meta.marker, 'canonical', 'canonical store was not overwritten');
});
