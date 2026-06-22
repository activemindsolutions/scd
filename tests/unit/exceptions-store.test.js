/**
 * exceptions-store.test.js
 * Unit tests for lib/exceptions-store.js (E1a Run 1).
 *
 * Run: npm test  (or: node --test tests/unit/exceptions-store.test.js)
 *
 * Each test uses a unique repoRoot under os.tmpdir(); config.yml and
 * exceptions.jsonl both live in the corresponding ~/.scd/repos/{id}/ store dir,
 * which is removed on cleanup.
 */

'use strict';

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const fs                 = require('fs');
const os                 = require('os');
const path               = require('path');
const crypto             = require('crypto');

const repoRoot = path.resolve(__dirname, '../..');
const {
  loadExceptions,
  loadExceptionsWithBootstrap,
  mapConfigExceptionToRecord,
  verifyBootstrapGate,
  MIGRATION_MARKER,
  buildExceptionRecord,
  writeExceptions,
} = require(path.join(repoRoot, 'lib/exceptions-store'));
const {
  configPath,
  exceptionsPathReadOnly,
  storeDir,
} = require(path.join(repoRoot, 'lib/store'));

// ── Helpers ────────────────────────────────────────────────────────────────

let setupCounter = 0;

function mkTempRepo() {
  const id = `${process.pid}-${Date.now()}-${setupCounter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-exceptions-store-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(testRepoRoot) {
  try {
    const storeFile = exceptionsPathReadOnly(testRepoRoot);
    fs.rmSync(path.dirname(storeFile), { recursive: true, force: true });
  } catch { /* best-effort */ }
  try { fs.rmSync(testRepoRoot, { recursive: true, force: true }); } catch {}
}

function writeConfig(testRepoRoot, content) {
  storeDir(testRepoRoot);   // ensure ~/.scd/repos/{id}/ exists (0o700)
  fs.writeFileSync(configPath(testRepoRoot), content, 'utf8');
}

function readConfig(testRepoRoot) {
  return fs.readFileSync(configPath(testRepoRoot), 'utf8');
}

// A config with two valid exceptions: one hashed, one redacted (no line_hash).
const CONFIG_TWO = `trust_level: balanced
scan_mode: full
locked_rules:
  - SECRET-001

exceptions:
  - id: "exc-1"
    type: "exception"
    status: "approved"
    rule: "SECRET-008"
    file: "src/a.js"
    line: 12
    line_hash: "abc123abc123abc123abc123abc12345"
    reason: "accepted risk"
    created_date: "2026-06-16"
    db_id: 7
    reviewed_by: "alice"
  - id: "exc-2"
    type: "ignore"
    status: "approved"
    rule: "SECRET-009"
    file: "src/b.js"
    line: 5
    reason: "false positive redacted"
    created_date: "2026-06-17"
`;

// A config whose second entry has no id → unmigratable → gate count mismatch.
const CONFIG_MALFORMED = `trust_level: balanced
scan_mode: full

exceptions:
  - id: "exc-good"
    type: "exception"
    status: "approved"
    rule: "SECRET-008"
    file: "src/a.js"
    line: 12
    line_hash: "abc123abc123abc123abc123abc12345"
    reason: "ok"
    created_date: "2026-06-16"
  - type: "exception"
    status: "approved"
    rule: "SECRET-010"
    file: "src/c.js"
    line: 1
    reason: "no id here"
    created_date: "2026-06-18"
`;

// ── Tests ────────────────────────────────────────────────────────────────────

describe('exceptions-store: mapConfigExceptionToRecord', () => {

  test('renames created_date → created_at (midnight UTC)', () => {
    const rec = mapConfigExceptionToRecord({
      id: 'exc-1', type: 'exception', status: 'approved',
      rule: 'R1', file: 'f.js', line: 3, line_hash: 'h', reason: 'r',
      created_date: '2026-06-16',
    });
    assert.equal(rec.created_at, '2026-06-16T00:00:00.000Z');
    assert.ok(!('created_date' in rec), 'created_date must not survive');
  });

  test('drops finding_id, never stored', () => {
    const rec = mapConfigExceptionToRecord({
      id: 'x', rule: 'R', file: 'f', reason: 'r', created_date: '2026-06-16',
      finding_id: 'f-deadbeef00',
    });
    assert.ok(!('finding_id' in rec));
  });

  test('omits optional line_hash entirely (not null-written)', () => {
    const rec = mapConfigExceptionToRecord({
      id: 'x', rule: 'R', file: 'f', line: 1, reason: 'r', created_date: '2026-06-16',
    });
    assert.ok(!('line_hash' in rec), 'absent line_hash must be omitted, not null');
  });

  test('preserves sync fields and unknown/reserved fields', () => {
    const rec = mapConfigExceptionToRecord({
      id: 'x', rule: 'R', file: 'f', line: 1, reason: 'r', created_date: '2026-06-16',
      db_id: 9, reviewed_by: 'bob', review_comment: 'ok',
      branch: 'feature/x',   // reserved (E1b) — must survive forward-compat
    });
    assert.equal(rec.db_id, 9);
    assert.equal(rec.reviewed_by, 'bob');
    assert.equal(rec.review_comment, 'ok');
    assert.equal(rec.branch, 'feature/x');
  });

  test('returns null when identity fields are missing', () => {
    assert.equal(mapConfigExceptionToRecord({ type: 'exception', rule: 'R', file: 'f' }), null); // no id
    assert.equal(mapConfigExceptionToRecord({ id: 'x', file: 'f' }), null);                       // no rule
    assert.equal(mapConfigExceptionToRecord({ id: 'x', rule: 'R' }), null);                       // no file
  });
});

describe('exceptions-store: verifyBootstrapGate', () => {
  const cfg = [
    { id: 'a', rule: 'R1', file: 'f1', line_hash: 'h1' },
    { id: 'b', rule: 'R2', file: 'f2' },
  ];

  test('passes when jsonl mirrors config', () => {
    const jsonl = [
      { id: 'a', rule: 'R1', file: 'f1', line_hash: 'h1' },
      { id: 'b', rule: 'R2', file: 'f2' },
    ];
    assert.equal(verifyBootstrapGate(jsonl, cfg).ok, true);
  });

  test('fails on count mismatch', () => {
    const r = verifyBootstrapGate([{ id: 'a', rule: 'R1', file: 'f1', line_hash: 'h1' }], cfg);
    assert.equal(r.ok, false);
    assert.match(r.reason, /count mismatch/);
  });

  test('fails on identity drift', () => {
    const jsonl = [
      { id: 'a', rule: 'R1', file: 'WRONG', line_hash: 'h1' },
      { id: 'b', rule: 'R2', file: 'f2' },
    ];
    assert.equal(verifyBootstrapGate(jsonl, cfg).ok, false);
  });

  test('fails on line_hash drift', () => {
    const jsonl = [
      { id: 'a', rule: 'R1', file: 'f1', line_hash: 'DIFFERENT' },
      { id: 'b', rule: 'R2', file: 'f2' },
    ];
    assert.equal(verifyBootstrapGate(jsonl, cfg).ok, false);
  });
});

describe('exceptions-store: loadExceptions', () => {

  test('returns [] when file is absent', () => {
    const r = mkTempRepo();
    try { assert.deepEqual(loadExceptions(r), []); } finally { cleanup(r); }
  });
});

describe('exceptions-store: bootstrap-on-read', () => {

  test('happy path: materializes jsonl, upgrades created_at, strips block, sets marker, preserves other keys', () => {
    const r = mkTempRepo();
    try {
      writeConfig(r, CONFIG_TWO);
      const res = loadExceptionsWithBootstrap(r);

      assert.equal(res.bootstrapped, true);
      assert.equal(res.records.length, 2);

      // jsonl on disk has both records
      const onDisk = loadExceptions(r);
      assert.equal(onDisk.length, 2);
      const e1 = onDisk.find(x => x.id === 'exc-1');
      const e2 = onDisk.find(x => x.id === 'exc-2');

      // created_at upgraded to UTC ISO-8601 (midnight UTC of the date)
      assert.equal(e1.created_at, '2026-06-16T00:00:00.000Z');
      assert.equal(e2.created_at, '2026-06-17T00:00:00.000Z');
      assert.ok(!('created_date' in e1));

      // hashed vs redacted
      assert.equal(e1.line_hash, 'abc123abc123abc123abc123abc12345');
      assert.ok(!('line_hash' in e2), 'redacted exception keeps line_hash absent');

      // sync fields preserved
      assert.equal(e1.db_id, 7);
      assert.equal(e1.reviewed_by, 'alice');

      // config: exceptions block gone, marker set, OTHER keys verbatim
      const cfg = readConfig(r);
      assert.ok(!/^exceptions:\s*$/m.test(cfg), 'exceptions: block must be removed');
      assert.match(cfg, new RegExp(`^${MIGRATION_MARKER}: true$`, 'm'));
      assert.match(cfg, /^trust_level: balanced$/m);
      assert.match(cfg, /^scan_mode: full$/m);
      assert.match(cfg, /^locked_rules:$/m);
      assert.match(cfg, /^ {2}- SECRET-001$/m);

      // file perms 0o600 on the jsonl
      const mode = fs.statSync(exceptionsPathReadOnly(r)).mode & 0o777;
      assert.equal(mode, 0o600);
    } finally { cleanup(r); }
  });

  test('second read does NOT re-bootstrap and does NOT touch config', () => {
    const r = mkTempRepo();
    try {
      writeConfig(r, CONFIG_TWO);
      loadExceptionsWithBootstrap(r);                 // first read migrates
      const cfgAfter1  = readConfig(r);
      const jsonlAfter1 = fs.readFileSync(exceptionsPathReadOnly(r), 'utf8');

      const res2 = loadExceptionsWithBootstrap(r);    // second read
      assert.equal(res2.bootstrapped, false);
      assert.equal(res2.records.length, 2);

      assert.equal(readConfig(r), cfgAfter1, 'config must be untouched on second read');
      assert.equal(fs.readFileSync(exceptionsPathReadOnly(r), 'utf8'), jsonlAfter1, 'jsonl must be untouched');
    } finally { cleanup(r); }
  });

  test('gate failure leaves config untouched, removes partial jsonl, idempotent on retry', () => {
    const r = mkTempRepo();
    try {
      writeConfig(r, CONFIG_MALFORMED);
      const before = readConfig(r);

      const res = loadExceptionsWithBootstrap(r);
      assert.equal(res.gateFailed, true);
      assert.equal(res.bootstrapped, false);

      // config untouched: block still present, no marker
      const after = readConfig(r);
      assert.equal(after, before, 'config must be byte-identical after a gate failure');
      assert.ok(/^exceptions:\s*$/m.test(after), 'block must remain');
      assert.ok(!new RegExp(`${MIGRATION_MARKER}`).test(after), 'marker must NOT be set');

      // partial jsonl removed → next read re-bootstraps from intact config
      assert.equal(fs.existsSync(exceptionsPathReadOnly(r)), false, 'partial jsonl must be removed');

      // retry: still fails the same way, config still intact (idempotent)
      const res2 = loadExceptionsWithBootstrap(r);
      assert.equal(res2.gateFailed, true);
      assert.equal(readConfig(r), before);
    } finally { cleanup(r); }
  });

  test('no exceptions in config → nothing migrated, no marker churn', () => {
    const r = mkTempRepo();
    try {
      writeConfig(r, 'trust_level: balanced\nscan_mode: full\n');
      const res = loadExceptionsWithBootstrap(r);
      assert.equal(res.bootstrapped, false);
      assert.deepEqual(res.records, []);
      assert.equal(fs.existsSync(exceptionsPathReadOnly(r)), false);
    } finally { cleanup(r); }
  });
});

describe('exceptions-store: buildExceptionRecord', () => {

  test('happy path: created_at verbatim, reserved fields absent, sync fields only when supplied', () => {
    const rec = buildExceptionRecord({
      id: 'exc-1', type: 'exception', tag: 'risk', status: 'approved',
      rule: 'R1', file: 'f.js', line: 3, line_hash: 'h',
      reason: 'r', created_at: '2026-06-16T00:00:00.000Z',
    });
    assert.equal(rec.created_at, '2026-06-16T00:00:00.000Z');   // taken verbatim, no date math
    for (const f of ['branch', 'archived_at', 'archive_reason', 'expires', 'review_date',
                     'db_id', 'reviewed_by', 'review_comment']) {
      assert.ok(!(f in rec), `${f} must be absent when not supplied`);
    }
  });

  test('redacted/hashless case: line_hash omitted, not null', () => {
    const rec = buildExceptionRecord({
      id: 'x', type: 'ignore', status: 'pending', rule: 'R', file: 'f', line: 1,
      reason: 'r', created_at: '2026-06-16T00:00:00.000Z',
    });
    assert.ok(!('line_hash' in rec));
  });

  test('finding_id is never emitted, even when supplied', () => {
    const rec = buildExceptionRecord({
      id: 'x', rule: 'R', file: 'f', reason: 'r', created_at: '2026-06-16T00:00:00.000Z',
      finding_id: 'f-deadbeef00',
    });
    assert.ok(!('finding_id' in rec));
  });

  test('sync fields and reserved fields pass through only when supplied', () => {
    const rec = buildExceptionRecord({
      id: 'x', rule: 'R', file: 'f', reason: 'r', created_at: '2026-06-16T00:00:00.000Z',
      db_id: 9, reviewed_by: 'bob', review_comment: 'ok', branch: 'feature/x',
    });
    assert.equal(rec.db_id, 9);
    assert.equal(rec.reviewed_by, 'bob');
    assert.equal(rec.review_comment, 'ok');
    assert.equal(rec.branch, 'feature/x');   // reserved name rides through forward-compat
  });
});

describe('exceptions-store: mapConfigExceptionToRecord (re-routed through builder)', () => {
  // Byte-identical expectations locked against the pre-refactor mapper output.

  test('accept: exact JSON preserved', () => {
    const out = mapConfigExceptionToRecord({
      id: 'exc-a', type: 'exception', tag: 'risk', status: 'approved',
      rule: 'SECRET-008', file: 'src/a.js', line: 12,
      line_hash: 'abc123abc123abc123abc123abc12345', reason: 'accepted',
      created_date: '2026-06-16', db_id: 7, reviewed_by: 'alice', review_comment: 'ok',
    });
    assert.equal(JSON.stringify(out),
      '{"id":"exc-a","type":"exception","tag":"risk","status":"approved","rule":"SECRET-008",' +
      '"file":"src/a.js","line":12,"line_hash":"abc123abc123abc123abc123abc12345","reason":"accepted",' +
      '"created_at":"2026-06-16T00:00:00.000Z","db_id":7,"reviewed_by":"alice","review_comment":"ok"}');
  });

  test('ignore: exact JSON preserved', () => {
    const out = mapConfigExceptionToRecord({
      id: 'exc-i', type: 'ignore', status: 'approved', rule: 'SECRET-009',
      file: 'src/b.js', line: 5, line_hash: 'def456def456def456def456def45678',
      reason: 'fp', created_date: '2026-06-17',
    });
    assert.equal(JSON.stringify(out),
      '{"id":"exc-i","type":"ignore","status":"approved","rule":"SECRET-009","file":"src/b.js",' +
      '"line":5,"line_hash":"def456def456def456def456def45678","reason":"fp",' +
      '"created_at":"2026-06-17T00:00:00.000Z"}');
  });

  test('redacted: hashless, finding_id dropped, exact JSON preserved', () => {
    const out = mapConfigExceptionToRecord({
      id: 'exc-r', type: 'ignore', status: 'pending', rule: 'SECRET-010',
      file: 'src/c.js', line: 8, reason: 'redacted', created_date: '2026-06-18',
      finding_id: 'f-deadbeef00',
    });
    assert.equal(JSON.stringify(out),
      '{"id":"exc-r","type":"ignore","status":"pending","rule":"SECRET-010","file":"src/c.js",' +
      '"line":8,"reason":"redacted","created_at":"2026-06-18T00:00:00.000Z"}');
  });

  test('missing identity still returns null (unchanged)', () => {
    assert.equal(mapConfigExceptionToRecord({ rule: 'R', file: 'f' }), null);
  });
});

describe('exceptions-store: writeExceptions', () => {

  test('writes the full set atomically (0o600, no leftover .tmp) and round-trips', () => {
    const r = mkTempRepo();
    try {
      const recs = [
        buildExceptionRecord({ id: 'e1', type: 'exception', status: 'approved',
          rule: 'R1', file: 'a.js', line: 1, line_hash: 'h1', reason: 'x',
          created_at: '2026-06-16T00:00:00.000Z' }),
        buildExceptionRecord({ id: 'e2', type: 'ignore', status: 'pending',
          rule: 'R2', file: 'b.js', line: 2, reason: 'y',
          created_at: '2026-06-17T00:00:00.000Z' }),
      ];
      writeExceptions(r, recs);

      const target = exceptionsPathReadOnly(r);
      assert.equal(fs.statSync(target).mode & 0o777, 0o600);
      assert.equal(fs.existsSync(target + '.tmp'), false);

      const back = loadExceptions(r);
      assert.equal(back.length, 2);
      assert.deepEqual(back, recs);
    } finally { cleanup(r); }
  });

  test('full-set rewrite replaces prior contents (not append)', () => {
    const r = mkTempRepo();
    try {
      writeExceptions(r, [{ id: 'old' }]);
      writeExceptions(r, [{ id: 'new' }]);
      const back = loadExceptions(r);
      assert.equal(back.length, 1);
      assert.equal(back[0].id, 'new');
    } finally { cleanup(r); }
  });

  test('empty set writes an empty store file', () => {
    const r = mkTempRepo();
    try {
      writeExceptions(r, []);
      assert.equal(fs.existsSync(exceptionsPathReadOnly(r)), true);
      assert.deepEqual(loadExceptions(r), []);
    } finally { cleanup(r); }
  });
});
