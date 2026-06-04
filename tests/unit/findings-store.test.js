/**
 * findings-store.test.js
 * Unit tests for lib/findings-store.js
 *
 * Run: npm test  (or: node --test tests/unit/findings-store.test.js)
 *
 * Note: each test creates a unique repoRoot under os.tmpdir() and cleans up
 * both the temp repoRoot and the corresponding ~/.scd/repos/{id}/ store dir.
 * Branch context is passed explicitly via options so tests don't spawn git.
 */

'use strict';

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const fs                 = require('fs');
const os                 = require('os');
const path               = require('path');
const crypto             = require('crypto');

const repoRoot = path.resolve(__dirname, '../..');
const { loadFindings, updateFindings } = require(path.join(repoRoot, 'lib/findings-store'));
const { findingsPath, findingsPathReadOnly } = require(path.join(repoRoot, 'lib/store'));

// ── Helpers ────────────────────────────────────────────────────────────────

let setupCounter = 0;

function mkTempRepo() {
  const id = `${process.pid}-${Date.now()}-${setupCounter++}-${crypto.randomBytes(4).toString('hex')}`;
  const dir = path.join(os.tmpdir(), `scd-findings-store-test-${id}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(testRepoRoot) {
  // Remove the store dir (~/.scd/repos/{id}/) created by findingsPath()
  try {
    const storeFile = findingsPathReadOnly(testRepoRoot);
    const storeDir  = path.dirname(storeFile);
    fs.rmSync(storeDir, { recursive: true, force: true });
  } catch { /* best-effort */ }
  // Remove the temp repo root
  try { fs.rmSync(testRepoRoot, { recursive: true, force: true }); } catch {}
}

function makeFinding(overrides = {}) {
  const ruleId   = overrides.ruleId   || 'TEST-001';
  const filePath = overrides.filePath || 'src/app.js';
  const line     = overrides.line     || 42;
  const snippet  = overrides.snippet  || 'const x = req.body.input;';
  const codeHash = overrides.codeHash !== undefined
    ? overrides.codeHash
    : crypto.createHash('sha256').update(snippet).digest('hex').slice(0, 32);
  const findingId = overrides.findingId || (
    'f-' + crypto.createHash('sha256')
      .update(ruleId + '|' + filePath + '|' + snippet)
      .digest('hex').slice(0, 10)
  );
  return {
    ruleId,
    filePath,
    line,
    snippet,
    codeHash,
    findingId,
    severity:   overrides.severity   || 'HIGH',
    ...(overrides.confidence !== undefined ? { confidence: overrides.confidence } : {}),
    ...(overrides.base_severity !== undefined ? { base_severity: overrides.base_severity } : {}),
    ...(overrides.excepted !== undefined ? { excepted: overrides.excepted } : {}),
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('findings-store', () => {

  test('loadFindings returns [] when file does not exist', () => {
    const r = mkTempRepo();
    try {
      assert.deepEqual(loadFindings(r), []);
    } finally { cleanup(r); }
  });

  test('updateFindings inserts a new finding with correct schema', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ confidence: 'HIGH' });
      const result = updateFindings(r, [f], {
        scanId: 's-aaaa1111',
        branch: 'main',
        isDefaultBranch: true,
      });

      assert.equal(result.added, 1);
      assert.equal(result.refreshed, 0);
      assert.equal(result.skipped, 0);
      assert.equal(result.total, 1);

      const records = loadFindings(r);
      assert.equal(records.length, 1);
      const rec = records[0];
      assert.equal(rec.finding_id, f.findingId);
      assert.equal(rec.rule_id, 'TEST-001');
      assert.equal(rec.file, 'src/app.js');
      assert.equal(rec.line, 42);
      assert.equal(rec.code_hash, f.codeHash);
      assert.equal(rec.status, 'open');
      assert.equal(rec.severity, 'HIGH');
      assert.equal(rec.base_severity, 'HIGH');
      assert.equal(rec.confidence, 'HIGH');
      assert.equal(rec.times_seen, 1);
      assert.equal(rec.reopen_count, 0);
      assert.equal(rec.snippet, f.snippet);
      assert.equal(rec.branch, 'main');
      assert.equal(rec.is_default_branch, true);
      assert.equal(rec.last_scan_id, 's-aaaa1111');
      assert.equal(rec.first_seen, rec.last_seen);
    } finally { cleanup(r); }
  });

  test('updateFindings refresh preserves first_seen, increments times_seen', async () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      updateFindings(r, [f], { scanId: 's-first', branch: 'main', isDefaultBranch: true });
      const initial = loadFindings(r)[0];

      // ensure timestamp changes (ISO ms resolution)
      await new Promise(res => setTimeout(res, 5));

      const result = updateFindings(r, [f], { scanId: 's-second', branch: 'main', isDefaultBranch: true });
      assert.equal(result.added, 0);
      assert.equal(result.refreshed, 1);
      assert.equal(result.total, 1);

      const updated = loadFindings(r)[0];
      assert.equal(updated.finding_id, initial.finding_id);
      assert.equal(updated.first_seen, initial.first_seen, 'first_seen preserved');
      assert.notEqual(updated.last_seen, initial.last_seen, 'last_seen advances');
      assert.equal(updated.last_scan_id, 's-second');
      assert.equal(updated.times_seen, 2);
      assert.equal(updated.reopen_count, 0);
      assert.equal(updated.status, 'open');
    } finally { cleanup(r); }
  });

  test('updateFindings refresh updates mutable fields (severity, line, snippet, branch)', () => {
    const r = mkTempRepo();
    try {
      const original = makeFinding({
        severity: 'CRITICAL',
        line:     10,
        snippet:  'const x = req.body.input;',
      });
      updateFindings(r, [original], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Same finding_id, but severity downgraded (modifier), line shifted, snippet updated
      const refreshed = makeFinding({
        findingId: original.findingId,
        codeHash:  original.codeHash,
        ruleId:    original.ruleId,
        filePath:  original.filePath,
        severity:  'HIGH',
        base_severity: 'CRITICAL',
        line:      15,
        snippet:   '  const x = req.body.input;', // leading whitespace
      });
      updateFindings(r, [refreshed], {
        scanId: 's-2',
        branch: 'feature/x',
        isDefaultBranch: false,
      });

      const rec = loadFindings(r)[0];
      assert.equal(rec.severity, 'HIGH');
      assert.equal(rec.base_severity, 'CRITICAL');
      assert.equal(rec.line, 15);
      assert.equal(rec.snippet, '  const x = req.body.input;');
      assert.equal(rec.branch, 'feature/x');
      assert.equal(rec.is_default_branch, false);
    } finally { cleanup(r); }
  });

  test('updateFindings preserves records not in scanner output', () => {
    const r = mkTempRepo();
    try {
      const fA = makeFinding({ ruleId: 'A', line: 1 });
      const fB = makeFinding({ ruleId: 'B', line: 2 });
      updateFindings(r, [fA, fB], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Second scan only sees A — B must be preserved (resolve is Step 2)
      updateFindings(r, [fA], { scanId: 's-2', branch: 'main', isDefaultBranch: true });

      const records = loadFindings(r);
      const ids = records.map(r => r.finding_id).sort();
      assert.deepEqual(ids, [fA.findingId, fB.findingId].sort());
    } finally { cleanup(r); }
  });

  test('updateFindings skips findings with null code_hash and reports skipped count', () => {
    const r = mkTempRepo();
    try {
      const valid    = makeFinding({ ruleId: 'A' });
      const noHash   = makeFinding({ ruleId: 'B', codeHash: null });
      const emptyStr = makeFinding({ ruleId: 'C', codeHash: '' });

      // Capture stderr (the WARN line)
      const originalWrite = process.stderr.write.bind(process.stderr);
      const captured = [];
      process.stderr.write = (chunk) => { captured.push(String(chunk)); return true; };

      let result;
      try {
        result = updateFindings(r, [valid, noHash, emptyStr], {
          scanId: 's-1',
          branch: 'main',
          isDefaultBranch: true,
        });
      } finally {
        process.stderr.write = originalWrite;
      }

      assert.equal(result.added, 1);
      assert.equal(result.skipped, 2);
      assert.equal(result.total, 1);
      const records = loadFindings(r);
      assert.equal(records.length, 1);
      assert.equal(records[0].rule_id, 'A');
      // Should have logged at least 2 WARN lines
      const warnLines = captured.filter(c => c.includes('[WARN]'));
      assert.ok(warnLines.length >= 2, 'expected 2+ WARN lines for skipped findings');
    } finally { cleanup(r); }
  });

  test('updateFindings silently skips findings without findingId', () => {
    const r = mkTempRepo();
    try {
      const valid = makeFinding({ ruleId: 'A' });
      const noFid = makeFinding({ ruleId: 'B' });
      noFid.findingId = '';  // helper's `|| default` swallows '' overrides — clear post-build
      const result = updateFindings(r, [valid, noFid], {
        scanId: 's-1', branch: 'main', isDefaultBranch: true,
      });
      assert.equal(result.added, 1);
      assert.equal(result.total, 1);
    } finally { cleanup(r); }
  });

  test('updateFindings with empty array still creates the file', () => {
    const r = mkTempRepo();
    try {
      const result = updateFindings(r, [], {
        scanId: 's-1', branch: 'main', isDefaultBranch: true,
      });
      assert.equal(result.added, 0);
      assert.equal(result.refreshed, 0);
      assert.equal(result.total, 0);

      const target = findingsPathReadOnly(r);
      assert.ok(fs.existsSync(target), 'findings.jsonl exists after empty update');
      assert.equal(fs.readFileSync(target, 'utf8'), '');
    } finally { cleanup(r); }
  });

  test('findings.jsonl is created with mode 0o600', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      const target = findingsPathReadOnly(r);
      const stat = fs.statSync(target);
      // Mask off file type bits, compare permission bits
      assert.equal(stat.mode & 0o777, 0o600);
    } finally { cleanup(r); }
  });

  test('confidence is omitted from record when scanner did not set it', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding(); // makeFinding does not set confidence by default
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      const rec = loadFindings(r)[0];
      assert.equal(Object.prototype.hasOwnProperty.call(rec, 'confidence'), false,
        'confidence key absent when undefined on input');
    } finally { cleanup(r); }
  });

  test('confidence is preserved on insert and refresh when present', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ confidence: 'MEDIUM' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      assert.equal(loadFindings(r)[0].confidence, 'MEDIUM');

      const f2 = makeFinding({
        findingId: f.findingId, codeHash: f.codeHash,
        ruleId: f.ruleId, filePath: f.filePath,
        confidence: 'LOW',
      });
      updateFindings(r, [f2], { scanId: 's-2', branch: 'main', isDefaultBranch: true });
      assert.equal(loadFindings(r)[0].confidence, 'LOW');
    } finally { cleanup(r); }
  });

  test('loadFindings skips corrupt lines and surfaces a WARN', () => {
    const r = mkTempRepo();
    try {
      // Seed a valid record + a corrupt line by going through updateFindings
      const f = makeFinding();
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Append a corrupt line directly
      const target = findingsPathReadOnly(r);
      fs.appendFileSync(target, '{not valid json\n', { mode: 0o600 });

      // Capture stderr
      const originalWrite = process.stderr.write.bind(process.stderr);
      const captured = [];
      process.stderr.write = (chunk) => { captured.push(String(chunk)); return true; };

      let records;
      try { records = loadFindings(r); }
      finally { process.stderr.write = originalWrite; }

      assert.equal(records.length, 1, 'valid record preserved');
      const warnLines = captured.filter(c => c.includes('[WARN]') && c.includes('corrupt'));
      assert.ok(warnLines.length >= 1, 'expected WARN for corrupt line');
    } finally { cleanup(r); }
  });

  test('roundtrip: write then read returns identical records', () => {
    const r = mkTempRepo();
    try {
      const fs1 = [
        makeFinding({ ruleId: 'A', line: 1, confidence: 'HIGH' }),
        makeFinding({ ruleId: 'B', line: 2 }),
        makeFinding({ ruleId: 'C', line: 3, base_severity: 'CRITICAL', severity: 'HIGH' }),
      ];
      updateFindings(r, fs1, { scanId: 's-1', branch: 'develop', isDefaultBranch: false });
      const records = loadFindings(r);
      assert.equal(records.length, 3);
      // Each record passes JSON.stringify→parse roundtrip equivalence (sanity)
      for (const rec of records) {
        const cloned = JSON.parse(JSON.stringify(rec));
        assert.deepEqual(cloned, rec);
      }
    } finally { cleanup(r); }
  });

  test('forward-compatibility: unknown fields on existing records are preserved on refresh', () => {
    const r = mkTempRepo();
    try {
      // Seed an initial record, then post-hoc add a future-field to simulate a
      // newer CLI version having written it.
      const f = makeFinding();
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      const target = findingsPathReadOnly(r);
      const lines = fs.readFileSync(target, 'utf8').split('\n').filter(Boolean);
      const rec = JSON.parse(lines[0]);
      rec.future_field_x = 'must-survive';
      fs.writeFileSync(target, JSON.stringify(rec) + '\n', { mode: 0o600 });

      // Refresh via a new scan
      updateFindings(r, [f], { scanId: 's-2', branch: 'main', isDefaultBranch: true });

      const after = loadFindings(r)[0];
      assert.equal(after.future_field_x, 'must-survive');
      assert.equal(after.times_seen, 2);
    } finally { cleanup(r); }
  });

});
