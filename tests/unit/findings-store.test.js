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
const { loadFindings, updateFindings, loadFindingsWithBootstrap } = require(path.join(repoRoot, 'lib/findings-store'));
const { findingsPath, findingsPathReadOnly, scanCachePath, updateMeta } = require(path.join(repoRoot, 'lib/store'));

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

  test('updateFindings with `at` option uses provided timestamp for first_seen/last_seen', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      const historical = '2026-04-01T08:00:00.000Z';
      updateFindings(r, [f], {
        scanId: 's-historical',
        branch: 'main',
        isDefaultBranch: true,
        at:     historical,
      });
      const rec = loadFindings(r)[0];
      assert.equal(rec.first_seen, historical);
      assert.equal(rec.last_seen,  historical);
    } finally { cleanup(r); }
  });

  test('updateFindings with `at` option accepts Date object', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      const historical = new Date('2026-04-01T08:00:00.000Z');
      updateFindings(r, [f], {
        scanId: 's-historical',
        branch: 'main',
        isDefaultBranch: true,
        at:     historical,
      });
      const rec = loadFindings(r)[0];
      assert.equal(rec.first_seen, historical.toISOString());
    } finally { cleanup(r); }
  });

});

// ── Bootstrap tests ────────────────────────────────────────────────────────

function writeFakeCache(repoRoot, payload) {
  const target = scanCachePath(repoRoot);
  fs.writeFileSync(target, JSON.stringify(payload, null, 2), { encoding: 'utf8', mode: 0o600 });
}

describe('loadFindingsWithBootstrap', () => {

  test('returns store records directly when findings.jsonl exists', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      // Touch meta so we can verify lastScanDate is read
      updateMeta(r, { findingCount: 1, criticalCount: 0 });

      const result = loadFindingsWithBootstrap(r);
      assert.equal(result.bootstrapped, false);
      assert.equal(result.records.length, 1);
      assert.equal(result.records[0].finding_id, f.findingId);
      assert.ok(result.lastScanDate, 'lastScanDate from meta.json');
    } finally { cleanup(r); }
  });

  test('bootstraps from last-scan.json when findings.jsonl missing', () => {
    const r = mkTempRepo();
    try {
      const cacheScanDate = '2026-04-15T10:30:00.000Z';
      const f = makeFinding({ confidence: 'HIGH' });

      writeFakeCache(r, {
        scanId:   's-cached',
        scanDate: cacheScanDate,
        target:   '.',
        totalFiles: 1,
        findings: [{
          findingId: f.findingId,
          ruleId:    f.ruleId,
          filePath:  f.filePath,
          line:      f.line,
          codeHash:  f.codeHash,
          snippet:   f.snippet,
          severity:  f.severity,
          confidence: f.confidence,
        }],
        suppressed_findings: [],
      });

      // No findings.jsonl yet — bootstrap path
      assert.equal(fs.existsSync(findingsPathReadOnly(r)), false);

      const result = loadFindingsWithBootstrap(r);
      assert.equal(result.bootstrapped, true);
      assert.equal(result.records.length, 1);
      assert.equal(result.records[0].finding_id, f.findingId);
      assert.equal(result.records[0].first_seen, cacheScanDate,
        'first_seen reflects cache scanDate, not now');
      assert.equal(result.records[0].last_seen, cacheScanDate);
      assert.equal(result.records[0].last_scan_id, 's-cached');
      assert.equal(result.lastScanDate, cacheScanDate);
      // And the file is now materialized
      assert.equal(fs.existsSync(findingsPathReadOnly(r)), true);
    } finally { cleanup(r); }
  });

  test('bootstrap is one-time — subsequent calls read directly without re-bootstrapping', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding();
      writeFakeCache(r, {
        scanId:   's-cached',
        scanDate: '2026-04-15T10:30:00.000Z',
        target:   '.',
        totalFiles: 1,
        findings: [{
          findingId: f.findingId, ruleId: f.ruleId, filePath: f.filePath,
          line: f.line, codeHash: f.codeHash, snippet: f.snippet,
          severity: f.severity,
        }],
        suppressed_findings: [],
      });

      const first  = loadFindingsWithBootstrap(r);
      const second = loadFindingsWithBootstrap(r);

      assert.equal(first.bootstrapped, true);
      assert.equal(second.bootstrapped, false, 'second call hits direct read path');
      assert.equal(second.records.length, first.records.length);
      assert.equal(second.records[0].finding_id, first.records[0].finding_id);
    } finally { cleanup(r); }
  });

  test('returns empty result when neither store nor cache exists', () => {
    const r = mkTempRepo();
    try {
      const result = loadFindingsWithBootstrap(r);
      assert.deepEqual(result.records, []);
      assert.equal(result.bootstrapped, false);
      assert.equal(result.lastScanDate, null);
      // No file materialized
      assert.equal(fs.existsSync(findingsPathReadOnly(r)), false);
    } finally { cleanup(r); }
  });

  test('bootstrap with empty cache.findings still materializes an empty store', () => {
    const r = mkTempRepo();
    try {
      writeFakeCache(r, {
        scanId:   's-empty',
        scanDate: '2026-04-15T10:30:00.000Z',
        target:   '.',
        totalFiles: 0,
        findings: [],
        suppressed_findings: [],
      });
      const result = loadFindingsWithBootstrap(r);
      assert.equal(result.bootstrapped, true);
      assert.equal(result.records.length, 0);
      assert.equal(fs.existsSync(findingsPathReadOnly(r)), true);
      // Second call: store exists → not bootstrap path
      const second = loadFindingsWithBootstrap(r);
      assert.equal(second.bootstrapped, false);
    } finally { cleanup(r); }
  });

});

// ── Step 2 — reconcile (resolve + reopen) ──────────────────────────────────
//
// Rule-id choices used below are intentional:
//   - 'JS-PATH-001'  is in getRegistry() but NOT in scanner-secrets.RULES
//     (full-domain eligible, secrets-domain ineligible).
//   - 'SECRET-001'   is in both (covers full + secrets domains).
//   - 'NONEXISTENT-999' is in neither (unknown to registry).

describe('updateFindings — reconcile (Step 2)', () => {

  // ── Test 1 ────────────────────────────────────────────────────────────────
  test('1. open + not reported + file covered + rule eligible → resolved (last_seen unchanged)', async () => {
    const r = mkTempRepo();
    try {
      // Seed an open finding via a normal scan-like insert
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      const seeded = loadFindings(r)[0];

      // ensure timestamps would differ if last_seen DID update
      await new Promise(res => setTimeout(res, 5));

      // Next scan: empty findings, file covered, full domain. Finding should resolve.
      const result = updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        branch:   'main',
        isDefaultBranch: true,
      });

      assert.equal(result.resolved, 1);
      assert.equal(result.reopened, 0);
      assert.equal(result.totalOpen, 0);
      assert.equal(result.resolvedRecords.length, 1);

      const rec = loadFindings(r)[0];
      assert.equal(rec.status, 'resolved');
      assert.ok(rec.resolved_at, 'resolved_at is set');
      assert.equal(rec.last_seen, seeded.last_seen,
        'last_seen MUST NOT advance on resolve (it means last confirmed present)');
      assert.equal(rec.last_scan_id, seeded.last_scan_id,
        'last_scan_id MUST NOT advance on resolve');
      assert.equal(rec.times_seen, seeded.times_seen,
        'times_seen MUST NOT advance on resolve');
    } finally { cleanup(r); }
  });

  // ── Test 2 ────────────────────────────────────────────────────────────────
  test('2. open + not reported + file NOT in coverage → untouched', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      const result = updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/other.js'], ruleDomain: 'all' },  // app.js not covered
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 0);
      assert.equal(loadFindings(r)[0].status, 'open');
    } finally { cleanup(r); }
  });

  // ── Test 3 ────────────────────────────────────────────────────────────────
  test('3. open non-secrets rule + ruleDomain=secrets + file covered → untouched (OWASP guard)', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Pre-commit-style secrets-only scan, file is covered, but rule is NOT secrets.
      // Must NOT resolve — the secrets scan never ran path-traversal rules.
      const result = updateFindings(r, [], {
        scanId:   's-secrets',
        coverage: { files: ['src/app.js'], ruleDomain: 'secrets' },
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 0);
      assert.equal(loadFindings(r)[0].status, 'open');
    } finally { cleanup(r); }
  });

  // ── Test 4 ────────────────────────────────────────────────────────────────
  test('4. secrets rule + ruleDomain=secrets + file covered + not reported → resolved', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'SECRET-001', filePath: 'config.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Clean pre-commit: file covered for secrets, finding gone → resolved.
      // This is the §3 hook-mode example.
      const result = updateFindings(r, [], {
        scanId:   's-secrets',
        coverage: { files: ['config.js'], ruleDomain: 'secrets' },
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 1);
      assert.equal(loadFindings(r)[0].status, 'resolved');
    } finally { cleanup(r); }
  });

  // ── Test 5 ────────────────────────────────────────────────────────────────
  test('5. resolved + reported again → reopened (status=open, reopen_count++, resolved_at gone)', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      // Resolve it
      updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        branch:   'main', isDefaultBranch: true,
      });
      assert.equal(loadFindings(r)[0].status, 'resolved');
      const timesBefore = loadFindings(r)[0].times_seen;

      // Reopen by reporting again
      const result = updateFindings(r, [f], {
        scanId:   's-3',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.reopened, 1);
      assert.equal(result.added, 0);
      assert.equal(result.refreshed, 0);
      const rec = loadFindings(r)[0];
      assert.equal(rec.status, 'open');
      assert.equal(rec.reopen_count, 1);
      assert.equal(rec.resolved_at, undefined, 'resolved_at is removed on reopen');
      assert.equal(rec.times_seen, timesBefore + 1, 'times_seen advances on reopen');
      assert.equal(rec.last_scan_id, 's-3');
    } finally { cleanup(r); }
  });

  // ── Test 6 ────────────────────────────────────────────────────────────────
  test('6. open + id present ONLY in suppressed → untouched (no refresh, no resolve)', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });
      const seeded = loadFindings(r)[0];

      // The finding shows up only in the suppressed bucket this scan.
      // Must NOT be refreshed (no active sighting) AND must NOT be resolved
      // (suppression is not absence — its rule ran and matched).
      const result = updateFindings(r, [], {
        scanId:     's-2',
        coverage:   { files: ['src/app.js'], ruleDomain: 'all' },
        suppressed: [f],
        branch:     'main', isDefaultBranch: true,
      });

      assert.equal(result.refreshed, 0);
      assert.equal(result.resolved, 0);
      const rec = loadFindings(r)[0];
      assert.equal(rec.status, 'open');
      assert.equal(rec.last_seen, seeded.last_seen, 'last_seen unchanged (no refresh)');
      assert.equal(rec.times_seen, seeded.times_seen, 'times_seen unchanged');
    } finally { cleanup(r); }
  });

  // ── Test 7 ────────────────────────────────────────────────────────────────
  test('7. open + (rule, file) matches scope rule-exclusion → untouched despite coverage', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      const scope = {
        file_excludes: [],
        rule_excludes: [{ rule: 'JS-PATH-001', files: ['src/app.js'], reason: 'test' }],
      };

      const result = updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        scope,
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 0);
      assert.equal(loadFindings(r)[0].status, 'open');
    } finally { cleanup(r); }
  });

  // ── Test 8 ────────────────────────────────────────────────────────────────
  test('8. stored rule_id unknown to registry + ruleDomain=all + covered → untouched', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'NONEXISTENT-999', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // The rule has been removed/renamed; its absence in scan output is not
      // evidence of fix — its rule no longer runs.
      const result = updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 0);
      assert.equal(loadFindings(r)[0].status, 'open');
    } finally { cleanup(r); }
  });

  // ── Test 9 ────────────────────────────────────────────────────────────────
  test('9. no `coverage` argument → zero resolves (bootstrap invariant)', () => {
    const r = mkTempRepo();
    try {
      // Seed a few open findings that would resolve if coverage were provided
      const f1 = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/a.js', snippet: 'a()' });
      const f2 = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/b.js', snippet: 'b()' });
      updateFindings(r, [f1, f2], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // No coverage option → bootstrap-style invocation.
      // Pass empty scanFindings to "prove" they'd all be eligible if coverage WERE there.
      const result = updateFindings(r, [], {
        scanId: 's-2',
        branch: 'main', isDefaultBranch: true,
        // coverage intentionally omitted
      });

      assert.equal(result.resolved, 0,
        'BOOTSTRAP INVARIANT: no coverage ⇒ zero resolves, regardless of store contents');
      const records = loadFindings(r);
      assert.equal(records.length, 2);
      assert.ok(records.every(rec => rec.status === 'open'),
        'all records remain open without coverage');
    } finally { cleanup(r); }
  });

  // ── Test 10 ───────────────────────────────────────────────────────────────
  test('10. zero scan findings + coverage present → all covered+eligible records resolved', () => {
    const r = mkTempRepo();
    try {
      const f1 = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/a.js', snippet: 'a()' });
      const f2 = makeFinding({ ruleId: 'SECRET-001',  filePath: 'src/b.js', snippet: 'b()' });
      updateFindings(r, [f1, f2], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      const result = updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/a.js', 'src/b.js'], ruleDomain: 'all' },
        branch:   'main', isDefaultBranch: true,
      });

      assert.equal(result.resolved, 2);
      assert.equal(result.totalOpen, 0);
    } finally { cleanup(r); }
  });

  // ── Test 11 ───────────────────────────────────────────────────────────────
  test('11. unknown extra field on record survives resolve transition verbatim', () => {
    const r = mkTempRepo();
    try {
      const f = makeFinding({ ruleId: 'JS-PATH-001', filePath: 'src/app.js' });
      updateFindings(r, [f], { scanId: 's-1', branch: 'main', isDefaultBranch: true });

      // Post-hoc add a future-field, simulating a newer CLI version
      const target = findingsPathReadOnly(r);
      const rec = JSON.parse(fs.readFileSync(target, 'utf8').split('\n').filter(Boolean)[0]);
      rec.future_field_x = 'must-survive-resolve';
      fs.writeFileSync(target, JSON.stringify(rec) + '\n', { mode: 0o600 });

      updateFindings(r, [], {
        scanId:   's-2',
        coverage: { files: ['src/app.js'], ruleDomain: 'all' },
        branch:   'main', isDefaultBranch: true,
      });

      const after = loadFindings(r)[0];
      assert.equal(after.status, 'resolved');
      assert.equal(after.future_field_x, 'must-survive-resolve',
        'unknown field preserved through resolve transition');
    } finally { cleanup(r); }
  });

  // ── Test 12 ───────────────────────────────────────────────────────────────
  test('12. logReconcile writes finding_resolved + finding_reopened events with correct shape', () => {
    const r = mkTempRepo();
    try {
      const { logReconcile, EVENTS } = require(path.join(repoRoot, 'lib/audit'));
      const { auditPath } = require(path.join(repoRoot, 'lib/store'));

      const resolvedRec = {
        finding_id: 'f-abc1234567', rule_id: 'JS-PATH-001',
        file: 'src/app.js', line: 12,
        code_hash: '3fa65931a045957aea27065b1233e608',
        resolved_at: '2026-06-04T16:00:00.000Z',
      };
      const reopenedRec = {
        finding_id: 'f-def0987654', rule_id: 'SECRET-001',
        file: 'config.js', line: 5,
        code_hash: 'aabbccddeeff00112233445566778899',
        reopen_count: 1,
      };

      logReconcile(r, {
        scanId:   's-test',
        resolved: [resolvedRec],
        reopened: [reopenedRec],
        hookType: 'manual',
        noSync:   true,  // skip push
      });

      const log = fs.readFileSync(auditPath(r), 'utf8')
        .split('\n').filter(Boolean).map(l => JSON.parse(l));

      const resolvedEvt = log.find(e => e.event === EVENTS.FINDING_RESOLVED);
      const reopenedEvt = log.find(e => e.event === EVENTS.FINDING_REOPENED);

      assert.ok(resolvedEvt, 'finding_resolved event written');
      assert.equal(resolvedEvt.session_id, 's-test');
      assert.equal(resolvedEvt.finding_id, 'f-abc1234567');
      assert.equal(resolvedEvt.rule_id, 'JS-PATH-001');
      assert.equal(resolvedEvt.code_hash, '3fa65931a045957aea27065b1233e608');
      assert.equal(resolvedEvt.resolved_at, '2026-06-04T16:00:00.000Z');
      assert.equal(resolvedEvt.hook, 'manual');

      assert.ok(reopenedEvt, 'finding_reopened event written');
      assert.equal(reopenedEvt.finding_id, 'f-def0987654');
      assert.equal(reopenedEvt.reopen_count, 1);
      assert.equal(reopenedEvt.code_hash, 'aabbccddeeff00112233445566778899');
    } finally { cleanup(r); }
  });

});
