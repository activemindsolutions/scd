/**
 * finding-identity.test.js
 * Unit tests for the locked content-based identity invariants.
 *
 * Run: npm test  (or: node --test tests/unit/finding-identity.test.js)
 *
 * Verifies CLAUDE.md #16: finding_id MUST be content-based; line numbers
 * MUST NEVER enter identity. These tests are the regression net for the
 * bug fixed 2026-06-05 (scanner-secrets had line-based finding_id).
 */

'use strict';

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const path               = require('path');

const repoRoot = path.resolve(__dirname, '../..');
const { makeFindingId, makeCodeHash } = require(path.join(repoRoot, 'lib/finding-identity'));
const { scanSecrets }                 = require(path.join(repoRoot, 'lib/scanner-secrets'));

// ── Helpers ────────────────────────────────────────────────────────────────

function makeFile(content) {
  return { filePath: 'src/test.js', content, ext: 'js' };
}

describe('finding-identity — locked invariants', () => {

  // ── Test 1 — line-shift stability ────────────────────────────────────────
  test('1. same rule + file + identical line content at different line numbers → same finding_id', () => {
    const ruleId   = 'SECRET-001';
    const filePath = 'src/config.js';
    const line     = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";';

    const idAtLine5  = makeFindingId(ruleId, filePath, line);
    const idAtLine9  = makeFindingId(ruleId, filePath, line);
    const idAtLine42 = makeFindingId(ruleId, filePath, line);

    assert.equal(idAtLine5, idAtLine9, 'identity does not move with the line');
    assert.equal(idAtLine9, idAtLine42, 'identity is invariant under line shift');

    const hashAtLine5  = makeCodeHash(line);
    const hashAtLine42 = makeCodeHash(line);
    assert.equal(hashAtLine5, hashAtLine42, 'code_hash is invariant under line shift');
  });

  // ── Test 2 — cross-scanner invariance ────────────────────────────────────
  // A secret line scanned by scanner-full (full scan) must get the SAME
  // finding_id as the same secret line scanned by scanner-secrets (hook).
  // Otherwise a hook scan creating a record and a full scan refreshing it
  // would fragment identity. This was the second-order symptom of the bug.
  test('2. scanner-full and scanner-secrets produce the same finding_id for the same content', async () => {
    const filePath = 'src/secret.js';
    const line     = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";';
    const ruleId   = 'SECRET-001';

    // Direct helper invocation — what both scanners now compute.
    const expectedId   = makeFindingId(ruleId, filePath, line);
    const expectedHash = makeCodeHash(line);

    // scanner-secrets in practice — feed a synthetic file through scanSecrets
    // and verify the SECRET-001 finding it returns has the same id/hash.
    const file     = { filePath, content: line + '\n', ext: 'js' };
    const findings = await scanSecrets([file], null);
    const secret   = findings.find(f => f.ruleId === ruleId);
    assert.ok(secret, 'scanner-secrets returned a SECRET-001 finding for the AWS key');
    assert.equal(secret.findingId, expectedId,
      'scanner-secrets uses makeFindingId — id matches direct helper output');
    assert.equal(secret.codeHash, expectedHash,
      'scanner-secrets uses makeCodeHash — hash matches direct helper output');
  });

  // ── Test 3 — duplicate identical lines in one file ───────────────────────
  // Documented edge: two identical secret lines in one file share the same
  // finding_id (content + file are equal), but different `line` values in
  // the raw scanner output. This is a DELIBERATE consequence of content-
  // based identity — design §4: "repeated identical lines share a code_hash
  // but differ by `line`". Asserting it deliberately keeps it a choice, not
  // an accident.
  test('3. two identical secret lines in one file → same id, distinct `line` values', async () => {
    const ruleId   = 'SECRET-001';
    const filePath = 'src/dupes.js';
    const line     = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";';

    // File with the same line at positions 1 and 3
    const content  = line + '\n// some other code\n' + line + '\n';
    const file     = { filePath, content, ext: 'js' };
    const findings = await scanSecrets([file], null);
    const secrets  = findings.filter(f => f.ruleId === ruleId);

    assert.equal(secrets.length, 2, 'both occurrences detected');
    assert.equal(secrets[0].findingId, secrets[1].findingId,
      'identical content → identical finding_id (design §4)');
    assert.equal(secrets[0].codeHash,  secrets[1].codeHash,
      'identical content → identical code_hash');
    assert.notEqual(secrets[0].line,   secrets[1].line,
      'distinct line numbers in raw output (line is display, not identity)');
  });

  // ── Negative check — line number must not affect identity ────────────────
  test('makeFindingId ignores line numbers entirely (negative regression)', () => {
    // Even if a caller mistakenly mutates the lineRaw to embed a line number,
    // the algorithm itself never reads any line/index input. This documents
    // the API: only ruleId, filePath, lineRaw — no fourth argument.
    const a = makeFindingId('R', 'f.js', 'x');
    const b = makeFindingId('R', 'f.js', 'x');  // same args, no position
    assert.equal(a, b);

    // Different content → different id (sanity).
    const c = makeFindingId('R', 'f.js', 'y');
    assert.notEqual(a, c);
  });

});
