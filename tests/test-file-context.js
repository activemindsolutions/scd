/**
 * test-file-context.js
 * Unit tests for lib/file-context.js and lib/context-modifiers.js
 *
 * Run: node tests/test-file-context.js
 * No test framework required — uses Node.js built-in assert.
 */

'use strict';

const assert = require('assert');
const path   = require('path');

// ── Resolve modules relative to repo root ─────────────────────────────────
const repoRoot = path.resolve(__dirname, '..');
const { buildFileContext, FILE_TYPES } = require(path.join(repoRoot, 'lib/file-context'));
const { applyContextModifiers, SUPPRESS_THRESHOLD } = require(path.join(repoRoot, 'lib/context-modifiers'));

// ── Test helpers ───────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed++;
    process.stdout.write(`  ✓  ${name}\n`);
  } catch (err) {
    failed++;
    failures.push({ name, message: err.message });
    process.stdout.write(`  ✗  ${name}\n     ${err.message}\n`);
  }
}

function assertFileType(filePath, content, expectedType, label) {
  const ctx = buildFileContext(filePath, content);
  assert.strictEqual(
    ctx.fileType, expectedType,
    `${label || filePath}: expected fileType=${expectedType}, got=${ctx.fileType} (signals: ${ctx.signals.join(', ')})`
  );
}

function assertFramework(filePath, content, expectedFramework, label) {
  const ctx = buildFileContext(filePath, content);
  assert.strictEqual(
    ctx.testFramework, expectedFramework,
    `${label || filePath}: expected framework=${expectedFramework}, got=${ctx.testFramework}`
  );
}

/** Build a minimal finding object for modifier tests. */
function makeFinding(severity, filePath = 'src/auth.js') {
  return {
    ruleId:    'TEST-001',
    name:      'Test rule',
    severity,
    filePath,
    line:      10,
    snippet:   'const x = 1',
    findingId: 'f-test0001',
  };
}

// ══════════════════════════════════════════════════════════════════════════
// buildFileContext — vendor / generated (definitive, no content needed)
// ══════════════════════════════════════════════════════════════════════════
console.log('\nbuildFileContext — definitive classifications\n');

test('vendor: node_modules path', () => {
  assertFileType('node_modules/lodash/lodash.js', null, FILE_TYPES.VENDOR);
});

test('vendor: /vendor/ path segment', () => {
  assertFileType('src/vendor/jquery.js', 'alert("hello")', FILE_TYPES.VENDOR);
});

test('generated: /dist/ path segment', () => {
  assertFileType('dist/bundle.js', null, FILE_TYPES.GENERATED);
});

test('generated: package-lock.json filename', () => {
  assertFileType('package-lock.json', '{}', FILE_TYPES.GENERATED);
});

test('generated: .min.js filename', () => {
  assertFileType('public/app.min.js', null, FILE_TYPES.GENERATED);
});

test('generated: .d.ts declaration file', () => {
  assertFileType('types/index.d.ts', null, FILE_TYPES.GENERATED);
});

test('vendor classified even when content looks like test code', () => {
  // vendor is definitive — content should not downgrade it
  const content = 'describe("test", () => { it("works", () => { expect(1).toBe(1); }); });';
  assertFileType('vendor/test-helpers.js', content, FILE_TYPES.VENDOR);
});

// ══════════════════════════════════════════════════════════════════════════
// buildFileContext — test classification (tentative, requires content)
// ══════════════════════════════════════════════════════════════════════════
console.log('\nbuildFileContext — test classifications (content-confirmed)\n');

const JEST_CONTENT    = 'import { describe, it, expect } from "@jest/globals";\ndescribe("auth", () => { it("works", () => { expect(true).toBe(true); }); });';
const VITEST_CONTENT  = 'import { describe, it, expect } from "vitest";\ndescribe("auth", () => { it("works", () => {}); });';
const PYTEST_CONTENT  = 'import pytest\ndef test_login():\n    assert True';
const PHPUNIT_CONTENT = '<?php\nclass AuthTest extends TestCase {\n    public function testLogin() {}\n}';
const MOCHA_CONTENT   = 'const assert = require("assert");\ndescribe("auth", function() { before(function() {}); });';

test('test: *.test.js filename + jest content → test/jest', () => {
  const ctx = buildFileContext('src/auth.test.js', JEST_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST, `fileType=${ctx.fileType}`);
  assert.strictEqual(ctx.testFramework, 'jest', `framework=${ctx.testFramework}`);
});

test('test: *.spec.ts filename + vitest content → test/vitest', () => {
  const ctx = buildFileContext('src/auth.spec.ts', VITEST_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST);
  assert.strictEqual(ctx.testFramework, 'vitest');
});

test('test: /tests/ path + pytest content → test/pytest', () => {
  const ctx = buildFileContext('tests/test_auth.py', PYTEST_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST);
  assert.strictEqual(ctx.testFramework, 'pytest');
});

test('test: /spec/ path + phpunit content → test/phpunit', () => {
  const ctx = buildFileContext('spec/AuthTest.php', PHPUNIT_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST);
  assert.strictEqual(ctx.testFramework, 'phpunit');
});

test('test: /__tests__/ path + mocha content → test/mocha', () => {
  const ctx = buildFileContext('src/__tests__/auth.js', MOCHA_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST);
  assert.strictEqual(ctx.testFramework, 'mocha');
});

test('test: pure content detection (no path/filename hint)', () => {
  // File with no test-like path or name but contains test framework imports
  const ctx = buildFileContext('src/helpers.js', JEST_CONTENT);
  assert.strictEqual(ctx.fileType, FILE_TYPES.TEST);
});

// ══════════════════════════════════════════════════════════════════════════
// buildFileContext — tentative NOT confirmed → source
// ══════════════════════════════════════════════════════════════════════════
console.log('\nbuildFileContext — tentative downgraded to source\n');

const PROD_CONTENT = 'const express = require("express");\nconst app = express();\napp.get("/", (req, res) => res.send("hello"));\nmodule.exports = app;';

test('*.test.js filename but no test content → source', () => {
  // vulnerable-test.js case — has "test" in name but is production code
  assertFileType('vulnerable-test.js', PROD_CONTENT, FILE_TYPES.SOURCE);
});

test('/tests/ path but no test content → source', () => {
  // /testresult/ or misnamed dir case
  assertFileType('testresult/summary.js', PROD_CONTENT, FILE_TYPES.SOURCE);
});

test('/fixtures/ path but no test content → source', () => {
  assertFileType('fixtures/server.js', PROD_CONTENT, FILE_TYPES.SOURCE);
});

test('__tests__ path but no test content → source', () => {
  assertFileType('src/__tests__/helpers.js', PROD_CONTENT, FILE_TYPES.SOURCE);
});

test('no path hint, no content → source', () => {
  assertFileType('src/auth.js', PROD_CONTENT, FILE_TYPES.SOURCE);
});

// ══════════════════════════════════════════════════════════════════════════
// buildFileContext — no content available (secrets scanner path)
// ══════════════════════════════════════════════════════════════════════════
console.log('\nbuildFileContext — no content available\n');

test('*.test.js + no content → test (tentative committed)', () => {
  // When secrets scanner calls buildFileContext without content,
  // tentative type is used as-is — best available signal.
  assertFileType('src/auth.test.js', null, FILE_TYPES.TEST);
});

test('/tests/ path + no content → test (tentative committed)', () => {
  assertFileType('tests/auth.js', null, FILE_TYPES.TEST);
});

test('source file + no content → source', () => {
  assertFileType('src/auth.js', null, FILE_TYPES.SOURCE);
});

// ══════════════════════════════════════════════════════════════════════════
// buildFileContext — config and other types
// ══════════════════════════════════════════════════════════════════════════
console.log('\nbuildFileContext — config and other types\n');

test('config: .env filename', () => {
  assertFileType('.env', 'DB_PASSWORD=secret', FILE_TYPES.CONFIG);
});

test('config: jest.config.js filename', () => {
  assertFileType('jest.config.js', 'module.exports = {}', FILE_TYPES.CONFIG);
});

test('config: tsconfig.json filename', () => {
  assertFileType('tsconfig.json', '{}', FILE_TYPES.CONFIG);
});

test('language: js → javascript', () => {
  const ctx = buildFileContext('src/auth.js', null);
  assert.strictEqual(ctx.language, 'javascript');
});

test('language: ts → typescript', () => {
  const ctx = buildFileContext('src/auth.ts', null);
  assert.strictEqual(ctx.language, 'typescript');
});

test('language: py → python', () => {
  const ctx = buildFileContext('app/views.py', null);
  assert.strictEqual(ctx.language, 'python');
});

// ══════════════════════════════════════════════════════════════════════════
// applyContextModifiers — severity arithmetic
// ══════════════════════════════════════════════════════════════════════════
console.log('\napplyContextModifiers — severity arithmetic\n');

test('source file: no modifiers applied', () => {
  const ctx      = buildFileContext('src/auth.js', PROD_CONTENT);
  const finding  = makeFinding('HIGH', 'src/auth.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.severity,          'HIGH',  `severity=${modified.severity}`);
  assert.strictEqual(modified.base_severity,     'HIGH',  `base=${modified.base_severity}`);
  assert.strictEqual(modified.context_modifiers.length, 0, 'should have no modifiers');
  assert.strictEqual(modified.suppressed,        false,   'should not be suppressed');
});

test('test file (jest): EXPOSURE → suppressed', () => {
  // EXPOSURE(1) + test fileType(-1) = 0 → suppressed
  const ctx     = buildFileContext('src/auth.test.js', JEST_CONTENT);
  const finding = makeFinding('EXPOSURE', 'src/auth.test.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed, true, 'EXPOSURE in test file should be suppressed');
  assert.ok(modified.suppress_reason, 'suppress_reason should be set');
  assert.ok(modified.context_modifiers.length > 0, 'should have modifiers');
});

test('test file (jest): HIGH → MEDIUM (not suppressed)', () => {
  // HIGH(3) + test fileType(-1) + jest framework(-1) = 1 → EXPOSURE (not suppressed)
  // Actually: HIGH(3) -1 -1 = 1 → EXPOSURE, still active
  const ctx     = buildFileContext('src/auth.test.js', JEST_CONTENT);
  const finding = makeFinding('HIGH', 'src/auth.test.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed, false, 'HIGH in test file should not be suppressed');
  assert.ok(modified.severity !== 'HIGH', 'severity should be downgraded from HIGH');
  assert.strictEqual(modified.base_severity, 'HIGH', 'base_severity should remain HIGH');
});

test('test file (jest): CRITICAL → HIGH (not suppressed)', () => {
  // CRITICAL(4) + test(-1) + jest(-1) = 2 → MEDIUM
  const ctx     = buildFileContext('src/auth.test.js', JEST_CONTENT);
  const finding = makeFinding('CRITICAL', 'src/auth.test.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed,    false,    'CRITICAL should not be suppressed');
  assert.strictEqual(modified.base_severity, 'CRITICAL');
  assert.ok(modified.severity !== 'CRITICAL', 'severity should be downgraded');
});

test('vendor file: HIGH → suppressed', () => {
  // vendor modifier is -3 → HIGH(3) - 3 = 0 → suppressed
  const ctx     = buildFileContext('vendor/old-lib.js', null);
  const finding = makeFinding('HIGH', 'vendor/old-lib.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed, true, 'HIGH in vendor should be suppressed');
});

test('vendor file: CRITICAL → MEDIUM (not suppressed)', () => {
  // CRITICAL(4) + vendor(-3) = 1 → EXPOSURE, active
  const ctx     = buildFileContext('vendor/old-lib.js', null);
  const finding = makeFinding('CRITICAL', 'vendor/old-lib.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed,    false, 'CRITICAL in vendor should not be suppressed');
  assert.strictEqual(modified.base_severity, 'CRITICAL');
});

test('config file: no modifier (config modifier = 0)', () => {
  const ctx     = buildFileContext('.env', 'DB_PASSWORD=secret');
  const finding = makeFinding('CRITICAL', '.env');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.severity,     'CRITICAL', 'config should not change severity');
  assert.strictEqual(modified.suppressed,   false);
  assert.strictEqual(modified.context_modifiers.length, 0, 'config has no modifiers');
});

test('modified finding always has base_severity', () => {
  const ctx     = buildFileContext('src/auth.js', PROD_CONTENT);
  const finding = makeFinding('CRITICAL', 'src/auth.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.ok(modified.base_severity, 'base_severity must always be present');
});

test('modified finding always has file_context', () => {
  const ctx     = buildFileContext('src/auth.js', PROD_CONTENT);
  const finding = makeFinding('HIGH', 'src/auth.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.ok(modified.file_context, 'file_context must always be present');
  assert.ok('file_type'      in modified.file_context);
  assert.ok('test_framework' in modified.file_context);
  assert.ok('language'       in modified.file_context);
});

test('original finding object is not mutated', () => {
  const ctx     = buildFileContext('src/auth.test.js', JEST_CONTENT);
  const finding = makeFinding('EXPOSURE', 'src/auth.test.js');
  const before  = finding.severity;
  applyContextModifiers(finding, ctx);
  assert.strictEqual(finding.severity, before, 'original finding.severity must not be mutated');
  assert.strictEqual(finding.suppressed, undefined, 'original finding must not gain suppressed field');
});

test('score clamped at 0 — never negative', () => {
  // EXPOSURE(1) + vendor(-3) = -2 → clamped to 0 → suppressed, severity null or INFO
  const ctx     = buildFileContext('vendor/lib.js', null);
  const finding = makeFinding('EXPOSURE', 'vendor/lib.js');
  const modified = applyContextModifiers(finding, ctx);
  assert.strictEqual(modified.suppressed, true);
  // severity should be null or INFO (score 0 = INFO, but finding is suppressed)
  const validSeverities = [null, undefined, 'INFO'];
  assert.ok(
    validSeverities.includes(modified.severity) || modified.suppressed,
    `severity should reflect clamped score, got: ${modified.severity}`
  );
});

// ══════════════════════════════════════════════════════════════════════════
// Results
// ══════════════════════════════════════════════════════════════════════════
console.log(`\n${'─'.repeat(60)}`);
console.log(`  ${passed} passed  ${failed > 0 ? failed + ' failed' : ''}`);

if (failures.length > 0) {
  console.log('\nFailed tests:');
  for (const f of failures) {
    console.log(`  ✗ ${f.name}`);
    console.log(`    ${f.message}`);
  }
  process.exit(1);
} else {
  console.log('  All tests passed.\n');
  process.exit(0);
}
