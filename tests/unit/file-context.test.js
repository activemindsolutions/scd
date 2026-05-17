/**
 * file-context.test.js
 * Unit tests for lib/file-context.js and lib/context-modifiers.js
 *
 * Run: npm test  (or: node --test tests/unit/file-context.test.js)
 */

'use strict';

const { test, describe } = require('node:test');
const assert             = require('node:assert/strict');
const path               = require('path');

const repoRoot = path.resolve(__dirname, '../..');
const { buildFileContext, FILE_TYPES }      = require(path.join(repoRoot, 'lib/file-context'));
const { applyContextModifiers }             = require(path.join(repoRoot, 'lib/context-modifiers'));

// ── Shared test content ────────────────────────────────────────────────────

const JEST_CONTENT = [
  'import { describe, it, expect } from "@jest/globals";',
  'describe("auth", () => { it("works", () => { expect(true).toBe(true); }); });',
].join('\n');

const VITEST_CONTENT = [
  'import { describe, it, expect } from "vitest";',
  'describe("auth", () => { it("works", () => {}); });',
].join('\n');

const PYTEST_CONTENT = [
  'import pytest',
  'def test_login():',
  '    assert True',
].join('\n');

const PHPUNIT_CONTENT = [
  '<?php',
  'class AuthTest extends TestCase {',
  '    public function testLogin() {}',
  '}',
].join('\n');

const MOCHA_CONTENT = [
  'const assert = require("assert");',
  'describe("auth", function() { before(function() {}); });',
].join('\n');

const PROD_CONTENT = [
  'const express = require("express");',
  'const app = express();',
  'app.get("/", (req, res) => res.send("hello"));',
  'module.exports = app;',
].join('\n');

// ── Helper ─────────────────────────────────────────────────────────────────

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
// buildFileContext
// ══════════════════════════════════════════════════════════════════════════

describe('buildFileContext — strong filename + test path (definitive)', () => {

  test('*.test.ts + tests/ path → definitive test', () => {
    const ctx = buildFileContext('tests/integration/ci/integration.test.ts', null);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
  });

  test('test_*.py + tests/ path → definitive test', () => {
    const ctx = buildFileContext('tests/components/pi_hole/test_config_flow.py', null);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
  });

  test('*.test.mjs + tests/ path → definitive test', () => {
    const ctx = buildFileContext('tests/agent-pool.test.mjs', null);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
  });

  test('*.test.ts in src/ (no test path) → source (no content)', () => {
    // Strong filename but not in a test directory — tentative, no content → source
    const ctx = buildFileContext('src/auth/session.test.ts', null);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

  test('*.test.js in src/models/ (no test path) → source (no content)', () => {
    // Evasion attempt: customer file named *.test.js — must not bypass scanning
    const ctx = buildFileContext('src/models/kunddata.test.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

});

describe('buildFileContext — definitive classifications', () => {

  test('vendor: node_modules path', () => {
    const ctx = buildFileContext('node_modules/lodash/lodash.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.VENDOR);
  });

  test('vendor: /vendor/ path segment', () => {
    const ctx = buildFileContext('src/vendor/jquery.js', PROD_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.VENDOR);
  });

  test('vendor classified even when content looks like test code', () => {
    // vendor is definitive — content must not override it
    const ctx = buildFileContext('vendor/test-helpers.js', JEST_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.VENDOR);
  });

  test('generated: /dist/ path segment', () => {
    const ctx = buildFileContext('dist/bundle.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.GENERATED);
  });

  test('generated: package-lock.json filename', () => {
    const ctx = buildFileContext('package-lock.json', '{}');
    assert.equal(ctx.fileType, FILE_TYPES.GENERATED);
  });

  test('generated: .min.js filename', () => {
    const ctx = buildFileContext('public/app.min.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.GENERATED);
  });

  test('generated: .d.ts declaration file', () => {
    const ctx = buildFileContext('types/index.d.ts', null);
    assert.equal(ctx.fileType, FILE_TYPES.GENERATED);
  });

});

describe('buildFileContext — test classifications (content-confirmed)', () => {

  test('*.test.js + jest content → test/jest', () => {
    const ctx = buildFileContext('src/auth.test.js', JEST_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
    assert.equal(ctx.testFramework, 'jest');
  });

  test('*.spec.ts + vitest content → test/vitest', () => {
    const ctx = buildFileContext('src/auth.spec.ts', VITEST_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
    assert.equal(ctx.testFramework, 'vitest');
  });

  test('/tests/ path + pytest content → test/pytest', () => {
    const ctx = buildFileContext('tests/test_auth.py', PYTEST_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
    assert.equal(ctx.testFramework, 'pytest');
  });

  test('/spec/ path + phpunit content → test/phpunit', () => {
    const ctx = buildFileContext('spec/AuthTest.php', PHPUNIT_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
    assert.equal(ctx.testFramework, 'phpunit');
  });

  test('/__tests__/ path + mocha content → test/mocha', () => {
    const ctx = buildFileContext('src/__tests__/auth.js', MOCHA_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
    assert.equal(ctx.testFramework, 'mocha');
  });

  test('pure content detection (no path/filename hint)', () => {
    // No test-like path or name — content alone drives classification
    const ctx = buildFileContext('src/helpers.js', JEST_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
  });

});

describe('buildFileContext — tentative downgraded to source', () => {

  test('*.test.js filename but no test content → source', () => {
    // The vulnerable-test.js case: "test" in name but production code
    const ctx = buildFileContext('vulnerable-test.js', PROD_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

  test('/tests/ path but no test content → source', () => {
    // /testresult/ or other creative directory naming
    const ctx = buildFileContext('testresult/summary.js', PROD_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

  test('/fixtures/ path but no test content → source', () => {
    const ctx = buildFileContext('fixtures/server.js', PROD_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

  test('/__tests__/ path but no test content → source', () => {
    const ctx = buildFileContext('src/__tests__/helpers.js', PROD_CONTENT);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

});

describe('buildFileContext — no content available', () => {

  test('*.test.js in src/ + no content → source (filename-only tentative)', () => {
    // Filename-only tentative is not committed without content — security requirement.
    // A *.test.js file outside a test directory might be a misnamed production file.
    const ctx = buildFileContext('src/auth.test.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

  test('/tests/ path + no content → test (tentative committed)', () => {
    const ctx = buildFileContext('tests/auth.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.TEST);
  });

  test('source file + no content → source', () => {
    const ctx = buildFileContext('src/auth.js', null);
    assert.equal(ctx.fileType, FILE_TYPES.SOURCE);
  });

});

describe('buildFileContext — config and language detection', () => {

  test('config: .env filename', () => {
    const ctx = buildFileContext('.env', 'DB_PASSWORD=secret');
    assert.equal(ctx.fileType, FILE_TYPES.CONFIG);
  });

  test('config: jest.config.js filename', () => {
    const ctx = buildFileContext('jest.config.js', 'module.exports = {}');
    assert.equal(ctx.fileType, FILE_TYPES.CONFIG);
  });

  test('config: tsconfig.json filename', () => {
    const ctx = buildFileContext('tsconfig.json', '{}');
    assert.equal(ctx.fileType, FILE_TYPES.CONFIG);
  });

  test('language: js → javascript', () => {
    const ctx = buildFileContext('src/auth.js', null);
    assert.equal(ctx.language, 'javascript');
  });

  test('language: ts → typescript', () => {
    const ctx = buildFileContext('src/auth.ts', null);
    assert.equal(ctx.language, 'typescript');
  });

  test('language: py → python', () => {
    const ctx = buildFileContext('app/views.py', null);
    assert.equal(ctx.language, 'python');
  });

});

// ══════════════════════════════════════════════════════════════════════════
// applyContextModifiers
// ══════════════════════════════════════════════════════════════════════════

describe('applyContextModifiers — severity arithmetic', () => {

  test('source file: no modifiers, severity unchanged', () => {
    const ctx      = buildFileContext('src/auth.js', PROD_CONTENT);
    const modified = applyContextModifiers(makeFinding('HIGH', 'src/auth.js'), ctx);
    assert.equal(modified.severity,                  'HIGH');
    assert.equal(modified.base_severity,             'HIGH');
    assert.equal(modified.context_modifiers.length,  0);
    assert.equal(modified.suppressed,                false);
  });

  test('test file (jest): EXPOSURE → suppressed', () => {
    // EXPOSURE(1) + test fileType(-1) = 0 → suppressed
    const ctx      = buildFileContext('src/auth.test.js', JEST_CONTENT);
    const modified = applyContextModifiers(makeFinding('EXPOSURE', 'src/auth.test.js'), ctx);
    assert.equal(modified.suppressed, true);
    assert.ok(modified.suppress_reason);
    assert.ok(modified.context_modifiers.length > 0);
  });

  test('test file (jest): HIGH downgraded, not suppressed', () => {
    // HIGH(3) + test(-1) + jest(-1) = 1 → EXPOSURE, still active
    const ctx      = buildFileContext('src/auth.test.js', JEST_CONTENT);
    const modified = applyContextModifiers(makeFinding('HIGH', 'src/auth.test.js'), ctx);
    assert.equal(modified.suppressed,    false);
    assert.equal(modified.base_severity, 'HIGH');
    assert.notEqual(modified.severity,   'HIGH');
  });

  test('test file (jest): CRITICAL downgraded, not suppressed', () => {
    // CRITICAL(4) + test(-1) + jest(-1) = 2 → MEDIUM, still active
    const ctx      = buildFileContext('src/auth.test.js', JEST_CONTENT);
    const modified = applyContextModifiers(makeFinding('CRITICAL', 'src/auth.test.js'), ctx);
    assert.equal(modified.suppressed,    false);
    assert.equal(modified.base_severity, 'CRITICAL');
    assert.notEqual(modified.severity,   'CRITICAL');
  });

  test('vendor file: CRITICAL → suppressed (fileType -3 + path -2 = -5)', () => {
    // CRITICAL(4) + vendor fileType(-3) + /vendor/ path(-2) = -1 → suppressed
    // Both modifiers stack — this is correct and expected behaviour.
    const ctx      = buildFileContext('vendor/old-lib.js', null);
    const modified = applyContextModifiers(makeFinding('CRITICAL', 'vendor/old-lib.js'), ctx);
    assert.equal(modified.suppressed,    true);
    assert.equal(modified.base_severity, 'CRITICAL');
  });

  test('config file: no modifier, severity unchanged', () => {
    // config modifier = 0 → no suppression regardless of severity
    const ctx      = buildFileContext('.env', 'DB_PASSWORD=secret');
    const modified = applyContextModifiers(makeFinding('CRITICAL', '.env'), ctx);
    assert.equal(modified.severity,                  'CRITICAL');
    assert.equal(modified.suppressed,                false);
    assert.equal(modified.context_modifiers.length,  0);
  });

  test('modified finding always has base_severity', () => {
    const ctx      = buildFileContext('src/auth.js', PROD_CONTENT);
    const modified = applyContextModifiers(makeFinding('CRITICAL', 'src/auth.js'), ctx);
    assert.ok(modified.base_severity);
  });

  test('modified finding always has file_context with required fields', () => {
    const ctx      = buildFileContext('src/auth.js', PROD_CONTENT);
    const modified = applyContextModifiers(makeFinding('HIGH', 'src/auth.js'), ctx);
    assert.ok(modified.file_context);
    assert.ok('file_type'      in modified.file_context);
    assert.ok('test_framework' in modified.file_context);
    assert.ok('language'       in modified.file_context);
  });

  test('original finding object is not mutated', () => {
    const ctx     = buildFileContext('src/auth.test.js', JEST_CONTENT);
    const finding = makeFinding('EXPOSURE', 'src/auth.test.js');
    const before  = finding.severity;
    applyContextModifiers(finding, ctx);
    assert.equal(finding.severity,    before);
    assert.equal(finding.suppressed,  undefined);
  });

  test('score clamped — never goes negative', () => {
    // EXPOSURE(1) + vendor(-3) + /vendor/ path(-2) = -4 → clamped to 0 → suppressed
    const ctx      = buildFileContext('vendor/lib.js', null);
    const modified = applyContextModifiers(makeFinding('EXPOSURE', 'vendor/lib.js'), ctx);
    assert.equal(modified.suppressed, true);
  });

});
