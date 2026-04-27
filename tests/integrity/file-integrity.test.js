'use strict';

/**
 * File integrity tests for scd CLI.
 *
 * These tests guard against accidental truncation or deletion of critical files.
 * They do NOT test correctness — only that files exist and are at least a minimum size.
 *
 * HOW TO SET MIN SIZES:
 *   Run `node -e "const fs=require('fs'); ['bin/scd.js','lib/scanner-full.js'].forEach(f => console.log(f, fs.statSync(f).size))"` 
 *   in the scd repo root to get current sizes, then set MIN_BYTES to ~70% of that value.
 *   Update after intentional large refactors.
 *
 * Run: node --test tests/integrity/file-integrity.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Resolve paths relative to repo root (two levels up from tests/integrity/)
const root = path.resolve(__dirname, '..', '..');
const abs = (f) => path.join(root, f);

// ---------------------------------------------------------------------------
// File list with minimum byte thresholds.
// Set each MIN_BYTES to ~70% of the file's current size on disk.
// ---------------------------------------------------------------------------
const CRITICAL_FILES = [
  // Entry point
  { file: 'bin/scd.js',                         minBytes: 57768 },

  // Scanners
  { file: 'lib/scanner-full.js',                minBytes: 14785 },
  { file: 'lib/scanner-secrets.js',             minBytes:  5948 },
  { file: 'lib/scanner-manual.js',              minBytes:  7140 },

  // Rules — these are large and high-value to guard
  { file: 'lib/rules/rules-js.js',              minBytes: 22855 },
  { file: 'lib/rules/rules-ts.js',              minBytes:  5380 },
  { file: 'lib/rules/rules-python.js',          minBytes: 23391 },
  { file: 'lib/rules/rules-php.js',             minBytes: 25631 },
  { file: 'lib/rules/rules-aspx.js',            minBytes: 13949 },
  { file: 'lib/rules/rules-aspx-cs.js',         minBytes: 23225 },
  { file: 'lib/rules/rules-sensitive-files.js', minBytes: 23471 },
  { file: 'lib/rules/rules-infra-leakage.js',   minBytes: 20585 },

  // Core modules
  { file: 'lib/store.js',                       minBytes:  6465 },
  { file: 'lib/push-queue.js',                  minBytes:  7389 },
  { file: 'lib/rule-registry.js',               minBytes:  4189 },
  { file: 'lib/report-html.js',                 minBytes: 33227 },
  { file: 'lib/doctor.js',                      minBytes:  5816 },
  { file: 'lib/config.js',                      minBytes:  8264 },
  { file: 'lib/global-config.js',               minBytes:  4019 },
  { file: 'lib/deep-analyzer.js',               minBytes:  5382 },
  { file: 'lib/audit.js',                       minBytes:  8656 },

  // Package manifest
  { file: 'package.json',                       minBytes:   448 },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('all critical files exist', () => {
  const missing = CRITICAL_FILES
    .map(({ file }) => abs(file))
    .filter((f) => !fs.existsSync(f));

  assert.deepStrictEqual(
    missing,
    [],
    `Missing files:\n${missing.join('\n')}`
  );
});

for (const { file, minBytes } of CRITICAL_FILES) {
  test(`${file} is at least ${minBytes} bytes`, () => {
    const fullPath = abs(file);
    assert.ok(
      fs.existsSync(fullPath),
      `File does not exist: ${file}`
    );

    const { size } = fs.statSync(fullPath);
    assert.ok(
      size >= minBytes,
      `${file} is ${size} bytes — expected at least ${minBytes} bytes. File may be truncated.`
    );
  });
}
