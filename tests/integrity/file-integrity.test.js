'use strict';

/**
 * File integrity tests for scd CLI.
 *
 * Reads file list and thresholds from tests/integrity/files.json.
 * Only tests files where enabled: true.
 *
 * To update files.json: node tests/integrity/measure-sizes.js
 * To disable a file:    set enabled: false in files.json
 *
 * Run: node --test tests/integrity/file-integrity.test.js
 */

const { test } = require('node:test');
const assert   = require('node:assert');
const fs       = require('node:fs');
const path     = require('node:path');

const root       = path.resolve(__dirname, '..', '..');
const abs        = (f) => path.join(root, f);
const FILES_JSON = path.join(__dirname, 'files.json');

// ── Load files.json ───────────────────────────────────────────────────────

let ALL_FILES;
try {
  const raw = JSON.parse(fs.readFileSync(FILES_JSON, 'utf8'));
  ALL_FILES = raw.files;
} catch (err) {
  throw new Error(
    `Cannot read ${FILES_JSON}: ${err.message}\n` +
    'Run: node tests/integrity/measure-sizes.js'
  );
}

if (!Array.isArray(ALL_FILES) || ALL_FILES.length === 0) {
  throw new Error(
    `${FILES_JSON} has no files entries.\n` +
    'Run: node tests/integrity/measure-sizes.js'
  );
}

// Only test enabled files
const CRITICAL_FILES = ALL_FILES.filter(f => f.enabled !== false);

// ── Tests ─────────────────────────────────────────────────────────────────

test(`all critical files exist (${CRITICAL_FILES.length} enabled)`, () => {
  const missing = CRITICAL_FILES
    .map(({ file }) => abs(file))
    .filter((f) => !fs.existsSync(f));

  assert.deepStrictEqual(
    missing,
    [],
    `Missing files:\n${missing.map(f => path.relative(root, f)).join('\n')}`
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
      `${file} is ${size} bytes — expected at least ${minBytes}. ` +
      `File may be truncated. Run: node tests/integrity/measure-sizes.js`
    );
  });
}
