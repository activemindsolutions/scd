'use strict';

/**
 * Rule regression tests for scd.
 *
 * Each test scans a minimal fixture file and verifies that:
 *   - The expected rule ID appears in the findings (vulnerable fixture)
 *   - The rule ID does NOT appear in the findings (clean fixture)
 *
 * Fixtures live in a dedicated repo at FIXTURES_ROOT (configurable via
 * SCD_TEST_FIXTURES env var) to isolate scan results from the scd project.
 *
 * Run: node --test tests/rules/rule-regression.test.js
 *
 * HOW TO ADD A NEW RULE TEST:
 *   1. Add a vulnerable fixture: tests/fixtures/<lang>/<RULE-ID>.ext
 *   2. Add a clean fixture:      tests/fixtures/<lang>/<RULE-ID>.clean.ext
 *   3. Add an entry to RULE_TESTS below.
 */

const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const SCD = path.resolve(__dirname, '..', '..', 'bin', 'scd.js');

// Fixtures repo — isolated from scd project to avoid polluting the store.
// Override with SCD_TEST_FIXTURES env var if repo lives elsewhere.
const FIXTURES_ROOT = process.env.SCD_TEST_FIXTURES ||
  path.join(os.homedir(), 'Projects', 'scd-test-fixtures');

// Sanity check — fail fast if fixtures root is missing
if (!fs.existsSync(FIXTURES_ROOT)) {
  throw new Error(
    `Fixtures root not found: ${FIXTURES_ROOT}\n` +
    `Set SCD_TEST_FIXTURES env var or create the directory.`
  );
}

// ---------------------------------------------------------------------------
// Rule test definitions
// ---------------------------------------------------------------------------

const RULE_TESTS = [
  {
    ruleId: 'INJ-003',
    description: 'Command injection JS – tainted variable in exec()',
    vulnerable: 'js/INJ-003.js',
    clean: 'js/INJ-003.clean.js',
  },
  {
    ruleId: 'PHP-INJ-002',
    description: 'SQL injection PHP – tainted variable concatenated into query',
    vulnerable: 'php/PHP-INJ-002.php',
    clean: 'php/PHP-INJ-002.clean.php',
  },
  {
    ruleId: 'PY-INJ-002',
    description: 'Command injection Python – subprocess shell=True with user input',
    vulnerable: 'python/PY-INJ-002.py',
    clean: 'python/PY-INJ-002.clean.py',
  },
  {
    ruleId: 'JSON-001',
    description: 'Hardcoded secret – API key in JSON file',
    vulnerable: 'secrets/JSON-001.json',
    clean: 'secrets/JSON-001.clean.json',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Run scd scan on a single file and return the parsed JSON findings array.
 * Runs with cwd set to FIXTURES_ROOT so scan context stays in that project.
 */
function scanFile(relPath) {
  const targetPath = path.join(FIXTURES_ROOT, relPath);
  const outFile = path.join(os.tmpdir(), `scd-test-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);

  const r = spawnSync(
    process.execPath,
    [SCD, 'scan', targetPath, '--format', 'json', '--output', outFile, '--no-audit', '--no-sync'],
    { cwd: FIXTURES_ROOT, encoding: 'utf8' }
  );

  if (!fs.existsSync(outFile)) {
    throw new Error(
      `scd scan produced no output file for ${relPath}.\n` +
      `stdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
  }

  const raw = fs.readFileSync(outFile, 'utf8');
  fs.unlinkSync(outFile); // clean up temp file

  try {
    const parsed = JSON.parse(raw);
    // scd JSON report wraps findings — handle both {findings:[]} and plain array
    return Array.isArray(parsed) ? parsed : (parsed.findings || []);
  } catch (e) {
    throw new Error(`Failed to parse scd JSON output for ${relPath}: ${e.message}\nRaw: ${raw.slice(0, 500)}`);
  }
}

function findingRuleIds(findings) {
  return findings.map(f => f.ruleId || f.rule_id || f.id).filter(Boolean);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

for (const { ruleId, description, vulnerable, clean } of RULE_TESTS) {
  test(`${ruleId} – detects vulnerability in vulnerable fixture (${description})`, () => {
    const findings = scanFile(vulnerable);
    const ruleIds = findingRuleIds(findings);
    assert.ok(
      ruleIds.includes(ruleId),
      `Expected ${ruleId} in findings but got: [${ruleIds.join(', ')}]`
    );
  });

  test(`${ruleId} – no finding in clean fixture`, () => {
    const findings = scanFile(clean);
    const ruleIds = findingRuleIds(findings);
    assert.ok(
      !ruleIds.includes(ruleId),
      `Expected NO ${ruleId} finding in clean fixture but it was flagged.\nAll findings: [${ruleIds.join(', ')}]`
    );
  });
}
