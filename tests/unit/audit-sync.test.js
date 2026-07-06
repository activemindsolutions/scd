'use strict';

/**
 * Regression tests for `scd sync --history` reconstruction.
 *
 * The server ingest requires rule_id/file/code_hash on every finding. History
 * sync reconstructs findings from audit.log FINDING_* events — those events (and
 * the reconstruction) must carry code_hash + finding_id, or the server skips every
 * finding (the sync silently "succeeds" with 0 landing).
 *
 * Run: node --test tests/unit/audit-sync.test.js
 */

const { test } = require('node:test');
const assert   = require('node:assert');
const path     = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const { buildFindingsBatches } = require(path.join(root, 'lib/audit-sync'));
const { EVENTS } = require(path.join(root, 'lib/audit'));

test('reconstructs findings WITH code_hash + finding_id (required by server ingest)', () => {
  const events = [
    { event: EVENTS.FINDING_WARNED, session_id: 's-1', hook: 'manual', timestamp: '2026-07-06T00:00:00Z',
      rule_id: 'JS-INJ-001', file: 'a.js', line: 5, severity: 'CRITICAL',
      code_hash: 'a'.repeat(32), finding_id: 'f-abc1234567' },
    { event: EVENTS.FINDING_BLOCKED, session_id: 's-1', hook: 'manual', timestamp: '2026-07-06T00:00:00Z',
      rule_id: 'SECRET-008', file: 'b.js', line: 8, severity: 'CRITICAL',
      code_hash: 'b'.repeat(32), finding_id: 'f-def4567890' },
  ];
  const batches = buildFindingsBatches(events);

  assert.equal(batches.length, 1, 'grouped into one session batch');
  assert.equal(batches[0].session_id, 's-1');
  const f = batches[0].findings;
  assert.equal(f.length, 2);
  assert.equal(f[0].code_hash, 'a'.repeat(32), 'code_hash carried through');
  assert.equal(f[0].finding_id, 'f-abc1234567', 'finding_id carried through');
  assert.ok(f.every(x => x.code_hash && x.finding_id), 'every reconstructed finding carries identity');
});

test('legacy events without code_hash reconstruct with null code_hash (syncHistory filters them)', () => {
  const events = [
    { event: EVENTS.FINDING_WARNED, session_id: 's-old', hook: 'manual', timestamp: '2026-01-01T00:00:00Z',
      rule_id: 'OLD-001', file: 'legacy.js', line: 1, severity: 'HIGH' },   // pre-code_hash entry
  ];
  const batches = buildFindingsBatches(events);
  assert.equal(batches[0].findings[0].code_hash, null,
    'legacy entry has null code_hash → filtered out before send, reported as skipped');
});
