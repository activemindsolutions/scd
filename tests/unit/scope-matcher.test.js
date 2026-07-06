'use strict';

/**
 * scope pattern matcher (isFileExcluded / makePatternMatcher) — regression for the
 * glob bug where a single '*' was never converted to [^/]* and a leading '*' (e.g.
 * '*.md') threw "Nothing to repeat", crashing the scan.
 *
 * These vectors are the SAME as scd-server tests/unit/scope-match.test.js — the
 * server ports this matcher verbatim, so the two must agree. Keep them in lockstep.
 *
 * Run: node --test tests/unit/scope-matcher.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { isFileExcluded } = require('../../lib/scope');

// Match a repo-relative path against a single file_excludes pattern.
const excluded = (pattern, rel) =>
  isFileExcluded({ file_excludes: [{ pattern }] }, path.join('/repo', rel), '/repo').excluded;

test('single * matches within one segment, not across separators', () => {
  assert.equal(excluded('src/*.js', 'src/a.js'), true, 'single * globs one segment');
  assert.equal(excluded('src/*.js', 'src/sub/a.js'), false, 'single * does not cross /');
});

test('double ** crosses path separators', () => {
  assert.equal(excluded('docs/**', 'docs/a/b/c.js'), true);
  assert.equal(excluded('**/*.test.js', 'a/b/c.test.js'), true);
});

test('leading-* glob no longer throws and matches root-level files', () => {
  assert.doesNotThrow(() => excluded('*.md', 'README.md'), 'must not crash (was "Nothing to repeat")');
  assert.equal(excluded('*.md', 'README.md'), true);
  assert.equal(excluded('*.md', 'docs/x.md'), false, 'single * stays within the root segment');
});

test('directory pattern matches the dir and everything under it', () => {
  assert.equal(excluded('docs/analysis/', 'docs/analysis/x.js'), true);
  assert.equal(excluded('docs/analysis/', 'docs/other.js'), false);
});

test('? matches exactly one non-separator character', () => {
  assert.equal(excluded('src/a?.js', 'src/ab.js'), true);
  assert.equal(excluded('src/a?.js', 'src/a/.js'), false, '? does not match /');
});
