/**
 * format-time.test.js
 * #102 — local-time display helpers. Storage stays UTC; display is local wall
 * clock in a locale-stable layout. Never throws.
 *
 * Run: node --test tests/unit/format-time.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path   = require('path');

const { formatLocalTime, formatLocalDate } = require(path.resolve(__dirname, '../../lib/format-time'));

const pad = n => String(n).padStart(2, '0');

describe('#102 format-time', () => {

  test('formatLocalTime → YYYY-MM-DD HH:mm in LOCAL time', () => {
    const iso = '2026-06-22T08:30:00.000Z';
    const d   = new Date(iso);
    const expected = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
                     `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    assert.equal(formatLocalTime(iso), expected);
    assert.match(formatLocalTime(iso), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });

  test('formatLocalDate → YYYY-MM-DD in LOCAL time', () => {
    const iso = '2026-06-22T08:30:00.000Z';
    const d   = new Date(iso);
    const expected = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    assert.equal(formatLocalDate(iso), expected);
    assert.match(formatLocalDate(iso), /^\d{4}-\d{2}-\d{2}$/);
  });

  test('accepts a Date object', () => {
    assert.match(formatLocalTime(new Date()), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
    assert.match(formatLocalDate(new Date()), /^\d{4}-\d{2}-\d{2}$/);
  });

  test('locale-stable layout (no month names, no raw Z)', () => {
    const s = formatLocalTime('2026-12-01T00:00:00.000Z');
    assert.doesNotMatch(s, /[A-Za-z]/, 'no locale month/AM-PM text');
    assert.doesNotMatch(s, /Z/, 'no raw UTC designator');
  });

  test('never throws — empty/null/garbage fall back to the raw input', () => {
    assert.equal(formatLocalTime(''), '');
    assert.equal(formatLocalTime(null), '');
    assert.equal(formatLocalTime(undefined), '');
    assert.equal(formatLocalTime('not-a-date'), 'not-a-date');
    assert.equal(formatLocalDate('garbage'), 'garbage');
  });
});
