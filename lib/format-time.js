'use strict';

/**
 * format-time.js
 * Local-time display for HUMAN output (design principle #18: the reader determines
 * the format — storage stays UTC ISO-8601 `Z`, human-facing output shows local wall
 * clock). Zero dependencies so it can be imported anywhere (commands, reports)
 * without pulling in heavier modules.
 *
 * Built from the local Date accessors (getFullYear/getHours/…) rather than
 * toLocaleString so the format is stable across machine locales — only the
 * timezone is local, the layout is fixed. Never throws: a bad/empty value falls
 * back to the raw input so it can't break a command.
 */

function pad(n) { return String(n).padStart(2, '0'); }

// 'YYYY-MM-DD HH:mm' in local time.
function formatLocalTime(value) {
  if (value === null || value === undefined || value === '') return '';
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return String(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// 'YYYY-MM-DD' in local time (date only).
function formatLocalDate(value) {
  if (value === null || value === undefined || value === '') return '';
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return String(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

module.exports = { formatLocalTime, formatLocalDate };
