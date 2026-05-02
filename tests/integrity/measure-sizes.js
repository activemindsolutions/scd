#!/usr/bin/env node
'use strict';

/**
 * measure-sizes.js
 *
 * Scans bin/ and lib/ automatically, updates tests/integrity/files.json.
 * Run from scd repo root: node tests/integrity/measure-sizes.js
 *
 * Behaviour:
 * - Scans all .js files in bin/ and lib/ (recursive)
 * - New files are added to files.json with enabled: true and marked (new)
 * - Existing files get updated actual + minBytes
 * - Files missing from disk are flagged and set to enabled: false
 * - Warns if any enabled file has shrunk > SHRINK_WARN since last measurement
 * - Skips updating files.json on shrinkage warnings unless --force is passed
 *
 * To disable a file from integrity testing, set enabled: false in files.json.
 * measure-sizes.js will still track it but file-integrity.test.js will skip it.
 */

const fs   = require('node:fs');
const path = require('node:path');

const FILES_JSON  = path.resolve(__dirname, 'files.json');
const SHRINK_WARN = 0.85;   // warn if file is <85% of previous actual
const MIN_FLOOR   = 0.70;   // minBytes = 70% of current actual size
const FORCE       = process.argv.includes('--force');

const RESET  = '\x1b[0m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN  = '\x1b[32m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[90m';
const CYAN   = '\x1b[36m';

// ── Helpers ───────────────────────────────────────────────────────────────

function walkDir(dir, ext = '.js') {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(full, ext));
    } else if (entry.isFile() && entry.name.endsWith(ext)) {
      results.push(full);
    }
  }
  return results;
}

// ── Load existing files.json ──────────────────────────────────────────────

let existing = {};
if (fs.existsSync(FILES_JSON)) {
  try {
    const raw = JSON.parse(fs.readFileSync(FILES_JSON, 'utf8'));
    for (const entry of raw.files || []) {
      existing[entry.file] = entry;
    }
  } catch (err) {
    console.error(`${RED}Could not parse ${FILES_JSON}: ${err.message}${RESET}`);
    process.exit(1);
  }
}

// ── Discover all .js files in bin/ and lib/ ───────────────────────────────

const root = path.resolve(__dirname, '..', '..');
const rel  = (f) => path.relative(root, f).replace(/\\/g, '/');
const abs  = (f) => path.join(root, f);

const discovered = [
  ...walkDir(path.join(root, 'bin')),
  ...walkDir(path.join(root, 'lib')),
].map(rel);

// Also include package.json
if (!discovered.includes('package.json')) discovered.push('package.json');

// Merge: discovered files + any existing entries not on disk (keep them)
const allFiles = [...new Set([
  ...discovered,
  ...Object.keys(existing),
])].sort();

// ── Measure ───────────────────────────────────────────────────────────────

console.log(`\n${BOLD}File sizes for scd integrity test${RESET}`);
console.log('='.repeat(78));
console.log(`${DIM}Config: ${FILES_JSON}${RESET}\n`);
console.log(
  `${'File'.padEnd(50)} ${'Actual'.padStart(8)}  ${'Min (70%)'.padStart(9)}  ` +
  `${'Change'.padStart(8)}  Status`
);
console.log('-'.repeat(94));

const results  = [];
const warnings = [];

for (const file of allFiles) {
  const fullPath   = abs(file);
  const prev       = existing[file] || null;
  const wasEnabled = prev ? prev.enabled !== false : true;

  if (!fs.existsSync(fullPath)) {
    console.log(
      `${YELLOW}${file.padEnd(50)}${RESET} ${'—'.padStart(8)}  ${'—'.padStart(9)}  ` +
      `${'—'.padStart(8)}  ${YELLOW}MISSING → disabled${RESET}`
    );
    results.push({ file, actual: prev?.actual ?? 0, minBytes: prev?.minBytes ?? 0, enabled: false });
    continue;
  }

  const actual   = fs.statSync(fullPath).size;
  const minBytes = Math.floor(actual * MIN_FLOOR);
  const isNew    = !prev;
  const enabled  = prev ? prev.enabled !== false : true;
  const ratio    = prev?.actual ? actual / prev.actual : null;

  // Change column
  let changeStr = DIM + '—'.padStart(8) + RESET;
  if (isNew) {
    changeStr = `${GREEN}${'(new)'.padStart(8)}${RESET}`;
  } else if (ratio !== null) {
    const pct  = ((ratio - 1) * 100).toFixed(1);
    const sign = ratio >= 1 ? '+' : '';
    if (ratio < SHRINK_WARN && wasEnabled) {
      changeStr = `${RED}${BOLD}${(sign + pct + '%').padStart(8)}${RESET}`;
      warnings.push({ file, prev: prev.actual, actual, ratio });
    } else if (ratio < 1) {
      changeStr = `${YELLOW}${(sign + pct + '%').padStart(8)}${RESET}`;
    } else if (ratio > 1) {
      changeStr = `${GREEN}${(sign + pct + '%').padStart(8)}${RESET}`;
    } else {
      changeStr = DIM + '='.padStart(8) + RESET;
    }
  }

  // Status column
  let statusStr;
  if (isNew)         statusStr = `${GREEN}new${RESET}`;
  else if (!enabled) statusStr = `${DIM}disabled${RESET}`;
  else               statusStr = `${DIM}enabled${RESET}`;

  console.log(
    `${file.padEnd(50)} ${String(actual).padStart(8)}  ${String(minBytes).padStart(9)}  ` +
    `${changeStr}  ${statusStr}`
  );

  results.push({ file, actual, minBytes, enabled });
}

console.log('');

// ── Shrinkage warnings ────────────────────────────────────────────────────

if (warnings.length > 0) {
  console.log(`${RED}${BOLD}⚠  Significant shrinkage detected (< ${Math.round(SHRINK_WARN * 100)}% of previous):${RESET}`);
  for (const w of warnings) {
    const pct = (w.ratio * 100).toFixed(1);
    console.log(`   ${YELLOW}${w.file}${RESET}`);
    console.log(`   ${DIM}was ${w.prev} bytes → now ${w.actual} bytes (${pct}% of previous)${RESET}`);
  }
  console.log('');

  if (!FORCE) {
    console.log(`${YELLOW}files.json NOT updated — review the changes above.${RESET}`);
    console.log(`${DIM}If this is expected (e.g. after a refactor), re-run with:${RESET}`);
    console.log(`${CYAN}  node tests/integrity/measure-sizes.js --force${RESET}`);
    console.log(`${DIM}To exclude a file from testing: set enabled: false in files.json${RESET}\n`);
    process.exit(0);
  }

  console.log(`${YELLOW}--force specified — updating files.json despite warnings.${RESET}\n`);
}

// ── Write files.json ──────────────────────────────────────────────────────

const output = {
  _comment:     'Auto-generated by measure-sizes.js — only edit "enabled" manually',
  _updated:     new Date().toISOString(),
  _shrink_warn: SHRINK_WARN,
  _min_floor:   MIN_FLOOR,
  files:        results,
};

fs.writeFileSync(FILES_JSON, JSON.stringify(output, null, 2) + '\n', 'utf8');

const newCount      = results.filter(r => !existing[r.file]).length;
const disabledCount = results.filter(r => !r.enabled).length;

console.log(`${GREEN}✓ files.json updated — ${results.length} files` +
  (newCount      ? `, ${newCount} new`          : '') +
  (disabledCount ? `, ${disabledCount} disabled` : '') +
  `${RESET}`);
console.log(`${DIM}  ${FILES_JSON}${RESET}\n`);
