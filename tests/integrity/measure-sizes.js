#!/usr/bin/env node
'use strict';

/**
 * Prints current file sizes and suggested minBytes (70% floor) for file-integrity.test.js.
 * Run from scd repo root: node tests/integrity/measure-sizes.js
 */

const fs = require('node:fs');
const path = require('node:path');

const files = [
  'bin/scd.js',
  'lib/scanner-full.js',
  'lib/scanner-secrets.js',
  'lib/scanner-manual.js',
  'lib/rules/rules-js.js',
  'lib/rules/rules-ts.js',
  'lib/rules/rules-python.js',
  'lib/rules/rules-php.js',
  'lib/rules/rules-aspx.js',
  'lib/rules/rules-aspx-cs.js',
  'lib/rules/rules-sensitive-files.js',
  'lib/rules/rules-infra-leakage.js',
  'lib/store.js',
  'lib/push-queue.js',
  'lib/rule-registry.js',
  'lib/report-html.js',
  'lib/doctor.js',
  'lib/config.js',
  'lib/global-config.js',
  'lib/deep-analyzer.js',
  'lib/audit.js',
  'package.json',
];

console.log('\nFile sizes for scd integrity test');
console.log('==================================');
console.log('Copy the minBytes values into file-integrity.test.js\n');
console.log(`${'File'.padEnd(45)} ${'Actual'.padStart(8)}  ${'Min (70%)'.padStart(9)}`);
console.log('-'.repeat(68));

for (const file of files) {
  if (!fs.existsSync(file)) {
    console.log(`${file.padEnd(45)} ${'MISSING'.padStart(8)}`);
    continue;
  }
  const size = fs.statSync(file).size;
  const min = Math.floor(size * 0.7);
  console.log(`${file.padEnd(45)} ${String(size).padStart(8)}  ${String(min).padStart(9)}`);
}

console.log('');
