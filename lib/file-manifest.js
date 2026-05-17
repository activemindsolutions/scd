'use strict';

/**
 * lib/file-manifest.js
 *
 * Pre-scan file classification — runs before any rules are applied.
 *
 * Classifies every file in the scan queue into a scan context:
 *
 *   source  — production code, scanned with full rule set
 *   test    — test/fixture files, scanned with test rule set (stub for now)
 *   excluded — vendor/generated files, not scanned, documented in output
 *
 * Classification is based on buildFileContext() from lib/file-context.js,
 * which uses two-layer detection: path/filename signals + content confirmation.
 * A file is only placed in the test context when classification is definitive
 * (content confirms the path/filename signal, or content alone is sufficient).
 * Tentative-only classifications fall back to source — conservative by design.
 *
 * This is the correct architectural layer for this decision. It replaces the
 * previous approach of post-scan severity modifiers that compensated for
 * findings in test files after rules had already been applied.
 *
 * Contexts are designed to be extensible — new contexts (e.g. 'config',
 * 'migration', 'schema') can be added without changing the core scan loop.
 * Individual contexts can also be force-included into the source loop via
 * config in the future (e.g. config.scan.force_source_context: ['test']).
 */

const { buildFileContext, FILE_TYPES } = require('./file-context');

/**
 * File types that are excluded from scanning entirely.
 * Vendor and generated files produce no actionable findings.
 */
const EXCLUDED_FILE_TYPES = new Set([
  FILE_TYPES.VENDOR,
  FILE_TYPES.GENERATED,
]);

/**
 * File types that are routed to the test scan context.
 * These are scanned with a separate, focused rule set (currently empty —
 * test rules will be defined in a future iteration).
 */
const TEST_FILE_TYPES = new Set([
  FILE_TYPES.TEST,
  FILE_TYPES.FIXTURE,
]);

/**
 * Build a file manifest by classifying all files before scanning begins.
 *
 * @param {Array<{filePath: string, content: string, ...}>} files
 *   The full list of files prepared by the file collector, in their
 *   original order. Each entry must have at minimum filePath and content.
 *
 * @returns {{
 *   source:   Array,   — files to scan with source rules (full rule set)
 *   test:     Array,   — files to scan with test rules (currently empty set)
 *   excluded: Array<{filePath, reason, fileType}>,
 *   summary:  {total, source, test, excluded},
 *   contexts: Map<string, string>  — filePath → context name, for scan-cache
 * }}
 */
function buildFileManifest(files) {
  const source   = [];
  const test     = [];
  const excluded = [];
  const contexts = new Map(); // filePath → 'source' | 'test' | 'excluded'

  // fileContexts maps filePath → fileContext for all non-excluded files.
  // Used by the secrets scanner which doesn't have file content available —
  // it must reuse the manifest classification rather than call buildFileContext()
  // without content (which would misclassify tentative test files as test
  // instead of falling back to source).
  const fileContexts = new Map();

  for (const file of files) {
    const { filePath, content } = file;

    // buildFileContext() runs two-layer detection:
    //   Layer 1: path/filename signals (tentative for test/fixture)
    //   Layer 2: content confirmation (first 50 lines)
    // If a tentative signal is not confirmed by content, fileType falls back
    // to SOURCE. We therefore trust fileType directly — the manifest is the
    // single authoritative classification for each file.
    const ctx = buildFileContext(filePath, content);

    if (EXCLUDED_FILE_TYPES.has(ctx.fileType)) {
      excluded.push({
        filePath,
        fileType: ctx.fileType,
        reason:   ctx.fileType === FILE_TYPES.VENDOR    ? 'vendor'    :
                  ctx.fileType === FILE_TYPES.GENERATED ? 'generated' : ctx.fileType,
        signals:  ctx.signals,
      });
      contexts.set(filePath, 'excluded');
      // excluded files get no fileContext entry — they are not scanned

    } else if (TEST_FILE_TYPES.has(ctx.fileType)) {
      test.push({ ...file, fileContext: ctx });
      contexts.set(filePath, 'test');
      fileContexts.set(filePath, ctx);

    } else {
      // SOURCE, CONFIG, DOCS, or any unrecognised type → source context.
      // Conservative: when in doubt, scan with full rule set.
      source.push({ ...file, fileContext: ctx });
      contexts.set(filePath, 'source');
      fileContexts.set(filePath, ctx);
    }
  }

  const summary = {
    total:    files.length,
    source:   source.length,
    test:     test.length,
    excluded: excluded.length,
  };

  return { source, test, excluded, summary, contexts, fileContexts };
}

/**
 * Format a one-line manifest summary for terminal output.
 * Shown before scanning begins so the user sees file breakdown upfront.
 *
 * Example:
 *   "312 source · 47 test (separate context) · 12 excluded (vendor/generated)"
 */
function formatManifestSummary(summary) {
  const parts = [`${summary.source} source`];

  if (summary.test > 0) {
    parts.push(`${summary.test} test (separate context)`);
  }
  if (summary.excluded > 0) {
    parts.push(`${summary.excluded} excluded (vendor/generated)`);
  }

  return parts.join(' · ');
}

module.exports = { buildFileManifest, formatManifestSummary };
