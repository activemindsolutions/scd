/**
 * file-context.js
 * Builds a context object for a file before rules are applied.
 *
 * Detection is two-layer:
 *   Layer 1 — path/filename signals (always evaluated, fast)
 *   Layer 2 — content signals (first 20 lines, always run when content available)
 *
 * Vendor and generated files are classified definitively from path/filename alone.
 * All other test/fixture classifications are tentative — content must confirm them.
 * If content is unavailable (e.g. secrets scanner path), tentative type is used as-is.
 */

'use strict';

const path = require('path');

// ── File type constants ────────────────────────────────────────────────────
// Ordered by specificity (fixture > vendor > generated > test > config > docs > source).
// A file can only have one fileType — the first match wins.
const FILE_TYPES = {
  FIXTURE:   'fixture',
  VENDOR:    'vendor',
  GENERATED: 'generated',
  TEST:      'test',
  CONFIG:    'config',
  DOCS:      'docs',
  SOURCE:    'source',
};

// ── Path/filename signal patterns ──────────────────────────────────────────

// Path segments that indicate fixture files (test data, mocks, stubs).
// Checked as lowercased path segment boundaries.
const FIXTURE_PATH_SEGMENTS = [
  '/fixtures/', '/fixture/', '/mocks/', '/mock/', '/stubs/', '/stub/',
  '/__fixtures__/', '/__mocks__/',
];

// Path segments that indicate test code.
const TEST_PATH_SEGMENTS = [
  '/test/', '/tests/', '/spec/', '/specs/',
  '/__tests__/', '/__specs__/',
  '/e2e/', '/integration-tests/', '/unit/',
];

// Path segments that indicate vendor/dependency code (not project source).
const VENDOR_PATH_SEGMENTS = [
  '/vendor/', '/node_modules/', '/bower_components/', '/site-packages/',
  '/lib/python', '/packages/', '/.venv/', '/venv/',
];

// Path segments that indicate generated code.
const GENERATED_PATH_SEGMENTS = [
  '/dist/', '/build/', '/out/', '/.next/', '/.nuxt/',
  '/generated/', '/gen/', '/auto-generated/',
  '/coverage/', '/.nyc_output/', '/__pycache__/',
];

// Path segments that indicate documentation.
const DOCS_PATH_SEGMENTS = [
  '/docs/', '/doc/', '/documentation/', '/wiki/',
];

// Filename patterns — checked against basename only.
const TEST_FILENAME_RE    = /(?:\.(?:test|spec)\.[a-z]+$|_test\.[a-z]+$|^test_.*\.[a-z]+$|Test\.[a-z]+$|\.test$|\.spec$)/i;
const GENERATED_FILE_RE   = /(?:\.min\.(?:js|css)$|package-lock\.json$|yarn\.lock$|composer\.lock$|Pipfile\.lock$|\.lock$|\.d\.ts$)/i;
const CONFIG_FILE_RE      = /(?:\.(?:env|config|conf|ini|cfg|properties|yml|yaml|toml|json)$|^\.env(?:\.[a-z]+)?$|webpack\.config\.|vite\.config\.|babel\.config\.|jest\.config\.|karma\.conf\.|rollup\.config\.|tsconfig\.|\.eslintrc|\.prettierrc|\.stylelintrc)/i;

// ── Test framework content signals ─────────────────────────────────────────
// Checked against the first 20 lines of the file (joined as a single string).
// Only read when path/filename signals are ambiguous.

const FRAMEWORK_CONTENT_SIGNALS = [
  // Jest (must come before generic describe/it — jest.mock is unambiguous)
  { framework: 'jest',    re: /\bjest\.(?:mock|fn|spyOn|setTimeout|useFakeTimers)\b/ },
  { framework: 'jest',    re: /from\s+['"](?:@jest\/globals|jest-each)['"]/  },
  // Vitest
  { framework: 'vitest',  re: /from\s+['"]vitest['"]/  },
  { framework: 'vitest',  re: /\bvi\.(?:mock|fn|spyOn)\b/ },
  // Mocha / Chai (generic describe/it — lower specificity, checked after jest/vitest)
  { framework: 'mocha',   re: /\b(?:before|after|beforeEach|afterEach)\s*\(/ },
  { framework: 'mocha',   re: /\bassert\.[a-z]+\s*\(/ },
  // Pytest
  { framework: 'pytest',  re: /\bimport\s+pytest\b/ },
  { framework: 'pytest',  re: /\bdef\s+test_[a-z_]+\s*\(/ },
  { framework: 'pytest',  re: /@pytest\.fixture\b/ },
  // PHPUnit
  { framework: 'phpunit', re: /\bextends\s+(?:TestCase|PHPUnit[\\]Framework[\\]TestCase)\b/ },
  { framework: 'phpunit', re: /public\s+function\s+test[A-Z]/ },
  // RSpec
  { framework: 'rspec',   re: /\b(?:describe|context|it)\s+['"].*['"],?\s*do\b/ },
  { framework: 'rspec',   re: /\bexpect\s*\(.*\)\.to\s/ },
  // Generic signals that suggest test code without a specific framework
  { framework: null,      re: /\b(?:describe|it|expect|assert|should)\s*[\.(]/ },
];

// Production config signals — presence of these in content boosts confidence
// that a file is a real config (not a test fixture pretending to be one).
// (Reserved for future context_boost feature; not used in v1.0.0.)
// const PRODUCTION_CONFIG_SIGNALS = [ ... ];

// ── Language detection from extension ─────────────────────────────────────
const EXT_TO_LANGUAGE = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript',
  jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript',
  py: 'python',
  php: 'php',
  cs: 'csharp',
  aspx: 'aspnet', ascx: 'aspnet', master: 'aspnet',
  rb: 'ruby',
  go: 'go',
  java: 'java',
  kt: 'kotlin',
  rs: 'rust',
  sh: 'shell', bash: 'shell',
  ps1: 'powershell',
  bat: 'batch', cmd: 'batch',
  yml: 'yaml', yaml: 'yaml',
  json: 'json',
  xml: 'xml',
  sql: 'sql',
  env: 'env',
  ini: 'ini', cfg: 'ini', conf: 'ini', properties: 'ini',
  txt: 'text',
  log: 'text',
  md: 'markdown',
  pem: 'pem', key: 'pem', pfx: 'pem', p12: 'pem',
};

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Normalise a file path for consistent matching:
 * - Backslashes → forward slashes
 * - Lowercased
 * - Always has a leading slash for segment boundary matching
 */
function normalisePath(filePath) {
  const normalised = filePath.replace(/\\/g, '/').toLowerCase();
  return normalised.startsWith('/') ? normalised : '/' + normalised;
}

/** Returns true if any of the segment strings appear in the normalised path. */
function hasPathSegment(normPath, segments) {
  return segments.some(seg => normPath.includes(seg));
}

/**
 * Extract the first 20 lines of content as a single string for signal matching.
 * Cheap — avoids reading the full file for content signals.
 */
function firstLines(content, n = 50) {
  if (!content) return '';
  let count = 0;
  let idx = 0;
  while (idx < content.length && count < n) {
    if (content[idx] === '\n') count++;
    idx++;
  }
  return content.slice(0, idx);
}

// ── Main export ────────────────────────────────────────────────────────────

/**
 * Build a context object for a file before rules are evaluated.
 *
 * @param {string} filePath  - Relative or absolute path to the file.
 * @param {string} [content] - File content (optional; used only for content signals).
 * @returns {FileContext}
 *
 * @typedef {Object} FileContext
 * @property {string}      filePath       - As supplied.
 * @property {string}      fileType       - One of: source | test | fixture | vendor | generated | config | docs
 * @property {string|null} testFramework  - Detected test framework, or null.
 * @property {string|null} language       - Detected language from extension, or null.
 * @property {string[]}    signals        - Human-readable list of signals that drove classification.
 */
function buildFileContext(filePath, content) {
  const normPath = normalisePath(filePath);
  const basename = path.basename(filePath).toLowerCase();
  const ext      = (filePath.split('.').pop() || '').toLowerCase();
  const language = EXT_TO_LANGUAGE[ext] || null;

  const signals = [];
  let fileType      = null;
  let testFramework = null;

  // ── Layer 1: path/filename signals ────────────────────────────────────────
  // Vendor and generated are definitive — they are never production code
  // regardless of content. All other test/fixture signals are tentative and
  // require content confirmation in Layer 2 when content is available.

  // Definitive: vendor — third-party code, never customer-owned
  if (!fileType && hasPathSegment(normPath, VENDOR_PATH_SEGMENTS)) {
    fileType = FILE_TYPES.VENDOR;
    signals.push(`path: vendor segment in ${normPath}`);
  }

  // Definitive: generated — machine output, findings not actionable
  if (!fileType && hasPathSegment(normPath, GENERATED_PATH_SEGMENTS)) {
    fileType = FILE_TYPES.GENERATED;
    signals.push(`path: generated segment in ${normPath}`);
  }

  // Definitive: generated filenames (lock files, minified, declaration files)
  if (!fileType && GENERATED_FILE_RE.test(basename)) {
    fileType = FILE_TYPES.GENERATED;
    signals.push(`filename: generated pattern (${basename})`);
  }

  // Tentative: fixture/mock path segments — strong signal but developers name
  // things creatively, so content confirmation is still applied when available.
  let tentativeType   = null;
  let tentativeSignal = null;

  if (!fileType && hasPathSegment(normPath, FIXTURE_PATH_SEGMENTS)) {
    tentativeType   = FILE_TYPES.FIXTURE;
    tentativeSignal = `path: fixture segment in ${normPath}`;
  }

  // Tentative: test filename pattern (*.test.js, *_test.py etc.)
  if (!fileType && !tentativeType && TEST_FILENAME_RE.test(basename)) {
    tentativeType   = FILE_TYPES.TEST;
    tentativeSignal = `filename: test pattern (${basename})`;
  }

  // Tentative: test path segment (/test/, /tests/, /spec/ etc.)
  if (!fileType && !tentativeType && hasPathSegment(normPath, TEST_PATH_SEGMENTS)) {
    tentativeType   = FILE_TYPES.TEST;
    tentativeSignal = `path: test segment in ${normPath}`;
  }

  // Config filenames — tentative, no content confirmation needed (config files
  // can legitimately contain secrets; modifier is 0 so suppression won't occur)
  if (!fileType && !tentativeType && CONFIG_FILE_RE.test(basename)) {
    fileType = FILE_TYPES.CONFIG;
    signals.push(`filename: config pattern (${basename})`);
  }

  // Docs path — tentative, low risk (modifier is -1, same as test)
  if (!fileType && !tentativeType && hasPathSegment(normPath, DOCS_PATH_SEGMENTS)) {
    tentativeType   = FILE_TYPES.DOCS;
    tentativeSignal = `path: docs segment in ${normPath}`;
  }

  // ── Layer 2: content signals ───────────────────────────────────────────────
  // Always run when content is available and fileType is not yet definitively set.
  // Three outcomes:
  //   (a) Content confirms tentative type → commit tentativeType + record signal
  //   (b) Content finds test signals with no tentative type → classify as test
  //   (c) Content finds nothing → tentative type is downgraded to source
  //
  // When content is NOT available (e.g. secrets scanner path), tentative type
  // is committed as-is — path/filename signals are the best we have.

  if (!fileType) {
    if (content) {
      const head = firstLines(content, 50);
      let contentConfirmed = false;

      for (const { framework, re } of FRAMEWORK_CONTENT_SIGNALS) {
        if (re.test(head)) {
          contentConfirmed = true;

          if (!testFramework && framework) {
            testFramework = framework;
            signals.push(`content: framework=${framework}`);
          }

          // First content hit commits the type
          if (!fileType) {
            if (tentativeType) {
              // Content confirms the path/filename hint
              fileType = tentativeType;
              signals.push(tentativeSignal);
              signals.push(`content: confirmed (${re.source.slice(0, 40)})`);
            } else {
              // Pure content detection — no path/filename hint
              fileType = FILE_TYPES.TEST;
              signals.push(`content: test signal (${re.source.slice(0, 40)})`);
            }
          }

          if (fileType && testFramework) break;
        }
      }

      // Tentative type not confirmed by content → treat as source
      if (!fileType && tentativeType) {
        signals.push(`path/filename: ${tentativeSignal} — not confirmed by content, treated as source`);
        fileType = FILE_TYPES.SOURCE;
      }

    } else {
      // No content available — commit tentative type from path/filename signals
      if (tentativeType) {
        fileType = tentativeType;
        signals.push(tentativeSignal);
        signals.push('content: unavailable — path/filename signal used without confirmation');
      }
    }
  }

  // ── Default ───────────────────────────────────────────────────────────────
  if (!fileType) {
    fileType = FILE_TYPES.SOURCE;
  }

  return {
    filePath,
    fileType,
    testFramework,
    language,
    signals,
  };
}

module.exports = { buildFileContext, FILE_TYPES };
