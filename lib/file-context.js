/**
 * file-context.js
 * Builds a context object for a file before rules are applied.
 *
 * Detection is two-layer:
 *   Layer 1 — path/filename signals (always evaluated, fast)
 *   Layer 2 — content signals (first 50 lines, always run when content available)
 *
 * Vendor and generated files are classified definitively from path/filename alone.
 * All other test/fixture classifications are tentative — content must confirm them.
 * If content is unavailable (e.g. secrets scanner path), tentative type is used as-is.
 *
 * The returned context is passed to applyContextModifiers() in context-modifiers.js.
 * Rules themselves are not modified — file context is a purely additive layer.
 */

'use strict';

const path = require('path');

// ── File type constants ────────────────────────────────────────────────────
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

// TENTATIVE — requires content confirmation when content is available.
const FIXTURE_PATH_SEGMENTS = [
  '/fixtures/', '/fixture/', '/mocks/', '/mock/', '/stubs/', '/stub/',
  '/__fixtures__/', '/__mocks__/',
];

// TENTATIVE — requires content confirmation when content is available.
const TEST_PATH_SEGMENTS = [
  '/test/', '/tests/', '/spec/', '/specs/',
  '/__tests__/', '/__specs__/',
  '/e2e/', '/integration-tests/', '/unit/',
];

// DEFINITIVE — never production code regardless of content.
const VENDOR_PATH_SEGMENTS = [
  '/vendor/', '/node_modules/', '/bower_components/', '/site-packages/',
  '/lib/python', '/packages/', '/.venv/', '/venv/',
];

// DEFINITIVE — machine output, findings are not actionable.
const GENERATED_PATH_SEGMENTS = [
  '/dist/', '/build/', '/out/', '/.next/', '/.nuxt/',
  '/generated/', '/gen/', '/auto-generated/',
  '/coverage/', '/.nyc_output/', '/__pycache__/',
];

// TENTATIVE — requires content confirmation when content is available.
const DOCS_PATH_SEGMENTS = [
  '/docs/', '/doc/', '/documentation/', '/wiki/',
];

// TEST_FILENAME_RE: TENTATIVE — requires content confirmation.
// STRONG_TEST_FILENAME_RE: DEFINITIVE — filename alone is sufficient, no content needed.
//   Rules: suffix .test.EXT or .spec.EXT, prefix test_*.EXT, suffix _test.EXT
//   These are language-standard test file naming conventions — ambiguity is negligible.
//   Path-only signals (/tests/ directory without filename signal) remain tentative.
// GENERATED_FILE_RE: DEFINITIVE.
// CONFIG_FILE_RE: DIRECT — config modifier is 0, no suppression risk.
const STRONG_TEST_FILENAME_RE = /(?:\.(?:test|spec)\.[a-z]+$|_test\.[a-z]+$|^test_[^/]+\.[a-z]+$)/i;
const TEST_FILENAME_RE        = /(?:\.(?:test|spec)\.[a-z]+$|_test\.[a-z]+$|^test_.*\.[a-z]+$|Test\.[a-z]+$|\.test$|\.spec$)/i;
const GENERATED_FILE_RE = /(?:\.min\.(?:js|css)$|package-lock\.json$|yarn\.lock$|composer\.lock$|Pipfile\.lock$|\.lock$|\.d\.ts$)/i;
const CONFIG_FILE_RE    = /(?:\.(?:env|config|conf|ini|cfg|properties|yml|yaml|toml|json)$|^\.env(?:\.[a-z]+)?$|webpack\.config\.|vite\.config\.|babel\.config\.|jest\.config\.|karma\.conf\.|rollup\.config\.|tsconfig\.|\.eslintrc|\.prettierrc|\.stylelintrc)/i;

// ── Test framework content signals ─────────────────────────────────────────
// Checked against the first 50 lines of the file.
// Ordered by specificity — more specific signals first.

const FRAMEWORK_CONTENT_SIGNALS = [
  // Jest
  { framework: 'jest',      re: /\bjest\.(?:mock|fn|spyOn|setTimeout|useFakeTimers)\b/ },
  { framework: 'jest',      re: /from\s+['"](?:@jest\/globals|jest-each)['"]/  },
  // Vitest
  { framework: 'vitest',    re: /from\s+['"]vitest['"]/  },
  { framework: 'vitest',    re: /\bvi\.(?:mock|fn|spyOn)\b/ },
  // Playwright — @playwright/test, widely used for E2E
  { framework: 'playwright', re: /from\s+['"]@playwright\/test['"]/ },
  { framework: 'playwright', re: /\btest\.(?:describe|beforeAll|afterAll|beforeEach|afterEach)\b/ },
  // Mocha / Chai
  { framework: 'mocha',     re: /\b(?:before|after|beforeEach|afterEach)\s*\(/ },
  { framework: 'mocha',     re: /\bassert\.[a-z]+\s*\(/ },
  // Pytest
  { framework: 'pytest',    re: /\bimport\s+pytest\b/ },
  { framework: 'pytest',    re: /\bdef\s+test_[a-z_]+\s*\(/ },
  { framework: 'pytest',    re: /@pytest\.fixture\b/ },
  // Python unittest (stdlib)
  { framework: 'unittest',  re: /\bimport\s+unittest\b/ },
  { framework: 'unittest',  re: /\bfrom\s+unittest\b/ },
  { framework: 'unittest',  re: /\bclass\s+\w+\s*\(\s*unittest\.TestCase\s*\)/ },
  // PHPUnit — direct extends
  { framework: 'phpunit',   re: /\bextends\s+(?:TestCase|PHPUnit[\\]Framework[\\]TestCase)\b/ },
  { framework: 'phpunit',   re: /public\s+function\s+test[A-Z]/ },
  // PHPUnit — import/namespace signals (catches indirect inheritance chains)
  { framework: 'phpunit',   re: /\buse\s+PHPUnit\\/ },
  { framework: 'phpunit',   re: /\bnamespace\s+\S+\\Tests?\\/ },
  // Pest — modern PHP testing framework
  { framework: 'pest',      re: /\buses\s*\(\s*\w+::class\s*\)/ },
  { framework: 'pest',      re: /\bit\s*\(\s*['"]/ },
  // C# — NUnit, xUnit, MSTest (attribute-based, detected without imports)
  { framework: 'nunit',     re: /\[(?:Test|TestFixture|SetUp|TearDown|OneTimeSetUp)\]/ },
  { framework: 'xunit',     re: /\[(?:Fact|Theory|InlineData|ClassData)\]/ },
  { framework: 'mstest',    re: /\[(?:TestMethod|TestClass|TestInitialize|TestCleanup)\]/ },
  // RSpec
  { framework: 'rspec',     re: /\b(?:describe|context|it)\s+['"].*['"],?\s*do\b/ },
  { framework: 'rspec',     re: /\bexpect\s*\(.*\)\.to\s/ },
  // Ruby Minitest
  { framework: 'minitest',  re: /require\s+['"]minitest\/autorun['"]/ },
  { framework: 'minitest',  re: /\bclass\s+\w+\s*<\s*Minitest::Test\b/ },
  // Node.js built-in test runner (node:test, Node 18+)
  { framework: 'node-test', re: /require\s*\(\s*['"]node:test['"]\s*\)/ },
  { framework: 'node-test', re: /from\s+['"]node:test['"]/ },
  // Bun test runner (bun:test)
  { framework: 'bun-test',  re: /from\s+['"]bun:test['"]/ },
  { framework: 'bun-test',  re: /require\s*\(\s*['"]bun:test['"]\s*\)/ },
  // Generic — lower specificity, checked last
  { framework: null,        re: /\b(?:describe|it|expect|assert|should)\s*[\.(]/ },
];

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

function normalisePath(filePath) {
  const normalised = filePath.replace(/\\/g, '/').toLowerCase();
  return normalised.startsWith('/') ? normalised : '/' + normalised;
}

function hasPathSegment(normPath, segments) {
  return segments.some(seg => normPath.includes(seg));
}

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
 * @param {string} [content] - File content (optional; used for content signals).
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
  // Vendor and generated are definitive. All test/fixture signals are tentative.

  // Definitive: vendor
  if (!fileType && hasPathSegment(normPath, VENDOR_PATH_SEGMENTS)) {
    fileType = FILE_TYPES.VENDOR;
    signals.push(`path: vendor segment in ${normPath}`);
  }

  // Definitive: generated path
  if (!fileType && hasPathSegment(normPath, GENERATED_PATH_SEGMENTS)) {
    fileType = FILE_TYPES.GENERATED;
    signals.push(`path: generated segment in ${normPath}`);
  }

  // Definitive: generated filename
  if (!fileType && GENERATED_FILE_RE.test(basename)) {
    fileType = FILE_TYPES.GENERATED;
    signals.push(`filename: generated pattern (${basename})`);
  }

  // Tentative classifications — stored, not committed until content confirms.
  // tentativeIsPathBased tracks whether the signal is path-based (reliable without
  // content) or filename-only (unreliable — must not be committed without content).
  let tentativeType        = null;
  let tentativeSignal      = null;
  let tentativeIsPathBased = false;

  if (!fileType && hasPathSegment(normPath, FIXTURE_PATH_SEGMENTS)) {
    tentativeType        = FILE_TYPES.FIXTURE;
    tentativeSignal      = `path: fixture segment in ${normPath}`;
    tentativeIsPathBased = true;
  }

  // Definitive: strong test filename signal AND known test path — both required.
  // Rationale: filename alone is insufficient — kunddata.test.js in /src/ must not
  // bypass scanning. An attacker can rename a file to evade detection.
  if (!fileType && !tentativeType
      && STRONG_TEST_FILENAME_RE.test(basename)
      && hasPathSegment(normPath, TEST_PATH_SEGMENTS)) {
    fileType = FILE_TYPES.TEST;
    signals.push(`filename+path: strong test signal (${basename}) — definitive`);
  }

  // Tentative: strong filename without test path, or weaker filename signals.
  // Filename-only tentative is NOT committed without content — see no-content branch.
  if (!fileType && !tentativeType && TEST_FILENAME_RE.test(basename)) {
    tentativeType        = FILE_TYPES.TEST;
    tentativeSignal      = `filename: test pattern (${basename})`;
    tentativeIsPathBased = false;
  }

  if (!fileType && !tentativeType && hasPathSegment(normPath, TEST_PATH_SEGMENTS)) {
    tentativeType        = FILE_TYPES.TEST;
    tentativeSignal      = `path: test segment in ${normPath}`;
    tentativeIsPathBased = true;
  }

  // Config: direct (modifier = 0, suppression never occurs)
  if (!fileType && !tentativeType && CONFIG_FILE_RE.test(basename)) {
    fileType = FILE_TYPES.CONFIG;
    signals.push(`filename: config pattern (${basename})`);
  }

  // Docs: tentative (path-based)
  if (!fileType && !tentativeType && hasPathSegment(normPath, DOCS_PATH_SEGMENTS)) {
    tentativeType        = FILE_TYPES.DOCS;
    tentativeSignal      = `path: docs segment in ${normPath}`;
    tentativeIsPathBased = true;
  }

  // ── Early commit for data/config extensions in test/fixture paths ──────────
  // Data and config file types (.json, .yaml, .txt, .sql etc.) cannot contain
  // test framework imports — Layer 2 content confirmation will never succeed.
  // If such a file is in a test/fixture path, commit the tentative type directly
  // without requiring content confirmation.
  // Rationale: a .json file in /tests/ is test data by definition.
  // A .yaml file in /fixtures/ is a fixture by definition.
  // These are never "source code" that needs scanning for vulnerabilities
  // at the same severity as production config.
  const DATA_EXTS_NO_CONFIRM = new Set([
    'json', 'yaml', 'yml', 'xml', 'txt', 'log', 'sql',
    'sqlite', 'sqlite3', 'db', 'pem', 'key', 'pfx', 'p12',
    'csv', 'tsv', 'toml', 'ini', 'cfg', 'conf', 'properties',
  ]);
  if (!fileType && tentativeType && DATA_EXTS_NO_CONFIRM.has(ext)) {
    fileType = tentativeType;
    signals.push(tentativeSignal);
    signals.push(`data/config extension in test path — committed without content confirmation`);
    tentativeType   = null;
    tentativeSignal = null;
  }

  // ── Layer 1.5: framework detection for filename-confirmed test files ─────────
  // Strong filename signals (*.test.js, *.spec.ts, test_*.py) commit fileType=TEST
  // in Layer 1, so Layer 2's content loop never runs and testFramework stays null.
  // Detect the framework here before Layer 2 guards on !fileType.
  if (fileType === FILE_TYPES.TEST && !testFramework && content) {
    const head = firstLines(content, 50);
    for (const { framework, re } of FRAMEWORK_CONTENT_SIGNALS) {
      if (framework && re.test(head)) {
        testFramework = framework;
        signals.push(`content: framework=${framework}`);
        break;
      }
    }
  }

  // ── Layer 2: content signals ───────────────────────────────────────────────
  // Run when fileType is not definitively set.
  // With content: tentative must be confirmed, or it falls back to source.
  // Without content: tentative is committed as-is (best available signal).

  if (!fileType) {
    if (content) {
      const head = firstLines(content, 50);

      for (const { framework, re } of FRAMEWORK_CONTENT_SIGNALS) {
        if (re.test(head)) {
          if (!testFramework && framework) {
            testFramework = framework;
            signals.push(`content: framework=${framework}`);
          }

          if (!fileType) {
            if (tentativeType) {
              fileType = tentativeType;
              signals.push(tentativeSignal);
              signals.push(`content: confirmed (${re.source.slice(0, 40)})`);
            } else {
              fileType = FILE_TYPES.TEST;
              signals.push(`content: test signal (${re.source.slice(0, 40)})`);
            }
          }

          if (fileType && testFramework) break;
        }
      }

      // Tentative not confirmed by content → source
      if (!fileType && tentativeType) {
        signals.push(`path/filename: ${tentativeSignal} — not confirmed by content, treated as source`);
        fileType = FILE_TYPES.SOURCE;
      }

    } else {
      // No content — only path-based tentative is committed; filename-only falls to source.
      // A path signal (/tests/, /fixtures/ etc.) is reliable without content.
      // A filename signal alone (*.test.js in /src/) is not — commit it as source to
      // avoid suppressing findings in misnamed production files.
      if (tentativeType && tentativeIsPathBased) {
        fileType = tentativeType;
        signals.push(tentativeSignal);
        signals.push('content: unavailable — path signal committed without confirmation');
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
