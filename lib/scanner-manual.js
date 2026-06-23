const { RESET, YELLOW } = require('./output-constants');
/**
 * scanner-manual.js
 * File discovery and orchestration for manual `scd scan` runs.
 *
 * --no-limit flag: bypasses size limit, scans all files with 30s timeout per file.
 */

const fs   = require('fs');
const path = require('path');
const { buildIgnoreFilter } = require('./file-filter');
const { loadScope, isFileExcluded, validateScope, summariseScope } = require('./scope');

// Simple glob expansion — supports * and ? wildcards in filename segment only
// e.g. "*.txt", "logs/*.log", "src/**/*.js" (** treated as any depth)
function expandGlob(pattern, cwd) {
  const resolved = path.resolve(cwd, pattern);
  const dir      = path.dirname(resolved);
  const basename = path.basename(resolved);

  // No wildcards — return as-is (existence checked later)
  if (!basename.includes('*') && !basename.includes('?')) return null;

  // Convert glob pattern to regex
  const reStr = basename
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex metacharacters
    .replace(/\*\*/g, '.+')                 // ** = one or more chars (any depth)
    .replace(/\*/g, '[^/]*')                // * = any chars except separator
    .replace(/\?/g, '[^/]');                // ? = single char
  const re = new RegExp('^' + reStr + '$', 'i');

  // Walk upward to find a real directory to scan
  let scanDir = dir;
  while (!fs.existsSync(scanDir) && scanDir !== path.dirname(scanDir)) {
    scanDir = path.dirname(scanDir);
  }
  if (!fs.existsSync(scanDir)) return [];

  // Collect matching files (recursive if ** used, flat otherwise)
  const recursive = basename.includes('**');
  return collectMatchingFiles(scanDir, re, recursive);
}

function collectMatchingFiles(dir, re, recursive) {
  const results = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return results; }

  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory() && recursive) {
      results.push(...collectMatchingFiles(fullPath, re, recursive));
    } else if (entry.isFile() && re.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

const SUPPORTED_EXTENSIONS = new Set([
  'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx',
  'py',
  'php',
  'aspx', 'ascx', 'master',
  'config',
  'cs',
  'txt', 'log',
  // Sensitive file types
  'env',
  'sql',
  'yml', 'yaml',
  'json',
  'xml',
  'properties',
  'ini', 'cfg', 'conf',
  'sh', 'bash',
  'ps1',
  'bat', 'cmd',
  'bak', 'old', 'orig',
  'pem', 'key', 'pfx', 'p12',
  'sqlite', 'sqlite3', 'db',
]);

const LANG_TO_EXTENSIONS = {
  js:         ['js', 'mjs', 'cjs'],
  javascript: ['js', 'mjs', 'cjs'],
  ts:         ['ts', 'tsx'],
  typescript: ['ts', 'tsx'],
  react:      ['jsx', 'tsx'],
  py:         ['py'],
  python:     ['py'],
  php:        ['php'],
  aspx:       ['aspx', 'ascx', 'master'],
  aspnet:     ['aspx', 'ascx', 'master', 'config', 'cs'],
  dotnet:     ['aspx', 'ascx', 'master', 'config', 'cs'],
  config:     ['config'],
  cs:         ['cs'],
  csharp:     ['cs'],
  // Sensitive file types
  env:        ['env'],
  sql:        ['sql'],
  yaml:       ['yml', 'yaml'],
  yml:        ['yml', 'yaml'],
  json:       ['json'],
  xml:        ['xml'],
  properties: ['properties'],
  ini:        ['ini', 'cfg', 'conf'],
  shell:      ['sh', 'bash'],
  sh:         ['sh', 'bash'],
  powershell: ['ps1'],
  ps1:        ['ps1'],
  batch:      ['bat', 'cmd'],
  bat:        ['bat', 'cmd'],
  secrets:    ['env', 'pem', 'key', 'pfx', 'p12', 'sqlite', 'sqlite3', 'db', 'bak'],
  txt:        ['txt'],
  log:        ['log'],
  logs:       ['log', 'txt'],
};

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt',
  'coverage', '.nyc_output', '__pycache__', '.cache',
  'target', 'out',
]);

// ── Vendor path patterns ───────────────────────────────────────────────────
// Matches paths that are vendor/dependency code, not project source.
// Used by isVendorPath() to filter files during discovery.
// Vendor path pattern — matches dependency/library code that is not project source.
// Covers: JS (node_modules), PHP (vendor), Python (site-packages, venv, __pycache__),
//         .NET (packages, bin/Release, obj/Debug), minified assets.
const VENDOR_PATH_RE = /(?:^|[/\\])(?:node_modules|vendor|site-packages|bower_components|packages)[/\\]|[/\\]lib[/\\]python[0-9]|(?:^|[/\\])__pycache__[/\\]|\.pyc$|(?:^|[/\\])(?:\.venv|venv|env)[/\\]|(?:^|[/\\])bin[/\\](?:Debug|Release)[/\\]|(?:^|[/\\])obj[/\\](?:Debug|Release)[/\\]|\.min\.(?:js|css)$/i;

/**
 * Returns true if a file path looks like vendor/dependency code.
 * Used to implement --include-vendor / --vendor-only behaviour.
 */
function isVendorPath(filePath) {
  return VENDOR_PATH_RE.test(filePath);
}

// Default max file size: 2MB. Overridden by scan.max_file_size_kb in yml.
const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;

// Timeout per file when --no-limit is active (ms)
const NO_LIMIT_TIMEOUT_MS = 30_000;

// ── File discovery ─────────────────────────────────────────────────────────

function discoverFiles(target, opts = {}) {
  const { lang, noLimit = false, includeVendor = false, vendorOnly = false, includeIgnored = false, repoRoot = null } = opts;

  const allowedExts = lang
    ? new Set(LANG_TO_EXTENSIONS[lang.toLowerCase()] || [])
    : SUPPORTED_EXTENSIONS;

  if (lang && allowedExts.size === 0) {
    throw new Error(
      `Unknown language: "${lang}". Available: ${Object.keys(LANG_TO_EXTENSIONS).join(', ')}`
    );
  }

  const resolved = path.resolve(process.cwd(), target || '.');

  // ── Glob pattern (contains * or ?) ──────────────────────────────────────
  if (target && (target.includes('*') || target.includes('?'))) {
    const matches = expandGlob(target, process.cwd());
    if (!matches || matches.length === 0) {
      throw new Error(`No files matched: ${target}`);
    }
    // Filter by allowed extensions if --lang was specified
    const filtered = allowedExts.size > 0
      ? matches.filter(f => allowedExts.has(path.extname(f).slice(1).toLowerCase()))
      : matches.filter(f => SUPPORTED_EXTENSIONS.has(path.extname(f).slice(1).toLowerCase()));
    if (filtered.length === 0) {
      throw new Error(`No files with supported extensions matched: ${target}`);
    }
    const r = readFiles(filtered, allowedExts, opts.config, noLimit);
    return { ...r, scopeExclusions: null, scope: null };
  }

  if (!fs.existsSync(resolved)) {
    throw new Error(`Not found: ${target}`);
  }

  const stat = fs.statSync(resolved);

  if (stat.isFile()) {
    const r = readFiles([resolved], allowedExts, opts.config, noLimit);
    return { ...r, scopeExclusions: null, scope: null };
  }

  if (stat.isDirectory()) {
    // Build .gitignore filter — respects git ls-files or manual .gitignore parsing
    const ignoreRoot   = repoRoot || resolved;

    // Load scope.yml exclusions (global + repo + server-managed)
    const scope = repoRoot ? loadScope(repoRoot) : { file_excludes: [], rule_excludes: [] };

    // Warn on incomplete scope entries (missing reason/added_by/added_at)
    const scopeWarnings = validateScope(scope);
    for (const w of scopeWarnings) {
      process.stderr.write(`${YELLOW}  ⚠ scope.yml: entry "${w.identifier}" is missing required fields: ${w.missing.join(', ')}${RESET}\n`);
    }

    // Build combined filter: .gitignore + scope file_excludes
    const shouldIgnoreGit  = includeIgnored ? () => false : buildIgnoreFilter(ignoreRoot);
    // Count files excluded by scope (not by .gitignore) for audit/output
    let scopeExcludedCount = 0;
    const shouldIgnoreWithCount = (filePath) => {
      if (shouldIgnoreGit(filePath)) return true;
      if (scope.file_excludes.length === 0) return false;
      const result = isFileExcluded(scope, filePath, ignoreRoot);
      if (result.excluded) { scopeExcludedCount++; return true; }
      return false;
    };

    const found = walkDir(resolved, allowedExts, { includeVendor, vendorOnly, shouldIgnore: shouldIgnoreWithCount });
    const { files, skipped } = readFiles(found, allowedExts, opts.config, noLimit);

    // Build scope exclusion summary for audit log and scan output
    const scopeSummary = summariseScope(scope);
    const scopeExclusions = scopeSummary.hasExclusions ? {
      files_excluded:   scopeExcludedCount,
      file_excludes:    scope.file_excludes,
      rule_excludes:    scope.rule_excludes,
      _summary:         scopeSummary,
      _warnings:        scopeWarnings,
    } : null;

    return { files, skipped, scopeExclusions, scope };
  }

  throw new Error(`Cannot scan: ${target} (neither a file nor a directory)`);
}

function walkDir(dir, allowedExts, opts = {}) {
  const { includeVendor = false, vendorOnly = false, shouldIgnore = () => false } = opts;
  const results = [];

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.env') continue;
    if (IGNORED_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      // Skip dirs ignored by .gitignore
      if (shouldIgnore(fullPath + path.sep)) continue;
      // Default mode: skip known vendor dir names
      const isDirVendor = isVendorPath(fullPath + '/');
      if (isDirVendor && !includeVendor && !vendorOnly) continue;
      results.push(...walkDir(fullPath, allowedExts, opts));
    } else if (entry.isFile()) {
      const ext  = entry.name.split('.').pop().toLowerCase();
      if (!allowedExts.has(ext)) continue;

      // Skip files ignored by .gitignore
      if (shouldIgnore(fullPath)) continue;

      const vendor = isVendorPath(fullPath);
      // Default: skip vendor files
      if (vendor && !includeVendor && !vendorOnly) continue;
      // --vendor-only: skip non-vendor files
      if (!vendor && vendorOnly) continue;

      results.push(fullPath);
    }
  }

  return results;
}

/**
 * Read files, enforce size limit (unless noLimit=true).
 * noLimit mode: reads all files but enforces a 30s scan timeout per file
 * by marking them so scanFull can bail out if scanning stalls.
 */
function readFiles(filePaths, allowedExts, config = null, noLimit = false) {
  const files   = [];
  const skipped = [];

  const maxBytes = noLimit
    ? Infinity
    : (config?.scan?.max_file_size_kb
        ? config.scan.max_file_size_kb * 1024
        : DEFAULT_MAX_FILE_SIZE);

  for (const filePath of filePaths) {
    const ext = filePath.split('.').pop().toLowerCase();
    if (!allowedExts.has(ext)) continue;

    const relativePath = path.relative(process.cwd(), filePath);

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const kb = Math.round(content.length / 1024);

      if (content.length > maxBytes) {
        skipped.push({
          filePath: relativePath,
          reason: 'too_large',
          sizeKb: kb,
          limitKb: Math.round(maxBytes / 1024),
        });
        continue;
      }

      // Flag large files so scanner can apply per-file timeout
      const isLarge = kb > 512; // > 512KB flaggas som stor
      files.push({ filePath: relativePath, content, sizeKb: kb, isLarge, noLimit });
    } catch (err) {
      skipped.push({ filePath: relativePath, reason: 'unreadable', error: err.message });
    }
  }

  return { files, skipped };
}

/**
 * Filter findings based on CLI options.
 */
function filterFindings(findings, opts = {}) {
  let result = findings;

  if (opts.severity) {
    const sev = opts.severity.toUpperCase();
    result = result.filter(f => f.severity === sev);
  }

  if (opts.rule) {
    const ruleId = opts.rule.toUpperCase();
    result = result.filter(f => f.ruleId.toUpperCase() === ruleId);
  }

  return result;
}

module.exports = {
  discoverFiles,
  filterFindings,
  isVendorPath,
  SUPPORTED_EXTENSIONS,
  LANG_TO_EXTENSIONS,
  NO_LIMIT_TIMEOUT_MS,
};
