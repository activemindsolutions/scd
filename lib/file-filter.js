'use strict';

/**
 * lib/file-filter.js
 *
 * Builds a file filter for use during scan file discovery.
 * Applies .gitignore rules and scd scope.yml file_excludes patterns.
 *
 * Previously named gitignore-filter.js — renamed as scope.yml support
 * extends filtering beyond git-related exclusions.
 *
 * Strategy:
 *   Level 1 (git available): `git ls-files --cached --others --exclude-standard`
 *     Returns exactly the files git tracks or would track — free and correct.
 *   Level 2 (fallback, no git): Parse .gitignore files manually.
 *     Handles the common case: someone downloaded a repo without git clone,
 *     or git is not installed on the machine.
 *
 * Usage:
 *   const { buildIgnoreFilter } = require('./gitignore-filter');
 *   const shouldIgnore = buildIgnoreFilter(repoRoot);
 *   if (shouldIgnore(filePath)) // skip this file
 */

const fs            = require('fs');
const path          = require('path');
const { execSync }  = require('child_process');

// ── Level 1: git ls-files ────────────────────────────────────────────────

/**
 * Get the set of files tracked or untracked-but-not-ignored by git.
 * Returns null if git is unavailable or the directory is not a git repo.
 */
function getGitTrackedFiles(repoRoot) {
  try {
    const output = execSync(
      'git ls-files --cached --others --exclude-standard',
      { cwd: repoRoot, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const files = new Set(
      output.split('\n')
        .map(f => f.trim())
        .filter(Boolean)
        .map(f => path.resolve(repoRoot, f))
    );
    return files;
  } catch {
    return null;
  }
}

// ── Level 2: manual .gitignore parsing ──────────────────────────────────

/**
 * Parse a single .gitignore file and return an array of pattern objects.
 * Each pattern: { regex, negated, anchored }
 */
function parseGitignoreFile(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const patterns = [];

  for (let line of lines) {
    line = line.trim();
    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    const negated = line.startsWith('!');
    if (negated) line = line.slice(1);

    // Anchored: pattern starts with / (relative to .gitignore location)
    const anchored = line.startsWith('/');
    if (anchored) line = line.slice(1);

    // Convert glob pattern to regex.
    // Order matters: ** and * must be marked before regex-escaping,
    // otherwise plain * survives the escape step and lands verbatim
    // in the final regex (causing "nothing to repeat" errors on ^*).
    let regexStr = line
      .replace(/\*\*/g, '__DOUBLESTAR__')       // protect ** first
      .replace(/\*/g,   '__STAR__')             // then protect plain *
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')    // escape regex special chars
      .replace(/__STAR__/g,       '[^/]*')      // * = anything except /
      .replace(/__DOUBLESTAR__/g, '.*')         // ** = anything including /
      .replace(/\?/g, '[^/]');                  // ? = single char except /

    // Directory pattern (ends with /)
    const dirOnly = regexStr.endsWith('/');
    if (dirOnly) regexStr = regexStr.slice(0, -1);

    patterns.push({
      regex:    new RegExp((anchored ? '^' : '(^|/)') + regexStr + (dirOnly ? '(/|$)' : '(/|$)')),
      negated,
      dirOnly,
    });
  }

  return patterns;
}

/**
 * Collect all .gitignore files from repoRoot down (including nested ones).
 * Returns array of { dir, patterns } objects.
 */
function collectGitignorePatterns(repoRoot) {
  const result = [];

  function walk(dir) {
    const gitignorePath = path.join(dir, '.gitignore');
    const patterns = parseGitignoreFile(gitignorePath);
    if (patterns.length > 0) {
      result.push({ dir, patterns });
    }
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          walk(path.join(dir, entry.name));
        }
      }
    } catch { /* permission errors etc — skip */ }
  }

  walk(repoRoot);
  return result;
}

/**
 * Given collected gitignore rules, check if a file path should be ignored.
 */
function isIgnoredByPatterns(filePath, gitignoreRules) {
  let ignored = false;

  for (const { dir, patterns } of gitignoreRules) {
    // Only apply rules from .gitignore files at or above this file
    if (!filePath.startsWith(dir + path.sep) && filePath !== dir) continue;

    // Make path relative to the .gitignore's directory
    const rel = path.relative(dir, filePath).split(path.sep).join('/');

    for (const { regex, negated } of patterns) {
      if (regex.test(rel)) {
        ignored = !negated;
      }
    }
  }

  return ignored;
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Build a filter function for the given repo root.
 *
 * Returns: shouldIgnore(absoluteFilePath) → boolean
 *
 * Level 1 (git available): uses git ls-files set — O(1) lookup per file.
 * Level 2 (fallback): parses .gitignore files — pattern matching per file.
 * Level 3 (no .gitignore): returns () => false — nothing ignored.
 *
 * @param {string} repoRoot  Absolute path to the repo root
 * @param {boolean} debug    Log which strategy was used
 */
function buildIgnoreFilter(repoRoot, { debug = false } = {}) {
  // Level 1: try git ls-files — only if this is actually a git repo.
  // Skipping the check for non-git dirs avoids spawning git subprocesses
  // that always fail, which causes fan spin-up and unnecessary latency.
  const isGitRepo = fs.existsSync(path.join(repoRoot, '.git'));
  const trackedFiles = isGitRepo ? getGitTrackedFiles(repoRoot) : null;
  if (trackedFiles !== null) {
    if (debug) console.error(`[gitignore] Using git ls-files (${trackedFiles.size} files tracked)`);
    // A file should be ignored if it is NOT in the tracked set
    // But we only want to ignore files that git explicitly ignores —
    // not untracked files that simply haven't been added yet.
    // So we use a different git call to get explicitly ignored files.
    try {
      const ignoredOutput = execSync(
        'git ls-files --others --ignored --exclude-standard',
        { cwd: repoRoot, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      const ignoredFiles = new Set(
        ignoredOutput.split('\n')
          .map(f => f.trim())
          .filter(Boolean)
          .map(f => path.resolve(repoRoot, f))
      );
      if (debug) console.error(`[gitignore] ${ignoredFiles.size} files explicitly ignored by git`);
      return (filePath) => ignoredFiles.has(filePath);
    } catch {
      // git available but ls-files --ignored failed — fall through to Level 2
    }
  }

  // Level 2: parse .gitignore files manually — only if this is a git repo.
  // collectGitignorePatterns() walks the entire tree, which is prohibitively
  // slow when repoRoot is a large directory like ~ (home dir). Skip entirely
  // for non-git directories — gitignore rules have no meaning without git.
  if (!isGitRepo) return () => false;

  const gitignoreRules = collectGitignorePatterns(repoRoot);
  if (gitignoreRules.length > 0) {
    if (debug) console.error(`[gitignore] Using manual parser (${gitignoreRules.length} .gitignore file(s))`);
    return (filePath) => isIgnoredByPatterns(filePath, gitignoreRules);
  }

  // Level 3: no .gitignore found — nothing to filter
  if (debug) console.error('[gitignore] No .gitignore found — no files filtered');
  return () => false;
}

module.exports = { buildIgnoreFilter };
