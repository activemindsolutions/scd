/**
 * git-context.js
 * Per-scan git context helpers: current branch and default branch detection.
 *
 * Both functions are safe in non-git contexts — always return a value,
 * never throw. stderr is suppressed via stdio pipe to prevent git error
 * messages leaking into CLI output when run outside a git repository.
 */

'use strict';

const { execSync } = require('child_process');

/**
 * Returns the current branch name, or null if not in a git repo
 * or if HEAD is detached.
 */
function getCurrentBranch() {
  try {
    const branch = execSync('git rev-parse --abbrev-ref HEAD', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    return branch === 'HEAD' ? null : (branch || null);
  } catch {
    return null;
  }
}

/**
 * Returns 1 if branch is the default branch, 0 otherwise.
 * Integer (not boolean) for SQLite compatibility — consistent with how
 * excepted and blocked are handled in the server schema.
 *
 * Resolution order:
 *   1. git symbolic-ref refs/remotes/origin/HEAD (authoritative when remote exists)
 *   2. Fallback to common default branch names: main, master, trunk, develop
 */
function isDefaultBranch(branch) {
  if (!branch) return 0;
  try {
    const remote = execSync('git symbolic-ref refs/remotes/origin/HEAD', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim().replace('refs/remotes/origin/', '');
    return branch === remote ? 1 : 0;
  } catch {
    return ['main', 'master', 'trunk', 'develop'].includes(branch) ? 1 : 0;
  }
}

module.exports = { getCurrentBranch, isDefaultBranch };
