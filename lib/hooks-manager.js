/**
 * hooks-manager.js
 * Per-repo git hook management.
 *
 * scd init sets core.hooksPath globally (all repos protected by default).
 * This module allows a specific repo to override that by setting
 * core.hooksPath locally — either disabling hooks entirely or pointing
 * explicitly back to ~/.scd/hooks.
 *
 * Status model:
 *   enabled        — hooks active (local or global points to a real dir)
 *   disabled       — explicitly disabled via scd repo hooks --disable
 *                    (local override set to /dev/null or NUL)
 *   global-broken  — no local override, but global points to /dev/null
 *                    (user mistake or old demo setup — not a scd operation)
 *   not-installed  — no hooksPath configured anywhere
 *   unknown        — could not read git config (not a git repo etc.)
 */

'use strict';

const { execSync } = require('child_process');
const os   = require('os');
const path = require('path');

const HOOKS_DIR   = path.join(os.homedir(), '.scd', 'hooks');
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

function gitConfig(args, cwd) {
  try {
    const val = execSync('git config ' + args, {
      encoding: 'utf8', cwd,
      stdio: ['pipe', 'pipe', 'pipe'],   // suppress stderr (e.g. 'fatal: not a git repo')
    }).trim();
    return val || null;
  } catch {
    return null;
  }
}

/**
 * Returns true if the given path is inside a git repository.
 */
function isGitRepo(dirPath) {
  try {
    execSync('git rev-parse --git-dir', {
      encoding: 'utf8', cwd: dirPath,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}

function isNullDevice(p) {
  return p === 'NUL' || p === '/dev/null';
}

/**
 * Returns current hook status for the given repo root.
 * @returns {{ status: string, hooksPath: string|null, source: 'local'|'global'|null }}
 */
function getHookStatus(repoRoot) {
  try {
    // 0. Check path exists and is a git repo
    if (!require('fs').existsSync(repoRoot)) {
      return { status: 'missing', hooksPath: null, source: null };
    }
    if (!isGitRepo(repoRoot)) {
      return { status: 'not-a-git-repo', hooksPath: null, source: null };
    }

    // 1. Local .git/config override (repo-specific, set by scd repo hooks)
    const localPath = gitConfig('--local core.hooksPath', repoRoot);
    if (localPath !== null) {
      return {
        status:    isNullDevice(localPath) ? 'disabled' : 'enabled',
        hooksPath: localPath,
        source:    'local',
      };
    }

    // 2. Global ~/.gitconfig (applies to all repos without local override)
    const globalPath = gitConfig('--global core.hooksPath', repoRoot);
    if (globalPath !== null) {
      if (isNullDevice(globalPath)) {
        // Global is broken — not a scd-managed per-repo disable
        return { status: 'global-broken', hooksPath: globalPath, source: 'global' };
      }
      return { status: 'enabled', hooksPath: globalPath, source: 'global' };
    }

    return { status: 'not-installed', hooksPath: null, source: null };

  } catch {
    return { status: 'unknown', hooksPath: null, source: null };
  }
}

/**
 * Disable hooks for this repo by setting local core.hooksPath to /dev/null.
 * This overrides the global setting without affecting other repos.
 */
function disableHooks(repoRoot) {
  execSync(`git config --local core.hooksPath "${NULL_DEVICE}"`, {
    encoding: 'utf8', cwd: repoRoot,
  });
}

/**
 * Re-enable hooks for this repo.
 *
 * Strategy: set local core.hooksPath explicitly to ~/.scd/hooks rather
 * than just unsetting the local key. This is safer because:
 *   - If global is /dev/null (like after a demo), unset would still leave
 *     hooks disabled — not what the user wants.
 *   - Explicit local set ensures hooks are active regardless of global state.
 *
 * To fully clean up (no local override at all), the user can run:
 *   git config --local --unset core.hooksPath
 * But for scd's purposes, explicit re-enable is the right default.
 */
function enableHooks(repoRoot) {
  execSync(`git config --local core.hooksPath "${HOOKS_DIR}"`, {
    encoding: 'utf8', cwd: repoRoot,
  });
}

module.exports = { getHookStatus, disableHooks, enableHooks, HOOKS_DIR, isNullDevice, isGitRepo };
