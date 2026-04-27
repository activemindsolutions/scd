'use strict';

/**
 * lib/scan-context.js
 *
 * Resolves the correct repository context for a manual scan.
 *
 * Problem: scd scan always used CWD as repo context, regardless of where
 * the scan target was. Scanning a file outside the current repo would
 * contaminate the wrong repo with findings, or create a spurious new repo
 * entry in the scd store.
 *
 * Solution: determine context from the target, not CWD. If the target is
 * outside any known git repo, prompt the user rather than silently
 * creating a bad repo entry.
 */

const path        = require('path');
const fs          = require('fs');
const { execSync } = require('child_process');
const readline    = require('readline');

/**
 * Find the git root for a given path (file or directory).
 * Returns null if the path is not inside a git repo.
 */
function findGitRoot(targetPath) {
  try {
    const dir = fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory()
      ? targetPath
      : path.dirname(targetPath);

    return execSync('git rev-parse --show-toplevel', {
      cwd: dir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Ask the user a question and return their answer.
 */
function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Resolve the repo context for a manual scan.
 *
 * @param {string[]} targetList  — resolved absolute paths of scan targets
 * @param {string}   cwdRepoRoot — git root of CWD (may be null)
 *
 * @returns {Promise<{
 *   repoRoot: string|null,    — the repo root to use for logging/config
 *   skipLogging: boolean,     — if true: no audit log, no server push
 *   cancelled: boolean,       — if true: user chose to cancel
 * }>}
 */
async function resolveTargetContext(targetList, cwdRepoRoot) {
  // Find git roots for all targets
  const targetRoots = new Set();
  for (const t of targetList) {
    const root = findGitRoot(path.resolve(t));
    if (root) targetRoots.add(root);
  }

  // Case A: all targets share the same git root as CWD — normal flow
  if (cwdRepoRoot && targetRoots.size === 1 && targetRoots.has(cwdRepoRoot)) {
    return { repoRoot: cwdRepoRoot, skipLogging: false, cancelled: false };
  }

  // Case B: targets are inside a different (but known) git repo
  // e.g. scd scan ~/other-project/file.js from inside ~/my-project
  if (targetRoots.size === 1) {
    const targetRoot = [...targetRoots][0];
    if (targetRoot !== cwdRepoRoot) {
      const YELLOW = '\x1b[33m';
      const CYAN   = '\x1b[36m';
      const DIM    = '\x1b[2m';
      const RESET  = '\x1b[0m';

      console.log(`\n${YELLOW}⚠️  Scan target is in a different repository than your current directory.${RESET}`);
      console.log(`${DIM}  CWD repo:    ${cwdRepoRoot || '(none)'}${RESET}`);
      console.log(`${DIM}  Target repo: ${targetRoot}${RESET}\n`);

      const cwdName    = cwdRepoRoot ? path.basename(cwdRepoRoot) : null;
      const targetName = path.basename(targetRoot);

      console.log(`  How would you like to proceed?\n`);
      console.log(`  ${CYAN}[1]${RESET} Log results to target repo ${DIM}(${targetName} — recommended)${RESET}`);
      if (cwdRepoRoot) {
        console.log(`  ${CYAN}[2]${RESET} Log results to current repo ${DIM}(${cwdName})${RESET}`);
        console.log(`  ${CYAN}[3]${RESET} Scan without logging ${DIM}(results shown only, nothing saved)${RESET}`);
        console.log(`  ${CYAN}[4]${RESET} Cancel`);
      } else {
        console.log(`  ${CYAN}[2]${RESET} Scan without logging ${DIM}(results shown only, nothing saved)${RESET}`);
        console.log(`  ${CYAN}[3]${RESET} Cancel`);
      }

      const choice = (await prompt(`\n  Choice [1]: `)).trim() || '1';

      const cancelChoice = cwdRepoRoot ? '4' : '3';
      const noLogChoice  = cwdRepoRoot ? '3' : '2';

      if (choice === cancelChoice || choice.toLowerCase() === 'cancel' || choice.toLowerCase() === 'q') {
        return { repoRoot: null, skipLogging: true, cancelled: true };
      }
      if (choice === noLogChoice) {
        return { repoRoot: null, skipLogging: true, cancelled: false };
      }
      if (choice === '2' && cwdRepoRoot) {
        console.log(`${DIM}  Logging results to current repo: ${cwdName}${RESET}\n`);
        return { repoRoot: cwdRepoRoot, skipLogging: false, cancelled: false };
      }
      // Default / choice 1: use target repo
      return { repoRoot: targetRoot, skipLogging: false, cancelled: false };
    }
  }

  // Case C: targets span multiple git repos — warn and use CWD if available
  if (targetRoots.size > 1) {
    const YELLOW = '\x1b[33m';
    const DIM    = '\x1b[2m';
    const RESET  = '\x1b[0m';
    console.log(`\n${YELLOW}⚠️  Scan targets span multiple repositories.${RESET}`);
    console.log(`${DIM}  Results will be logged to the current repo context.${RESET}\n`);
    return { repoRoot: cwdRepoRoot, skipLogging: !cwdRepoRoot, cancelled: false };
  }

  // Case D: target is outside any git repo
  const YELLOW = '\x1b[33m';
  const DIM    = '\x1b[2m';
  const CYAN   = '\x1b[36m';
  const RESET  = '\x1b[0m';
  const BOLD   = '\x1b[1m';

  const targetDisplay = targetList.length === 1
    ? path.resolve(targetList[0])
    : `${targetList.length} targets`;

  console.log(`\n${YELLOW}⚠️  Scan target is outside any known repository.${RESET}`);
  console.log(`${DIM}  Target: ${targetDisplay}${RESET}`);
  console.log(`${DIM}  CWD:    ${process.cwd()}${cwdRepoRoot ? '' : ' (no scd repo)'}${RESET}\n`);

  console.log(`  How would you like to proceed?\n`);
  console.log(`  ${CYAN}[1]${RESET} Scan without logging ${DIM}(results shown only, nothing saved)${RESET}`);
  if (cwdRepoRoot) {
    console.log(`  ${CYAN}[2]${RESET} Log results to current repo ${DIM}(${path.basename(cwdRepoRoot)})${RESET}`);
    console.log(`  ${CYAN}[3]${RESET} Cancel`);
  } else {
    console.log(`  ${CYAN}[2]${RESET} Cancel`);
  }

  const maxChoice = cwdRepoRoot ? 3 : 2;
  const cancelChoice = cwdRepoRoot ? '3' : '2';

  const answer = await prompt(`\n  Choice [1]: `);
  const choice = answer === '' ? '1' : answer;

  if (choice === cancelChoice || choice === 'cancel' || choice === 'q') {
    return { repoRoot: null, skipLogging: true, cancelled: true };
  }

  if (choice === '2' && cwdRepoRoot) {
    // Log to CWD repo
    return { repoRoot: cwdRepoRoot, skipLogging: false, cancelled: false };
  }

  // Default / choice 1: scan without logging
  return { repoRoot: null, skipLogging: true, cancelled: false };
}

module.exports = { resolveTargetContext, findGitRoot };
