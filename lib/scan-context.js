'use strict';
const { RESET, BOLD, DIM, RED, YELLOW, CYAN } = require('./output-constants');

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
 *
 * Non-interactive use:
 * - No TTY detected: automatically scans without logging (pipeline-safe default).
 * - --log-to none:    always skip logging, no prompt.
 * - --log-to current: log to CWD repo, no prompt (for cron/scheduled tasks).
 * - --log-to target:  log to target repo, no prompt (for cron/scheduled tasks).
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
 * @param {object}   opts
 * @param {string}   opts.logTo  — 'none' | 'current' | 'target' | undefined
 *
 * @returns {Promise<{
 *   repoRoot: string|null,    — the repo root to use for logging/config
 *   skipLogging: boolean,     — if true: no audit log, no server push
 *   cancelled: boolean,       — if true: user chose to cancel
 * }>}
 */
async function resolveTargetContext(targetList, cwdRepoRoot, { logTo } = {}) {
  // ── Non-interactive / --log-to handling ──────────────────────────────────
  // Resolved before any prompts or git root discovery so pipelines exit fast.
  const isInteractive = !!process.stdin.isTTY;

  if (logTo === 'none') {
    return { repoRoot: null, skipLogging: true, cancelled: false };
  }

  if (logTo === 'current') {
    if (!cwdRepoRoot) {
      process.stderr.write(`${RED}  --log-to current: current directory is not a known scd repo.${RESET}\n`);
      process.stderr.write(`  Run ${CYAN}scd init${RESET} first, or use ${CYAN}--log-to none${RESET}.\n\n`);
      process.exit(1);
    }
    return { repoRoot: cwdRepoRoot, skipLogging: false, cancelled: false };
  }

  if (!isInteractive && !logTo) {
    // No TTY and no explicit --log-to: pipeline-safe default — scan without logging.
    // Use --log-to current|target to log results from a non-interactive context.
    process.stderr.write(`${DIM}ℹ Non-interactive mode: scanning without logging. Use --log-to current|target to log results.${RESET}\n`);
    return { repoRoot: null, skipLogging: true, cancelled: false };
  }
  // ── end non-interactive handling ─────────────────────────────────────────

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

      // --log-to target: use target repo, no prompt
      if (logTo === 'target') {
        return { repoRoot: targetRoot, skipLogging: false, cancelled: false };
      }

      console.log(`\n${YELLOW}⚠  Scan target is in a different repository than your current directory.${RESET}`);
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
    console.log(`\n${YELLOW}⚠  Scan targets span multiple repositories.${RESET}`);
    console.log(`${DIM}  Results will be logged to the current repo context.${RESET}\n`);
    return { repoRoot: cwdRepoRoot, skipLogging: !cwdRepoRoot, cancelled: false };
  }

  // Case D: target is outside any git repo

  const targetDisplay = targetList.length === 1
    ? path.resolve(targetList[0])
    : `${targetList.length} targets`;

  // --log-to target: no git repo found for target — warn and fall back to none
  if (logTo === 'target') {
    process.stderr.write(`${YELLOW}  --log-to target: scan target is outside any git repo. Scanning without logging.${RESET}\n`);
    return { repoRoot: null, skipLogging: true, cancelled: false };
  }

  console.log(`\n${YELLOW}⚠  Scan target is outside any known repository.${RESET}`);
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

/**
 * Read all known scd repo paths from ~/.scd/repos/{repoId}/meta.json.
 * Returns array of { repoId, name, localPath } for repos with a known localPath.
 */
function getKnownRepoPaths() {
  try {
    const os        = require('os');
    const reposDir  = path.join(os.homedir(), '.scd', 'repos');
    if (!fs.existsSync(reposDir)) return [];

    return fs.readdirSync(reposDir)
      .map(id => {
        try {
          const meta = JSON.parse(fs.readFileSync(path.join(reposDir, id, 'meta.json'), 'utf8'));
          return meta.localPath ? { repoId: id, name: meta.name || id, localPath: meta.localPath } : null;
        } catch { return null; }
      })
      .filter(Boolean);
  } catch { return []; }
}

/**
 * Check if repoRoot overlaps with any known scd repo (parent or child).
 * Returns array of overlapping repos: { repoId, name, localPath, relation }
 * where relation is 'parent' or 'child'.
 */
function findOverlappingRepos(repoRoot, excludeRepoId = null) {
  const known   = getKnownRepoPaths();
  const absRoot = path.resolve(repoRoot);
  const sep     = path.sep;

  return known
    .filter(r => r.repoId !== excludeRepoId)
    .filter(r => {
      const absKnown = path.resolve(r.localPath);
      if (absKnown === absRoot) return false; // same repo — skip

      const rootWithSep  = absRoot.endsWith(sep)  ? absRoot  : absRoot  + sep;
      const knownWithSep = absKnown.endsWith(sep) ? absKnown : absKnown + sep;

      const isChild  = absKnown.startsWith(rootWithSep);   // known is inside current
      const isParent = absRoot.startsWith(knownWithSep);   // current is inside known

      if (isChild)  { r.relation = 'child';  return true; }
      if (isParent) { r.relation = 'parent'; return true; }
      return false;
    });
}

/**
 * Warn the user if the resolved repoRoot overlaps with another known scd repo.
 * Returns { proceed: bool, skipLogging: bool, cancelled: bool }.
 *
 * For hook mode (interactive=false): warn but always proceed — hooks can't prompt.
 * For non-interactive mode (no TTY): warn but always proceed — same as hook mode.
 */
async function checkRepoOverlap(repoRoot, { interactive = true, repoId = null } = {}) {
  const overlaps = findOverlappingRepos(repoRoot, repoId);
  if (overlaps.length === 0) return { proceed: true, skipLogging: false, cancelled: false };

  const children = overlaps.filter(r => r.relation === 'child');
  const parents  = overlaps.filter(r => r.relation === 'parent');

  console.log(`\n${YELLOW}⚠  This repo overlaps with another scd repository.${RESET}`);
  console.log(`${DIM}  Current scan: ${repoRoot}${RESET}`);

  for (const r of parents)  console.log(`${DIM}  Parent repo:  ${r.localPath} (${r.name})${RESET}`);
  for (const r of children) console.log(`${DIM}  Child repo:   ${r.localPath} (${r.name})${RESET}`);

  if (children.length > 0) {
    console.log(`\n${DIM}  Scanning from here will include files already tracked in the child repo,${RESET}`);
    console.log(`${DIM}  potentially duplicating findings in scd-server.${RESET}`);
  }
  if (parents.length > 0) {
    console.log(`\n${DIM}  This repo is nested inside another scd repo — findings may appear twice.${RESET}`);
  }

  // Hook mode or no TTY — can't prompt, warn and proceed
  if (!interactive || !process.stdin.isTTY) {
    console.log(`${YELLOW}  Continuing scan (non-interactive — cannot prompt).${RESET}\n`);
    return { proceed: true, skipLogging: false, cancelled: false };
  }

  console.log(`\n  How would you like to proceed?\n`);
  console.log(`  ${CYAN}[1]${RESET} Continue anyway`);
  console.log(`  ${CYAN}[2]${RESET} Scan without logging ${DIM}(results shown only, nothing saved)${RESET}`);
  console.log(`  ${CYAN}[3]${RESET} Cancel`);

  const choice = (await prompt(`\n  Choice [1]: `)).trim() || '1';

  if (choice === '3' || choice.toLowerCase() === 'cancel') {
    return { proceed: false, skipLogging: true, cancelled: true };
  }
  if (choice === '2') {
    return { proceed: true, skipLogging: true, cancelled: false };
  }
  return { proceed: true, skipLogging: false, cancelled: false };
}

module.exports = { resolveTargetContext, findGitRoot, checkRepoOverlap, findOverlappingRepos };
