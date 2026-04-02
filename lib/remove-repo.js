/**
 * remove-repo.js
 * Removes scd integration from the current repo.
 *
 * Hooks are global (shared across all repos via core.hooksPath) so they
 * are NOT removed — removing them would break all other repos on this machine.
 * Instead, the repo is marked as inactive in the store.
 *
 * Scan history in ~/.scd/repos/{repoId}/ is kept by default.
 * The user must explicitly type "yes" to delete it.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

async function removeRepo(repoRoot) {
  const store = require('./store');

  const GREEN  = '\x1b[32m';
  const YELLOW = '\x1b[33m';
  const RED    = '\x1b[31m';
  const DIM    = '\x1b[90m';
  const BOLD   = '\x1b[1m';
  const CYAN   = '\x1b[36m';
  const RESET  = '\x1b[0m';

  const repoId   = store.getRepoId(repoRoot);
  const storePath = store.storeDir(repoRoot);
  const meta      = store.readMeta(repoRoot);
  const repoName  = meta?.name || path.basename(repoRoot);

  console.log('\n' + BOLD + 'scd remove' + RESET);
  console.log(DIM + '  Repository: ' + repoName + RESET);
  console.log(DIM + '  Store ID:   ' + repoId + RESET);
  console.log(DIM + '  Path:       ' + repoRoot + RESET);
  console.log('');

  // Note about hooks
  console.log(DIM + '  Note: git hooks are shared across all repos on this machine' + RESET);
  console.log(DIM + '  and will not be removed. To disable hooks entirely, run:' + RESET);
  console.log(DIM + '    git config --global --unset core.hooksPath' + RESET);
  console.log('');

  // Mark as inactive in store
  try {
    const metaPath = path.join(storePath, 'meta.json');
    let existing = {};
    try { existing = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch {}
    existing.removed   = true;
    existing.removedAt = new Date().toISOString();
    fs.writeFileSync(metaPath, JSON.stringify(existing, null, 2), 'utf8');
    console.log(GREEN + '  ✓ Repository marked as inactive' + RESET);
  } catch (err) {
    console.log(YELLOW + '  ⚠ Could not update store: ' + err.message + RESET);
  }

  // Ask about scan history
  console.log('');
  console.log('  Scan history is stored in:');
  console.log(DIM + '  ' + storePath + RESET);
  console.log('');
  console.log(DIM + '  Keeping history lets you run ' + CYAN + 'scd init' + DIM + ' again and continue' + RESET);
  console.log(DIM + '  from where you left off. You can also clean up later with:' + RESET);
  console.log(DIM + '    scd store --verify --clean' + RESET);
  console.log('');

  const answer = await promptLine(
    YELLOW + '  Delete scan history? Type "yes" to confirm, or press Enter to keep: ' + RESET
  );

  if (answer.trim().toLowerCase() === 'yes') {
    try {
      fs.rmSync(storePath, { recursive: true, force: true });
      console.log('');
      console.log(RED + '  ✓ Scan history deleted' + RESET);
    } catch (err) {
      console.log(RED + '  ✗ Could not delete history: ' + err.message + RESET);
    }
  } else {
    console.log('');
    console.log(DIM + '  ✓ Scan history kept' + RESET);
  }

  console.log('');
  console.log(GREEN + BOLD + '  Done.' + RESET);
  console.log(DIM + '  Run ' + CYAN + 'scd init' + DIM + ' to re-register this repo.' + RESET);
  console.log(DIM + '  Run ' + CYAN + 'scd store --verify --clean' + DIM + ' to manage inactive repos.' + RESET);
  console.log('');
}

function promptLine(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.once('data', data => {
      process.stdin.pause();
      resolve(data.toString().trim());
    });
  });
}

module.exports = { removeRepo };
