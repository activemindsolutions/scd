'use strict';
const { RESET, DIM, RED, GREEN, YELLOW, CYAN } = require('../output-constants');
// lib/commands/sync.js

module.exports = { register };

function register(program) {
  program
    .command('sync')
    .description('Pull approved exceptions from scd-server and update local config')
    .option('--history', 'Sync full audit.log history to scd-server (one-time, idempotent)')
    .action(async (opts) => {
      const { getRepoRoot } = require('../config');
      const { warnIfOutdated } = require('../cli-helpers');
      const repoRoot = getRepoRoot();

      if (opts.history) {
        const { syncHistory } = require('../audit-sync');
        console.log('\n' + DIM + ' Syncing audit history to scd-server…' + RESET);
        const result = await syncHistory(repoRoot);
        if (result.error) {
          console.log('\n' + RED + 'Error: ' + result.error + RESET + '\n');
          process.exit(1);
        }
        if (result.message) {
          console.log('\n' + DIM + ' ' + result.message + RESET + '\n');
          return;
        }
        console.log('\n' + GREEN + ' ✓ History sync complete' + RESET);
        console.log(DIM + '   Sessions: ' + result.sessions + '  ·  Findings: ' + result.findings +
          (result.errors > 0 ? '  ·  ' + YELLOW + 'Errors: ' + result.errors + RESET : '') + '\n' + RESET);
        console.log(DIM + '   Safe to re-run — server ignores duplicates.\n' + RESET);
        return;
      }

      const { syncExceptions, pushPendingExceptions } = require('../exception-manager');

      // Events queue flush FIRST — registers the repo server-side before any
      // exception push FK-references it (see fix(delivery-order)). Never throws.
      // Surface a server-side failure: a silent push can leave the user believing
      // findings synced when the server actually rejected them.
      const { flushEvents, flushStatusNotice } = require('../push-queue');
      const flushNotice = flushStatusNotice(await flushEvents(repoRoot));
      if (flushNotice) {
        if (flushNotice.level === 'warn') {
          console.log(`\n ${YELLOW}[WARN]${RESET} ${flushNotice.message}`);
          if (flushNotice.hint) console.log(`${DIM}   ${flushNotice.hint}${RESET}`);
        } else {
          console.log(`${DIM}  ${flushNotice.message}${RESET}`);
        }
      }

      // Then push local exceptions, then pull — surface any local exceptions to
      // the server before fetching status updates. Quiet on failure: same
      // offline-first philosophy as the event push queue.
      try { await pushPendingExceptions(repoRoot); }
      catch { /* quiet retry */ }

      await syncExceptions(repoRoot);
      warnIfOutdated();
    });
}
