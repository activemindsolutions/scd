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
        console.log(DIM + '   Sessions: ' + result.sessions + '  ·  Findings synced: ' + result.findings +
          (result.errors > 0 ? '  ·  ' + YELLOW + 'Errors: ' + result.errors + RESET : '') + '\n' + RESET);
        if (result.skipped > 0) {
          console.log(YELLOW + '   ' + result.skipped + ' finding(s) not synced' + RESET +
            DIM + ' — recorded before code_hash was tracked; re-scan the repo to sync them.\n' + RESET);
        }
        console.log(DIM + '   Safe to re-run — server ignores duplicates.\n' + RESET);
        return;
      }

      const { syncExceptions, pushPendingExceptions, reassertApprovedExceptions } = require('../exception-manager');

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

      // Re-assert locally-approved exceptions so a diverged server re-converges
      // (#235). Runs AFTER the pull, when the local approved set is freshest.
      // Quiet unless there is something to act on.
      try {
        const rc = await reassertApprovedExceptions(repoRoot);
        printReconcileSummary(rc);
      } catch { /* offline-first — quiet */ }

      warnIfOutdated();
    });
}

// Report exception reconciliation outcomes. Silent when everything is converged
// (no news is good news); loud only for the healed / needs-attention cases.
function printReconcileSummary(rc) {
  if (!rc || (!rc.healed && !rc.reapproval_required && !rc.conflict_rejected)) return;
  console.log(`\n${DIM} Exception reconciliation:${RESET}`);
  if (rc.healed) {
    console.log(`${GREEN}   ✓ ${rc.healed} exception(s) re-applied on the server${RESET}`);
  }
  if (rc.reapproval_required) {
    console.log(`${YELLOW}   ⚠ ${rc.reapproval_required} exception(s) need re-approval — the server had no approval record${RESET}`);
    console.log(`${DIM}     A team-lead must re-approve them in the dashboard.${RESET}`);
  }
  if (rc.conflict_rejected) {
    console.log(`${YELLOW}   ⚠ ${rc.conflict_rejected} exception(s) conflict with a server-side rejection — manual resolve${RESET}`);
  }
}
