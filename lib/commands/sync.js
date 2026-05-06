'use strict';
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
        const CYAN  = '\x1b[36m';
        const DIM   = '\x1b[90m';
        const GREEN = '\x1b[32m';
        const RESET = '\x1b[0m';
        console.log('\n' + DIM + ' Syncing audit history to scd-server…' + RESET);
        const result = await syncHistory(repoRoot);
        if (result.error) {
          console.log('\n\x1b[31m Error: ' + result.error + '\x1b[0m\n');
          process.exit(1);
        }
        if (result.message) {
          console.log('\n' + DIM + ' ' + result.message + RESET + '\n');
          return;
        }
        console.log('\n' + GREEN + ' ✓ History sync complete' + RESET);
        console.log(DIM + '   Sessions: ' + result.sessions + '  ·  Findings: ' + result.findings +
          (result.errors > 0 ? '  ·  \x1b[33mErrors: ' + result.errors + RESET : '') + '\n' + RESET);
        console.log(DIM + '   Safe to re-run — server ignores duplicates.\n' + RESET);
        return;
      }

      const { syncExceptions } = require('../exception-manager');
      await syncExceptions(repoRoot);
      warnIfOutdated();
    });
}
