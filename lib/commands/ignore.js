'use strict';
const { RESET, DIM, RED } = require('../output-constants');
// lib/commands/ignore.js

module.exports = { register };

function register(program) {
  program
    .command('ignore [findingId]')
    .description('Ignore a finding (requires team-lead approval via scd-server)')
    .option('--reason <text>', 'Reason for ignoring this finding (required)')
    .option('--tag <tag>',     'Optional tag for filtering (e.g. false_positive, out_of_scope, third_party)')
    .action(async (findingId, opts) => {
      const { addExceptionById } = require('../exception-manager');
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      if (!findingId) {
        console.error(RED + '❌ Finding ID required. Run scd findings to see IDs.' + RESET);
        console.error(DIM + '   Usage: scd ignore <finding-id> --reason "..."' + RESET);
        process.exit(1);
      }
      if (!opts.reason) {
        console.error(RED + '❌ --reason is required.' + RESET);
        process.exit(1);
      }
      await addExceptionById(repoRoot, findingId, opts, 'ignore');
    });
}
