'use strict';
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
        console.error('\x1b[31m❌ Finding ID required. Run scd findings to see IDs.\x1b[0m');
        console.error('\x1b[90m   Usage: scd ignore <finding-id> --reason "..."\x1b[0m');
        process.exit(1);
      }
      if (!opts.reason) {
        console.error('\x1b[31m❌ --reason is required.\x1b[0m');
        process.exit(1);
      }
      await addExceptionById(repoRoot, findingId, opts, 'ignore');
    });
}
