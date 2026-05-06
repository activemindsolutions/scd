'use strict';
// lib/commands/resolve.js

module.exports = { register };

function register(program) {
  program
    .command('resolve')
    .description('Mark an EXPOSURE finding as handled, or remove a rejected exception by ID')
    .option('--rule <id>',      'Rule ID (for EXPOSURE findings)')
    .option('--file <path>',   'File path (for EXPOSURE findings)')
    .option('--line <n>',      'Line number (for EXPOSURE findings)')
    .option('--rejected <id>', 'Remove a rejected exception from local config by exception ID')
    .action(async (opts) => {
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      if (opts.rejected) {
        const { removeRejected } = require('../exception-manager');
        removeRejected(repoRoot, opts.rejected);
      } else {
        const { resolveExposure } = require('../resolve-manager');
        await resolveExposure(repoRoot, opts);
      }
    });
}
