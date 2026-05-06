'use strict';
// lib/commands/exceptions.js

module.exports = { register };

function register(program) {
  program
    .command('exceptions')
    .description('List exceptions and ignores in the local store')
    .option('--list <status>', 'Filter by status: pending | approved | rejected | all (default: all)')
    .action(async (opts) => {
      const { listExceptions } = require('../exception-manager');
      const { getRepoRoot } = require('../config');
      const { warnIfOutdated } = require('../cli-helpers');
      const repoRoot = getRepoRoot();
      listExceptions(repoRoot, opts.list || 'all');
      warnIfOutdated();
    });
}
