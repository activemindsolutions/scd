'use strict';
// lib/commands/remove.js

module.exports = { register };

function register(program) {
  program
    .command('remove')
    .description('Remove this repo from scd — marks as inactive and optionally deletes scan history')
    .action(async () => {
      const { removeRepo } = require('../remove-repo');
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      await removeRepo(repoRoot);
    });
}
