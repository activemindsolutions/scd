'use strict';
// lib/commands/init.js

module.exports = { register };

function register(program) {
  program
    .command('init')
    .description('Initialise Secure Code by Design in this repo and install git hooks')
    .action(async () => {
      const { initRepo } = require('../init-repo');
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      await initRepo(repoRoot);
    });
}
