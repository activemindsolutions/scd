'use strict';
// lib/commands/exceptions.js

const { Command } = require('commander');

module.exports = { register };

function register(program) {
  const exceptionsCmd = new Command('exceptions')
    .description('List and manage exceptions and ignores in the local store')
    .option('--list <status>', 'Filter by status: pending | approved | rejected | archived | all (default: all)')
    .action(async (opts) => {
      const { listExceptions } = require('../exception-manager');
      const { getRepoRoot } = require('../config');
      const { warnIfOutdated } = require('../cli-helpers');
      const repoRoot = getRepoRoot();
      listExceptions(repoRoot, opts.list || 'all');
      warnIfOutdated();
    });

  // scd exceptions withdraw <id> — non-destructive: archive locally with reason
  // 'withdrawn' (never deletes). Replaces the retired `scd resolve --rejected`.
  exceptionsCmd
    .command('withdraw <id>')
    .description('Withdraw an exception — archive it locally (reason: withdrawn); never deletes')
    .action(async (id) => {
      const { withdrawException } = require('../exception-manager');
      const { getRepoRoot } = require('../config');
      withdrawException(getRepoRoot(), id);
    });

  program.addCommand(exceptionsCmd);
}
