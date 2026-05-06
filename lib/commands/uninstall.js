'use strict';
// lib/commands/uninstall.js

module.exports = { register };

function register(program) {
  const { Command } = require('commander');
  const cmd = new Command('uninstall')
    .description('Remove global git hooks from this machine')
    .action(async () => {
      const { uninstall } = require('../installer');
      await uninstall();
    });
  program.addCommand(cmd);
}
