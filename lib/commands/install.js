'use strict';
// lib/commands/install.js

module.exports = { register };

function register(program) {
  const { Command } = require('commander');
  const cmd = new Command('install')
    .description('Install global git hooks on this machine')
    .action(async () => {
      const { install } = require('../installer');
      await install();
    });
  program.addCommand(cmd);
}
