'use strict';
const { RESET, BOLD, DIM, CYAN } = require('../output-constants');
// lib/commands/version.js

module.exports = { register };

function register(program) {
  const pkg          = require('../../package.json');
  const { RULES_VERSION } = require('../rule-registry');

  program
    .command('version')
    .description('Show detailed version information')
    .action(() => {
      const os  = require('os');
      const { getRegistry } = require('../rule-registry');
      const rules = getRegistry();


      const sevCount = (sev) => rules.filter(r => r.severity === sev).length;

      console.log('\n' + BOLD + 'Secure Code by Design' + RESET);
      console.log(DIM + '─'.repeat(40) + RESET);
      console.log('  CLI:    ' + BOLD + pkg.version + RESET);
      console.log('  Rules:  ' + BOLD + RULES_VERSION + RESET +
        DIM + '  (' + rules.length + ' rules' +
        '  ·  CRITICAL: ' + sevCount('CRITICAL') +
        '  HIGH: ' + sevCount('HIGH') +
        '  MEDIUM: ' + sevCount('MEDIUM') +
        '  EXPOSURE: ' + sevCount('EXPOSURE') + ')' + RESET);
      console.log('  Node:   ' + DIM + process.version + RESET);
      console.log('  OS:     ' + DIM + os.platform() + ' ' + os.arch() + RESET);
      console.log();
    });
}
