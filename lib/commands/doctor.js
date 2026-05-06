'use strict';
// lib/commands/doctor.js

module.exports = { register };

function register(program) {
  program
    .command('doctor')
    .description('Check installation health')
    .action(async () => {
      const { doctor } = require('../doctor');
      await doctor();
    });
}
