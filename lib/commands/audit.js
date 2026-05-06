'use strict';
// lib/commands/audit.js

module.exports = { register };

function register(program) {
  program
    .command('audit')
    .description('Show recent audit log')
    .option('--limit <n>', 'Number of events', '50')
    .action(async (opts) => {
      const { showAuditReport } = require('../audit-report');
      const { getRepoRoot } = require('../config');
      const repoRoot = getRepoRoot();
      await showAuditReport(repoRoot, parseInt(opts.limit));
    });
}
