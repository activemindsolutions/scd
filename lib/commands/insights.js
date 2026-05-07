'use strict';
const { RESET } = require('../output-constants');
// lib/commands/insights.js

module.exports = { register };

function register(program) {
  program
    .command('insights')
    .description('Analyze behavioral patterns and knowledge gaps from the audit log')
    .option('--days <n>', 'Analyze the last N days (default: 90)', '90')
    .action(async (opts) => {
      const { analyzeInsights } = require('../insights-analyzer');
      const { renderInsights }  = require('../insights-output');
      const { getRepoRoot }     = require('../config');
      const repoRoot            = getRepoRoot();
      const days                = Math.max(1, parseInt(opts.days) || 90);

      console.log(`\nDIM↺ Analyzing audit log (last ${days} days)…${RESET}`);

      const analysis = await analyzeInsights(repoRoot, { days });
      renderInsights(analysis);
    });
}
