'use strict';
const { RESET, BOLD, DIM, RED, YELLOW } = require('../output-constants');
// lib/commands/list.js

module.exports = { register };

function register(program) {
  program
    .command('list')
    .description('List all repos registered with Secure Code by Design')
    .option('--json', 'Output as JSON')
    .action((opts) => {
      const store = require('../store');
      const repos = store.listRepos();

      if (opts.json) {
        console.log(JSON.stringify(repos, null, 2));
        return;
      }

      if (repos.length === 0) {
        console.log(DIM + '\n No repos found. Run scd init in a project to get started.' + RESET + '\n');
        return;
      }

      const { cacheAge } = require('../scan-cache');

      console.log('\n' + BOLD + 'Secure Code by Design – Known repos' + RESET);
      console.log(DIM + '─'.repeat(72) + RESET);

      const namW = 24, scanW = 18, findW = 10;
      console.log(
        DIM +
        'Name'.padEnd(namW) +
        'Last scan'.padEnd(scanW) +
        'Findings'.padEnd(findW) +
        'Type'.padEnd(10) +
        'Store ID' +
        RESET
      );
      console.log(DIM + '─'.repeat(72) + RESET);

      for (const r of repos.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''))) {
        const name     = (r.name || r.repoId).slice(0, namW - 1).padEnd(namW);
        const lastScan = r.lastScan ? cacheAge(r.lastScan).padEnd(scanW) : DIM + '(never)' + RESET.padEnd(scanW + 8);
        const findings = r.lastScanFindings != null
          ? (String(r.lastScanFindings) + (r.lastScanCritical ? ' ' + RED + '(' + r.lastScanCritical + 'C)' + RESET : '')).padEnd(findW + (r.lastScanCritical ? 12 : 0))
          : DIM + '–' + RESET.padEnd(findW + 4);
        const type     = r.type === 'path-based' ? YELLOW + 'path' + RESET + '    ' : DIM + 'git' + RESET + '     ';
        const id       = DIM + r.repoId + RESET;

        console.log(name + lastScan + findings + type + id);
      }
      console.log();

      const pathBased = repos.filter(r => r.type === 'path-based');
      if (pathBased.length > 0) {
        console.log(YELLOW + '⚠  ' + pathBased.length + ' repo(s) use path-based IDs (no git remote).');
        console.log('   IDs may change if the folder is renamed or moved.' + RESET + '\n');
      }
    });
}
