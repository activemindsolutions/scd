'use strict';
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
        console.log('\n\x1b[90m No repos found. Run scd init in a project to get started.\x1b[0m\n');
        return;
      }

      const { cacheAge } = require('../scan-cache');

      console.log('\n\x1b[1mSecure Code by Design – Known repos\x1b[0m');
      console.log('\x1b[90m' + '─'.repeat(72) + '\x1b[0m');

      const namW = 24, scanW = 18, findW = 10;
      console.log(
        '\x1b[90m' +
        'Name'.padEnd(namW) +
        'Last scan'.padEnd(scanW) +
        'Findings'.padEnd(findW) +
        'Type'.padEnd(10) +
        'Store ID' +
        '\x1b[0m'
      );
      console.log('\x1b[90m' + '─'.repeat(72) + '\x1b[0m');

      for (const r of repos.sort((a, b) => (b.lastSeen || '').localeCompare(a.lastSeen || ''))) {
        const name     = (r.name || r.repoId).slice(0, namW - 1).padEnd(namW);
        const lastScan = r.lastScan ? cacheAge(r.lastScan).padEnd(scanW) : '\x1b[90m(never)\x1b[0m'.padEnd(scanW + 8);
        const findings = r.lastScanFindings != null
          ? (String(r.lastScanFindings) + (r.lastScanCritical ? ' \x1b[31m(' + r.lastScanCritical + 'C)\x1b[0m' : '')).padEnd(findW + (r.lastScanCritical ? 12 : 0))
          : '\x1b[90m–\x1b[0m'.padEnd(findW + 4);
        const type     = r.type === 'path-based' ? '\x1b[33mpath\x1b[0m    ' : '\x1b[90mgit\x1b[0m     ';
        const id       = '\x1b[90m' + r.repoId + '\x1b[0m';

        console.log(name + lastScan + findings + type + id);
      }
      console.log();

      const pathBased = repos.filter(r => r.type === 'path-based');
      if (pathBased.length > 0) {
        console.log('\x1b[33m⚠  ' + pathBased.length + ' repo(s) use path-based IDs (no git remote).');
        console.log('   IDs may change if the folder is renamed or moved.\x1b[0m\n');
      }
    });
}
