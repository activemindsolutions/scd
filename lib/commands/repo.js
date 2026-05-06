'use strict';
// lib/commands/repo.js

module.exports = { register };

function register(program) {
  const { Command } = require('commander');
  const { getRepoRoot } = require('../config');

  // ── scd repo configure ────────────────────────────────────────────────────
  const repoConfigureCmd = new Command('configure')
    .description('Show and manage per-repo configuration')
    .option('--show',                      'Show current effective configuration (default)')
    .option('--trust-level <value>',       'Set trust level (maximum_privacy|balanced|maximum_analysis)')
    .option('--scan-mode <value>',         'Set scan mode (full|fast)')
    .option('--block-on-high <value>',     'Set block-on-high (true|false)')
    .option('--block-on-critical <value>', 'Set block-on-critical (true|false)')
    .action((opts) => {
      const fs         = require('fs');
      const store      = require('../store');
      const yaml       = require('../config');
      const gc         = require('../global-config');
      const repoRoot   = getRepoRoot();
      const configPath = store.configPath(repoRoot);

      const CYAN  = '\x1b[36m';
      const GREEN = '\x1b[32m';
      const RED   = '\x1b[31m';
      const DIM   = '\x1b[90m';
      const BOLD  = '\x1b[1m';
      const RESET = '\x1b[0m';

      const VALID_TRUST = ['maximum_privacy', 'balanced', 'maximum_analysis'];
      const VALID_MODES = ['full', 'fast'];
      const KEYS        = ['trust_level', 'scan_mode', 'block_on_critical', 'block_on_high'];

      // Helper: read config.yml, update a key value in-place, write back
      function updateConfigYml(key, value) {
        if (!fs.existsSync(configPath)) {
          console.error(`\n${RED}✗ No config.yml found for this repo.${RESET}`);
          console.error(`  Run ${CYAN}scd init${RESET} first.\n`);
          process.exit(1);
        }
        let content = fs.readFileSync(configPath, 'utf8');
        const re = new RegExp(`^(${key}:\\s*).*$`, 'm');
        if (re.test(content)) {
          content = content.replace(re, `$1${value}`);
        } else {
          content = content.trimEnd() + `\n${key}: ${value}\n`;
        }
        fs.writeFileSync(configPath, content, 'utf8');
      }

      // ── set operations ──────────────────────────────────────────────────

      if (opts.trustLevel !== undefined) {
        if (!VALID_TRUST.includes(opts.trustLevel)) {
          console.error(`\n${RED}✗ Invalid trust level. Use: ${VALID_TRUST.join(' | ')}${RESET}\n`);
          process.exit(1);
        }
        updateConfigYml('trust_level', opts.trustLevel);
        console.log(`\n${GREEN}✓ trust_level set to ${opts.trustLevel}${RESET} for this repo\n`);
        return;
      }

      if (opts.scanMode !== undefined) {
        if (!VALID_MODES.includes(opts.scanMode)) {
          console.error(`\n${RED}✗ Invalid scan mode. Use: full | fast${RESET}\n`);
          process.exit(1);
        }
        updateConfigYml('scan_mode', opts.scanMode);
        console.log(`\n${GREEN}✓ scan_mode set to ${opts.scanMode}${RESET} for this repo\n`);
        return;
      }

      if (opts.blockOnHigh !== undefined) {
        const val = opts.blockOnHigh.toLowerCase();
        if (val !== 'true' && val !== 'false') {
          console.error(`\n${RED}✗ Invalid value. Use: true | false${RESET}\n`);
          process.exit(1);
        }
        updateConfigYml('block_on_high', val);
        console.log(`\n${GREEN}✓ block_on_high set to ${val}${RESET} for this repo\n`);
        return;
      }

      if (opts.blockOnCritical !== undefined) {
        const val = opts.blockOnCritical.toLowerCase();
        if (val !== 'true' && val !== 'false') {
          console.error(`\n${RED}✗ Invalid value. Use: true | false${RESET}\n`);
          process.exit(1);
        }
        updateConfigYml('block_on_critical', val);
        console.log(`\n${GREEN}✓ block_on_critical set to ${val}${RESET} for this repo\n`);
        return;
      }

      // ── show (default) ──────────────────────────────────────────────────
      const config = yaml.loadConfig(repoRoot);

      let repoYaml = {};
      if (fs.existsSync(configPath)) {
        try {
          const raw = fs.readFileSync(configPath, 'utf8');
          for (const key of KEYS) {
            const m = raw.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
            if (m) repoYaml[key] = m[1].trim();
          }
        } catch { /* ignore */ }
      }

      console.log(`\n${CYAN}${BOLD}Secure Code by Design – Repo configuration${RESET}`);
      console.log(`${DIM}${'─'.repeat(52)}${RESET}`);
      console.log(`${DIM}Repo:   ${repoRoot}${RESET}`);
      console.log(`${DIM}Config: ${configPath}${RESET}\n`);
      console.log(`  ${'Setting'.padEnd(22)}${'Value'.padEnd(22)}Source`);
      console.log(`  ${DIM}${'─'.repeat(54)}${RESET}`);

      for (const key of KEYS) {
        const inRepo    = key in repoYaml;
        const globalRaw = gc.get('REPO_' + key.toUpperCase());
        const inGlobal  = globalRaw !== undefined;
        const val       = String(config[key]);
        const source    = inRepo   ? `${GREEN}repo${RESET}`
                        : inGlobal ? `${CYAN}global${RESET}`
                        :            `${DIM}default${RESET}`;
        console.log(`  ${DIM}${key.padEnd(22)}${RESET}${val.padEnd(22)}${source}`);
      }

      console.log('');
      console.log(`  ${DIM}scd repo configure --scan-mode <fast|full>        set for this repo${RESET}`);
      console.log(`  ${DIM}scd repo configure --trust-level <value>          set for this repo${RESET}`);
      console.log(`  ${DIM}scd repo configure --block-on-high <true|false>   set for this repo${RESET}`);
      console.log(`  ${DIM}scd configure --scan-mode <value>                 set global default${RESET}`);
      console.log('');
    });


  // ── scd repo hooks ────────────────────────────────────────────────────────
  const repoHooksCmd = new Command('hooks')
    .description('Show or manage git hook status for the current repo')
    .option('--disable', 'Disable git hooks for this repo (requires --reason)')
    .option('--enable',  'Re-enable git hooks for this repo')
    .option('--reason <text>', 'Required reason when disabling hooks (logged to audit trail)')
    .action((opts) => {
      const { getHookStatus, disableHooks, enableHooks } = require('../hooks-manager');
      const { logHooks } = require('../audit');
      const repoRoot = getRepoRoot();

      const CYAN   = '\x1b[36m';
      const GREEN  = '\x1b[32m';
      const RED    = '\x1b[31m';
      const DIM    = '\x1b[90m';
      const BOLD   = '\x1b[1m';
      const YELLOW = '\x1b[33m';
      const RESET  = '\x1b[0m';

      // ── disable ────────────────────────────────────────────────────────
      if (opts.disable) {
        if (!opts.reason || opts.reason.trim().length < 5) {
          console.error(`\n${RED}✗ --reason is required when disabling hooks.${RESET}`);
          console.error(`  Example: scd repo hooks --disable --reason "demo repo, no real secrets"\n`);
          process.exit(1);
        }
        const current = getHookStatus(repoRoot);
        if (current.status === 'disabled') {
          console.log(`\n${YELLOW}⚠  Hooks are already disabled for this repo.${RESET}\n`);
          process.exit(0);
        }
        try {
          disableHooks(repoRoot, opts.reason);
          logHooks(repoRoot, { action: 'disable', reason: opts.reason.trim(), noSync: false });
          console.log(`\n${YELLOW}⚠  Git hooks disabled for this repo.${RESET}`);
          console.log(`  ${DIM}Reason: ${opts.reason.trim()}${RESET}`);
          console.log(`  ${DIM}This action has been logged to the audit trail.${RESET}`);
          console.log(`  ${DIM}Re-enable with: scd repo hooks --enable${RESET}\n`);
        } catch (err) {
          console.error(`\n${RED}✗ Failed to disable hooks: ${err.message}${RESET}\n`);
          process.exit(1);
        }
        return;
      }

      // ── enable ─────────────────────────────────────────────────────────
      if (opts.enable) {
        const current = getHookStatus(repoRoot);
        if (current.status === 'enabled' && current.source !== 'local') {
          console.log(`\n${GREEN}✓ Hooks are already enabled (via global config).${RESET}\n`);
          process.exit(0);
        }
        try {
          enableHooks(repoRoot);
          logHooks(repoRoot, { action: 'enable', reason: 'manually re-enabled', noSync: false });
          console.log(`\n${GREEN}✓ Git hooks re-enabled for this repo.${RESET}`);
          console.log(`  ${DIM}This action has been logged to the audit trail.${RESET}\n`);
        } catch (err) {
          console.error(`\n${RED}✗ Failed to enable hooks: ${err.message}${RESET}\n`);
          process.exit(1);
        }
        return;
      }

      // ── show (default) ─────────────────────────────────────────────────
      const status = getHookStatus(repoRoot);
      console.log(`\n${CYAN}${BOLD}Git hook status${RESET}`);
      console.log(`${DIM}${'─'.repeat(40)}${RESET}`);
      console.log(`${DIM}Repo: ${repoRoot}${RESET}\n`);

      const statusLabel = status.status === 'enabled'
        ? `${GREEN}enabled${RESET}`
        : status.status === 'disabled'
          ? `${YELLOW}disabled${RESET}`
          : status.status === 'global-broken'
            ? `${RED}disabled (global config broken)${RESET}`
            : status.status === 'not-installed'
              ? `${RED}not installed${RESET}`
              : `${DIM}unknown${RESET}`;

      console.log(`  Status:  ${statusLabel}`);
      if (status.hooksPath) {
        console.log(`  Path:    ${DIM}${status.hooksPath}${RESET}`);
      }
      if (status.source) {
        console.log(`  Source:  ${DIM}${status.source} config${RESET}`);
      }
      console.log('');
      if (status.status === 'disabled') {
        console.log(`  ${DIM}Re-enable with: scd repo hooks --enable${RESET}`);
      } else if (status.status === 'global-broken') {
        console.log(`  ${RED}Global git config has core.hooksPath set to /dev/null.${RESET}`);
        console.log(`  ${DIM}Fix with: git config --global core.hooksPath ~/.scd/hooks${RESET}`);
        console.log(`  ${DIM}Or re-enable for this repo only: scd repo hooks --enable${RESET}`);
      } else if (status.status === 'enabled') {
        console.log(`  ${DIM}Disable for this repo: scd repo hooks --disable --reason "<reason>"${RESET}`);
      } else {
        console.log(`  ${DIM}Install with: scd init${RESET}`);
      }
      console.log('');
    });


  // ── scd hooks (global overview) ───────────────────────────────────────────
  program
    .command('hooks')
    .description('Show git hook status for all known repos')
    .action(() => {
      const store  = require('../store');
      const { getHookStatus } = require('../hooks-manager');

      const CYAN   = '\x1b[36m';
      const GREEN  = '\x1b[32m';
      const RED    = '\x1b[31m';
      const DIM    = '\x1b[90m';
      const BOLD   = '\x1b[1m';
      const YELLOW = '\x1b[33m';
      const RESET  = '\x1b[0m';

      const repos = store.listRepos().filter(r => !r.removed);
      console.log(`\n${CYAN}${BOLD}Git hook status — all repos${RESET}`);
      console.log(`${DIM}${'─'.repeat(60)}${RESET}\n`);

      if (!repos.length) {
        console.log(`  ${DIM}No repos registered. Run scd init in a project.${RESET}\n`);
        return;
      }

      const nameW = 28, statusW = 14;
      console.log(
        `  ${DIM}${'Repo'.padEnd(nameW)}${'Status'.padEnd(statusW)}Source${RESET}`
      );
      console.log(`  ${DIM}${'─'.repeat(56)}${RESET}`);

      for (const repo of repos) {
        const repoPath = repo.localPath || repo.root;
        if (!repoPath) continue;
        const status = getHookStatus(repoPath);
        const name   = (repo.name || repoPath.split('/').pop() || '?').slice(0, nameW - 2).padEnd(nameW);
        // Skip repos that are missing or not git repos — not relevant for hook management
        if (status.status === 'missing' || status.status === 'not-a-git-repo') continue;

        const statusLabel = status.status === 'enabled'
          ? (GREEN + 'enabled' + RESET).padEnd(statusW + GREEN.length + RESET.length)
          : status.status === 'disabled'
            ? (YELLOW + 'disabled' + RESET).padEnd(statusW + YELLOW.length + RESET.length)
            : status.status === 'global-broken'
              ? (RED + 'global broken' + RESET).padEnd(statusW + RED.length + RESET.length)
              : (DIM + status.status + RESET).padEnd(statusW + DIM.length + RESET.length);
        const source = status.source ? `${DIM}${status.source}${RESET}` : '';
        console.log(`  ${DIM}${name}${RESET}${statusLabel}${source}`);
      }
      const hasBroken = repos.some(repo => { const p = repo.localPath || repo.root; return p && getHookStatus(p).status === 'global-broken'; });
      if (hasBroken) {
        console.log(`  ${RED}⚠  Global git config has core.hooksPath set to /dev/null.${RESET}`);
        console.log(`  ${DIM}Fix: git config --global core.hooksPath ~/.scd/hooks${RESET}\n`);
      }
      console.log(`  ${DIM}Manage hooks per repo: scd repo hooks [--disable|--enable]${RESET}\n`);
    });


  // ── scd repo (main command) ───────────────────────────────────────────────
  const repoCmd = new Command('repo')
    .description('Show and manage the current repo configuration and store')
    .option('--open',         'Open store folder in Finder / Explorer / file manager')
    .option('--open-reports', 'Open reports folder')
    .option('--reports',      'List saved reports for this repo')
    .option('--path',         'Print store path (for scripting)')
    .option('--show',         'Show full meta.json info for the current repo')
    .option('--scans',         'List all saved scans for current repo')
    .option('--verify',       'Verify all repos in store still exist on disk')
    .option('--clean',        'Interactive cleanup of missing/stale repos (use with --verify)')
    .option('--verbose',      'Show detail lines for each issue (use with --verify)')
    .option('--json',         'Output verification results as JSON (use with --verify)')
    .action(async (opts) => {
      const store    = require('../store');
      const repoRoot = getRepoRoot();
      const dir      = store.storeDir(repoRoot);
      const identity = store.getRepoIdentity(repoRoot);

      // --path  – minimal output for scripting
      if (opts.path) {
        console.log(dir);
        return;
      }

      // --show  – full meta.json for current repo
      if (opts.show) {
        const fs   = require('fs');
        const path = require('path');
        const store    = require('../store');
        const repoRoot = getRepoRoot();
        const dir      = store.storeDir(repoRoot);
        const metaPath = path.join(dir, 'meta.json');

        const BOLD  = '\x1b[1m';
        const DIM   = '\x1b[90m';
        const CYAN  = '\x1b[36m';
        const RESET = '\x1b[0m';

        let meta;
        try {
          meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
        } catch {
          const repoId = store.getRepoId(repoRoot);
          console.log('\n\x1b[33m No meta.json found — this repo has not been initialised.\x1b[0m');
          console.log(DIM + '  Working directory : ' + RESET + CYAN + repoRoot + RESET);
          console.log(DIM + '  Store ID          : ' + RESET + DIM + repoId + RESET);
          console.log(DIM + '  Store path        : ' + RESET + DIM + dir + RESET);
          console.log(DIM + '\n  Run ' + RESET + CYAN + 'scd init' + RESET + DIM + ' to register this repo and install git hooks.\n' + RESET);
          return;
        }

        const { cacheAge } = require('../scan-cache');

        console.log('\n' + BOLD + 'Secure Code by Design – Repo meta' + RESET);
        console.log(DIM + '─'.repeat(52) + RESET + '\n');
        console.log('  ' + DIM + 'Working directory'.padEnd(18) + RESET + CYAN + repoRoot + RESET);
        console.log(DIM + '─'.repeat(52) + RESET + '\n');

        const row = (label, value, color) =>
          console.log('  ' + DIM + label.padEnd(18) + RESET + (color||'') + value + RESET);

        row('Name:',       meta.name     || '(unknown)');
        row('Store ID:',   meta.repoId,    DIM);
        row('Type:',       meta.type === 'remote' ? 'remote (git)' : 'path-based (directory scan)',
            meta.type === 'path-based' ? '\x1b[33m' : '');

        if (meta.remote) row('Remote:',    meta.remote,  DIM);
        row('Local path:', meta.localPath || '(none)',    CYAN);

        console.log();

        if (meta.lastSeen) {
          row('Last seen:',  cacheAge(meta.lastSeen) + '  ' + DIM + meta.lastSeen + RESET);
        }
        if (meta.lastScan) {
          const critStr = meta.lastScanCritical > 0
            ? '  \x1b[31m' + meta.lastScanCritical + ' CRITICAL\x1b[0m' : '';
          row('Last scan:',  cacheAge(meta.lastScan) + '  '
            + DIM + (meta.lastScanFindings ?? '?') + ' findings' + RESET + critStr);
        } else {
          row('Last scan:',  '(none yet)', DIM);
        }

        // Reports
        const reports = store.listReports(repoRoot);
        row('Reports:',    reports.length + ' saved', DIM);

        // Store location
        console.log();
        row('Store path:', dir, CYAN);

        console.log();
        return;
      }

      // --scans – list saved scans
      if (opts.scans) {
        const store    = require('../store');
        const repoRoot = getRepoRoot();
        const scans    = store.listScans(repoRoot);

        const BOLD  = '\x1b[1m';
        const DIM   = '\x1b[90m';
        const CYAN  = '\x1b[36m';
        const GREEN = '\x1b[32m';
        const RESET = '\x1b[0m';

        const repoId   = store.getRepoId(repoRoot);
        const scansPath = store.scansDir(repoRoot);

        if (scans.length === 0) {
          console.log('\n\x1b[33m No scans found for this repo.\x1b[0m');
          console.log(DIM + '  Working directory : ' + RESET + CYAN + repoRoot + RESET);
          console.log(DIM + '  Store ID          : ' + RESET + DIM + repoId + RESET);
          console.log(DIM + '  Scans directory   : ' + RESET + DIM + scansPath + RESET);
          console.log(DIM + '\n  Run ' + RESET + CYAN + 'scd scan' + RESET + DIM + ' from your project root to create a scan.\n' + RESET);
          return;
        }

        console.log('\n' + BOLD + 'Saved scans' + RESET + '  ' + DIM + scansPath + RESET);
        console.log(DIM + 'Working directory: ' + RESET + CYAN + repoRoot + RESET);
        console.log(DIM + '─'.repeat(72) + RESET);
        console.log(DIM + 'Scan ID (UTC)'.padEnd(22) + 'Date (local)'.padEnd(22) + 'Findings'.padEnd(10) + 'Files'.padEnd(8) + 'Deep' + RESET);
        console.log(DIM + '─'.repeat(72) + RESET);

        const { cacheAge } = require('../scan-cache');
        for (const s of scans) {
          const date    = s.scanDate ? new Date(s.scanDate).toLocaleString('en-SE') : '—';
          const deepStr = s.hasDeep ? GREEN + '✓' + RESET : DIM + '—' + RESET;
          console.log(
            CYAN + s.scanId.padEnd(22)          + RESET +
            DIM  + date.padEnd(22)              + RESET +
            (String(s.findingCount)).padEnd(10) +
            DIM + String(s.totalFiles).padEnd(8) + RESET +
            deepStr
          );
        }
        console.log(DIM + '─'.repeat(72) + RESET);
        console.log('  ' + scans.length + ' scan' + (scans.length !== 1 ? 's' : '') + ' saved\n');
        console.log(DIM + '  Scan IDs are in UTC. Date column shows your local time.' + RESET);
        console.log(DIM + '  scd report --scan <id>   generate report from a specific scan\n' + RESET);
        return;
      }

      // --verify  – check all repos in store
      if (opts.verify) {
        const { verifyAll, renderResults, promptClean } = require('../store-verify');
        const results = verifyAll();

        if (results.length === 0) {
          console.log('\n\x1b[90m No repos found in store.\x1b[0m\n');
          return;
        }

        if (opts.json) {
          console.log(JSON.stringify(results.map(r => ({
            repoId:            r.repoId,
            name:              r.name,
            status:            r.status,
            localPath:         r.localPath,
            remote:            r.remote,
            type:              r.type,
            daysSinceLastSeen: r.daysSinceLastSeen,
            lastScan:          r.lastScan,
            detail:            r.detail,
            stats:             r.stats,
          })), null, 2));
          return;
        }

        const issues = results.filter(r => r.status !== 'OK');
        console.log('\n\x1b[1mSecure Code by Design – Store verify\x1b[0m');
        console.log('\x1b[90m' + '─'.repeat(60) + '\x1b[0m');
        console.log('\x1b[90m Checking ' + results.length + ' repo' + (results.length !== 1 ? 's' : '') + ' in store…\x1b[0m');

        renderResults(results, { verbose: opts.verbose || opts.clean });

        if (opts.clean && issues.length > 0) {
          await promptClean(results);
        }
        return;
      }

      // --reports  – list saved reports
      if (opts.reports) {
        const reports = store.listReports(repoRoot);
        if (reports.length === 0) {
          console.log('\n\x1b[90m No reports found. Run scd report to generate one.\x1b[0m\n');
          return;
        }
        console.log('\n\x1b[1mSaved reports\x1b[0m  \x1b[90m' + dir + '/reports\x1b[0m\n');
        for (const r of reports) {
          const size = r.size > 1024 * 1024
            ? (r.size / 1024 / 1024).toFixed(1) + ' MB'
            : Math.round(r.size / 1024) + ' KB';
          const age  = require('../scan-cache').cacheAge(r.mtime);
          console.log('  \x1b[36m' + r.filename.padEnd(48) + '\x1b[0m' +
            '\x1b[90m' + size.padStart(8) + '  ' + age + '\x1b[0m');
        }
        console.log();
        return;
      }

      // --open / --open-reports
      if (opts.open || opts.openReports) {
        const { execSync } = require('child_process');
        const target  = opts.openReports ? store.reportsDir(repoRoot) : dir;
        const openCmd = process.platform === 'darwin' ? 'open'
                      : process.platform === 'win32'  ? 'explorer'
                      : 'xdg-open';
        try {
          execSync(openCmd + ' "' + target + '"');
          console.log('\x1b[90m Opened: ' + target + '\x1b[0m\n');
        } catch {
          console.log('\x1b[33m Could not open file manager. Path:\x1b[0m\n  ' + target + '\n');
        }
        return;
      }

      // Default – show store info for current repo
      const fs = require('fs');
      const path = require('path');
      const meta = (() => {
        try { return JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')); }
        catch { return null; }
      })();

      console.log('\n\x1b[1mSecure Code by Design – Store\x1b[0m');
      console.log('\x1b[90m' + '─'.repeat(52) + '\x1b[0m\n');
      console.log('  Working dir: \x1b[36m' + repoRoot + '\x1b[0m');
      console.log('  Repo:        \x1b[1m' + (meta?.name || path.basename(repoRoot)) + '\x1b[0m');
      if (identity.type === 'remote') {
        console.log('  Remote:      \x1b[90m' + identity.identifier + '\x1b[0m');
      } else {
        console.log('  Type:        \x1b[33mpath-based\x1b[0m (no git remote – ID may change if folder moves)');
      }
      console.log('  Store ID:    \x1b[90m' + store.getRepoId(repoRoot) + '\x1b[0m');
      console.log('  Location:    \x1b[36m' + dir + '\x1b[0m\n');

      if (meta?.lastScan) {
        const { cacheAge } = require('../scan-cache');
        const critStr = meta.lastScanCritical > 0
          ? ' \x1b[31m(' + meta.lastScanCritical + ' CRITICAL)\x1b[0m' : '';
        console.log('  Last scan: ' + cacheAge(meta.lastScan) +
          '  \x1b[90m' + meta.lastScanFindings + ' findings\x1b[0m' + critStr);
      } else {
        console.log('  Last scan: \x1b[90m(none yet)\x1b[0m');
      }

      const reports = store.listReports(repoRoot);
      console.log('  Reports:   \x1b[90m' + reports.length + ' saved\x1b[0m');
      console.log();
      console.log('  \x1b[90mscd repo configure          show per-repo configuration\x1b[0m');
      console.log('  \x1b[90mscd repo configure --scan-mode fast   set scan mode\x1b[0m');
      console.log('  \x1b[90mscd repo --reports          list saved reports\x1b[0m');
      console.log('  \x1b[90mscd repo --open             open in file manager\x1b[0m');
      console.log('  \x1b[90mscd repo --open-reports     open reports folder\x1b[0m');
      console.log('  \x1b[90mscd repo --path             print path (for scripting)\x1b[0m');
      console.log('  \x1b[90mscd repo --show             show full meta info for current repo\x1b[0m');
      console.log('  \x1b[90mscd repo --scans            list all saved scans\x1b[0m');
      console.log('  \x1b[90mscd repo --verify           verify all repos exist on disk\x1b[0m');
      console.log('  \x1b[90mscd repo --verify --clean   interactive cleanup of stale repos\x1b[0m\n');
    });

  repoCmd.addCommand(repoConfigureCmd);
  repoCmd.addCommand(repoHooksCmd);
  program.addCommand(repoCmd);
}
