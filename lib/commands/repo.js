'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN, OK } = require('../output-constants');
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

      // --verify operates on all known repos — does not require current repo to be known
      if (opts.verify) {
        const { verifyAll, renderResults, promptClean } = require('../store-verify');
        const results = verifyAll();

        if (results.length === 0) {
          console.log(DIM + ' No repos found in store.' + RESET + '\n');
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
        console.log('\n' + BOLD + 'Secure Code by Design – Store verify' + RESET);
        console.log(DIM + '─'.repeat(60) + RESET);
        console.log(DIM + ' Checking ' + results.length + ' repo' + (results.length !== 1 ? 's' : '') + ' in store…' + RESET);

        renderResults(results, { verbose: opts.verbose || opts.clean });

        if (opts.clean && issues.length > 0) {
          await promptClean(results);
        }
        return;
      }

      // All remaining flags and the default view require the repo to be known.
      // Guard here — before storeDir() which would otherwise create the directory.
      if (!store.isRepoKnown(repoRoot)) {
        const repoId = store.getRepoId(repoRoot);
        console.log('\n' + YELLOW + '  This directory is not known to scd.' + RESET);
        console.log(DIM + '  Working dir: ' + RESET + CYAN + repoRoot + RESET);
        console.log(DIM + '  Store ID:    ' + RESET + DIM + repoId + RESET + '\n');
        console.log('  To start scanning this repo, run:');
        console.log(CYAN + '    scd init' + RESET + DIM + '      initialise this repo and configure git hooks' + RESET);
        console.log(CYAN + '    scd scan' + RESET + DIM + '      scan now (auto-registers on first scan)' + RESET);
        console.log('');
        console.log(DIM + '  Run ' + RESET + CYAN + 'scd list' + RESET + DIM + ' to see all known repos.' + RESET + '\n');
        process.exit(0);
      }

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

        let meta;
        try {
          meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
        } catch {
          const repoId = store.getRepoId(repoRoot);
          console.log('\n' + YELLOW + ' No meta.json found — this repo has not been initialised.' + RESET);
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
            meta.type === 'path-based' ? YELLOW : '');

        if (meta.remote) row('Remote:',    meta.remote,  DIM);
        row('Local path:', meta.localPath || '(none)',    CYAN);

        console.log();

        if (meta.lastSeen) {
          row('Last seen:',  cacheAge(meta.lastSeen) + '  ' + DIM + meta.lastSeen + RESET);
        }
        if (meta.lastScan) {
          const critStr = meta.lastScanCritical > 0
            ? '  ' + RED + meta.lastScanCritical + ' CRITICAL' + RESET : '';
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

        const repoId   = store.getRepoId(repoRoot);
        const scansPath = store.scansDir(repoRoot);

        if (scans.length === 0) {
          console.log('\n' + YELLOW + ' No scans found for this repo.' + RESET);
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

      // --reports  – list saved reports
      if (opts.reports) {
        const reports = store.listReports(repoRoot);
        if (reports.length === 0) {
          console.log(DIM + '\n No reports found. Run scd report to generate one.' + RESET + '\n');
          return;
        }
        console.log('\n' + BOLD + 'Saved reports' + RESET + '  ' + DIM + dir + '/reports' + RESET + '\n');
        for (const r of reports) {
          const size = r.size > 1024 * 1024
            ? (r.size / 1024 / 1024).toFixed(1) + ' MB'
            : Math.round(r.size / 1024) + ' KB';
          const age  = require('../scan-cache').cacheAge(r.mtime);
          console.log('  ' + CYAN + r.filename.padEnd(48) + RESET +
            DIM + size.padStart(8) + '  ' + age + RESET);
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
          console.log(DIM + ' Opened: ' + target + RESET + '\n');
        } catch {
          console.log(YELLOW + ' Could not open file manager. Path:' + RESET + '\n  ' + target + '\n');
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

      console.log('\n' + BOLD + 'Secure Code by Design – Store' + RESET);
      console.log(DIM + '─'.repeat(52) + RESET + '\n');
      console.log('  Working dir: ' + CYAN + repoRoot + RESET);
      console.log('  Repo:        ' + BOLD + (meta?.name || path.basename(repoRoot)) + RESET);
      if (identity.type === 'remote') {
        console.log('  Remote:      ' + DIM + identity.identifier + RESET);
      } else {
        console.log('  Type:        ' + YELLOW + 'path-based' + RESET + ' (no git remote – ID may change if folder moves)');
      }
      console.log('  Store ID:    ' + DIM + store.getRepoId(repoRoot) + RESET);
      console.log('  Location:    ' + CYAN + dir + RESET + '\n');

      if (meta?.lastScan) {
        const { cacheAge } = require('../scan-cache');
        const critStr = meta.lastScanCritical > 0
          ? ' ' + RED + '(' + meta.lastScanCritical + ' CRITICAL)' + RESET : '';
        console.log('  Last scan: ' + cacheAge(meta.lastScan) +
          '  ' + DIM + meta.lastScanFindings + ' findings' + RESET + critStr);
      } else {
        console.log('  Last scan: ' + DIM + '(none yet)' + RESET);
      }

      const reports = store.listReports(repoRoot);
      console.log('  Reports:   ' + DIM + reports.length + ' saved' + RESET);
      console.log();
      console.log('  ' + DIM + 'scd repo scope --show       show active scope exclusions' + RESET);
      console.log('  ' + DIM + 'scd repo configure          show per-repo configuration' + RESET);
      console.log('  ' + DIM + 'scd repo configure --scan-mode fast   set scan mode' + RESET);
      console.log('  ' + DIM + 'scd repo --reports          list saved reports' + RESET);
      console.log('  ' + DIM + 'scd repo --open             open in file manager' + RESET);
      console.log('  ' + DIM + 'scd repo --open-reports     open reports folder' + RESET);
      console.log('  ' + DIM + 'scd repo --path             print path (for scripting)' + RESET);
      console.log('  ' + DIM + 'scd repo --show             show full meta info for current repo' + RESET);
      console.log('  ' + DIM + 'scd repo --scans            list all saved scans' + RESET);
      console.log('  ' + DIM + 'scd repo --verify           verify all repos exist on disk' + RESET);
      console.log('  ' + DIM + 'scd repo --verify --clean   interactive cleanup of stale repos' + RESET + '\n');
    });


  // ── scd repo scope ────────────────────────────────────────────────────────
  const repoScopeCmd = new Command('scope')
    .description('Manage per-repo scan scope exclusions')
    .addHelpText('after', `
Examples:
  scd repo scope --show
  scd repo scope --add-file "tests/fixtures/" --reason "Test fixtures with intentional vulns"
  scd repo scope --add-rule INFRA-001 --reason "Cloud-managed infrastructure"
  scd repo scope --add-rule JS-ERR-002 --files "lib/rules/,**/*.test.js" --reason "Rule definition files"

  For global (all repos) scope: scd scope --show`)
    .option('--show',              'Show active scope exclusions for this repo (merged: global + repo + server)')
    .option('--add-file <pattern>','Add a file/directory exclusion pattern')
    .option('--add-rule <ruleId>', 'Add a rule exclusion')
    .option('--files <globs>',     'Comma-separated file globs to scope a rule exclusion (use with --add-rule)')
    .option('--reason <text>',     'Reason for the exclusion (required with --add-file and --add-rule)')
    .option('--remove-file <pattern>','Remove a file exclusion by pattern')
    .option('--remove-rule <ruleId>', 'Remove a rule exclusion by rule ID')
    .action((opts) => {
      const fs    = require('fs');
      const store = require('../store');
      const { loadScope, validateScope, summariseScope } = require('../scope');
      const { appendToScope, buildFileEntry, buildRuleEntry, removeFromScope } = require('../commands/scope');

      const repoRoot  = getRepoRoot();
      const scopeFile = store.scopePath(repoRoot);

      // ── --show ─────────────────────────────────────────────────────────────
      if (opts.show || (!opts.addFile && !opts.addRule && !opts.removeFile && !opts.removeRule)) {
        const scope    = loadScope(repoRoot);
        const warnings = validateScope(scope);
        const summary  = summariseScope(scope);

        console.log(`\n${BOLD}Scope exclusions for this repo${RESET}  ${DIM}(merged: global + repo + server)${RESET}\n`);

        if (!summary.hasExclusions) {
          console.log(`${DIM}  No active exclusions.${RESET}\n`);
          return;
        }

        if (summary.fileLines.length > 0) {
          console.log(`${BOLD}  File exclusions:${RESET}`);
          for (const line of summary.fileLines) console.log(`  ${line.trim()}`);
          console.log();
        }

        if (summary.ruleLines.length > 0) {
          console.log(`${BOLD}  Rule exclusions:${RESET}`);
          for (const line of summary.ruleLines) console.log(`  ${line.trim()}`);
          console.log();
        }

        if (warnings.length > 0) {
          console.log(`${YELLOW}  ⚠ Incomplete entries (missing required fields):${RESET}`);
          for (const w of warnings) {
            console.log(`${YELLOW}    ${w.identifier}: missing ${w.missing.join(', ')}${RESET}`);
          }
          console.log();
        }

        const serverFile = store.serverScopePath(repoRoot);
        if (fs.existsSync(serverFile)) {
          console.log(`${DIM}  Server scope active (scope-server.yml) — entries marked [server] above.${RESET}\n`);
        }
        return;
      }

      // ── require --reason ────────────────────────────────────────────────────
      if (!opts.reason) {
        console.error(`\n${RED}✗ --reason is required.${RESET}`);
        console.error(`  Every scope exclusion must have a documented reason.\n`);
        process.exit(1);
      }

      const { getMachineFingerprint } = require('../store');
      const installId = getMachineFingerprint() || 'unknown';
      const addedAt   = new Date().toLocaleString('sv-SE', {
        timeZone: 'Europe/Stockholm', year: 'numeric', month: '2-digit',
        day: '2-digit', hour: '2-digit', minute: '2-digit',
      }).replace(',', '');

      // ── --add-file ──────────────────────────────────────────────────────────
      if (opts.addFile) {
        const entry = buildFileEntry(opts.addFile, opts.reason, installId, addedAt);
        appendToScope(scopeFile, 'file_excludes', entry);
        console.log(`\n${GREEN}✓ File exclusion added to repo scope.yml${RESET}`);
        console.log(`  ${DIM}Pattern : ${opts.addFile}${RESET}`);
        console.log(`  ${DIM}Reason  : ${opts.reason}${RESET}`);
        console.log(`  ${DIM}Added by: ${installId}${RESET}\n`);
        console.log(`${YELLOW}  ⚠ Active file exclusions are visible in every scan output.${RESET}\n`);
        return;
      }

      // ── --add-rule ──────────────────────────────────────────────────────────
      if (opts.addRule) {
        const files = opts.files
          ? opts.files.split(',').map(s => s.trim()).filter(Boolean)
          : null;
        const entry = buildRuleEntry(opts.addRule, files, opts.reason, installId, addedAt);
        appendToScope(scopeFile, 'rule_excludes', entry);
        const scopeDesc = files ? files.join(', ') : 'all files';
        console.log(`\n${GREEN}✓ Rule exclusion added to repo scope.yml${RESET}`);
        console.log(`  ${DIM}Rule    : ${opts.addRule}${RESET}`);
        console.log(`  ${DIM}Scope   : ${scopeDesc}${RESET}`);
        console.log(`  ${DIM}Reason  : ${opts.reason}${RESET}`);
        console.log(`  ${DIM}Added by: ${installId}${RESET}\n`);
        console.log(`${YELLOW}  ⚠ Active rule exclusions are visible in every scan output.${RESET}\n`);
        return;
      }

      // ── --remove-file ────────────────────────────────────────────────────────
      if (opts.removeFile) {
        const removed = removeFromScope(scopeFile, 'file_excludes', 'pattern', opts.removeFile);
        if (removed.length === 0) {
          console.log(`\n${YELLOW}  No file exclusion found matching: ${opts.removeFile}${RESET}\n`);
        } else {
          console.log(`\n${GREEN}✓ Removed ${removed.length} file exclusion(s) from repo scope.yml${RESET}`);
          for (const r of removed) {
            console.log(`  ${DIM}Pattern : ${r.pattern}${RESET}`);
            console.log(`  ${DIM}Reason  : ${r.reason || '(none)'}${RESET}`);
            console.log(`  ${DIM}Added by: ${r.added_by || '(unknown)'}  ${r.added_at || ''}${RESET}`);
          }
          console.log();
        }
        return;
      }

      // ── --remove-rule ────────────────────────────────────────────────────────
      if (opts.removeRule) {
        const removed = removeFromScope(scopeFile, 'rule_excludes', 'rule', opts.removeRule);
        if (removed.length === 0) {
          console.log(`\n${YELLOW}  No rule exclusion found matching: ${opts.removeRule}${RESET}\n`);
        } else {
          console.log(`\n${GREEN}✓ Removed ${removed.length} rule exclusion(s) from repo scope.yml${RESET}`);
          for (const r of removed) {
            const scopeDesc = r.files && r.files.length ? r.files.join(', ') : 'all files';
            console.log(`  ${DIM}Rule    : ${r.rule} (${scopeDesc})${RESET}`);
            console.log(`  ${DIM}Reason  : ${r.reason || '(none)'}${RESET}`);
            console.log(`  ${DIM}Added by: ${r.added_by || '(unknown)'}  ${r.added_at || ''}${RESET}`);
          }
          console.log();
        }
        return;
      }
    });

  repoCmd.addCommand(repoConfigureCmd);
  repoCmd.addCommand(repoHooksCmd);
  repoCmd.addCommand(repoScopeCmd);
  program.addCommand(repoCmd);
}
