'use strict';
// lib/commands/configure.js

module.exports = { register };

function register(program) {
  program
    .command('configure')
    .description('Manage global configuration (API key etc.)')
    .option('--show',             'Show current global configuration')
    .option('--central-url <url>',  'Set scd-server URL (enables push queue)')
    .option('--clear-central-url',  'Remove scd-server URL (disables push queue)')
    .option('--token <token>',         'Set scd-server API token')
    .option('--clear-token',           'Remove scd-server API token')
    .option('--server-timeout <value>', 'Set server API timeout (e.g. 15s, 30s). Default: 30s')
    .option('--deep-timeout <value>',   'Set deep analysis timeout (e.g. 10m, 20m). Default: 20m')
    .option('--trust-level <value>',    'Set global default trust level (maximum_privacy|balanced|maximum_analysis)')
    .option('--scan-mode <value>',      'Set global default scan mode (full|fast)')
    .option('--block-on-high <value>',  'Set global default block-on-high (true|false)')
    .option('--block-on-critical <value>', 'Set global default block-on-critical (true|false)')
    .action((opts) => {
      const { getCentralUrl, setCentralUrl, removeCentralUrl, getCentralToken, setCentralToken, removeCentralToken,
              getServerTimeout, setServerTimeout, getDeepTimeout, setDeepTimeout, parseTimeoutArg,
              GLOBAL_CONFIG } =
        require('../global-config');

      const CYAN  = '\x1b[36m';
      const GREEN = '\x1b[32m';
      const RED   = '\x1b[31m';
      const DIM   = '\x1b[2m';
      const BOLD  = '\x1b[1m';
      const RESET = '\x1b[0m';

      // ── --central-url <url> ───────────────────────────────────────────────
      if (opts.centralUrl) {
        const url = opts.centralUrl.trim();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
          console.error(`\n${RED}✗ Invalid URL – must start with http:// or https://${RESET}\n`);
          process.exit(1);
        }
        setCentralUrl(url);
        const savedUrl = getCentralUrl();
        console.log(`\n${GREEN}✓ Central URL saved${RESET} → ${DIM}${savedUrl}${RESET}`);
        if (savedUrl !== url) {
          console.log(`  ${DIM}(normalized from ${url})${RESET}`);
        }
        console.log(`  ${DIM}Push queue enabled – events will sync on each scd command.${RESET}\n`);
        process.exit(0);
      }

      // ── --clear-central-url ───────────────────────────────────────────────
      if (opts.clearCentralUrl) {
        const removed = removeCentralUrl();
        if (removed) {
          console.log(`\n${GREEN}✓ Central URL removed${RESET} – push queue disabled.\n`);
        } else {
          console.log(`\n${DIM}No central URL configured.${RESET}\n`);
        }
        process.exit(0);
      }

      // ── --token <token> ───────────────────────────────────────────────────
      if (opts.token) {
        const token = opts.token.trim();
        if (!token.startsWith('scd-')) {
          console.error(`\n${RED}✗ Invalid token format – scd-server tokens start with scd-${RESET}\n`);
          process.exit(1);
        }
        setCentralToken(token);
        console.log(`\n${GREEN}✓ Token saved${RESET} → ${DIM}${GLOBAL_CONFIG}${RESET}`);
        console.log(`  ${DIM}${token.slice(0, 12)}...${RESET}\n`);
        process.exit(0);
      }

      // ── --clear-token ─────────────────────────────────────────────────────
      if (opts.clearToken) {
        const removed = removeCentralToken();
        if (removed) {
          console.log(`\n${GREEN}✓ Token removed${RESET} from ${DIM}${GLOBAL_CONFIG}${RESET}\n`);
        } else {
          console.log(`\n${DIM}No token to remove.${RESET}\n`);
        }
        process.exit(0);
      }

      // ── --server-timeout <value> ─────────────────────────────────────────
      if (opts.serverTimeout !== undefined) {
        try {
          const ms = parseTimeoutArg(opts.serverTimeout);
          setServerTimeout(ms);
          const fmt = ms >= 60000 ? `${Math.round(ms/60000)}m` : `${Math.round(ms/1000)}s`;
          console.log(`\n${GREEN}✓ Server timeout set to ${fmt} (${ms}ms)${RESET}\n`);
        } catch (err) {
          console.error(`\n${RED}❌ ${err.message}${RESET}\n`);
          process.exit(1);
        }
        process.exit(0);
      }

      // ── --deep-timeout <value> ────────────────────────────────────────────
      if (opts.deepTimeout !== undefined) {
        try {
          const ms = parseTimeoutArg(opts.deepTimeout);
          setDeepTimeout(ms);
          const fmt = ms >= 60000 ? `${Math.round(ms/60000)}m` : `${Math.round(ms/1000)}s`;
          console.log(`\n${GREEN}✓ Deep analysis timeout set to ${fmt} (${ms}ms)${RESET}\n`);
        } catch (err) {
          console.error(`\n${RED}❌ ${err.message}${RESET}\n`);
          process.exit(1);
        }
        process.exit(0);
      }

      // ── global repo defaults ─────────────────────────────────────────────
      const VALID_TRUST  = ['maximum_privacy', 'balanced', 'maximum_analysis'];
      const VALID_MODES  = ['full', 'fast'];

      if (opts.trustLevel !== undefined) {
        if (!VALID_TRUST.includes(opts.trustLevel)) {
          console.error(`\n${RED}✗ Invalid trust level. Use: ${VALID_TRUST.join(' | ')}${RESET}\n`);
          process.exit(1);
        }
        require('../global-config').set('REPO_TRUST_LEVEL', opts.trustLevel);
        console.log(`\n${GREEN}✓ Global default trust_level set to ${opts.trustLevel}${RESET}\n`);
        process.exit(0);
      }

      if (opts.scanMode !== undefined) {
        if (!VALID_MODES.includes(opts.scanMode)) {
          console.error(`\n${RED}✗ Invalid scan mode. Use: full | fast${RESET}\n`);
          process.exit(1);
        }
        require('../global-config').set('REPO_SCAN_MODE', opts.scanMode);
        console.log(`\n${GREEN}✓ Global default scan_mode set to ${opts.scanMode}${RESET}\n`);
        process.exit(0);
      }

      if (opts.blockOnHigh !== undefined) {
        const val = opts.blockOnHigh.toLowerCase();
        if (val !== 'true' && val !== 'false') {
          console.error(`\n${RED}✗ Invalid value. Use: true | false${RESET}\n`);
          process.exit(1);
        }
        require('../global-config').set('REPO_BLOCK_ON_HIGH', val);
        console.log(`\n${GREEN}✓ Global default block_on_high set to ${val}${RESET}\n`);
        process.exit(0);
      }

      if (opts.blockOnCritical !== undefined) {
        const val = opts.blockOnCritical.toLowerCase();
        if (val !== 'true' && val !== 'false') {
          console.error(`\n${RED}✗ Invalid value. Use: true | false${RESET}\n`);
          process.exit(1);
        }
        require('../global-config').set('REPO_BLOCK_ON_CRITICAL', val);
        console.log(`\n${GREEN}✓ Global default block_on_critical set to ${val}${RESET}\n`);
        process.exit(0);
      }

      // ── --show (default if no flags) ──────────────────────────────────────
      const centralUrl = getCentralUrl();
      const gc         = require('../global-config');

      console.log(`\n${CYAN}${BOLD}Secure Code by Design – Global configuration${RESET}\n`);
      console.log(`  Central URL:  ${centralUrl ? GREEN + centralUrl : DIM + '(not set – push queue disabled)'}${RESET}`);
      console.log('');
      if (centralUrl) {
        const token   = getCentralToken();
        const { queueSize, staleCount } = require('../push-queue');
        const pending = queueSize();
        const stale   = staleCount();
        console.log(`  Token:        ${token ? DIM + token.slice(0, 12) + '...' + RESET : RED + '(not set)' + RESET}`);
        console.log(`  Queue:        ${DIM}${pending} pending event(s)${stale > 0 ? '  ' + RED + stale + ' stale' + RESET : ''}${RESET}`);
        const fmtMs  = ms => ms >= 60000 ? `${Math.round(ms/60000)}m` : `${Math.round(ms/1000)}s`;
        console.log(`  Server timeout: ${DIM}${fmtMs(getServerTimeout())}${RESET}  Deep timeout: ${DIM}${fmtMs(getDeepTimeout())}${RESET}`);
        console.log('');
        console.log(`  ${DIM}Clear URL:       scd configure --clear-central-url${RESET}`);
        if (token) {
          console.log(`  ${DIM}Clear token:     scd configure --clear-token${RESET}`);
        } else {
          console.log(`  ${DIM}Set token:       scd configure --token <token>${RESET}`);
        }
      } else {
        console.log(`  ${DIM}Set server URL:  scd configure --central-url https://your-server:3000${RESET}`);
        console.log(`  ${DIM}Then set token:  scd configure --token <token>${RESET}`);
      }

      // Show global repo defaults
      const REPO_KEYS = ['trust_level','scan_mode','block_on_critical','block_on_high'];
      const CODE_DEFAULTS = { trust_level: 'balanced', scan_mode: 'full', block_on_critical: true, block_on_high: true };
      const hasAny = REPO_KEYS.some(k => gc.get('REPO_' + k.toUpperCase()) !== undefined);
      console.log(`  ${BOLD}Global repo defaults${RESET} ${DIM}(fallback for all repos unless overridden in config.yml)${RESET}`);
      for (const key of REPO_KEYS) {
        const raw = gc.get('REPO_' + key.toUpperCase());
        const val = raw !== undefined ? raw : String(CODE_DEFAULTS[key]);
        const src = raw !== undefined ? GREEN + val + RESET : DIM + val + ' (code default)' + RESET;
        console.log(`  ${DIM}${key.padEnd(20)}${RESET}${src}`);
      }
      console.log('');
      console.log(`  ${DIM}Change global repo defaults with: scd configure --trust-level <value>${RESET}`);
      console.log(`  ${DIM}                                  scd configure --scan-mode <fast|full>${RESET}`);
      console.log(`  ${DIM}                                  scd configure --block-on-high <true|false>${RESET}`);
      console.log('');
    });
}
