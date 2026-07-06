const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('./output-constants');
/**
 * doctor.js
 * Checks that hooks are active, up to date, and working.
 * Maps to "Layer 1 – Technical self-check" in the architecture.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOKS_DIR       = path.join(os.homedir(), '.scd', 'hooks');
const STALE_ATTEMPTS  = 10;
const GRACE_DAYS      = 7;

// Count of ⚠ rows emitted this run — the summary must not say "all good" when
// any warning was shown (#67 d). Reset at the start of every doctor() run.
let warnCount = 0;

async function doctor() {
  console.log(CYAN + '\n Secure Code by Design – System check' + RESET + '\n');

  let allOk = true;
  warnCount = 0;

  // 1. Check global hooks path
  const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';
  try {
    const hooksPath = execSync('git config --global core.hooksPath', {
      encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    if (hooksPath === HOOKS_DIR) {
      ok('Global hooks configured', hooksPath);
    } else if (hooksPath === NULL_DEVICE) {
      fail('Global hooks disabled — core.hooksPath set to ' + hooksPath);
      console.log(DIM + '    This disables hooks for ALL repos on this machine.' + RESET);
      console.log(DIM + '    Fix: git config --global core.hooksPath "' + HOOKS_DIR + '"' + RESET);
      allOk = false;
    } else {
      warn('Global hooks pointing to unexpected directory', hooksPath);
      console.log(DIM + '    Expected: ' + HOOKS_DIR + RESET);
      console.log(DIM + '    Fix: git config --global core.hooksPath "' + HOOKS_DIR + '"' + RESET);
    }
  } catch {
    fail('Global hooks NOT configured');
    console.log(DIM + '    Run: scd install' + RESET);
    allOk = false;
  }

  // 2. Check hook files exist and are executable
  const isWindows = process.platform === 'win32';
  for (const hook of ['pre-commit', 'pre-push']) {
    const hookPath = path.join(HOOKS_DIR, hook);
    if (fs.existsSync(hookPath)) {
      if (isWindows) {
        // Windows does not have executable bits — presence is sufficient
        ok(`${hook} hook active`);
      } else {
        try {
          fs.accessSync(hookPath, fs.constants.X_OK);
          ok(`${hook} hook active`);
        } catch {
          fail(`${hook} hook exists but is not executable`);
          console.log(`${DIM}    Run: chmod +x ${hookPath}${RESET}`);
          allOk = false;
        }
      }
    } else {
      fail(`${hook} hook missing`);
      allOk = false;
    }
  }

  // 3. Check current repo (if in one)
  try {
    const repoRoot = execSync('git rev-parse --show-toplevel', { encoding: 'utf8', stdio: 'pipe' }).trim();
    ok('Inside a git repo', repoRoot);

    // Check if scd repo hooks --disable has been used for this repo
    const { getHookStatus } = require('./hooks-manager');
    const hookStatus = getHookStatus(repoRoot);
    if (hookStatus.status === 'disabled') {
      warn('Hooks disabled for this repo', 'core.hooksPath → ' + hookStatus.hooksPath);
      console.log(DIM + '    Re-enable with: scd repo hooks enable' + RESET);
    } else if (hookStatus.status === 'shadowed') {
      // A foreign core.hooksPath silently bypasses scd's hooks — git runs that
      // dir instead while scd shows nothing. Exactly the "silently hidden" bug
      // the product exists to reveal (#72).
      fail('scd hooks are shadowed — core.hooksPath points elsewhere');
      console.log(DIM + '    Effective: ' + hookStatus.hooksPath + '  (' + hookStatus.source + ')' + RESET);
      console.log(DIM + '    scd hooks do NOT run for this repo. Fix:' + RESET);
      console.log(DIM + (hookStatus.source === 'local'
        ? '      git config --unset core.hooksPath   (then global ~/.scd/hooks applies)'
        : '      git config --global core.hooksPath "' + HOOKS_DIR + '"') + RESET);
      allOk = false;
    } else if (hookStatus.status === 'global-broken') {
      fail('Global hooks disabled — core.hooksPath set to /dev/null');
      console.log(DIM + '    Fix: git config --global core.hooksPath "' + HOOKS_DIR + '"' + RESET);
      allOk = false;
    }

    // Check if local .git/hooks would override global (old-style hook setup)
    const localHooksDir = path.join(repoRoot, '.git', 'hooks');
    const localPrePush = path.join(localHooksDir, 'pre-push');
    if (fs.existsSync(localPrePush)) {
      const content = fs.readFileSync(localPrePush, 'utf8');
      if (!content.includes('scd')) {
        warn('Local pre-push hook found that is not Secure Code by Design', localPrePush);
        console.log(DIM + '    Local hooks override global. Verify that your hooks work together.' + RESET);
      }
    }
  } catch {
    info('Not inside a git repo');
  }

  // 4. Push queue status
  try {
    const { getCentralUrl } = require('./global-config');
    const centralUrl = getCentralUrl();
    if (centralUrl) {
      const { queueSize, staleCount, isPastGrace } = require('./push-queue');
      const pending = queueSize();
      const stale   = staleCount();
      const grace   = isPastGrace();

      ok('Central URL configured', centralUrl);

      if (stale > 0) {
        warn(`Push queue has ${stale} stale event(s) (${STALE_ATTEMPTS}+ failed attempts)`);
        console.log(DIM + '    Run: scd queue reset to recover the queue (scd queue list to inspect)' + RESET);
        allOk = false;
      } else if (grace) {
        warn(`Push queue has events older than ${GRACE_DAYS} days – central may be unreachable`);
        allOk = false;
      } else if (pending > 0) {
        info(`Push queue: ${pending} event(s) pending sync`);
      } else {
        ok('Push queue empty – all events synced');
      }

      // Exception delivery status. Attempt retry first so we report the
      // truth after a fresh delivery pass, not the stale pre-retry count.
      try {
        const repoRoot = require('./config').getRepoRoot();
        if (repoRoot) {
          const em = require('./exception-manager');
          // Events queue flush FIRST — registers the repo server-side before
          // the exception retry FK-references it (see fix(delivery-order)).
          const flushStatus = await require('./push-queue').flushEvents(repoRoot);
          await em.pushPendingExceptions(repoRoot);

          // Surface a server-side push failure (rejected batch / bad token /
          // invalid licence) — otherwise it is silent and the user assumes sync worked.
          const flushNotice = require('./push-queue').flushStatusNotice(flushStatus);
          if (flushNotice) {
            if (flushNotice.level === 'warn') { warn(flushNotice.message, flushNotice.hint); allOk = false; }
            else info(flushNotice.message);
          }

          const tracker = require('./exceptions-push-tracker');
          const excPending = tracker.pendingCount(repoRoot);
          if (excPending > 0) {
            const oldest = tracker.oldestQueuedAt(repoRoot);
            const age    = oldest ? require('./scan-cache').cacheAge(oldest) : 'unknown';
            warn(`${excPending} exception(s) pending delivery to scd-server (oldest: ${age})`);
          }
          // 0 pending → no extra output; the push queue line above carries the OK.
        }
      } catch { /* non-fatal */ }
    } else {
      info('Push queue inactive (no central URL configured)');
      console.log(DIM + '    scd configure --central-url https://your-server:3000' + RESET);
    }
  } catch {
    // Non-fatal if push-queue module unavailable
  }

  // 5. scd-server health check (if central URL configured)
  try {
    const { getCentralUrl, getCentralToken } = require('./global-config');
    const centralUrl = getCentralUrl();
    if (centralUrl) {
      const token   = getCentralToken();
      const http    = centralUrl.startsWith('https') ? require('https') : require('http');
      const baseUrl = centralUrl.replace(/\/$/, '');

      const result = await new Promise((resolve) => {
        const req = http.get(
          baseUrl + '/api/v1/health',
          { headers: token ? { 'Authorization': `Bearer ${token}` } : {}, timeout: 5000 },
          (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
              try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
              catch { resolve({ status: res.statusCode, body: null }); }
            });
          }
        );
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: null }); });
        req.on('error', () => resolve({ status: 0, body: null }));
      });

      if (result.status === 0) {
        fail('scd-server unreachable');
        console.log(`${DIM}    ${baseUrl}${RESET}`);
        allOk = false;
      } else if (result.body && result.body.license) {
        const lic = result.body.license;
        if (lic.tier === 'invalid') {
          // Strip support URL from reason — administrator should resolve, not end users
          const reason = (lic.reason || 'unknown reason')
            .replace(/\.?\s*Contact support@[^.]+\.com\.?/gi, '').trim();
          fail(`scd-server license invalid — ${reason}`);
          console.log(DIM + '    Contact your local scd-server administrator.' + RESET);
          allOk = false;
        } else {
          const exp = lic.expiry ? ` · expires ${lic.expiry}` : '';
          ok('scd-server reachable', `${lic.tier}${exp} · ${baseUrl}`);
        }

        // Show server version + min CLI version
        try {
          const srvVer = result.body.version      || null;
          const minVer = result.body.min_cli_version || null;
          const { setServerVersionInfo } = require('./global-config');
          setServerVersionInfo(srvVer, minVer);

          if (srvVer) console.log(`${DIM}    Server version:   v${srvVer}${RESET}`);
          if (minVer) console.log(`${DIM}    Min CLI version:  v${minVer}${RESET}`);

          const { getVersionWarning } = require('./version-check');
          const versionWarn = getVersionWarning();
          if (versionWarn) {
            console.log('');
            console.log(`${YELLOW}    ${versionWarn.replace(/\n   /g, '\n    ')}${RESET}`);
            allOk = false;
          }
        } catch { /* non-fatal */ }

        // Show AI provider status
        try {
          const aiProvider = result.body.ai && result.body.ai.provider;
          if (aiProvider) {
            if (aiProvider === 'disabled') {
              info('AI provider: disabled');
              console.log(`${DIM}    Enable in Admin → Operations → AI Settings to use --deep${RESET}`);
            } else {
              const aiModel     = result.body.ai.model;
              const providerStr = aiModel ? `${aiProvider} · ${aiModel}` : aiProvider;
              ok('AI provider: ' + providerStr);
            }
          }
        } catch { /* non-fatal */ }

        // Show configured timeouts
        try {
          const { getServerTimeout, getDeepTimeout } = require('./global-config');
          const sTout = getServerTimeout();
          const dTout = getDeepTimeout();
          const fmt   = ms => ms >= 60000 ? `${Math.round(ms/60000)}m` : `${Math.round(ms/1000)}s`;
          console.log(`${DIM}    Server timeout: ${fmt(sTout)}  ·  Deep timeout: ${fmt(dTout)}${RESET}`);
        } catch { /* non-fatal */ }
      } else {
        ok('scd-server reachable', baseUrl);
      }

      // Authenticated token-validity probe (#67). /health does NOT validate the
      // personal token, so a dead token shows "reachable" green while every
      // delivery is silently blocked. /api/v1/entitlements requires the Bearer
      // token, so it tells the truth.
      if (token) {
        const authResult = await new Promise((resolve) => {
          const req = http.get(
            baseUrl + '/api/v1/entitlements',
            { headers: { 'Authorization': `Bearer ${token}` }, timeout: 5000 },
            (res) => {
              let data = '';
              res.on('data', chunk => { data += chunk; });
              res.on('end', () => {
                let body = null;
                try { body = JSON.parse(data); } catch {}
                resolve({ status: res.statusCode, body });
              });
            }
          );
          req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: null }); });
          req.on('error', () => resolve({ status: 0, body: null }));
        });

        if (authResult.status === 401 || authResult.status === 403) {
          fail('scd-server rejects your token — delivery is blocked');
          const hint = (authResult.body && (authResult.body.error || authResult.body.message))
            || 'Re-create the token on the server, then run: scd configure --token <token>';
          console.log(`${DIM}    ${hint}${RESET}`);
          allOk = false;
        } else if (authResult.status >= 200 && authResult.status < 300) {
          ok('scd-server token valid');
        }
        // Other statuses (0 / 5xx): reachability is already reported via /health.
      } else {
        warn('No scd-server token configured — pushes cannot be delivered');
        console.log(`${DIM}    Set one with: scd configure --token <token>${RESET}`);
      }
    }
  } catch { /* non-fatal */ }

  // 6. Summary
  console.log('');
  if (!allOk) {
    console.log(RED + BOLD + ' ⚠  Action required (see above)' + RESET);
  } else if (warnCount > 0) {
    console.log(YELLOW + BOLD + ' ⚠  Mostly good — review the warning(s) above' + RESET);
  } else {
    console.log(GREEN + BOLD + ' ✓ Everything looks good!' + RESET);
  }
  console.log('');
}


function ok(msg, detail = null) {
  console.log(`${GREEN} ✓ ${msg}${RESET}${detail ? DIM + ' – ' + detail + RESET : ''}`);
}
function fail(msg) {
  console.log(`${RED} ✗ ${msg}${RESET}`);
}
function warn(msg, detail = null) {
  warnCount++;
  console.log(`${YELLOW} ⚠  ${msg}${RESET}${detail ? DIM + ' – ' + detail + RESET : ''}`);
}
function info(msg) {
  console.log(`${CYAN} ℹ  ${msg}${RESET}`);
}

module.exports = { doctor };
