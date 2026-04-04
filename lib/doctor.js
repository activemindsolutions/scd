/**
 * doctor.js
 * Checks that hooks are active, up to date, and working.
 * Maps to "Lager 1 – Teknisk självkontroll" in the architecture.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOKS_DIR       = path.join(os.homedir(), '.scd', 'hooks');
const STALE_ATTEMPTS  = 10;
const GRACE_DAYS      = 7;

async function doctor() {
  console.log('\n\x1b[36m Secure Code by Design – System check\x1b[0m\n');

  let allOk = true;

  // 1. Check global hooks path
  try {
    const hooksPath = execSync('git config --global core.hooksPath', { encoding: 'utf8' }).trim();
    if (hooksPath === HOOKS_DIR) {
      ok('Global hooks configured', hooksPath);
    } else {
      warn('Global hooks pointing to wrong directory', hooksPath);
    }
  } catch {
    fail('Global hooks NOT configured');
    console.log('\x1b[90m    Run: scd install\x1b[0m');
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
          console.log(`\x1b[90m    Run: chmod +x ${hookPath}\x1b[0m`);
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
    const repoRoot = execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
    ok('Inside a git repo', repoRoot);

    // Check if local hooks would override global
    const localHooksDir = path.join(repoRoot, '.git', 'hooks');
    const localPrePush = path.join(localHooksDir, 'pre-push');
    if (fs.existsSync(localPrePush)) {
      const content = fs.readFileSync(localPrePush, 'utf8');
      if (!content.includes('scd')) {
        warn('Local pre-push hook found that is not Secure Code by Design', localPrePush);
        console.log('\x1b[90m    Local hooks override global. Verify that your hooks work together.\x1b[0m');
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
        console.log('\x1b[90m    Run: scd store --verify --clean to purge stale events\x1b[0m');
        allOk = false;
      } else if (grace) {
        warn(`Push queue has events older than ${GRACE_DAYS} days – central may be unreachable`);
        allOk = false;
      } else if (pending > 0) {
        info(`Push queue: ${pending} event(s) pending sync`);
      } else {
        ok('Push queue empty – all events synced');
      }
    } else {
      info('Push queue inactive (no central URL configured)');
      console.log('\x1b[90m    scd configure --central-url https://your-server:3000\x1b[0m');
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
        console.log(`\x1b[90m    ${baseUrl}\x1b[0m`);
        allOk = false;
      } else if (result.body && result.body.license) {
        const lic = result.body.license;
        if (lic.tier === 'invalid') {
          // Strip support URL from reason — administrator should resolve, not end users
          const reason = (lic.reason || 'unknown reason')
            .replace(/\.?\s*Contact support@[^.]+\.com\.?/gi, '').trim();
          fail(`scd-server license invalid — ${reason}`);
          console.log('\x1b[90m    Contact your local scd-server administrator.\x1b[0m');
          allOk = false;
        } else if (lic.tier === 'development') {
          ok('scd-server reachable', `development mode · ${baseUrl}`);
        } else {
          const exp = lic.expiry ? ` · expires ${lic.expiry}` : '';
          ok('scd-server reachable', `${lic.tier}${exp} · ${baseUrl}`);
        }
      } else {
        ok('scd-server reachable', baseUrl);
      }
    }
  } catch { /* non-fatal */ }

  // 6. Summary
  console.log('');
  if (allOk) {
    console.log('\x1b[32m\x1b[1m ✅ Everything looks good!\x1b[0m');
  } else {
    console.log('\x1b[31m\x1b[1m ⚠️  Action required (see above)\x1b[0m');
  }
  console.log('');
}


function ok(msg, detail = null) {
  console.log(`\x1b[32m ✅ ${msg}\x1b[0m${detail ? '\x1b[90m – ' + detail + '\x1b[0m' : ''}`);
}
function fail(msg) {
  console.log(`\x1b[31m ❌ ${msg}\x1b[0m`);
}
function warn(msg, detail = null) {
  console.log(`\x1b[33m ⚠️  ${msg}\x1b[0m${detail ? '\x1b[90m – ' + detail + '\x1b[0m' : ''}`);
}
function info(msg) {
  console.log(`\x1b[36m ℹ️  ${msg}\x1b[0m`);
}

module.exports = { doctor };
