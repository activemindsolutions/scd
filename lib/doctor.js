/**
 * doctor.js
 * Checks that hooks are active, up to date, and working.
 * Maps to "Lager 1 – Teknisk självkontroll" in the architecture.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOKS_DIR = path.join(os.homedir(), '.security-copilot', 'hooks');

async function doctor() {
  console.log('\n\x1b[36m Security Copilot – Systemkontroll\x1b[0m\n');

  let allOk = true;

  // 1. Check global hooks path
  try {
    const hooksPath = execSync('git config --global core.hooksPath', { encoding: 'utf8' }).trim();
    if (hooksPath === HOOKS_DIR) {
      ok('Global hooks konfigurerad', hooksPath);
    } else {
      warn('Global hooks pekar på annan mapp', hooksPath);
    }
  } catch {
    fail('Global hooks EJ konfigurerad');
    console.log('\x1b[90m    Kör: security-copilot install\x1b[0m');
    allOk = false;
  }

  // 2. Check hook files exist and are executable
  for (const hook of ['pre-commit', 'pre-push']) {
    const hookPath = path.join(HOOKS_DIR, hook);
    if (fs.existsSync(hookPath)) {
      try {
        fs.accessSync(hookPath, fs.constants.X_OK);
        ok(`${hook} hook aktiv`);
      } catch {
        fail(`${hook} hook finns men är inte exekverbar`);
        console.log(`\x1b[90m    Kör: chmod +x ${hookPath}\x1b[0m`);
        allOk = false;
      }
    } else {
      fail(`${hook} hook saknas`);
      allOk = false;
    }
  }

  // 3. Check current repo (if in one)
  try {
    const repoRoot = execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
    ok('Befinner sig i git-repo', repoRoot);

    // Check if local hooks would override global
    const localHooksDir = path.join(repoRoot, '.git', 'hooks');
    const localPrePush = path.join(localHooksDir, 'pre-push');
    if (fs.existsSync(localPrePush)) {
      const content = fs.readFileSync(localPrePush, 'utf8');
      if (!content.includes('security-copilot')) {
        warn('Lokalt pre-push hook hittad som inte är Security Copilot', localPrePush);
        console.log('\x1b[90m    Lokala hooks åsidosätter globala. Kontrollera att era hooks samverkar.\x1b[0m');
      }
    }
  } catch {
    info('Inte i ett git-repo');
  }

  // 4. Summary
  console.log('');
  if (allOk) {
    console.log('\x1b[32m\x1b[1m ✅ Allt ser bra ut!\x1b[0m');
  } else {
    console.log('\x1b[31m\x1b[1m ⚠️  Åtgärder krävs (se ovan)\x1b[0m');
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
