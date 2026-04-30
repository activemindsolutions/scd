/**
 * installer.js
 * Sets up global git hooks that point to the CLI agent.
 *
 * After install, ALL repos on this machine are protected automatically.
 * Uses git config --global core.hooksPath
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOKS_DIR = path.join(os.homedir(), '.scd', 'hooks');
const CLI_PATH = path.resolve(__dirname, '../bin/scd.js');

const PRE_COMMIT_HOOK = `#!/bin/sh
# Secure Code by Design – pre-commit hook
# Scans for secrets BEFORE they enter git history
# Installed by: scd install

node "${CLI_PATH}" scan --hook=pre-commit
exit $?
`;

const PRE_PUSH_HOOK = `#!/bin/sh
# Secure Code by Design – pre-push hook
# Full security scan before code leaves this machine
# Installed by: scd install

node "${CLI_PATH}" scan --hook=pre-push
exit $?
`;

async function install() {
  console.log('\n\x1b[36m Secure Code by Design – Installation\x1b[0m\n');

  // 1. Create hooks directory
  fs.mkdirSync(HOOKS_DIR, { recursive: true });
  console.log(`\x1b[32m✅ Hooks directory created:\x1b[0m ${HOOKS_DIR}`);

  // 2. Write hook files
  const preCommitPath = path.join(HOOKS_DIR, 'pre-commit');
  const prePushPath   = path.join(HOOKS_DIR, 'pre-push');

  fs.writeFileSync(preCommitPath, PRE_COMMIT_HOOK, { mode: 0o755 });
  fs.writeFileSync(prePushPath,   PRE_PUSH_HOOK,   { mode: 0o755 });
  console.log(`\x1b[32m✅ pre-commit hook installed\x1b[0m (secrets scanning)`);
  console.log(`\x1b[32m✅ pre-push hook installed\x1b[0m (full OWASP scan)`);

  // 3. Configure git to use our hooks globally
  try {
    execSync(`git config --global core.hooksPath "${HOOKS_DIR}"`, { encoding: 'utf8' });
    console.log(`\x1b[32m✅ Git configured\x1b[0m (core.hooksPath → ${HOOKS_DIR})`);
  } catch (err) {
    console.error('\x1b[31m❌ Kunde inte konfigurera git:\x1b[0m', err.message);
    console.log('\x1b[33m   Run manually:\x1b[0m git config --global core.hooksPath "' + HOOKS_DIR + '"');
  }

  console.log('\n\x1b[32m\x1b[1m Installation complete!\x1b[0m');
  console.log('\x1b[90m All git repos on this machine are now protected.\x1b[0m');
  console.log('');
  console.log('\x1b[90m By using scd you agree to the disclaimer at:\x1b[0m');
  console.log('\x1b[90m https://github.com/activemindsolutions/scd/blob/main/DISCLAIMER.md\x1b[0m');
  console.log('\x1b[90m scd is a static analysis aid — it does not replace penetration testing.\x1b[0m\n');
}

async function uninstall() {
  const CYAN  = '\x1b[36m';
  const GREEN = '\x1b[32m';
  const RED   = '\x1b[31m';
  const DIM   = '\x1b[90m';
  const RESET = '\x1b[0m';
  const BOLD  = '\x1b[1m';

  console.log(`\n${CYAN} Secure Code by Design – Uninstall${RESET}\n`);

  let anyAction = false;

  // 1. Remove hook files
  const preCommitPath = path.join(HOOKS_DIR, 'pre-commit');
  const prePushPath   = path.join(HOOKS_DIR, 'pre-push');
  let hooksRemoved = false;
  for (const p of [preCommitPath, prePushPath]) {
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
      hooksRemoved = true;
    }
  }
  if (hooksRemoved) {
    console.log(`${GREEN}✅ Hook files removed${RESET}`);
    anyAction = true;
  } else {
    console.log(`${DIM}   No hook files found — skipping${RESET}`);
  }

  // 2. Remove hooks directory if empty
  if (fs.existsSync(HOOKS_DIR)) {
    const remaining = fs.readdirSync(HOOKS_DIR);
    if (remaining.length === 0) {
      fs.rmdirSync(HOOKS_DIR);
      console.log(`${GREEN}✅ Hooks directory removed${RESET} (${HOOKS_DIR})`);
    } else {
      console.log(`${DIM}   Hooks directory not empty — left in place${RESET} (${HOOKS_DIR})`);
    }
    anyAction = true;
  }

  // 3. Remove global git core.hooksPath
  try {
    const current = execSync('git config --global core.hooksPath', { encoding: 'utf8' }).trim();
    if (current) {
      execSync('git config --global --unset core.hooksPath', { encoding: 'utf8' });
      console.log(`${GREEN}✅ Global git core.hooksPath removed${RESET}`);
      anyAction = true;
    }
  } catch (_) {
    // Not set — nothing to do
    console.log(`${DIM}   No global core.hooksPath configured — skipping${RESET}`);
  }

  // 4. Leave ~/.scd/ store intact — user data (scans, audit log, exceptions)
  console.log(`${DIM}   ~/.scd/ store preserved — your scan history and exceptions are kept${RESET}`);
  console.log(`${DIM}   Remove manually with: rm -rf ~/.scd${RESET}`);

  console.log(`\n${GREEN}${BOLD} Uninstall complete!${RESET}`);
  if (anyAction) {
    console.log(`${DIM} Git hooks are no longer active on this machine.${RESET}`);
    console.log(`${DIM} Run ${RESET}scd install${DIM} to re-enable.${RESET}\n`);
  }
}

module.exports = { install, uninstall };
