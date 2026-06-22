const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('./output-constants');
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
  console.log('\n' + CYAN + 'Secure Code by Design – Installation' + RESET + '\n');

  // 1. Create hooks directory
  fs.mkdirSync(HOOKS_DIR, { recursive: true });
  console.log(`${GREEN}✅ Hooks directory created:${RESET} ${HOOKS_DIR}`);

  // 2. Write hook files
  const preCommitPath = path.join(HOOKS_DIR, 'pre-commit');
  const prePushPath   = path.join(HOOKS_DIR, 'pre-push');

  fs.writeFileSync(preCommitPath, PRE_COMMIT_HOOK, { mode: 0o755 });
  fs.writeFileSync(prePushPath,   PRE_PUSH_HOOK,   { mode: 0o755 });
  console.log(`${GREEN}✅ pre-commit hook installed${RESET} (secrets scanning)`);
  console.log(`${GREEN}✅ pre-push hook installed${RESET} (full OWASP scan)`);

  // 3. Configure git to use our hooks globally
  try {
    execSync(`git config --global core.hooksPath "${HOOKS_DIR}"`, { encoding: 'utf8' });
    console.log(`${GREEN}✅ Git configuredRESET (core.hooksPath → ${HOOKS_DIR})`);
  } catch (err) {
    console.error(RED + '❌ Kunde inte konfigurera git:' + RESET, err.message);
    console.log(YELLOW + '   Run manually:' + RESET + ' git config --global core.hooksPath "' + HOOKS_DIR + '"');
  }

  console.log('\n' + GREEN + BOLD + 'Installation complete!' + RESET);
  console.log(DIM + ' All git repos on this machine are now protected.' + RESET);
  console.log('');
  console.log(DIM + ' By using scd you agree to the disclaimer at:' + RESET);
  console.log(DIM + ' https://github.com/activemindsolutions/scd/blob/main/DISCLAIMER.md' + RESET);
  console.log(DIM + ' scd is a static analysis aid — it does not replace penetration testing.' + RESET + '\n');
}

async function uninstall() {

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
