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
  console.log(`\x1b[32m✅ Hooks-mapp skapad:\x1b[0m ${HOOKS_DIR}`);

  // 2. Write hook files
  const preCommitPath = path.join(HOOKS_DIR, 'pre-commit');
  const prePushPath   = path.join(HOOKS_DIR, 'pre-push');

  fs.writeFileSync(preCommitPath, PRE_COMMIT_HOOK, { mode: 0o755 });
  fs.writeFileSync(prePushPath,   PRE_PUSH_HOOK,   { mode: 0o755 });
  console.log(`\x1b[32m✅ pre-commit hook installerad\x1b[0m (secrets-scanning)`);
  console.log(`\x1b[32m✅ pre-push hook installerad\x1b[0m (fullständig scanning)`);

  // 3. Configure git to use our hooks globally
  try {
    execSync(`git config --global core.hooksPath "${HOOKS_DIR}"`, { encoding: 'utf8' });
    console.log(`\x1b[32m✅ Git konfigurerad\x1b[0m (core.hooksPath → ${HOOKS_DIR})`);
  } catch (err) {
    console.error('\x1b[31m❌ Kunde inte konfigurera git:\x1b[0m', err.message);
    console.log('\x1b[33m   Kör manuellt:\x1b[0m git config --global core.hooksPath "' + HOOKS_DIR + '"');
  }

  console.log('\n\x1b[32m\x1b[1m Installation klar!\x1b[0m');
  console.log('\x1b[90m Alla git-repos på den här datorn är nu skyddade.\x1b[0m\n');
}

module.exports = { install };
