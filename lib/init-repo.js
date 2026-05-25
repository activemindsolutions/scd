/**
 * init-repo.js
 * Initialises Secure Code by Design for a specific git repo.
 *
 * scd init  – run once per repo, once per developer
 *
 * What it does:
 *   1. Creates ~/.scd/repos/{repoId}/config.yml with defaults
 *   2. Installs git hooks (pre-commit, pre-push) into .git/hooks/
 *
 * What it does NOT do:
 *   - Write any files into the repo itself
 *   - Modify .gitignore
 *   - Commit anything
 *
 * The repo remains completely untouched.
 */

'use strict';
const { RESET, BOLD, DIM, GREEN, YELLOW, CYAN } = require('./output-constants');

const fs    = require('fs');
const path  = require('path');
const os    = require('os');
const store = require('./store');
const { getRepoRoot } = require('./config');


const DEFAULT_CONFIG = `# ═══════════════════════════════════════════════════════════════
# Secure Code by Design – Per-repo configuration
# Stored in ~/.scd/repos/{repoId}/config.yml
# Never committed to the repository.
#
# Edit with: scd repo configure --<option> <value>
# View with: scd repo configure --show
# ═══════════════════════════════════════════════════════════════

# ── Trust level ──────────────────────────────────────────────────
# Controls what is sent to AI analysis (scd scan --deep)
# maximum_privacy  – Everything runs locally, nothing sent externally
# balanced         – Default. Anonymised patterns sent for deep analysis
# maximum_analysis – Full AI analysis via Claude API
trust_level: balanced

# ── Scan mode ────────────────────────────────────────────────────
# full (default) – All rules including taint analysis
# fast           – Regex rules only, no taint analysis.
#                  Use for large codebases (800+ files) where scan time is a concern.
scan_mode: full

# ── Blocking behaviour ───────────────────────────────────────────
# CRITICAL always blocks commit/push (cannot be disabled)
# HIGH blocks push by default – set to false to warn only
block_on_critical: true
block_on_high: true

# ── Rule overrides ───────────────────────────────────────────────
# Change action for specific rules: block | warn | report
#
# Hardlocked rules (can NEVER be downgraded):
#   SECRET-001 (AWS), SECRET-002 (OpenAI), SECRET-003 (GitHub),
#   SECRET-006 (PEM), SECRET-007 (JWT secrets), JWT-001
#
# rule_overrides:
#   SECRET-005:
#     action: warn
#     reason: "Test environment"

# ── Exceptions ───────────────────────────────────────────────────
# For findings that are conscious, documented decisions.
# Create interactively: scd accept <finding-id> --reason "..."
#
# exceptions:
#   - id: "exc-001"
#     rule: "FRONT-001"
#     file: "src/maps/mapbox-config.js"
#     line_range: [12, 12]
#     line_hash: "sha256:a3f9b2c1d4e5f6a7"
#     reason: "Mapbox public token – domain restriction enabled in Mapbox dashboard"
#     approved_by: "cto@company.com"
#     approved_date: "2026-03-01"
#     expires: "2026-09-01"

# ── Resolutions (EXPOSURE findings) ─────────────────────────────
# For EXPOSURE findings handled at the service level.
# Create interactively: scd resolve --rule <id> --file <f> --line <n>
#
# resolutions:
#   - id: "res-abc123"
#     rule: "FRONT-002"
#     file: "src/config/maps.js"
#     line: 3
#     line_hash: "sha256:b4c8d2e1f5a9"
#     action_taken: "HTTP referrer restriction enabled in Google Cloud Console"
#     resolved_by: "dev@company.com"
#     resolved_date: "2026-03-01"
#     review_date: "2026-09-01"
`;

async function initRepo(repoRoot) {
  const storeDir   = store.storeDir(repoRoot);
  const configPath = store.configPath(repoRoot);

  console.log(`\n${CYAN}${BOLD}Secure Code by Design – Initialising repo${RESET}`);
  console.log(`${'─'.repeat(45)}`);
  console.log(`${DIM}Repo:  ${repoRoot}${RESET}`);
  console.log(`${DIM}Store: ${storeDir}${RESET}\n`);

  store.updateMeta(repoRoot);

  // Config
  if (fs.existsSync(configPath)) {
    console.log(`${YELLOW}⚠️  Config already exists – not overwritten${RESET}`);
    console.log(`${DIM}   ${configPath}${RESET}`);
    console.log(`${DIM}   Delete it manually to re-initialise.${RESET}\n`);
  } else {
    fs.writeFileSync(configPath, DEFAULT_CONFIG, 'utf8');
    console.log(`${GREEN}✓ Config created${RESET}`);
    console.log(`${DIM}  ${configPath}${RESET}`);
  }

  // Check if global hooks are installed — check files directly, not via getHookStatus()
  // which requires a git repo context and returns 'not-a-git-repo' outside one.
  const { execSync } = require('child_process');
  const HOOKS_DIR = path.join(os.homedir(), '.scd', 'hooks');
  const hooksFilesExist = fs.existsSync(path.join(HOOKS_DIR, 'pre-commit')) &&
                          fs.existsSync(path.join(HOOKS_DIR, 'pre-push'));
  let globalHooksPath = null;
  try {
    globalHooksPath = execSync('git config --global core.hooksPath', { encoding: 'utf8' }).trim();
  } catch { /* not set */ }
  const hooksOk = hooksFilesExist && !!globalHooksPath;

  console.log(`\n${BOLD}Next steps:${RESET}`);
  let step = 1;
  if (!hooksOk) {
    console.log(`  ${DIM}${step++}.${RESET} Run ${CYAN}scd install${RESET} to install global git hooks ${YELLOW}(not done yet)${RESET}`);
  }
  console.log(`  ${DIM}${step++}.${RESET} Review and adjust the config if needed`);
  console.log(`  ${DIM}${step++}.${RESET} Run ${DIM}scd doctor${RESET} to verify the installation`);
  console.log(`  ${DIM}${step++}.${RESET} Run ${DIM}scd scan${RESET} to do your first scan\n`);

  console.log(`${DIM}Note: nothing has been written to your repository.${RESET}`);
  console.log(`${DIM}      All data is stored in ${storeDir}${RESET}\n`);
}

module.exports = { initRepo };
