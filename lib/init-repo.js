/**
 * init-repo.js
 * Initialises Security Co-Pilot for a specific git repo.
 *
 * sc init  – run once per repo, once per developer
 *
 * What it does:
 *   1. Creates ~/.security-copilot/repos/{repoId}/config.yml with defaults
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

const fs    = require('fs');
const path  = require('path');
const store = require('./store');
const { getRepoRoot } = require('./config');

const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const BOLD   = '\x1b[1m';
const DIM    = '\x1b[90m';
const RESET  = '\x1b[0m';

const DEFAULT_CONFIG = `# ═══════════════════════════════════════════════════════════════
# Security Co-Pilot – Per-repo configuration
# Stored in ~/.security-copilot/repos/{repoId}/config.yml
# Never committed to the repository.
# ═══════════════════════════════════════════════════════════════

# ── Trust level ──────────────────────────────────────────────────
# maximum_privacy  – Everything runs locally, no code sent externally
# balanced         – Default. Anonymised patterns for deep analysis
# maximum_analysis – Full AI analysis via Claude API
trust_level: balanced

# Which AI coding tool is used in this project? (informational)
# claude_code | copilot | cursor | none
ai_coding_tool: none

# ── Blocking behaviour ───────────────────────────────────────────
# CRITICAL always blocks commit/push (cannot be disabled)
block_on_critical: true
block_on_high: true
report_all: true

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
# Create interactively: sc approve --rule <id> --file <f> --line <n>
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
# Create interactively: sc resolve --rule <id> --file <f> --line <n>
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

  console.log(`\n${CYAN}${BOLD}Security Co-Pilot – Initialising repo${RESET}`);
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

  console.log(`\n${BOLD}Next steps:${RESET}`);
  console.log(`  ${DIM}1.${RESET} Review and adjust the config if needed`);
  console.log(`  ${DIM}2.${RESET} Run ${DIM}sc doctor${RESET} to verify the installation`);
  console.log(`  ${DIM}3.${RESET} Run ${DIM}sc scan${RESET} to do your first scan\n`);

  console.log(`${DIM}Note: nothing has been written to your repository.${RESET}`);
  console.log(`${DIM}      All data is stored in ${storeDir}${RESET}\n`);
}

module.exports = { initRepo };
