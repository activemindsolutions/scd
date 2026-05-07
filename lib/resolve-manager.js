const { RESET, BOLD, DIM, GREEN, YELLOW, CYAN } = require('./output-constants');
/**
 * resolve-manager.js
 * Interactive CLI for resolving EXPOSURE-class findings.
 *
 * Unlike exceptions (approve), a resolve means:
 * "We have taken action outside the code to make this safe."
 *
 * Usage: scd resolve --rule FRONT-001 --file src/maps/config.js --line 3
 *
 * Creates a resolution record in ~/.scd/repos/{repoId}/config.yml under `resolutions:`
 * and logs the event to the audit trail.
 */

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { CONFIG_FILENAME, hashLine, EXPOSURE_RULES } = require('./config');
const { logEvent } = require('./audit');

// Import EXPOSURE_RULES for checklist display
let EXPOSURE_RULE_MAP = {};
try {
  const { EXPOSURE_RULES } = require('./scanner-full');
  for (const r of EXPOSURE_RULES) EXPOSURE_RULE_MAP[r.id] = r;
} catch { /* scanner-full may not be loaded yet */ }


async function resolveExposure(repoRoot, opts) {
  const { rule, file, line } = opts;

  if (!rule || !file || !line) {
    console.log(`\nREDUsage: scd resolve --rule <id> --file <path> --line <n>${RESET}`);
    console.log(`${DIM}Example: scd resolve --rule FRONT-001 --file src/maps/config.js --line 3${RESET}\n`);
    process.exit(1);
  }

  const lineNum  = parseInt(line);
  const filePath = path.resolve(repoRoot, file);

  // Show which rule this is
  const ruleInfo = EXPOSURE_RULE_MAP[rule];

  console.log(`\n${CYAN}${BOLD}Secure Code by Design – Resolve EXPOSURE finding${RESET}`);
  console.log(`${'─'.repeat(50)}`);
  console.log(`Regel:  ${rule}${ruleInfo ? ' – ' + ruleInfo.name : ''}`);
  console.log(`Fil:    ${file}:${lineNum}`);

  // Show the actual line
  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    const lineContent = lines[lineNum - 1];
    if (lineContent) {
      console.log(`Kod:    ${DIM}${lineContent.trim()}${RESET}`);
    }
  }

  // Show checklist if available
  if (ruleInfo?.checklist) {
    console.log(`\n${BOLD}Confirm the following is in place:${RESET}`);
    ruleInfo.checklist.forEach((item, i) => {
      console.log(`  ${YELLOW}☐${RESET} ${item}`);
    });
  }

  console.log('');

  // Prompt
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  const action_taken = await ask('Action taken (describe what was done):       ');
  const resolved_by  = await ask('Hanterat av (e-post):                        ');
  const reviewDays   = await ask('Review in (days, Enter = 180):               ');
  rl.close();

  const days        = parseInt(reviewDays) || 180;
  const review_date = new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
  const resId       = `res-${Date.now().toString(36)}`;

  // Read line hash
  let lineHash = null;
  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    const lineContent = lines[lineNum - 1];
    if (lineContent) lineHash = hashLine(lineContent);
  }

  const resolution = {
    id:            resId,
    rule,
    file:          file.replace(/\\/g, '/'),
    line:          lineNum,
    line_hash:     lineHash,
    action_taken:  action_taken.trim(),
    resolved_by:   resolved_by.trim(),
    resolved_date: new Date().toISOString().slice(0, 10),
    review_date,
  };

  writeResolution(repoRoot, resolution);

  logEvent(repoRoot, 'exposure_resolved', {
    resolution_id: resId,
    rule,
    file,
    line:         lineNum,
    action_taken: action_taken.trim(),
    resolved_by:  resolved_by.trim(),
    review_date,
  });

  console.log(`\n${GREEN}${BOLD}✅ Resolution recorded (${resId})${RESET}`);
  console.log(`${DIM}   Review due: ${review_date} (in ${days} days)${RESET}`);
  console.log(`${DIM}   Finding will show as "Resolved" in reports until review is due.${RESET}\n`);
}

function writeResolution(repoRoot, resolution) {
  const configPath = require('./store').configPath(repoRoot);

  let content = '';
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, 'utf8');
  } else {
    content = '# Secure Code by Design configuration\ntrust_level: balanced\n\n';
  }

  const block = `
  - id: "${resolution.id}"
    rule: "${resolution.rule}"
    file: "${resolution.file}"
    line: ${resolution.line}
    line_hash: "${resolution.line_hash || ''}"
    action_taken: "${resolution.action_taken}"
    resolved_by: "${resolution.resolved_by}"
    resolved_date: "${resolution.resolved_date}"
    review_date: "${resolution.review_date}"`;

  if (content.includes('\nresolutions:')) {
    content = content.replace(/\nresolutions:\n/, `\nresolutions:\n${block}\n`);
  } else {
    content += `\nresolutions:${block}\n`;
  }

  fs.writeFileSync(configPath, content);
}

module.exports = { resolveExposure };
