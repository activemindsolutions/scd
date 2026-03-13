/**
 * exception-manager.js
 * Interactive CLI for adding config-based exceptions.
 *
 * Usage: security-copilot approve --rule FRONT-001 --file src/maps/config.js --line 12
 *
 * Reads the actual file, hashes the line, prompts for reason + approver,
 * then writes the exception to .securityagent.yml.
 */

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { hashLine, CONFIG_FILENAME } = require('./config');
const { logEvent, EVENTS } = require('./audit');

async function addException(repoRoot, opts) {
  const { rule, file, line } = opts;

  if (!rule || !file || !line) {
    console.log('\n\x1b[31mAnvändning: security-copilot approve --rule <id> --file <path> --line <n>\x1b[0m\n');
    process.exit(1);
  }

  const lineNum  = parseInt(line);
  const filePath = path.resolve(repoRoot, file);

  // Read the actual line from file
  let lineContent = null;
  let lineHash    = null;

  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    lineContent = lines[lineNum - 1];
    if (lineContent) {
      lineHash = hashLine(lineContent);
      console.log(`\n\x1b[90mRad ${lineNum}: ${lineContent.trim()}\x1b[0m`);
      console.log(`\x1b[90mHash:      ${lineHash}\x1b[0m\n`);
    }
  } else {
    console.log(`\x1b[33mFil hittades inte lokalt – undantag skapas utan hash\x1b[0m`);
  }

  // Prompt for details
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise(resolve => rl.question(q, resolve));

  console.log('\x1b[36mLägg till undantag i .securityagent.yml\x1b[0m');
  console.log('─'.repeat(45));

  const reason      = await ask('Motivering (varför är detta undantaget?): ');
  const approvedBy  = await ask('Godkänt av (e-post):                      ');
  const expiresIn   = await ask('Granskas om (dagar, Enter = 90):          ');
  rl.close();

  const days    = parseInt(expiresIn) || 90;
  const expires = new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
  const excId   = `exc-${Date.now().toString(36)}`;

  const exception = {
    id:            excId,
    rule,
    file:          file.replace(/\\/g, '/'),
    line_range:    [lineNum, lineNum],
    line_hash:     lineHash,
    reason:        reason.trim(),
    approved_by:   approvedBy.trim(),
    approved_date: new Date().toISOString().slice(0, 10),
    expires,
  };

  // Write to config
  writeException(repoRoot, exception);

  // Audit log
  logEvent(repoRoot, 'exception_added', {
    exception_id:  excId,
    rule,
    file,
    line:          lineNum,
    line_hash:     lineHash,
    reason:        reason.trim(),
    approved_by:   approvedBy.trim(),
    expires,
  });

  console.log(`\n\x1b[32m✅ Undantag ${excId} tillagt i .securityagent.yml\x1b[0m`);
  console.log(`\x1b[90m   Granskas: ${expires} (om ${days} dagar)\x1b[0m\n`);
}

function writeException(repoRoot, exception) {
  const configPath = require('./store').configPath(repoRoot);

  // Read existing config or create minimal one
  let content = '';
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, 'utf8');
  } else {
    content = '# Security Copilot configuration\n# https://github.com/your-org/security-copilot\n\ntrust_level: balanced\n\n';
  }

  // Build exception YAML block
  const block = `
  - id: "${exception.id}"
    rule: "${exception.rule}"
    file: "${exception.file}"
    line_range: [${exception.line_range[0]}, ${exception.line_range[1]}]
    line_hash: "${exception.line_hash || ''}"
    reason: "${exception.reason}"
    approved_by: "${exception.approved_by}"
    approved_date: "${exception.approved_date}"
    expires: "${exception.expires}"`;

  // Append to exceptions section or create it
  if (content.includes('exceptions:')) {
    content = content.replace(/exceptions:\s*\n/, `exceptions:\n${block}\n`);
  } else {
    content += `\nexceptions:${block}\n`;
  }

  fs.writeFileSync(configPath, content);
}

module.exports = { addException };
