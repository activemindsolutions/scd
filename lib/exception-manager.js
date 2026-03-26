/**
 * exception-manager.js
 * Manages exceptions and ignores for scd findings.
 *
 * scd approve --rule <id> --file <path> --line <n> --reason <text>
 *   → Accepted risk: finding is real but justified. Requires team-lead approval via scd-server.
 *
 * scd ignore --rule <id> --file <path> --line <n> --reason <text>
 *   → False positive: finding is not exploitable in this context. Requires approval.
 *
 * Both commands:
 *   1. Write a pending exception to store config.yml (status: pending)
 *   2. Push exception-request to scd-server via push queue
 *
 * scd sync
 *   → Pull approved exceptions from scd-server, update local config.yml
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { CONFIG_FILENAME } = require('./config');
const { logEvent, EVENTS } = require('./audit');

// ── Add exception or ignore ───────────────────────────────────────────────

async function addException(repoRoot, opts, type = 'exception') {
  const { rule, file, line, reason, tag } = opts;

  // Validate required fields
  if (!rule || !file || !line) {
    console.error('\n\x1b[31mUsage: scd approve --rule <id> --file <path> --line <n> --reason <text>\x1b[0m\n');
    process.exit(1);
  }

  if (!reason || !reason.trim()) {
    console.error('\n\x1b[31m❌ --reason is required.\x1b[0m');
    console.error('\x1b[90m   Example: scd approve --rule PY-INJ-001 --file src/db.py --line 68 \\\x1b[0m');
    console.error('\x1b[90m            --reason "PRAGMA uses whitelist-validated table names only"\x1b[0m\n');
    process.exit(1);
  }

  // Validate tag if provided (fritext, max 40 chars, no whitespace)
  const cleanTag = tag ? String(tag).trim().slice(0, 40).replace(/\s+/g, '_') : null;

  const lineNum  = parseInt(line, 10);
  const filePath = path.resolve(repoRoot, file);

  // Hash the triggering line for stale-detection
  let lineContent = null;
  let codeHash    = null;

  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    lineContent = lines[lineNum - 1];
    if (lineContent) {
      codeHash = crypto.createHash('sha256').update(lineContent).digest('hex').slice(0, 16);
      console.log(`\n\x1b[90mLine ${lineNum}: ${lineContent.trim()}\x1b[0m`);
      console.log(`\x1b[90mHash:       ${codeHash}\x1b[0m`);
    }
  } else {
    console.log(`\x1b[33m⚠  File not found locally — exception created without code hash\x1b[0m`);
  }

  const excId   = `exc-${Date.now().toString(36)}`;
  const created = new Date().toISOString().slice(0, 10);

  const exception = {
    id:           excId,
    type,                              // 'exception' | 'ignore'
    tag:          cleanTag,            // optional free-text tag
    rule,
    file:         file.replace(/\\/g, '/'),
    line:         lineNum,
    code_hash:    codeHash,
    reason:       reason.trim(),
    status:       'pending',           // pending until team-lead approves
    created_date: created,
  };

  // Write to store config
  writeException(repoRoot, exception);

  // Push to scd-server via push queue
  pushExceptionToServer(repoRoot, exception);

  // Audit log
  logEvent(repoRoot, 'exception_requested', {
    exception_id: excId,
    type,
    tag:          cleanTag,
    rule,
    file,
    line:         lineNum,
    code_hash:    codeHash,
    reason:       reason.trim(),
  });

  const typeLabel = type === 'ignore' ? 'Ignore' : 'Exception';
  const DIM   = '\x1b[90m';
  const GREEN = '\x1b[32m';
  const RESET = '\x1b[0m';

  console.log(`\n${GREEN}✓ ${typeLabel} ${excId} created${RESET}`);
  console.log(`${DIM}  Status: pending team-lead approval${RESET}`);
  console.log(`${DIM}  Rule:   ${rule}${RESET}`);
  console.log(`${DIM}  File:   ${file}:${lineNum}${RESET}`);
  console.log(`${DIM}  Reason: ${reason.trim()}${RESET}`);
  if (cleanTag) console.log(`${DIM}  Tag:    ${cleanTag}${RESET}`);

  const centralUrl = require('./global-config').getCentralUrl();
  if (centralUrl) {
    console.log(`${DIM}  → Pushed to scd-server for approval${RESET}\n`);
  } else {
    console.log(`${DIM}  ⚠  No scd-server configured — exception is local only${RESET}`);
    console.log(`${DIM}     Run: scd configure --central-url <url>${RESET}\n`);
  }
}

// ── Push exception to scd-server ─────────────────────────────────────────

function pushExceptionToServer(repoRoot, exception) {
  try {
    const { getCentralUrl, getCentralToken } = require('./global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;

    const token = getCentralToken();
    const meta  = require('./push-queue').buildMeta(repoRoot);
    const url   = centralUrl.replace(/\/$/, '') + '/api/v1/exceptions/batch';
    const http  = url.startsWith('https') ? require('https') : require('http');

    const body = JSON.stringify({
      exceptions: [{
        rule_id:   exception.rule,
        file_path: exception.file,
        line:      exception.line,
        code_hash: exception.code_hash,
        type:      exception.type,
        tag:       exception.tag || null,
        reason:    exception.reason,
      }],
      meta,
    });

    // Fire-and-forget — non-blocking, failure is silent
    const parsed = new (require('url').URL)(url);
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (url.startsWith('https') ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization':  `Bearer ${token}`,
      },
    };

    const req = http.request(options, (res) => {
      // Consume response to free socket
      res.resume();
    });
    req.on('error', () => {});
    req.setTimeout(8000, () => req.destroy());
    req.write(body);
    req.end();

  } catch {
    // Non-fatal
  }
}

// ── Write exception to local config ──────────────────────────────────────

function writeException(repoRoot, exception) {
  const configPath = require('./store').configPath(repoRoot);

  let content = '';
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, 'utf8');
  } else {
    content = '# Secure Code by Design – repo configuration\n\ntrust_level: balanced\n\n';
  }

  const block = [
    `  - id: "${exception.id}"`,
    `    type: "${exception.type}"`,
    exception.tag ? `    tag: "${exception.tag}"` : null,
    `    status: "${exception.status}"`,
    `    rule: "${exception.rule}"`,
    `    file: "${exception.file}"`,
    `    line: ${exception.line}`,
    exception.code_hash ? `    code_hash: "${exception.code_hash}"` : null,
    `    reason: "${exception.reason}"`,
    `    created_date: "${exception.created_date}"`,
  ].filter(Boolean).join('\n');

  if (content.includes('exceptions:')) {
    content = content.replace(/exceptions:\s*\n/, `exceptions:\n${block}\n`);
  } else {
    content += `\nexceptions:\n${block}\n`;
  }

  fs.writeFileSync(configPath, content, 'utf8');
}

// ── Sync approved exceptions from scd-server ─────────────────────────────

async function syncExceptions(repoRoot) {
  const { getCentralUrl, getCentralToken } = require('./global-config');
  const centralUrl = getCentralUrl();
  const token      = getCentralToken();

  if (!centralUrl) {
    console.error('\n\x1b[31m❌ No scd-server configured.\x1b[0m');
    console.error('\x1b[90m   Run: scd configure --central-url <url>\x1b[0m\n');
    process.exit(1);
  }

  const store   = require('./store');
  const repoId  = store.getRepoId(repoRoot);
  const http    = centralUrl.startsWith('https') ? require('https') : require('http');
  const url     = new URL(`/api/v1/exceptions/approved?repo_id=${encodeURIComponent(repoId)}`, centralUrl);

  console.log('\n\x1b[36m↓ Syncing approved exceptions from scd-server…\x1b[0m');

  try {
    const approved = await httpGet(http, url.toString(), token);
    const list     = approved.exceptions || [];

    if (list.length === 0) {
      console.log('\x1b[90m  No approved exceptions for this repo.\x1b[0m\n');
      return;
    }

    // Update status in local config for each approved exception
    let updated = 0;
    for (const ex of list) {
      if (updateExceptionStatus(repoRoot, ex.id, 'approved', ex.reviewed_by, ex.review_comment)) {
        updated++;
      }
    }

    const DIM   = '\x1b[90m';
    const GREEN = '\x1b[32m';
    const RESET = '\x1b[0m';

    console.log(`${GREEN}✓ Synced ${list.length} approved exception(s)${RESET}`);
    if (updated > 0) {
      console.log(`${DIM}  ${updated} updated in local config${RESET}`);
    }
    console.log(`${DIM}  These findings will no longer be flagged in scans${RESET}\n`);

  } catch (err) {
    console.error(`\n\x1b[31m❌ Sync failed: ${err.message}\x1b[0m`);
    console.error('\x1b[90m   Check that scd-server is reachable and token is correct\x1b[0m\n');
    process.exit(1);
  }
}

function updateExceptionStatus(repoRoot, excId, status, reviewedBy, comment) {
  const configPath = require('./store').configPath(repoRoot);
  if (!fs.existsSync(configPath)) return false;

  let content = fs.readFileSync(configPath, 'utf8');
  const idPattern = new RegExp(`(  - id: "${excId}"[\\s\\S]*?status: )"[^"]*"`);

  if (!idPattern.test(content)) return false;

  content = content.replace(idPattern, `$1"${status}"`);

  // Add reviewer info if not present
  if (reviewedBy && !content.includes(`reviewed_by: "${reviewedBy}"`)) {
    const entryEnd = new RegExp(`(  - id: "${excId}"[\\s\\S]*?created_date: "[^"]*")`);
    content = content.replace(entryEnd, (m) =>
      m + `\n    reviewed_by: "${reviewedBy}"` +
      (comment ? `\n    review_comment: "${comment.replace(/"/g, '\\"')}"` : '')
    );
  }

  fs.writeFileSync(configPath, content, 'utf8');
  return true;
}

// ── HTTP helper ───────────────────────────────────────────────────────────

function httpGet(http, url, token) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
    };
    const req = http.get(url, opts, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          } else {
            resolve(JSON.parse(data));
          }
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

module.exports = { addException, syncExceptions };
