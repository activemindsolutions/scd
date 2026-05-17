/**
 * exception-manager.js
 * Manages exceptions and ignores for scd findings.
 *
 * scd accept <findingId> --reason <text>
 *   → Accepted risk: finding is real but justified. Requires team-lead approval via scd-server.
 *
 * scd ignore <findingId> --reason <text>
 *   → False positive / ignore: finding not exploitable in this context. Requires approval.
 *
 * Both commands:
 *   1. Resolve findingId (f-{8hex}) from last scan cache
 *   2. Write a pending exception to store config.yml (status: pending)
 *   3. Push exception-request to scd-server via push queue
 *
 * scd sync
 *   → Pull approved/rejected exceptions from scd-server, update local config.yml
 */

'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW } = require('./output-constants');

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { CONFIG_FILENAME } = require('./config');
const { logEvent, EVENTS } = require('./audit');

// ── stdin prompt helper ───────────────────────────────────────────────────
function prompt(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.once('data', data => {
      process.stdin.pause();
      resolve(data.toString().trim());
    });
  });
}

// ── Add exception by finding ID (new primary API) ────────────────────────

/**
 * Add exception or ignore by finding ID (f-{8hex}).
 * Looks up the finding in the last scan cache, then delegates to addException.
 * This is the primary entry point from CLI commands.
 */
async function addExceptionById(repoRoot, findingId, opts, type = 'exception') {

  if (!findingId) {
    const cmd = type === 'ignore' ? 'ignore' : 'accept';
    console.error(`\n${RED}❌ Finding ID required.${RESET}`);
    console.error(`${DIM}   Usage: scd ${cmd} <finding-id> --reason "..."${RESET}`);
    console.error(`${DIM}   Finding IDs are shown in scd scan --verbose output (e.g. f-20eb992e1f)${RESET}\n`);
    process.exit(1);
  }

  if (!findingId.startsWith('f-') || findingId.length !== 12) {
    console.error(`\n${RED}❌ Invalid finding ID: ${findingId}${RESET}`);
    console.error(`${DIM}   Finding IDs look like: f-20eb992e1f (shown in scd scan --verbose)${RESET}\n`);
    process.exit(1);
  }

  if (!opts.reason || !opts.reason.trim()) {
    console.error(`\n${RED}❌ --reason is required.${RESET}`);
    const cmd = type === 'ignore' ? 'ignore' : 'accept';
    console.error(`${DIM}   Example: scd ${cmd} ${findingId} --reason "Not exploitable in this context"${RESET}\n`);
    process.exit(1);
  }

  // Load finding from last scan cache
  const { loadCache } = require('./scan-cache');
  const cache = loadCache(repoRoot);
  const findings = cache?.findings || [];

  const finding = findings.find(f => f.findingId === findingId || f.codeHash?.startsWith(findingId.slice(2)));

  if (!finding) {
    console.error(`\n${RED}❌ Finding ${findingId} not found in last scan.${RESET}`);
    console.error(`${DIM}   Run scd scan --verbose to see finding IDs, then re-run this command.${RESET}\n`);
    process.exit(1);
  }

  // Check for duplicate — same finding already has a pending/approved exception
  const { loadConfig } = require('./config');
  const config = loadConfig(repoRoot);
  const exceptions = config.exceptions || [];
  const existing = exceptions.find(e =>
    e.rule === finding.ruleId &&
    e.file === finding.filePath &&
    e.line === finding.line &&
    (e.status === 'pending' || e.status === 'approved')
  );

  if (existing) {
    console.log(`\n${YELLOW}⚠  A ${existing.status} exception already exists for this finding.${RESET}`);
    console.log(`${DIM}   ID: ${existing.id}  Status: ${existing.status}  Type: ${existing.type}${RESET}`);
    const answer = await prompt('   Create another exception anyway? [y/N] ');
    if (!answer.trim().toLowerCase().startsWith('y')) {
      console.log(`${DIM}   Aborted.${RESET}\n`);
      process.exit(0);
    }
  }

  // Delegate to addException with resolved fields including the finding's codeHash
  await addException(repoRoot, {
    rule:      finding.ruleId,
    file:      finding.filePath,
    line:      String(finding.line),
    reason:    opts.reason,
    tag:       opts.tag,
    codeHash:  finding.codeHash || null,   // pass through — do not recompute
  }, type);
}

// ── Add exception or ignore ───────────────────────────────────────────────

async function addException(repoRoot, opts, type = 'exception') {
  const { rule, file, line, reason, tag } = opts;

  // Validate required fields
  if (!rule || !file || !line) {
    console.error('\n' + RED + 'Usage: scd approve --rule <id> --file <path> --line <n> --reason <text>' + RESET + '\n');
    process.exit(1);
  }

  if (!reason || !reason.trim()) {
    console.error('\nRED❌ --reason is required.' + RESET);
    console.error(DIM + '   Example: scd approve --rule PY-INJ-001 --file src/db.py --line 68 \\' + RESET);
    console.error(DIM + '            --reason "PRAGMA uses whitelist-validated table names only"' + RESET + '\n');
    process.exit(1);
  }

  // Validate tag if provided (fritext, max 40 chars, no whitespace)
  const cleanTag = tag ? String(tag).trim().slice(0, 40).replace(/\s+/g, '_') : null;

  const lineNum  = parseInt(line, 10);
  const filePath = path.resolve(repoRoot, file);

  // Hash the triggering line for stale-detection
  let lineContent   = null;
  let codeHash      = opts.codeHash || null;  // prefer hash from finding (32-char, matches scanner)
  let codeHashValid = !!codeHash;

  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    lineContent = lines[lineNum - 1];
    if (lineContent) {
      if (!codeHash) {
        // Fallback: recompute from file (used when called directly, not via addExceptionById)
        codeHash = crypto.createHash('sha256').update(lineContent).digest('hex').slice(0, 32);
        codeHashValid = true;
      }
      console.log(`\nDIMLine ${lineNum}: ${lineContent.trim()}${RESET}`);
      console.log(`DIMHash:       ${codeHash}${RESET}`);
    }
  } else {
    console.log(`\nYELLOW⚠  File not found: ${file}${RESET}`);
    console.log(`${DIM}   Exception will be created without code hash.${RESET}`);
    console.log(`${DIM}   This means it matches ANY occurrence of ${rule} in that file — not just line ${lineNum}.${RESET}\n`);

    const answer = await prompt('   Continue anyway? [y/N] ');
    if (!answer.trim().toLowerCase().startsWith('y')) {
      console.log(DIM + '   Aborted.' + RESET + '\n');
      process.exit(0);
    }
  }

  const { getCentralUrl } = require('./global-config');
  const isStandalone = !getCentralUrl();

  const excId   = `exc-${Date.now().toString(36)}`;
  const created = new Date().toISOString().slice(0, 10);

  const exception = {
    id:           excId,
    type,                              // 'exception' | 'ignore'
    tag:          cleanTag,            // optional free-text tag
    rule,
    file:         file.replace(/\\/g, '/'),
    line:         lineNum,
    code_hash:       codeHash,
    code_hash_valid: codeHashValid,
    reason:       reason.trim(),
    status:       isStandalone ? 'approved' : 'pending',
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

  console.log(`\n${GREEN}✓ ${typeLabel} ${excId} created${RESET}`);
  if (isStandalone) {
    console.log(`${DIM}  Status: approved locally${RESET}`);
    console.log(`${DIM}  (No scd-server configured — exception takes effect immediately)${RESET}`);
  } else {
    console.log(`${DIM}  Status: pending team-lead approval${RESET}`);
    console.log(`${DIM}  → Pushed to scd-server for approval${RESET}`);
  }
  console.log(`${DIM}  Rule:   ${rule}${RESET}`);
  console.log(`${DIM}  File:   ${file}:${lineNum}${RESET}`);
  console.log(`${DIM}  Reason: ${reason.trim()}${RESET}`);
  if (cleanTag) console.log(`${DIM}  Tag:    ${cleanTag}${RESET}`);
  console.log();
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
    // line_hash only written when content was actually hashed (not for secrets rules that redact lineRaw)
    exception.code_hash && exception.code_hash_valid ? `    line_hash: "${exception.code_hash}"` : null,
    `    reason: "${exception.reason}"`,
    `    created_date: "${exception.created_date}"`,
  ].filter(Boolean).join('\n');

  // Check for an active (non-commented) exceptions: section
  if (/^exceptions:\s*$/m.test(content)) {
    content = content.replace(/^exceptions:\s*$/m, `exceptions:\n${block}`);
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
    console.error('\nRED❌ No scd-server configured.' + RESET);
    console.error(DIM + '   Run: scd configure --central-url <url>' + RESET + '\n');
    process.exit(1);
  }

  const store  = require('./store');
  const repoId = store.getRepoId(repoRoot);
  const http   = centralUrl.startsWith('https') ? require('https') : require('http');

  console.log('\nCYAN↓ Syncing exceptions from scd-server…' + RESET);

  try {
    // Fetch approved
    const approvedUrl = new URL(`/api/v1/exceptions/approved?repo_id=${encodeURIComponent(repoId)}`, centralUrl);
    const approved    = await httpGet(http, approvedUrl.toString(), token);
    const list        = approved.exceptions || [];

    // Also check for rejected so we can notify the developer
    const rejectedUrl = new URL(`/api/v1/exceptions/approved?repo_id=${encodeURIComponent(repoId)}&status=rejected`, centralUrl);
    let   rejected    = [];
    try {
      const rData = await httpGet(http, rejectedUrl.toString(), token);
        rejected = rData.exceptions || [];
    } catch { /* non-fatal — server may not support status filter */ }

    if (list.length === 0 && rejected.length === 0) {
      console.log(`${DIM}  No approved or rejected exceptions for this repo.${RESET}\n`);
      return;
    }

    // Apply approved exceptions locally — also updates pending exceptions that have now been reviewed
    let applied = 0;
    let skipped = 0;
    for (const ex of list) {
      const updated = updateExceptionStatus(repoRoot, ex, 'approved', ex.reviewed_by, ex.review_comment);
      if (updated) applied++;
      else         skipped++;
    }

    if (list.length > 0) {
      console.log(`${GREEN}✓ ${list.length} approved exception(s)${RESET}`);
      if (applied > 0) console.log(`${DIM}  ${applied} applied to local config — findings will no longer be flagged${RESET}`);
      if (skipped > 0) console.log(`${DIM}  ${skipped} already up to date${RESET}`);
    }

    // Show rejected so developer knows to fix the finding
    if (rejected.length > 0) {
      console.log(`\n${YELLOW}⚠  ${rejected.length} rejected exception(s) — these findings need to be fixed:${RESET}`);
      for (const ex of rejected) {
        console.log(`${DIM}  ${ex.rule_id}  ${ex.file_path}${ex.line ? ':' + ex.line : ''}${RESET}`);
        if (ex.review_comment) {
          console.log(`${DIM}  Reason: ${ex.review_comment}${RESET}`);
        }
            // Mark as rejected locally
        updateExceptionStatus(repoRoot, ex, 'rejected', ex.reviewed_by, ex.review_comment);
      }
    }

    // Update lastSynced timestamp and store handled IDs in meta.json
    // so getSyncNotice can exclude them even if they were never in local config
    const { updateLastSynced } = require('./store');
    const handledIds = [
      ...list.map(e => e.id),
      ...rejected.map(e => e.id),
    ];
    updateLastSynced(repoRoot, handledIds);

    console.log('');

  } catch (err) {
    // Detect server license invalid — show actionable message, not raw JSON
    const msg = err.message || '';
    if (msg.includes('HTTP 503') && msg.includes('License invalid')) {
      console.error('\nYELLOW⚠  Server license invalid — exceptions cannot be synced.' + RESET);
      console.error(DIM + '   Contact your local scd-server administrator to resolve this.' + RESET + '\n');
    } else {
      console.error(`\nRED❌ Sync failed: ${err.message}${RESET}`);
      console.error(DIM + '   Check that scd-server is reachable and token is correctRESET\n');
    }
    process.exit(1);
  }
}

function updateExceptionStatus(repoRoot, serverEx, status, reviewedBy, comment) {
  const configPath = require('./store').configPath(repoRoot);
  if (!fs.existsSync(configPath)) return false;

  const lines = fs.readFileSync(configPath, 'utf8').split('\n');

  // Find the entry by scanning line by line
  // Match by CLI id first, then fall back to rule+file+line
  let firstLine = -1;
  let lastLine  = -1;

  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].startsWith('  - id: "')) continue;

    // Check if this is our entry
    const excId = serverEx.id || '';
    const isById = excId && lines[i].includes(`  - id: "${excId}"`);

    // Look ahead to collect ALL lines belonging to this entry
    // An entry ends at the next '  - id:' line, a blank line, or end of file
    // BUT we must include reviewer lines that may have been appended
    let j = i + 1;
    const entryLines = [lines[i]];
    while (j < lines.length && !lines[j].startsWith('  - id: "') && lines[j].trim() !== '') {
      entryLines.push(lines[j]);
      j++;
    }
    const entryText = entryLines.join('\n');

    const isByRuleLine = !isById && serverEx.rule_id && serverEx.file_path
      && entryText.includes(`rule: "${serverEx.rule_id}"`)
      && entryText.includes(`file: "${serverEx.file_path}"`)
      && (!serverEx.line || entryText.includes(`line: ${serverEx.line}`));

    if (isById || isByRuleLine) {
      firstLine = i;
      lastLine  = j - 1;
      break;
    }
  }

  if (firstLine === -1) {
    // Debug: show why no entry matched
    return false;
  }

  // Update status field within entry
  let statusUpdated = false;
  for (let i = firstLine; i <= lastLine; i++) {
    if (/^\s+status:/.test(lines[i])) {
      lines[i] = lines[i].replace(/status: "[^"]*"/, `status: "${status}"`);
      statusUpdated = true;
      break;
    }
  }
  if (!statusUpdated) return false;

  // Add reviewer info + db_id if not already in this entry
  const entryText = lines.slice(firstLine, lastLine + 1).join('\n');
  if (reviewedBy && !entryText.includes('reviewed_by:')) {
    const insertAfter = lastLine;
    const toInsert = [];
    // Store server DB id for resolved notification
    if (serverEx.id && !entryText.includes('db_id:')) {
      toInsert.push(`    db_id: ${serverEx.id}`);
    }
    toInsert.push(`    reviewed_by: "${reviewedBy}"`);
    if (comment) toInsert.push(`    review_comment: "${comment.replace(/"/g, '\\"')}"`);
    lines.splice(insertAfter + 1, 0, ...toInsert);
  }

  fs.writeFileSync(configPath, lines.join('\n'), 'utf8');
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

// ── Sync notice for terminal output ──────────────────────────────────────
// Returns a notice string if there are pending exceptions, or null.
// Reads only from local config + meta — zero network cost.
function getSyncNotice(repoRoot) {
  try {
    const { readMeta } = require('./store');
    const { loadConfig } = require('./config');

    const config  = loadConfig(repoRoot);
    const meta    = readMeta(repoRoot);

    // Exclude exceptions already handled by server (approved or rejected)
    const handled = new Set(Array.isArray(meta.handledExceptionIds) ? meta.handledExceptionIds : []);
    const pending = config.exceptions.filter(e => e.status === 'pending' && !handled.has(e.id));

    if (pending.length === 0) return null;

    const lastSynced  = meta.lastSynced ? new Date(meta.lastSynced) : null;
    const hoursSince  = lastSynced
      ? Math.floor((Date.now() - lastSynced.getTime()) / 3_600_000)
      : null;

    const stale = hoursSince === null || hoursSince >= 24;

    const icon  = stale ? YELLOW + '⚠ ' + RESET : CYAN + 'ℹ ' + RESET;
    const age   = hoursSince === null
      ? 'never synced'
      : hoursSince < 1 ? 'synced recently'
      : hoursSince < 24 ? `synced ${hoursSince}h ago`
      : `last synced ${Math.floor(hoursSince / 24)}d ago`;

    return `${icon}${DIM} ${pending.length} exception(s) pending approval – ${age} – run ${RESET}${BOLD}scd sync${RESET}`;
  } catch {
    return null;
  }
}

// ── List exceptions from local config ────────────────────────────────────

function listExceptions(repoRoot, statusFilter = 'all') {
  const { loadConfig } = require('./config');
  const config = loadConfig(repoRoot);

  const valid = ['pending', 'approved', 'rejected', 'all'];
  if (!valid.includes(statusFilter)) {
    console.error(`${RED}❌ Invalid status: ${statusFilter}. Use: pending | approved | rejected | all${RESET}`);
    process.exit(1);
  }

  const list = statusFilter === 'all'
    ? config.exceptions
    : config.exceptions.filter(e => e.status === statusFilter);


  if (list.length === 0) {
    console.log(`\n${DIM}  No ${statusFilter === 'all' ? '' : statusFilter + ' '}exceptions found.${RESET}\n`);
    return;
  }

  const statusColor = (s) =>
    s === 'approved' ? GREEN :
    s === 'rejected' ? YELLOW :
    DIM;

  // Build a lookup map from (rule+file+line) → findingId using last scan cache
  const findingIdMap = {};
  try {
    const { loadCache } = require('./scan-cache');
    const cache = loadCache(repoRoot);
    for (const f of (cache?.findings || [])) {
      if (f.findingId) {
        const key = `${f.ruleId}|${f.filePath}|${f.line}`;
        findingIdMap[key] = f.findingId;
      }
    }
  } catch { /* non-fatal */ }

  console.log(`\n${BOLD}Exceptions${statusFilter !== 'all' ? ' (' + statusFilter + ')' : ''}:${RESET}\n`);

  for (const ex of list) {
    const sc = statusColor(ex.status);
    const findingId = findingIdMap[`${ex.rule}|${ex.file}|${ex.line}`] || null;
    console.log(`  ${BOLD}${ex.id || '—'}${RESET}  ${sc}[${ex.status}]${RESET}  ${DIM}${ex.type}${RESET}`);
    console.log(`  ${DIM}Rule:   ${RESET}${ex.rule}`);
    console.log(`  ${DIM}File:   ${RESET}${ex.file}${ex.line ? ':' + ex.line : ''}${findingId ? `  ${DIM}${findingId}${RESET}` : ''}`);
    console.log(`  ${DIM}Reason: ${RESET}${ex.reason}`);
    if (ex.tag) console.log(`  ${DIM}Tag:    ${RESET}${ex.tag}`);
    if (ex.reviewed_by)    console.log(`  ${DIM}Reviewed by: ${RESET}${ex.reviewed_by}`);
    if (ex.review_comment) console.log(`  ${DIM}Comment:     ${RESET}${ex.review_comment}`);
    if (ex.status === 'rejected') {
      console.log(`  ${YELLOW}→ scd resolve --rejected ${ex.id}${RESET}  ${DIM}(remove from local config)${RESET}`);
    }
    console.log('');
  }
}

// ── Remove a rejected exception from local config by ID ──────────────────

function removeRejected(repoRoot, excId) {
  const configPath = require('./store').configPath(repoRoot);

  if (!fs.existsSync(configPath)) {
    console.error(`${RED}❌ No config.yml found for this repo.${RESET}`);
    process.exit(1);
  }

  let content = fs.readFileSync(configPath, 'utf8');

  // Find the entry by id
  const idx = content.indexOf(`  - id: "${excId}"`);
  if (idx === -1) {
    console.error(`${RED}❌ Exception ${excId} not found in local config.${RESET}`);
    console.error(`${DIM}   Run 'scd exceptions --list rejected' to see available IDs.${RESET}`);
    process.exit(1);
  }

  // Find the extent of the entry (until next entry or end of exceptions block)
  const nextEntry = content.indexOf('  - id: "', idx + 1);
  const entryEnd  = nextEntry !== -1 ? nextEntry : content.length;
  const entry     = content.slice(idx, entryEnd);

  // Verify it's rejected before removing
  if (!entry.includes('status: "rejected"')) {
    console.error(`${RED}❌ Exception ${excId} is not rejected — only rejected exceptions can be removed this way.${RESET}`);
    process.exit(1);
  }

  // Extract server DB id from entry if present (stored as db_id field)
  // Fall back to notifying server by rule+file+line if no db_id
  const dbIdMatch = entry.match(/db_id:\s*(\d+)/);
  const dbId      = dbIdMatch ? parseInt(dbIdMatch[1], 10) : null;

  content = content.slice(0, idx) + content.slice(entryEnd);

  // Clean up empty exceptions block
  content = content.replace(/^exceptions:\s*\n(\s*\n)*$/m, '');

  fs.writeFileSync(configPath, content, 'utf8');

  // Mark as resolved on server (fire-and-forget)
  // We need the DB id — store it in handledExceptionIds and try to notify server
  const { getCentralUrl, getCentralToken } = require('./global-config');
  const centralUrl = getCentralUrl();
  if (centralUrl && dbId) {
    const token  = getCentralToken();
    const url    = centralUrl.replace(/\/$/, '') + `/api/v1/exceptions/${dbId}/resolved`;
    const http   = url.startsWith('https') ? require('https') : require('http');
    const parsed = new (require('url').URL)(url);
    const opts   = {
      hostname: parsed.hostname,
      port:     parsed.port || (url.startsWith('https') ? 443 : 80),
      path:     parsed.pathname,
      method:   'POST',
      headers:  { 'Authorization': `Bearer ${token}`, 'Content-Length': 0 },
    };
    const req = http.request(opts, (res) => { res.resume(); });
    req.on('error', () => {}); // non-fatal
    req.end();
  }

  // Store handled ID in meta so getSyncNotice doesn't re-show it
  const { updateLastSynced, readMeta } = require('./store');
  updateLastSynced(repoRoot, [excId]);

  console.log(`\n${GREEN}✓ Rejected exception ${excId} removed from local config.${RESET}`);
  console.log(`${DIM}  The finding will be flagged normally in future scans.${RESET}\n`);
}

module.exports = { addException, addExceptionById, syncExceptions, getSyncNotice, listExceptions, removeRejected };
