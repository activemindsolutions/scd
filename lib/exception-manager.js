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
 *   1. Resolve findingId (f-{10hex}) from the findings store (findings.jsonl)
 *   2. Write a pending exception to store config.yml (status: pending)
 *   3. Push exception-request to scd-server via push queue
 *
 * scd sync
 *   → Pull approved/rejected exceptions from scd-server, update local config.yml
 */

'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('./output-constants');
const { formatLocalDate } = require('./format-time');

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { makeCodeHash }    = require('./finding-identity');
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
 * Add exception or ignore by finding ID (f-{10hex}).
 * Looks up the finding in the findings store (findings.jsonl), then delegates to addException.
 * This is the primary entry point from CLI commands.
 */
async function addExceptionById(repoRoot, findingId, opts, type = 'exception') {

  if (!findingId) {
    const cmd = type === 'ignore' ? 'ignore' : 'accept';
    console.error(`\n${RED}✗ Finding ID required.${RESET}`);
    console.error(`${DIM}   Usage: scd ${cmd} <finding-id> --reason "..."${RESET}`);
    console.error(`${DIM}   Finding IDs are shown in scd scan --verbose output (e.g. f-20eb992e1f)${RESET}\n`);
    process.exit(1);
  }

  if (!findingId.startsWith('f-') || findingId.length !== 12) {
    console.error(`\n${RED}✗ Invalid finding ID: ${findingId}${RESET}`);
    console.error(`${DIM}   Finding IDs look like: f-20eb992e1f (shown in scd scan --verbose)${RESET}\n`);
    process.exit(1);
  }

  if (!opts.reason || !opts.reason.trim()) {
    console.error(`\n${RED}✗ --reason is required.${RESET}`);
    const cmd = type === 'ignore' ? 'ignore' : 'accept';
    console.error(`${DIM}   Example: scd ${cmd} ${findingId} --reason "Not exploitable in this context"${RESET}\n`);
    process.exit(1);
  }

  // Resolve the finding from the accumulated store (findings.jsonl) — the same
  // source `scd findings` reads (loadFindingsWithBootstrap). A finding raised by a
  // pre-push hook is materialised into the store but never into last-scan.json, so
  // resolving against the cache made hook findings visible-but-unactionable. The
  // store is the locked source of truth and a strict superset of the cache (it
  // bootstraps from last-scan.json for legacy repos with no store yet).
  const { loadFindingsWithBootstrap } = require('./findings-store');
  const { records } = loadFindingsWithBootstrap(repoRoot);
  const rec = records.find(r => r.finding_id === findingId);

  if (!rec) {
    console.error(`\n${RED}✗ Finding ${findingId} not found.${RESET}`);
    console.error(`${DIM}   Run scd findings to see current finding IDs, then re-run this command.${RESET}\n`);
    process.exit(1);
  }

  // Store records are snake_case; map the four identity fields addException needs.
  const finding = {
    ruleId:   rec.rule_id,
    filePath: rec.file,
    line:     rec.line,
    codeHash: rec.code_hash,
  };

  // Check for duplicate — same finding already has a pending/approved exception.
  // Reads the machine-local store (Run 2 re-home), not config.yml.
  const { loadExceptions } = require('./exceptions-store');
  const exceptions = loadExceptions(repoRoot);
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
    reviewIn:  opts.reviewIn,              // E1c.3 — --review-in passthrough
    codeHash:  finding.codeHash || null,   // pass through — do not recompute
  }, type);
}

// ── Add exception or ignore ───────────────────────────────────────────────

// Parse a --review-in duration ("30d", "2w", "3m", or a bare number = days) to a
// day count. Returns a positive integer, or null when the input is invalid.
function parseReviewIn(s) {
  if (s == null || s === '') return null;
  const m = /^(\d+)\s*([dwm]?)$/i.exec(String(s).trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (!n || n < 1) return null;
  const unit = (m[2] || 'd').toLowerCase();
  return unit === 'w' ? n * 7 : unit === 'm' ? n * 30 : n;
}

async function addException(repoRoot, opts, type = 'exception') {
  const { rule, file, line, reason, tag, reviewIn } = opts;

  // --review-in <duration> → an explicit expiry/review deadline (E1c.3).
  let expires = null;
  if (reviewIn != null && reviewIn !== '') {
    const days = parseReviewIn(reviewIn);
    if (!days) {
      console.error(`\n${RED}✗ Invalid --review-in value: ${reviewIn}${RESET}`);
      console.error(`${DIM}   Use a duration like 30d (days), 2w (weeks) or 3m (months).${RESET}\n`);
      process.exit(1);
    }
    expires = new Date(Date.now() + days * 86400000).toISOString();
  }

  // Validate required fields
  if (!rule || !file || !line) {
    console.error('\n' + RED + 'Usage: scd accept <finding-id> --reason "..."' + RESET + '\n');
    process.exit(1);
  }

  if (!reason || !reason.trim()) {
    console.error(`\n${RED}✗ --reason is required.${RESET}`);
    console.error(DIM + '   Example: scd accept abc123 --reason "PRAGMA uses whitelist-validated table names only"' + RESET + '\n');
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
        // Uses the canonical algorithm in lib/finding-identity.js — never re-implement.
        codeHash = makeCodeHash(lineContent);
        codeHashValid = true;
      }
      console.log(`\n${DIM}Line ${lineNum}: ${lineContent.trim()}${RESET}`);
      console.log(`${DIM}Hash:       ${codeHash}${RESET}`);
    }
  } else {
    console.log(`\n${YELLOW}⚠  File not found: ${file}${RESET}`);
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

  const excId     = `exc-${Date.now().toString(36)}`;
  const createdAt = new Date().toISOString();   // store-format: full UTC ISO-8601

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
    created_at:   createdAt,
    expires:      expires,            // E1c.3 — null unless --review-in given
  };

  // Write to store config
  writeException(repoRoot, exception);

  // Track delivery state. Standalone mode (no centralUrl) never queues — nothing
  // to deliver, the exception was already set to 'approved' locally above. With central
  // configured, mark pending immediately so a network failure during the initial
  // push still leaves a recoverable retry record.
  if (!isStandalone) {
    try {
      require('./exceptions-push-tracker').markPending(repoRoot, excId);
    } catch { /* non-fatal — tracker write is best-effort */ }
  }

  // Push to scd-server. The unified path means this call may also deliver
  // older queued exceptions (if any). We await it because the creation-time
  // messaging below keys on whether THIS exception's id was acked.
  let deliveredNow = false;
  let pushResult   = null;
  if (!isStandalone) {
    // Events queue flush FIRST — registers the repo server-side before the
    // exception push FK-references it. Without this, a first-contact accept
    // (e.g. after scanning with the server down) hits the repo FK on the server
    // before the events flush creates the repo. See fix(delivery-order). The
    // server now answers a clean 409 (not 500) when the repo is unregistered.
    try { await require('./push-queue').flushEvents(repoRoot); }
    catch { /* non-fatal */ }

    try {
      pushResult = await pushPendingExceptions(repoRoot);
      deliveredNow = pushResult.deliveredIds.has(excId);
    } catch { /* quiet — tracker still holds the id for the next retry */ }
  }

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
    if (deliveredNow) {
      console.log(`${DIM}  → Pushed to scd-server for approval${RESET}`);
    } else if (pushResult && pushResult.repoNotRegistered) {
      // Do NOT claim automatic sync — delivery is blocked until the repo is
      // registered (the [WARN] above explains it). Saying "will sync
      // automatically" here would be the deferred-success illusion (#67 class).
      console.log(`${YELLOW}  ⚠  Saved locally, but NOT delivered — this repo is not registered on the server.${RESET}`);
      console.log(`${DIM}     Register the repo with the server first; it then delivers automatically.${RESET}`);
    } else {
      // Quiet, honest, calm. Covers network failure, invalid-stop, and the
      // slice case where this id is queued behind a larger backlog. Working
      // offline must never feel like an error state.
      console.log(`${DIM}  Exception saved locally — will sync to scd-server automatically.${RESET}`);
    }
  }
  console.log(`${DIM}  Rule:   ${rule}${RESET}`);
  console.log(`${DIM}  File:   ${file}:${lineNum}${RESET}`);
  console.log(`${DIM}  Reason: ${reason.trim()}${RESET}`);
  if (cleanTag) console.log(`${DIM}  Tag:    ${cleanTag}${RESET}`);
  console.log();
}

// ── Acknowledged push to scd-server ──────────────────────────────────────
//
// Replaces the previous fire-and-forget pushExceptionToServer with an
// acknowledged, retry-friendly batch sender. Delivery state lives in
// exceptions-push.jsonl (the tracker module); this function consumes that
// list, sends what is unacked, and removes confirmed ids on success.
//
// Branch B (scd-server) made /api/v1/exceptions/batch idempotent on the
// identity tuple, which is what makes retries safe to do here.
//
// Returns { sent, delivered, remaining, orphaned, error? } for callers that
// want to introspect. Never throws to the caller — failure leaves the tracker
// intact for the next retry.

async function pushPendingExceptions(repoRoot) {
  // deliveredIds: Set of exception ids confirmed acked by the server in THIS
  // call. Callers (notably addException) key creation-time messaging on
  // `deliveredIds.has(excId)` so the "→ Pushed to scd-server" line only fires
  // when the just-created exception was actually delivered — covers network
  // failure, invalid-stop, AND the slice case where a new id is queued after
  // a 100+-item backlog and therefore not in this batch.
  const result = { sent: 0, delivered: 0, remaining: 0, orphaned: 0, deliveredIds: new Set() };

  let centralUrl, token;
  try {
    const { getCentralUrl, getCentralToken } = require('./global-config');
    centralUrl = getCentralUrl();
    if (!centralUrl) return result;   // standalone: nothing to do
    token = getCentralToken();
  } catch {
    return result;
  }

  const tracker = require('./exceptions-push-tracker');
  const pending = tracker.loadPending(repoRoot);
  if (pending.length === 0) return result;

  // Resolve payload for each pending id from the machine-local store (Run 2
  // re-home). Ids without a matching exception record are ORPHANS — drop them
  // silently. Otherwise a manually-deleted exception would loop forever in the
  // tracker.
  let cfgIndex;
  try {
    const { loadExceptions } = require('./exceptions-store');
    cfgIndex = new Map(loadExceptions(repoRoot).map(e => [e.id, e]));
  } catch {
    cfgIndex = new Map();
  }

  const orphans = [];
  const batch   = [];   // [{ exception_id, payload }]
  for (const entry of pending) {
    const ex = cfgIndex.get(entry.exception_id);
    if (!ex) { orphans.push(entry.exception_id); continue; }
    batch.push({
      exception_id: entry.exception_id,
      payload: {
        rule_id:   ex.rule,
        file_path: ex.file,
        line:      ex.line,
        code_hash: ex.line_hash || null,
        type:      ex.type,
        tag:       ex.tag || null,
        reason:    ex.reason,
      },
    });
  }

  if (orphans.length > 0) {
    tracker.clearIds(repoRoot, orphans);
    result.orphaned = orphans.length;
  }

  if (batch.length === 0) {
    result.remaining = tracker.pendingCount(repoRoot);
    return result;
  }

  // Server caps at 100 per batch (routes-exceptions.js). Slice if needed.
  const MAX_PER_BATCH = 100;
  const chunk = batch.slice(0, MAX_PER_BATCH);

  let meta;
  try { meta = require('./push-queue').buildMeta(repoRoot); }
  catch { meta = {}; }

  const body = JSON.stringify({
    exceptions: chunk.map(b => b.payload),
    meta,
  });

  let response;
  try {
    response = await postJson(centralUrl.replace(/\/$/, '') + '/api/v1/exceptions/batch', body, token);
  } catch (err) {
    // Network error / timeout / non-2xx — leave tracker intact.
    result.remaining = tracker.pendingCount(repoRoot);
    result.error = err.message || 'network';
    // A 409 means the server does not have this repo registered yet. Unlike a
    // network blip this does NOT self-heal by retrying (the repo must be
    // registered first), so it must never be swallowed silently or look like a
    // deferred success (the dead-token #67 class). Surface it clearly and flag
    // it so callers don't claim automatic sync. The tracker is kept — the
    // exception delivers once the repo exists.
    if (err && err.message === 'http_409') {
      result.repoNotRegistered = true;
      process.stderr.write(
        `${YELLOW}[WARN]${RESET} scd-server: this repository is not registered yet — ` +
        `${result.remaining} exception(s) cannot be delivered until it is.\n` +
        `       Register the repo with the server first (e.g. run a scan that reports to it); ` +
        `they are kept locally and deliver once it exists.\n` +
        `       You can also check them against your current findings.\n`
      );
    } else if (err && (err.message === 'http_401' || err.message === 'http_403')) {
      // Token rejected — permanent until fixed (the dead-token #67 class). Do not
      // let it look like a deferred success; surface it. The tracker is kept — the
      // exception delivers once a valid token is configured.
      result.authFailed = true;
      process.stderr.write(
        `${YELLOW}[WARN]${RESET} scd-server rejected your token — ` +
        `${result.remaining} exception(s) cannot be delivered until it is fixed.\n` +
        `       Re-create the token on the server, then: scd configure --token <token>\n` +
        `       They are kept locally and deliver once the token is valid.\n`
      );
    }
    return result;
  }

  const inserted  = Number(response.inserted)  || 0;
  const duplicate = Number(response.duplicate) || 0;   // 0 if older server
  const invalid   = Number(response.invalid)   || 0;   // 0 if older server
  const delivered = inserted + duplicate;
  result.sent = chunk.length;

  if (invalid > 0) {
    // Contract bug — same-version CLI/server should never disagree on validity.
    // Surface loudly but do NOT clear the tracker: the user can re-investigate
    // without losing data.
    process.stderr.write(
      `${YELLOW}[WARN]${RESET} scd-server rejected ${invalid} exception(s) as invalid — ` +
      `not clearing local queue. This indicates a CLI/server contract mismatch.\n`
    );
    result.remaining = tracker.pendingCount(repoRoot);
    return result;
  }

  if (delivered >= chunk.length) {
    // All acked — clear those ids from the tracker.
    const ids = chunk.map(b => b.exception_id);
    tracker.clearIds(repoRoot, ids);
    result.delivered = delivered;
    result.deliveredIds = new Set(ids);
  }
  result.remaining = tracker.pendingCount(repoRoot);
  return result;
}

/**
 * Re-assert locally-approved exceptions so a diverged server can re-converge
 * (#235 Phase 1). Unlike pushPendingExceptions (which delivers *undelivered*
 * pending exceptions via the tracker), this re-sends the exceptions the CLI holds
 * as APPROVED, tagged `client_status: 'approved'`. The server acts on what IT
 * holds — this can never approve anything it hasn't already approved: a lost
 * approval degrades to pending server-side (reported back as reapproval_required).
 *
 * Idempotent — pushes the whole approved set every sync (Phase 2 will gate this on
 * a digest). Offline-first and quiet on error: pushPendingExceptions has already
 * surfaced any connectivity/auth problem in the same sync.
 *
 * Returns per-outcome counts from the server's `reconciled` response.
 * See DESIGN-exception-sync-reconciliation.md.
 */
async function reassertApprovedExceptions(repoRoot) {
  const result = { sent: 0, skipped: 0, skippedScoped: 0, skippedGone: 0, healed: 0, converged: 0, pending: 0, reapproval_required: 0, conflict_rejected: 0 };

  let centralUrl, token;
  try {
    const { getCentralUrl, getCentralToken } = require('./global-config');
    centralUrl = getCentralUrl();
    if (!centralUrl) return result;   // standalone — nothing to reconcile
    token = getCentralToken();
  } catch {
    return result;
  }

  let approved;
  try {
    const { loadExceptions } = require('./exceptions-store');
    const { loadScope, isFileExcluded } = require('./scope');
    const fs   = require('fs');
    const path = require('path');
    const scope = loadScope(repoRoot) || { file_excludes: [], rule_excludes: [] };
    // Only approved exceptions carrying a code_hash can reconcile line-independently.
    const candidates = loadExceptions(repoRoot).filter(e => e.status === 'approved' && e.line_hash);
    // Re-assert ONLY exceptions whose finding is actually reported to the server —
    // i.e. LIVE (the file still exists on disk) and NOT scoped-out. An exception for
    // a scoped-out or renamed/deleted finding must not be pushed: the finding itself
    // is never sent (scoped/gone → not scanned), so pushing the exception creates
    // reapproval churn + an orphan exception on the server. The exception stays in
    // the local store regardless (never deleted) — it is just not re-asserted.
    approved = candidates.filter((e) => {
      const abs = path.join(repoRoot, e.file);
      if (isFileExcluded(scope, abs, repoRoot).excluded) { result.skippedScoped++; return false; }  // scoped-out
      if (!fs.existsSync(abs))                           { result.skippedGone++;   return false; }  // gone (rename/delete)
      return true;
    });
    result.skipped = result.skippedScoped + result.skippedGone;
  } catch {
    return result;
  }
  if (approved.length === 0) return result;

  let meta;
  try { meta = require('./push-queue').buildMeta(repoRoot); }
  catch { meta = {}; }

  const MAX_PER_BATCH = 100;   // server cap (routes-exceptions.js)
  for (let i = 0; i < approved.length; i += MAX_PER_BATCH) {
    const chunk = approved.slice(i, i + MAX_PER_BATCH);
    const body  = JSON.stringify({
      exceptions: chunk.map(ex => ({
        rule_id:       ex.rule,
        file_path:     ex.file,
        line:          ex.line,
        code_hash:     ex.line_hash,
        type:          ex.type,
        tag:           ex.tag || null,
        reason:        ex.reason,
        client_status: 'approved',
      })),
      meta,
    });

    let response;
    try {
      response = await postJson(centralUrl.replace(/\/$/, '') + '/api/v1/exceptions/batch', body, token);
    } catch (err) {
      result.error = err.message || 'network';
      return result;   // quiet — offline-first
    }

    result.sent += chunk.length;
    const rc = response.reconciled || {};   // {} against an older server → no-op reporting
    for (const k of ['healed', 'converged', 'pending', 'reapproval_required', 'conflict_rejected']) {
      result[k] += Number(rc[k]) || 0;
    }
  }

  return result;
}

/**
 * POST JSON helper — resolves with the parsed body on 2xx, rejects on any
 * other outcome (network, timeout, non-2xx). 8s timeout matches the previous
 * fire-and-forget implementation.
 */
function postJson(url, body, token) {
  return new Promise((resolve, reject) => {
    const http = url.startsWith('https') ? require('https') : require('http');
    const parsed = new (require('url').URL)(url);
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (url.startsWith('https') ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`http_${res.statusCode}`));
        }
        try { resolve(JSON.parse(data || '{}')); }
        catch { reject(new Error('invalid_json')); }
      });
    });
    req.on('error', (err) => reject(err));
    req.setTimeout(8000, () => { req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

// ── Write exception to the machine-local store ────────────────────────────
// Re-homed to exceptions.jsonl (Run 2): load → build the canonical store record
// via buildExceptionRecord → append → atomic full-set write. No config.yml write
// from this path anymore. The record is store-format (created_at UTC ISO-8601,
// line_hash only when valid, finding_id never stored) — the builder enforces it.

function writeException(repoRoot, exception) {
  const { loadExceptions, buildExceptionRecord, writeExceptions, withExceptionsLock } = require('./exceptions-store');

  // #170: lock the whole load→modify→write cycle — read inside the lock.
  withExceptionsLock(repoRoot, () => {
    const records = loadExceptions(repoRoot);
    const record  = buildExceptionRecord({
      id:         exception.id,
      type:       exception.type,
      tag:        exception.tag || undefined,        // optional — builder omits when absent
      status:     exception.status,
      rule:       exception.rule,
      file:       exception.file,
      line:       exception.line,
      // line_hash only when content was actually hashed (secrets rules redact lineRaw)
      line_hash:  (exception.code_hash && exception.code_hash_valid) ? exception.code_hash : undefined,
      reason:     exception.reason,
      created_at: exception.created_at,
      expires:    exception.expires || undefined,   // E1c.3 — only when --review-in given
    });

    records.push(record);
    writeExceptions(repoRoot, records);
  });
}

// ── Sync approved exceptions from scd-server ─────────────────────────────

async function syncExceptions(repoRoot) {
  const { getCentralUrl, getCentralToken } = require('./global-config');
  const centralUrl = getCentralUrl();
  const token      = getCentralToken();


  if (!centralUrl) {
    console.error(`\n${RED}✗ No scd-server configured.${RESET}`);
    console.error(DIM + '   Run: scd configure --central-url <url>' + RESET + '\n');
    process.exit(1);
  }

  const store  = require('./store');
  const repoId = store.getRepoId(repoRoot);
  const http   = centralUrl.startsWith('https') ? require('https') : require('http');

  console.log(`\n${CYAN}↓ Syncing exceptions from scd-server…${RESET}`);

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

    // Apply via the shared decision path — same function the push-response
    // channel uses. Pull updates the staleness timestamp (below), never the
    // ack token (that channel has its own filtering; see Branch C contract).
    const decisions = [
      ...list.map(e => ({ ...e, status: 'approved' })),
      ...rejected.map(e => ({ ...e, status: 'rejected' })),
    ];
    const applyResult = applyServerDecisions(repoRoot, decisions);

    if (list.length > 0) {
      const approved = applyResult.records.filter(r => r.input.status === 'approved');
      const applied  = approved.filter(r => r.outcome === 'applied').length;
      const skipped  = approved.filter(r => r.outcome === 'alreadyApplied' || r.outcome === 'unknown').length;
      console.log(`${GREEN}✓ ${list.length} approved exception(s)${RESET}`);
      if (applied > 0) console.log(`${DIM}  ${applied} applied to local config — findings will no longer be flagged${RESET}`);
      if (skipped > 0) console.log(`${DIM}  ${skipped} already up to date${RESET}`);
    }

    // Show rejected so developer knows to fix the finding (pull shows all)
    if (rejected.length > 0) {
      renderRejectedNotice(rejected);
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
      console.error(`\n${YELLOW}⚠  Server license invalid — exceptions cannot be synced.${RESET}`);
      console.error(DIM + '   Contact your local scd-server administrator to resolve this.' + RESET + '\n');
    } else {
      console.error(`\n${RED}✗ Sync failed: ${err.message}${RESET}`);
      console.error(DIM + '   Check that scd-server is reachable and token is correct' + RESET + '\n');
    }
    process.exit(1);
  }
}

// Apply a single server decision to the local config.yml entry it identifies.
//
// Outcome-aware (Branch C): the caller must be able to tell APPLIED (local
// state actually changed) from NO-OP (state already matched) so a redelivered
// boundary record stays silent and advances the ack high-water mark instead of
// parking the cursor forever.
//
// Returns { found, changed, error }:
//   found   — an entry matched this decision (see identity precedence below)
//   changed — the file was actually rewritten (status flipped and/or reviewer
//             info appended); false means the entry already matched
//   error   — non-null when a matched entry could not be written (I/O error, or
//             a malformed entry with no status field). Reported, never thrown.
//
// Identity precedence (canonical exception identity is
// (repo_id, rule_id, code_hash, line); repo is implicit here):
//   1. finding_id — when BOTH the decision and the local entry carry one.
//   2. CLI id — exact `- id:` match (pull may also carry the numeric server id).
//   3. (rule_id, file_path, line, code_hash) — when the local entry HAS a hash,
//      code_hash MUST match. This is the canonical tuple, not a tightening:
//      code_hash was added to the sync_exceptions payload in v1.2.1 precisely
//      so the CLI matches the exact record. Without it, a decision for an old
//      exception (hash H1) could be misapplied to a newer exception (H2) on the
//      same rule/file/line after the code changed.
//   4. (rule_id, file_path, line) legacy fallback — ONLY when the local entry
//      has no hash at all (pre-hash exceptions). A hash mismatch is NOT a
//      fallback: it means the decision's target does not exist locally → the
//      caller treats it as 'unknown' (silent, advances the ack mark).
// Identity-match precedence — carried over BYTE-FOR-BYTE in behavior from the
// prior config text-scan. Iterate records in array order (= insertion / file
// order) and return the FIRST record that matches by, in this priority within a
// single record: id, finding_id (dormant — the store never writes finding_id, so
// this stays inert), or the canonical rule+file+line+code_hash tuple (a hashless
// legacy record falls back to rule+file+line). The ONLY change vs the old code is
// text scan → array find; the predicate is identical.
function findExceptionMatch(records, serverEx) {
  for (const rec of records) {
    const isById = serverEx.id && rec.id === serverEx.id;

    // finding_id — strongest, only when both sides have it (store never writes it).
    const isByFindingId = serverEx.finding_id && rec.finding_id === serverEx.finding_id;

    // canonical tuple with code_hash; legacy fallback only when hashless.
    const localHash = rec.line_hash != null ? rec.line_hash : null;
    const codeHashMatches = serverEx.code_hash && localHash && (
      localHash === serverEx.code_hash ||                                       // exact 32-char
      (localHash.length === 16 && serverEx.code_hash.startsWith(localHash))     // legacy 16-char prefix
    );
    const isByRuleLine = !isById && !isByFindingId && serverEx.rule_id && serverEx.file_path
      && rec.rule === serverEx.rule_id
      && rec.file === serverEx.file_path
      && (!serverEx.line || String(rec.line) === String(serverEx.line))
      && (localHash ? codeHashMatches : true);   // hashed entry → hash must match; hashless → legacy fallback

    if (isByFindingId || isById || isByRuleLine) return rec;
  }
  return null;
}

function updateExceptionStatus(repoRoot, serverEx, status, reviewedBy, comment) {
  const { loadExceptions, writeExceptions, withExceptionsLock } = require('./exceptions-store');

  // #170: lock the whole match→mutate→write cycle — read inside the lock.
  return withExceptionsLock(repoRoot, () => {
    const records = loadExceptions(repoRoot);

    const record = findExceptionMatch(records, serverEx);
    if (!record) {
      // No local record matches this decision — caller treats as 'unknown'.
      return { found: false, changed: false, error: null };
    }

    // Status flip — track whether it actually changed so a redelivered decision
    // (status already at target) reports as a no-op.
    if (record.status == null) {
      // Matched record has no status field — malformed local state. Redelivery
      // cannot fix it; surface as an error so the caller parks the ack token.
      return { found: true, changed: false, error: 'matched entry has no status field' };
    }
    const statusChanged = record.status !== status;
    if (statusChanged) record.status = status;

    // Add reviewer info + db_id once. db_id is the server's numeric exception id,
    // present only on the pull channel (/exceptions/approved returns SELECT *);
    // push-response records carry no numeric id, so db_id is simply omitted there.
    // Comment is stored raw — JSON serialization handles escaping (the old YAML
    // path needed manual quote-escaping; the store does not).
    let reviewerAdded = false;
    if (reviewedBy && record.reviewed_by == null) {
      if (serverEx.id != null && record.db_id == null) record.db_id = serverEx.id;
      record.reviewed_by = reviewedBy;
      if (comment) record.review_comment = comment;
      reviewerAdded = true;
    }

    const changed = statusChanged || reviewerAdded;
    if (!changed) return { found: true, changed: false, error: null };

    try {
      writeExceptions(repoRoot, records);
    } catch (err) {
      return { found: true, changed: false, error: err.message || 'write failed' };
    }
    return { found: true, changed: true, error: null };
  });
}

// ── Shared decision-application path (Branch C) ────────────────────────────
//
// THE single function that applies a list of server decisions to local state,
// used by BOTH arrival channels: the `scd sync` GET pull and the
// events/batch push-response. Pure state mutation + classification — performs
// NO console output (callers render at their own verbosity) and NEVER throws.
//
// Each decision record (shared shape across both channels):
//   { rule_id, file_path, line, status, reviewed_by, review_comment,
//     updated_at, id?, code_hash?, finding_id? }
// `id` (numeric server id) is present on pull records only; identity otherwise
// matches on the canonical (rule_id, file_path, line, code_hash) tuple inside
// updateExceptionStatus (legacy rule+file+line fallback only for hashless local
// entries). A code_hash mismatch yields 'unknown', not a loose match.
//
// Server wins on status conflict (the decision is authoritative). Per-record
// outcomes are returned in INPUT ORDER so the push caller can compute its
// at-least-once high-water mark.
//
// Outcomes:
//   applied        — local state actually changed
//   alreadyApplied — state already matched (idempotent no-op)
//   unknown        — no local entry for this decision (skip; cannot become
//                    applicable by redelivery, so counts as processed)
//   failed         — matched but could not be written / malformed / bad status
function applyServerDecisions(repoRoot, decisions) {
  const result = { applied: 0, alreadyApplied: 0, unknown: 0, skipped: 0, failed: 0, records: [] };
  const list = Array.isArray(decisions) ? decisions : [];

  for (const d of list) {
    const rec = { input: d, outcome: null, error: null };
    const status = d && d.status;

    // Unknown/unsupported status — anything outside approved|rejected (e.g. a
    // server-side 'resolved'). This is NOT a delivery failure: the record WAS
    // delivered, we simply cannot act on it, and redelivery would never help
    // (still unknown next round). Mark it 'skipped' (benign) — NOT 'failed' —
    // so the ack high-water-mark advances past it instead of jamming on it (and
    // every record after it) forever. See applyFlushDecisions' mark loop.
    if (status !== 'approved' && status !== 'rejected') {
      rec.outcome = 'skipped';
      rec.error   = null;
      result.skipped++;
      result.records.push(rec);
      continue;
    }

    let r;
    try {
      r = updateExceptionStatus(repoRoot, d, status, d.reviewed_by, d.review_comment);
    } catch (err) {
      rec.outcome = 'failed';
      rec.error   = err.message || 'apply error';
      result.failed++;
      result.records.push(rec);
      continue;
    }

    if (r.error)          { rec.outcome = 'failed';         rec.error = r.error; result.failed++; }
    else if (!r.found)    { rec.outcome = 'unknown';        result.unknown++; }
    else if (r.changed)   { rec.outcome = 'applied';        result.applied++; }
    else                  { rec.outcome = 'alreadyApplied'; result.alreadyApplied++; }
    result.records.push(rec);
  }

  return result;
}

// Render the rejected-decision notice (YELLOW block + per-finding reason).
// Single source of the rejected UX, reused by both channels: the pull command
// shows all rejected decisions each sync; the push-response channel passes only
// the newly-applied ones so redelivered rejects stay silent.
function renderRejectedNotice(records) {
  if (!records.length) return;
  console.log(`\n${YELLOW}⚠  ${records.length} rejected exception(s) — these findings need to be fixed:${RESET}`);
  for (const d of records) {
    console.log(`${DIM}  ${d.rule_id}  ${d.file_path}${d.line ? ':' + d.line : ''}${RESET}`);
    if (d.review_comment) {
      console.log(`${DIM}  Reason: ${d.review_comment}${RESET}`);
    }
  }
}

// Push-response entry point (events/batch). Applies the delivered decisions,
// renders quiet UX, and returns the ack high-water-mark token to send back.
// NEVER throws into the flush caller; a malformed payload yields one [WARN]
// and no token advance.
//
// High-water mark (at-least-once): walk records in delivered order
// (updated_at ASC); after each SUCCESSFULLY processed record (applied, no-op,
// unknown, or skipped) the mark becomes that record's updated_at string,
// VERBATIM. Only a genuine 'failed' (or a record whose updated_at is unusable)
// stops the advance: the failing record and everything after it redeliver next
// flush. An unsupported status is 'skipped', not 'failed', so it never jams the
// cursor — it is acked past like any handled record.
//
// Returns the token string to persist/send, or null if nothing acked.
function applyFlushDecisions(repoRoot, records) {
  let result;
  try {
    result = applyServerDecisions(repoRoot, records);
  } catch (err) {
    process.stderr.write(
      `${YELLOW}[WARN]${RESET} could not apply sync_exceptions from server: ${err.message || 'error'}\n`
    );
    return null;
  }

  // Compute the high-water mark: stop at the first non-success or unusable ts.
  let mark = null;
  for (const rec of result.records) {
    if (rec.outcome === 'failed') break;
    const ua = rec.input && rec.input.updated_at;
    if (typeof ua !== 'string' || !ua) break;   // cannot ack a record we can't name
    mark = ua;                                    // verbatim — no Date round-trip
  }

  // Persist verbatim (store layer enforces monotonicity).
  if (mark) {
    try { require('./store').setSyncAckToken(repoRoot, mark); }
    catch { /* non-fatal — token simply not advanced this round */ }
  }

  // Quiet UX: only NEWLY applied decisions speak. No-op / alreadyApplied /
  // unknown stay completely silent (boundary redelivery happens every flush).
  const approvedNew = result.records.filter(r => r.outcome === 'applied' && r.input.status === 'approved');
  const rejectedNew = result.records.filter(r => r.outcome === 'applied' && r.input.status === 'rejected');

  if (approvedNew.length > 0) {
    const n = approvedNew.length;
    console.log(`${GREEN}✓ ${n} exception${n === 1 ? '' : 's'} approved by server${RESET}`);
  }
  if (rejectedNew.length > 0) {
    renderRejectedNotice(rejectedNew.map(r => r.input));
  }

  return mark;
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
    const { loadExceptions } = require('./exceptions-store');

    const exceptions = loadExceptions(repoRoot);   // Run 2 re-home: store, not config.yml
    const meta       = readMeta(repoRoot);

    // Exclude exceptions already handled by server (approved or rejected)
    const handled = new Set(Array.isArray(meta.handledExceptionIds) ? meta.handledExceptionIds : []);
    const pending = exceptions.filter(e => e.status === 'pending' && !handled.has(e.id));

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

    // Approvals/rejections now arrive automatically at every server contact
    // (scan/accept/doctor), so we no longer tell the user to run `scd sync`.
    return `${icon}${DIM} ${pending.length} exception(s) pending team-lead approval – ${age} · applied automatically once approved${RESET}`;
  } catch {
    return null;
  }
}

// ── List exceptions from local config ────────────────────────────────────

function listExceptions(repoRoot, statusFilter = 'all') {
  const { loadExceptions } = require('./exceptions-store');   // Run 2 re-home: store, not config.yml
  const exceptions = loadExceptions(repoRoot);

  const valid = ['pending', 'approved', 'rejected', 'archived', 'all'];
  if (!valid.includes(statusFilter)) {
    console.error(`${RED}✗ Invalid status: ${statusFilter}. Use: pending | approved | rejected | archived | all${RESET}`);
    process.exit(1);
  }

  // 'all' and the status filters show ACTIVE (non-archived) exceptions; archived
  // ones are terminal history shown only via --list archived (E1c.2).
  const list = statusFilter === 'archived'
    ? exceptions.filter(e => e.archived_at)
    : statusFilter === 'all'
      ? exceptions.filter(e => !e.archived_at)
      : exceptions.filter(e => e.status === statusFilter && !e.archived_at);


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
    if (ex.archived_at) console.log(`  ${DIM}Archived: ${RESET}${ex.archive_reason || 'archived'}  ${DIM}(${formatLocalDate(ex.archived_at)})${RESET}`);
    if (ex.reviewed_by)    console.log(`  ${DIM}Reviewed by: ${RESET}${ex.reviewed_by}`);
    if (ex.review_comment) console.log(`  ${DIM}Comment:     ${RESET}${ex.review_comment}`);
    if (!ex.archived_at && ex.status === 'rejected') {
      console.log(`  ${YELLOW}→ Rejected by team lead${RESET}  ${DIM}— fix the underlying code; this finding is flagged until then.${RESET}`);
    }
    console.log('');
  }
}

// ── Lifecycle: archive-with-reason (E1c.2) ──────────────────────────────────
// An exception is never deleted — it is archived WITH a reason, preserving the
// decision record and WHY it ended. Archive is CLI-local (per machine) in the
// first cut; a multi-machine sync of archive state is a deferred enhancement.

const ARCHIVE_REASONS = ['finding_resolved', 'review_expired', 'withdrawn', 'identity_changed'];

// Archive a single exception by id. Idempotent: an already-archived record is a
// no-op (the first reason wins — archiving is terminal). Returns
// { found, archived, already, error }.
function archiveException(repoRoot, id, reason) {
  if (!ARCHIVE_REASONS.includes(reason)) {
    return { found: false, archived: false, error: 'invalid archive reason: ' + reason };
  }
  const { loadExceptions, writeExceptions, withExceptionsLock } = require('./exceptions-store');
  // #170: lock the whole load→modify→write cycle — read inside the lock.
  return withExceptionsLock(repoRoot, () => {
    const records = loadExceptions(repoRoot);
    const rec = records.find(e => e.id === id);
    if (!rec) return { found: false, archived: false };
    if (rec.archived_at) return { found: true, archived: false, already: true };

    rec.archived_at     = new Date().toISOString();
    rec.archive_reason  = reason;
    writeExceptions(repoRoot, records);
    return { found: true, archived: true };
  });
}

// `scd exceptions withdraw <id>` — the non-destructive replacement for the retired
// `scd resolve --rejected`. Archives locally with reason 'withdrawn' (never
// deletes); the finding is no longer excepted by this record.
function withdrawException(repoRoot, id) {
  const r = archiveException(repoRoot, id, 'withdrawn');
  if (!r.found) {
    console.error(`\n${RED}✗ Exception ${id} not found.${RESET}`);
    console.error(`${DIM}   Run ${CYAN}scd exceptions${RESET}${DIM} to list local exceptions.${RESET}\n`);
    process.exit(1);
  }
  if (r.already) {
    console.log(`\n${DIM}Exception ${id} is already archived — nothing to do.${RESET}\n`);
    return;
  }
  console.log(`\n${GREEN}✓ Exception ${id} withdrawn${RESET}`);
  console.log(`${DIM}  Archived locally (reason: withdrawn). The finding is no longer excepted by it.${RESET}\n`);
}

// Auto-archive exceptions whose underlying finding was just resolved by scan
// evidence (findings-store pass 2). CLI-local, silent. Matched through the single
// gatekeeper so the same identity logic applies. A reopened finding (code returns)
// leaves the exception archived — the developer re-accepts if still wanted.
function archiveResolvedExceptions(repoRoot, resolvedFindings) {
  if (!Array.isArray(resolvedFindings) || resolvedFindings.length === 0) return { archived: 0 };
  const { loadExceptions, writeExceptions, withExceptionsLock } = require('./exceptions-store');
  const { reconcileException } = require('./exception-gatekeeper');

  // #170: lock the whole load→modify→write cycle — read inside the lock.
  return withExceptionsLock(repoRoot, () => {
    const records = loadExceptions(repoRoot);
    if (records.length === 0) return { archived: 0 };

    const now = new Date().toISOString();
    let archived = 0;
    for (const rf of resolvedFindings) {
      // Map the store-finding record (snake_case) to the gatekeeper's finding shape.
      const finding = {
        ruleId:   rf.rule_id,
        filePath: rf.file,
        codeHash: rf.code_hash,
        line:     rf.line,
        snippet:  rf.snippet,
      };
      const exc = reconcileException(finding, records).exception;  // archived ones are skipped already
      if (exc && !exc.archived_at) {
        exc.archived_at    = now;
        exc.archive_reason = 'finding_resolved';
        archived++;
      }
    }
    if (archived > 0) writeExceptions(repoRoot, records);
    return { archived };
  });
}

// Auto-archive exceptions whose effective expiry has passed (E1c.3): an explicit
// `expires` deadline, or a pending exception past its default TTL. Archives with
// reason 'review_expired'. CLI-local, called on scan. Read-time the gatekeeper
// already treats an expired exception as not-excepting; this persists the terminal
// state so it stops lingering and surfaces in `scd exceptions --list archived`.
function archiveExpiredExceptions(repoRoot) {
  const { loadExceptions, writeExceptions, withExceptionsLock } = require('./exceptions-store');
  const { effectiveExpiry } = require('./exception-gatekeeper');

  // #170: lock the whole load→modify→write cycle — read inside the lock.
  return withExceptionsLock(repoRoot, () => {
    const records = loadExceptions(repoRoot);
    if (records.length === 0) return { archived: 0 };

    const now = new Date();
    const stamp = now.toISOString();
    let archived = 0;
    for (const exc of records) {
      if (exc.archived_at) continue;
      const expiry = effectiveExpiry(exc);
      if (expiry && expiry < now) {
        exc.archived_at    = stamp;
        exc.archive_reason = 'review_expired';
        archived++;
      }
    }
    if (archived > 0) writeExceptions(repoRoot, records);
    return { archived };
  });
}

module.exports = {
  addException, addExceptionById, syncExceptions, pushPendingExceptions,
  reassertApprovedExceptions,
  getSyncNotice, listExceptions, applyServerDecisions, applyFlushDecisions,
  archiveException, withdrawException, archiveResolvedExceptions,
  archiveExpiredExceptions, ARCHIVE_REASONS,
};
