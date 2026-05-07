/**
 * audit-sync.js
 * Sync audit.log history to scd-server.
 *
 * Used by `scd sync --history` to send existing local findings to the server.
 * Safe to re-run — server uses INSERT OR IGNORE (idempotent).
 *
 * What is synced:
 *   - findings_batch events reconstructed from FINDING_* events in audit.log
 *   - Grouped by session_id so each scan becomes one batch
 *   - scan_completed events for any sessions not already on the server
 *
 * What is NOT synced:
 *   - SCAN_STARTED, SCAN_PASSED, SCAN_BLOCKED (server already has these via push queue)
 *   - Events without a session_id
 */

'use strict';
const { RESET, YELLOW } = require('./output-constants');

const fs    = require('fs');
const store = require('./store');
const { EVENTS } = require('./audit');

const FINDING_EVENTS = new Set([
  EVENTS.FINDING_BLOCKED,
  EVENTS.FINDING_WARNED,
  EVENTS.FINDING_EXCEPTED,
  EVENTS.FINDING_EXCEPTION_EXPIRED,
]);

/**
 * Read entire audit.log without limit.
 */
function readFullAuditLog(repoRoot) {
  const p = store.auditPath(repoRoot);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8')
    .split('\n').filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

/**
 * Reconstruct findings_batch events from audit.log.
 * Groups FINDING_* events by session_id.
 * Returns array of findings_batch objects ready for push-queue.
 */
function buildFindingsBatches(events) {
  const sessions = new Map(); // session_id → { hook, ts, findings[] }

  for (const e of events) {
    if (!e.session_id) continue;
    if (!FINDING_EVENTS.has(e.event)) continue;

    if (!sessions.has(e.session_id)) {
      sessions.set(e.session_id, {
        session_id: e.session_id,
        hook:       e.hook || 'manual',
        ts:         e.timestamp,
        findings:   [],
      });
    }

    sessions.get(e.session_id).findings.push({
      rule_id:      e.rule_id,
      rule_name:    e.rule_name     || null,
      category:     e.category      || null,
      severity:     e.severity,
      file:         e.file,
      line:         e.line          || null,
      snippet:      e.snippet       || null,
      taint_source: e.taint_source  || null,
      excepted:     e.excepted      || false,
      blocked:      e.event === EVENTS.FINDING_BLOCKED,
      exception_id: e.exception_id  || null,
    });
  }

  // Return as findings_batch events, skip sessions with no findings
  return Array.from(sessions.values())
    .filter(s => s.findings.length > 0)
    .map(s => ({
      type:       'findings_batch',
      session_id: s.session_id,
      hook:       s.hook,
      ts:         s.ts,
      findings:   s.findings,
    }));
}

/**
 * Sync full audit.log history to scd-server.
 * Chunks into batches of 50 sessions to avoid huge payloads.
 * Returns { sessions, findings, errors }.
 */
async function syncHistory(repoRoot) {
  const { getCentralUrl, getCentralToken } = require('./global-config');
  const centralUrl = getCentralUrl();
  if (!centralUrl) {
    return { error: 'No scd-server configured. Run: scd configure --central-url <url>' };
  }

  const token = getCentralToken();
  if (!token) {
    return { error: 'No API token configured. Run: scd configure --central-url <url>' };
  }

  const identity = store.getRepoIdentity(repoRoot);
  const repoId   = store.getRepoId(repoRoot);
  const meta     = store.readMeta(repoRoot) || {};

  const events  = readFullAuditLog(repoRoot);
  if (events.length === 0) {
    return { sessions: 0, findings: 0, errors: 0, message: 'No audit log entries found.' };
  }

  const batches = buildFindingsBatches(events);
  if (batches.length === 0) {
    return { sessions: 0, findings: 0, errors: 0, message: 'No finding events in audit log.' };
  }

  // Chunk into groups of 10 sessions to keep payloads manageable
  const CHUNK_SIZE = 10;
  let totalFindings = 0;
  let totalErrors   = 0;

  for (let i = 0; i < batches.length; i += CHUNK_SIZE) {
    const chunk = batches.slice(i, i + CHUNK_SIZE);
    const chunkFindings = chunk.reduce((n, b) => n + b.findings.length, 0);

    try {
      const res = await fetch(centralUrl + '/api/v1/events/batch', {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': 'Bearer ' + token,
        },
        body: JSON.stringify({
          events: chunk,
          meta: {
            repoId:         repoId,
            repoName:       meta.name        || null,
            repoRemote:     meta.remote      || null,
            installationId: meta.installationId || null,
            hostname:       require('os').hostname(),
            platform:       process.platform,
            scdVersion:     require('../package.json').version,
          },
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      totalFindings += chunkFindings;
    } catch (err) {
      totalErrors++;
      console.error(`${YELLOW}  [sync] Chunk ${Math.floor(i/CHUNK_SIZE)+1} failed: ${err.message}${RESET}`);
    }
  }

  return {
    sessions: batches.length,
    findings: totalFindings,
    errors:   totalErrors,
  };
}

module.exports = { syncHistory, buildFindingsBatches, readFullAuditLog };
