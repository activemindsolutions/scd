/**
 * audit.js
 * Append-only audit trail for all security events.
 *
 * All data lives in ~/.scd/repos/{repoId}/
 * Nothing is written inside the user's git repository.
 *
 * Two files per repo:
 *   audit.log         – Full detail log (rule IDs, file paths, git user, machine)
 *   audit-summary.log – Anonymised statistics only (counts, dates, no paths)
 *
 * Future tiers (Team/Professional):
 *   Events pushed to scd-server via push queue (push-queue.js).
 *   The repo remains completely untouched.
 */

'use strict';

const fs     = require('fs');
const os     = require('os');
const crypto = require('crypto');
const store  = require('./store');

// ── Event types ────────────────────────────────────────────────────────────
const EVENTS = {
  SCAN_STARTED:              'scan_started',
  FINDING_BLOCKED:           'finding_blocked',
  FINDING_WARNED:            'finding_warned',
  FINDING_EXCEPTED:          'finding_excepted',
  FINDING_EXCEPTION_EXPIRED: 'finding_exception_expired',
  SCAN_PASSED:               'scan_passed',
  SCAN_BLOCKED:              'scan_blocked',
  CONFIG_LOADED:             'config_loaded',
  CONFIG_NOT_FOUND:          'config_not_found',
  RISK_ACCEPTED:             'risk_accepted',
  EXPOSURE_RESOLVED:         'exposure_resolved',
};

// ── Git user ───────────────────────────────────────────────────────────────
function getGitUser() {
  try {
    const { execSync } = require('child_process');
    const name  = execSync('git config user.name',  { encoding: 'utf8' }).trim();
    const email = execSync('git config user.email', { encoding: 'utf8' }).trim();
    return { name, email };
  } catch {
    return { name: 'unknown', email: 'unknown' };
  }
}

// ── Build base event ───────────────────────────────────────────────────────
function buildEvent(type, data = {}) {
  const gitUser = getGitUser();
  return {
    timestamp: new Date().toISOString(),
    event:     type,
    git_user:  gitUser.email,
    git_name:  gitUser.name,
    machine:   os.hostname(),
    platform:  process.platform,
    ...data,
  };
}

// ── Append event to full audit log ────────────────────────────────────────
function logEvent(repoRoot, type, data = {}) {
  try {
    const event = buildEvent(type, data);
    fs.appendFileSync(store.auditPath(repoRoot), JSON.stringify(event) + '\n');
    return event;
  } catch (err) {
    console.error(`\x1b[90m[scd] Audit log warning: ${err.message}\x1b[0m`);
  }
}

// ── Append anonymised entry to summary log ────────────────────────────────
function logSummaryEntry(repoRoot, summary) {
  try {
    fs.appendFileSync(store.auditSummaryPath(repoRoot), JSON.stringify(summary) + '\n');
  } catch (err) {
    console.error(`\x1b[90m[scd] Summary log warning: ${err.message}\x1b[0m`);
  }
}

// ── Log a complete scan session ────────────────────────────────────────────
function logScan(repoRoot, { hookType, files, findings, blocked, exceptions_applied, scanId, noSync }) {
  // Use the scanId from scan-cache (s-XXXXXXXX format) for full CLI↔server traceability.
  // Falls back to generating a random ID if called without one (e.g. from hooks).
  const sessionId = scanId || ('s-' + crypto.randomBytes(4).toString('hex'));

  store.updateMeta(repoRoot, {
    findingCount:  findings.length,
    criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
  });

  logEvent(repoRoot, EVENTS.SCAN_STARTED, {
    session_id:  sessionId,
    hook:        hookType,
    files_count: files.length,
    files:       files.map(f => f.filePath),
  });

  for (const f of findings) {
    const eventType = f.excepted
      ? (f.exception_expired ? EVENTS.FINDING_EXCEPTION_EXPIRED : EVENTS.FINDING_EXCEPTED)
      : (f.blocks ? EVENTS.FINDING_BLOCKED : EVENTS.FINDING_WARNED);

    logEvent(repoRoot, eventType, {
      session_id:   sessionId,
      hook:         hookType,
      rule_id:      f.ruleId,
      rule_name:    f.name,
      category:     f.category || null,
      severity:     f.severity,
      file:         f.filePath,
      line:         f.line,
      action:       f.action,
      excepted:     f.excepted || false,
      exception_id: f.exception?.id || null,
      exception_by: f.exception?.approved_by || null,
    });
  }

  const outcomeType = blocked ? EVENTS.SCAN_BLOCKED : EVENTS.SCAN_PASSED;
  logEvent(repoRoot, outcomeType, {
    session_id:         sessionId,
    hook:               hookType,
    total_findings:     findings.length,
    blocked_findings:   findings.filter(f => f.blocks && !f.excepted).length,
    excepted_findings:  findings.filter(f => f.excepted).length,
    expired_exceptions: findings.filter(f => f.exception_expired).length,
  });

  // Anonymised summary – counts only, no paths or identities
  logSummaryEntry(repoRoot, {
    date:               new Date().toISOString().slice(0, 10),
    session_id:         sessionId,
    hook:               hookType,
    files_scanned:      files.length,
    findings_total:     findings.length,
    findings_critical:  findings.filter(f => f.severity === 'CRITICAL').length,
    findings_high:      findings.filter(f => f.severity === 'HIGH').length,
    findings_exposure:  findings.filter(f => f.severity === 'EXPOSURE').length,
    blocked,
    exceptions_applied: findings.filter(f => f.excepted).length,
  });

  // ── Push queue integration ───────────────────────────────────────────────
  // If a central URL is configured, add a compact scan summary to the queue.
  // Push to scd-server (unless --no-sync or no central URL configured)
  if (!noSync) {
    try {
      const { getCentralUrl } = require('./global-config');
      const centralUrl = getCentralUrl();
      if (centralUrl) {
        const { enqueue } = require('./push-queue');

      // Build category breakdown: { "Injection (OWASP A03)": { critical, high, medium, exposure } }
      const categories = {};
      for (const f of findings) {
        if (!f.category) continue;
        if (!categories[f.category]) {
          categories[f.category] = { critical: 0, high: 0, medium: 0, exposure: 0 };
        }
        const sev = (f.severity || '').toLowerCase();
        if (categories[f.category][sev] !== undefined) {
          categories[f.category][sev]++;
        }
      }

      // Build top rules: [{ id, name, severity, count }] sorted by count desc, max 20
      const ruleCounts = {};
      for (const f of findings) {
        if (!f.ruleId) continue;
        if (!ruleCounts[f.ruleId]) {
          ruleCounts[f.ruleId] = { id: f.ruleId, name: f.name || f.ruleId, severity: f.severity, count: 0 };
        }
        ruleCounts[f.ruleId].count++;
      }
      const top_rules = Object.values(ruleCounts)
        .sort((a, b) => b.count - a.count)
        .slice(0, 20);

        enqueue({
          type:               'scan_completed',
          session_id:         sessionId,
          hook:               hookType,
          files_scanned:      files.length,
          findings_total:     findings.length,
          findings_critical:  findings.filter(f => f.severity === 'CRITICAL').length,
          findings_high:      findings.filter(f => f.severity === 'HIGH').length,
          findings_medium:    findings.filter(f => f.severity === 'MEDIUM').length,
          findings_exposure:  findings.filter(f => f.severity === 'EXPOSURE').length,
          blocked,
          exceptions_applied: findings.filter(f => f.excepted).length,
          categories,
          top_rules,
          ts:                 new Date().toISOString(),
        });
      }
    } catch {
      // Non-fatal — push queue is best-effort
    }
  }

  return sessionId;
}

// ── Read audit log ─────────────────────────────────────────────────────────
function readAuditLog(repoRoot, limit = 100) {
  const p = store.auditPath(repoRoot);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8')
    .split('\n').filter(Boolean).slice(-limit)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

// ── Read summary log ───────────────────────────────────────────────────────
function readSummaryLog(repoRoot, limit = 100) {
  const p = store.auditSummaryPath(repoRoot);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8')
    .split('\n').filter(Boolean).slice(-limit)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

// ── Quick summary for terminal ─────────────────────────────────────────────
function getRecentSummary(repoRoot) {
  const events = readAuditLog(repoRoot, 200);
  if (events.length === 0) return null;
  const scans    = events.filter(e => e.event === EVENTS.SCAN_STARTED);
  const blocked  = events.filter(e => e.event === EVENTS.FINDING_BLOCKED);
  const excepted = events.filter(e => e.event === EVENTS.FINDING_EXCEPTED);
  const expired  = events.filter(e => e.event === EVENTS.FINDING_EXCEPTION_EXPIRED);
  return {
    total_scans:        scans.length,
    total_blocked:      blocked.length,
    total_excepted:     excepted.length,
    expired_exceptions: expired.length,
    last_scan:          scans[scans.length - 1]?.timestamp,
  };
}

module.exports = {
  logEvent, logScan, readAuditLog, readSummaryLog, getRecentSummary, EVENTS,
};
