/**
 * findings-store.js
 * Per-repo accumulated open-finding store at ~/.scd/repos/{repoId}/findings.jsonl
 *
 * Step 1a scope: insert + refresh paths only — no resolve, no reopen.
 *
 * Lifecycle:
 *   - loadFindings(repoRoot): reads findings.jsonl, returns array of records
 *     (empty array if file missing). Corrupt lines are skipped with a single
 *     [WARN] summary.
 *
 *   - updateFindings(repoRoot, scannerFindings, { scanId, branch, isDefaultBranch }):
 *     diffs scanner output against the store and writes back atomically.
 *       - finding_id present in store → refresh (preserve first_seen / status /
 *         reopen_count; update last_seen, last_scan_id, times_seen, snippet,
 *         severity, base_severity, line, branch, is_default_branch).
 *       - finding_id new → insert with status='open', times_seen=1, reopen_count=0.
 *     Existing records NOT in scannerFindings are preserved untouched.
 *     (Resolve/reopen reconciliation is Step 2.)
 *
 *   Returns { added, refreshed, skipped, total }.
 *
 * Invariants:
 *   - code_hash MUST be truthy. Findings with null/missing code_hash are skipped
 *     and a [WARN] is logged to stderr. (Defensive: a null code_hash indicates a
 *     scanner bug; see scanner-full.js:138 — the `: null` branch is a relic from
 *     the redaction era and should be removed in a follow-up.)
 *   - File mode 0o600, dir mode 0o700.
 *   - Atomic write: tmp → fsync → rename.
 *   - Forward-compatible: existing records are spread (`...prior`) so unknown
 *     fields written by a future version survive a downgrade-then-upgrade.
 *   - Empty result still writes an empty file — keeps the invariant that the
 *     store exists after any successful scan.
 */

'use strict';

const fs = require('fs');

const { findingsPath, findingsPathReadOnly } = require('./store');
const { getCurrentBranch, isDefaultBranch }  = require('./git-context');

// ANSI for [WARN] tag (tag-only, matching project convention)
const YELLOW = '\x1b[33m';
const RESET  = '\x1b[0m';

function loadFindings(repoRoot) {
  const target = findingsPathReadOnly(repoRoot);
  if (!fs.existsSync(target)) return [];

  let content;
  try {
    content = fs.readFileSync(target, 'utf8');
  } catch {
    return [];
  }

  const lines = content.split('\n').filter(l => l.length > 0);
  const records = [];
  let corrupt = 0;
  for (const line of lines) {
    try {
      records.push(JSON.parse(line));
    } catch {
      corrupt++;
    }
  }
  if (corrupt > 0) {
    process.stderr.write(
      `${YELLOW}[WARN]${RESET} findings.jsonl: ${corrupt} corrupt line(s) skipped\n`
    );
  }
  return records;
}

function writeFindingsAtomic(repoRoot, records) {
  const target = findingsPath(repoRoot);   // creates ~/.scd/repos/{id}/ at 0o700
  const tmp    = target + '.tmp';

  const body    = records.map(r => JSON.stringify(r)).join('\n');
  const content = records.length > 0 ? body + '\n' : '';

  // Open tmp with mode 0o600 (file creation only — chmod after rename is defensive)
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    if (content.length > 0) fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tmp, target);
  // Defensive: rename preserves source mode; chmod ensures invariant on edge platforms.
  try { fs.chmodSync(target, 0o600); } catch { /* best-effort */ }
}

function updateFindings(repoRoot, scannerFindings, options = {}) {
  const { scanId } = options;

  // Compute branch context once per call. Both functions are safe outside git
  // (return null / 0).
  const branchVal = options.branch !== undefined
    ? options.branch
    : getCurrentBranch();
  const isDefBranchVal = options.isDefaultBranch !== undefined
    ? !!options.isDefaultBranch
    : !!isDefaultBranch(branchVal);

  const existing = loadFindings(repoRoot);
  const byId     = new Map(existing.map(r => [r.finding_id, r]));
  const now      = new Date().toISOString();

  let added     = 0;
  let refreshed = 0;
  let skipped   = 0;

  for (const f of scannerFindings) {
    // Defensive: every scanner sets findingId — guard anyway
    if (!f || !f.findingId) continue;

    // Hard invariant: code_hash is required (server identity + exception matching).
    // scanner-full.js currently has a `: null` fallback (relic) when lineRaw is empty.
    if (!f.codeHash) {
      process.stderr.write(
        `${YELLOW}[WARN]${RESET} findings-store: skipping finding with null code_hash ` +
        `(rule=${f.ruleId || '?'} file=${f.filePath || '?'}:${f.line || '?'})\n`
      );
      skipped++;
      continue;
    }

    const prior = byId.get(f.findingId);
    if (prior) {
      // Refresh: preserve identity + history, update mutable fields.
      // Spread prior first so any forward-compatible fields written by a future
      // version survive a downgrade.
      const updated = {
        ...prior,
        last_seen:         now,
        last_scan_id:      scanId,
        times_seen:        (prior.times_seen || 0) + 1,
        snippet:           f.snippet,
        severity:          f.severity,
        base_severity:     f.base_severity !== undefined ? f.base_severity : f.severity,
        line:              f.line,
        branch:            branchVal,
        is_default_branch: isDefBranchVal,
      };
      if (f.confidence !== undefined) updated.confidence = f.confidence;
      byId.set(f.findingId, updated);
      refreshed++;
    } else {
      // Insert: new record. status='open' even for excepted findings —
      // exception state handling is Step 2.
      const record = {
        finding_id:        f.findingId,
        rule_id:           f.ruleId,
        file:              f.filePath,
        line:              f.line,
        code_hash:         f.codeHash,
        status:            'open',
        severity:          f.severity,
        base_severity:     f.base_severity !== undefined ? f.base_severity : f.severity,
        first_seen:        now,
        last_seen:         now,
        last_scan_id:      scanId,
        times_seen:        1,
        reopen_count:      0,
        snippet:           f.snippet,
        branch:            branchVal,
        is_default_branch: isDefBranchVal,
      };
      if (f.confidence !== undefined) record.confidence = f.confidence;
      byId.set(f.findingId, record);
      added++;
    }
  }

  const allRecords = Array.from(byId.values());
  writeFindingsAtomic(repoRoot, allRecords);

  return { added, refreshed, skipped, total: allRecords.length };
}

module.exports = { loadFindings, updateFindings };
