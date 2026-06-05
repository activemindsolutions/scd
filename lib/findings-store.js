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

function updateFindings(repoRoot, scanFindings, options = {}) {
  const { scanId, coverage, suppressed = [], scope = null } = options;

  // Compute branch context once per call. Both functions are safe outside git
  // (return null / 0).
  const branchVal = options.branch !== undefined
    ? options.branch
    : getCurrentBranch();
  const isDefBranchVal = options.isDefaultBranch !== undefined
    ? !!options.isDefaultBranch
    : !!isDefaultBranch(branchVal);

  // `at` overrides the "now" timestamp used for first_seen / last_seen — bootstrap
  // uses it to attribute historical findings to the original scan time, not to the
  // moment the store was materialized. Defaults to actual now for normal scans.
  const now = options.at !== undefined
    ? (options.at instanceof Date ? options.at.toISOString() : String(options.at))
    : new Date().toISOString();

  // RESOLVE-INVARIANT: coverage is REQUIRED to resolve. Bootstrap-on-read
  // (loadFindingsWithBootstrap) never passes coverage → pass 2 below is skipped →
  // no records get resolved during bootstrap. A cache is not coverage proof
  // (see docs/DESIGN-findings-jsonl.md §10 OQ-E). This invariant must be preserved.
  const resolveEnabled = !!coverage;

  // Build eligible-rule-set per ruleDomain (Decision A: coverage is source bucket only,
  // attached by the scanners post-OQ-B). A pre-commit (ruleDomain === 'secrets') must
  // never resolve a non-secrets finding — its rules never ran.
  let eligibleRuleIds = null;
  if (resolveEnabled) {
    if (coverage.ruleDomain === 'secrets') {
      const { RULES } = require('./scanner-secrets');
      eligibleRuleIds = new Set(RULES.map(r => r.id));
    } else if (coverage.ruleDomain === 'all') {
      const { getRegistry } = require('./rule-registry');
      eligibleRuleIds = new Set(getRegistry().map(r => r.id));
    } else {
      // Unknown ruleDomain → resolve nothing defensively. Absence-of-rule ≠ fix.
      eligibleRuleIds = new Set();
    }
  }
  const coveredFiles = resolveEnabled ? new Set(coverage.files || []) : null;

  // Presence evidence for the resolve gate.
  // activeIds: actively reported by the scan (drives refresh + reopen).
  // suppressedIds: detected but suppressed by file context — its rule RAN and matched,
  //                so its absence cannot be claimed; do NOT refresh (no active sighting)
  //                and do NOT resolve (suppression is not absence).
  const activeIds     = new Set();
  const suppressedIds = new Set();
  for (const f of scanFindings) if (f && f.findingId) activeIds.add(f.findingId);
  for (const f of suppressed)   if (f && f.findingId) suppressedIds.add(f.findingId);

  const existing = loadFindings(repoRoot);
  const byId     = new Map(existing.map(r => [r.finding_id, r]));

  let added = 0, refreshed = 0, skipped = 0, resolved = 0, reopened = 0;
  const resolvedRecords = [];
  const reopenedRecords = [];

  // Dedupe scanFindings by finding_id — scanner output can contain multiple
  // findings with the same identity in one scan (e.g. two identical secret
  // lines in the same file → same content → same finding_id but distinct
  // `line` values; design §4 explicitly allows this).
  // Spec (Step 1a): exactly one insert/refresh/reopen per identity per scan,
  // `line` from the FIRST occurrence (lowest line number, since scanners emit
  // in source order). The Step 2 restructure that introduced status-branching
  // lost this guarantee — repeated identities ran the loop body twice,
  // producing refresh-after-insert (or refresh-after-refresh, doubling
  // times_seen) and overwriting `line` with the last occurrence. Restored
  // here via a processed-ids set checked BEFORE the code_hash guard so
  // skipped-counting also respects per-identity uniqueness.
  const processedIds = new Set();

  // ── Pass 1 — process scanFindings (insert / refresh / reopen) ───────────
  for (const f of scanFindings) {
    if (!f || !f.findingId) continue;
    if (processedIds.has(f.findingId)) continue;   // first occurrence wins
    processedIds.add(f.findingId);
    if (!f.codeHash) {
      process.stderr.write(
        `${YELLOW}[WARN]${RESET} findings-store: skipping finding with null code_hash ` +
        `(rule=${f.ruleId || '?'} file=${f.filePath || '?'}:${f.line || '?'})\n`
      );
      skipped++;
      continue;
    }

    const prior = byId.get(f.findingId);

    if (!prior) {
      // INSERT — Step 1a logic preserved
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
      continue;
    }

    if (prior.status === 'open') {
      // REFRESH — Step 1a logic preserved (preserve unknown fields via spread)
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
    } else if (prior.status === 'resolved') {
      // REOPEN — finding has returned. Drop resolved_at; apply normal refresh fields;
      // bump reopen_count. last_seen + last_scan_id + times_seen all advance — this
      // IS an active sighting (distinct from resolve, which is absence-with-evidence).
      const { resolved_at, ...rest } = prior;
      const updated = {
        ...rest,
        status:            'open',
        reopen_count:      (prior.reopen_count || 0) + 1,
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
      reopened++;
      reopenedRecords.push(updated);
    }
    // Any other status ('excepted' or future) → untouched, verbatim
    // (instruction §2: "Records with any status other than open/resolved → untouched").
  }

  // ── Pass 2 — RESOLVE (only when coverage was provided) ──────────────────
  if (resolveEnabled) {
    const { isRuleExcluded } = scope ? require('./scope') : { isRuleExcluded: null };
    for (const [fid, record] of byId) {
      if (record.status !== 'open') continue;
      if (activeIds.has(fid)) continue;           // handled in pass 1
      if (suppressedIds.has(fid)) continue;       // suppression ≠ absence evidence
      if (!coveredFiles.has(record.file)) continue;
      if (!eligibleRuleIds.has(record.rule_id)) continue;
      if (isRuleExcluded) {
        const r = isRuleExcluded(scope, record.rule_id, record.file);
        if (r.excluded) continue;
      }
      // All guards pass → resolved.
      // last_seen / last_scan_id / times_seen are deliberately NOT updated — this is
      // absence-with-evidence, not a sighting. last_seen retains "last confirmed present".
      const updated = { ...record, status: 'resolved', resolved_at: now };
      byId.set(fid, updated);
      resolved++;
      resolvedRecords.push(updated);
    }
  }

  const allRecords = Array.from(byId.values());
  writeFindingsAtomic(repoRoot, allRecords);

  const totalOpen = allRecords.filter(r => r.status === 'open').length;

  return {
    added, refreshed, skipped, resolved, reopened,
    totalOpen,
    total: allRecords.length,
    resolvedRecords,
    reopenedRecords,
  };
}

/**
 * Read accumulated findings with bootstrap-on-read.
 *
 * Returns { records, bootstrapped, lastScanDate }.
 *
 *   - findings.jsonl exists → read it directly, lastScanDate from meta.json.
 *   - findings.jsonl missing but last-scan.json exists → bootstrap: feed
 *     cache.findings through updateFindings() using cache.scanDate as the
 *     timestamp (`at:` option), then read the resulting store. Marks
 *     bootstrapped=true so callers may log a release note one-shot if desired.
 *   - Neither exists → returns empty result with bootstrapped=false. Callers
 *     show "run scd scan first".
 *
 * Bootstrap is a one-time materialization per repo: the file exists after the
 * first call and subsequent calls take the direct read path.
 *
 * Decision rationale: see docs/DESIGN-findings-jsonl.md §10 OQ-E (2026-06-04).
 */
function loadFindingsWithBootstrap(repoRoot) {
  const target = findingsPathReadOnly(repoRoot);

  if (fs.existsSync(target)) {
    return {
      records:      loadFindings(repoRoot),
      bootstrapped: false,
      lastScanDate: getLastScanDate(repoRoot),
    };
  }

  // Bootstrap path — try last-scan.json
  const { loadCache } = require('./scan-cache');
  const cache = loadCache(repoRoot);

  if (!cache || !Array.isArray(cache.findings)) {
    return { records: [], bootstrapped: false, lastScanDate: null };
  }

  updateFindings(repoRoot, cache.findings, {
    scanId: cache.scanId,
    at:     cache.scanDate,
  });

  return {
    records:      loadFindings(repoRoot),
    bootstrapped: true,
    lastScanDate: cache.scanDate || null,
  };
}

function getLastScanDate(repoRoot) {
  const { readMeta } = require('./store');
  const meta = readMeta(repoRoot);
  return meta.lastScan || null;
}

module.exports = { loadFindings, updateFindings, loadFindingsWithBootstrap };
