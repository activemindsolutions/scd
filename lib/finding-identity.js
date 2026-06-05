/**
 * finding-identity.js — single source of truth for finding identity algorithms.
 *
 * THIS MODULE IS THE ONLY PLACE THESE ALGORITHMS MAY LIVE. Both scanners
 * (scanner-full, scanner-secrets) and any other site that needs to generate
 * or recompute a finding identity MUST import from here. No re-implementations.
 *
 *   makeFindingId(ruleId, filePath, lineRaw) → 'f-' + 10 hex chars
 *   makeCodeHash(lineRaw)                    → 32 hex chars
 *
 * ─── Why content-based ────────────────────────────────────────────────────
 *
 * Identity is content-based — derived from the RAW line content, never from
 * the line NUMBER. This is a locked design decision:
 *
 *   - CLAUDE.md #15 (code_hash): sha256(<raw line>).slice(0,32). Hashes the
 *     raw line ONLY; never includes filePath, line number, or any other field.
 *   - CLAUDE.md #16 (finding_id): content-based via makeFindingId in
 *     lib/finding-identity.js; line numbers are display-only and must never
 *     enter identity; never re-implement the algorithm outside this module.
 *   - DESIGN-findings-jsonl.md §3 / §5: a finding must survive a line shift
 *     without fragmenting its history in findings.jsonl. The reconciler trusts
 *     finding_id as the only identity; if identity changes when a line moves,
 *     resolve+reopen churn fragments the record per shift.
 *
 * The lesson originated with code_hash: scanner-full was always content-based;
 * scanner-secrets had drifted into a file-scoped variant (sha256(filePath+'|'+line)),
 * corrected 2026-06-02. finding_id had the same anti-pattern in scanner-secrets
 * (file + line NUMBER), discovered 2026-06-05 — same root cause, same fix:
 * one module, both algorithms.
 *
 * ─── Degenerate input (empty lineRaw) ─────────────────────────────────────
 *
 * Both functions accept `lineRaw === ''` and return a deterministic but
 * DEGENERATE value — every empty-line call within the same (ruleId, filePath)
 * returns the same id, and makeCodeHash('') returns sha256('').slice(0,32).
 * Degenerate values are kept out of the persistent store by the gate in
 * `lib/findings-store.js:updateFindings()` which skips findings with falsy
 * code_hash and logs [WARN]. The relic `: null` codeHash fallback in
 * scanner-full.js:138 is tracked in PROGRESS.md (post-pilot) and is the
 * mechanism that makes the degenerate id functionally unreachable in storage
 * and push payloads; this module need not (and must not) guard against
 * degeneracy itself.
 *
 * ─── Migration note ───────────────────────────────────────────────────────
 *
 * Existing stores hold position-based secrets ids written by the previous
 * scanner-secrets. The first secrets-covered scan AFTER this module lands
 * will: (a) not see the old id reported → resolve it, (b) insert the new
 * content-based id as a new record. One self-healing churn per persistent
 * secret finding. Documented and expected, no migration code required.
 */

'use strict';

const crypto = require('crypto');

/**
 * Stable, content-based identity for a finding.
 *
 * @param {string} ruleId   — rule's id field (e.g. 'SECRET-001').
 * @param {string} filePath — repo-relative file path. Keeps ids portable
 *                            across machines/users.
 * @param {string} lineRaw  — the RAW line content (un-trimmed). NEVER pass
 *                            a line number, a trimmed snippet, or anything
 *                            position-derived.
 * @returns {string} 'f-' + first 10 hex chars of sha256(ruleId|filePath|lineRaw).
 */
function makeFindingId(ruleId, filePath, lineRaw) {
  return 'f-' + crypto.createHash('sha256')
    .update((ruleId || '') + '|' + filePath + '|' + (lineRaw || ''))
    .digest('hex')
    .slice(0, 10);
}

/**
 * Content-based hash of the raw line. Lives here so updates touch one place.
 *
 * @param {string} lineRaw — the RAW line content. NEVER pass a trimmed
 *                           snippet or anything position-derived.
 * @returns {string} first 32 hex chars of sha256(lineRaw).
 */
function makeCodeHash(lineRaw) {
  return crypto.createHash('sha256')
    .update(lineRaw || '')
    .digest('hex')
    .slice(0, 32);
}

module.exports = { makeFindingId, makeCodeHash };
