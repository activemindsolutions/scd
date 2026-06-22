/**
 * exceptions-store.js
 * Per-machine accumulated exception store at ~/.scd/repos/{repoId}/exceptions.jsonl
 *
 * E1a Run 1 scope: store format + bootstrap-on-read migration only.
 *   - This module materializes and owns exceptions.jsonl.
 *   - It does NOT re-home the writers (`writeException` / `updateExceptionStatus`)
 *     or the read consumers (gatekeeper, report, sync) — those still operate on
 *     config.yml. Switching consumers over is Run 2. Until then this module is
 *     dormant infrastructure: it can be invoked to build the store and verify the
 *     migration, but nothing in the live command paths calls it yet.
 *
 * Storage model (mirrors findings-store.js):
 *   - One JSON line per record. Atomic write via the shared jsonl-atomic helper
 *     (tmp → fsync → rename, file mode 0o600, dir 0o700).
 *   - Corrupt lines are skipped on read with a single [WARN] summary.
 *
 * Record format — DESIGN-exceptions-jsonl.md §2.1. Carries every field the
 * config.yml record carried (dropping one silently = status-by-absence, the axiom
 * this design prevents), with `created_date` (date-only) upgraded to `created_at`
 * (UTC ISO-8601). `finding_id` is intentionally NOT stored.
 *
 * Bootstrap-on-read — §2.2. On first read where exceptions.jsonl is absent and the
 * config still carries an `exceptions:` block (no migration marker), the block is
 * materialized to jsonl, verified by a three-check gate, and only then removed from
 * config.yml with the marker set in the SAME write. Gate failure leaves config
 * untouched and the bootstrap idempotent.
 */

'use strict';

const fs = require('fs');

const {
  exceptionsPath,
  exceptionsPathReadOnly,
  configPath,
} = require('./store');
const { writeJsonlAtomic } = require('./jsonl-atomic');

// ANSI for [WARN] tag (tag-only, matching project convention)
const YELLOW = '\x1b[33m';
const RESET  = '\x1b[0m';

const MIGRATION_MARKER = 'exceptions_migrated_to_jsonl';

// ── Read ────────────────────────────────────────────────────────────────────

function loadExceptions(repoRoot) {
  const target = exceptionsPathReadOnly(repoRoot);
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
      `${YELLOW}[WARN]${RESET} exceptions.jsonl: ${corrupt} corrupt line(s) skipped\n`
    );
  }
  return records;
}

// ── Write ─────────────────────────────────────────────────────────────────────

// Low-level write primitive: atomically replace the whole store with `records`.
// Full-set rewrite (read-all → mutate array → writeExceptions), NOT append —
// same semantics as findings-store. No match logic and no record construction
// live here: it writes exactly what it is given, so callers keep ownership of
// identity-match precedence (Run 2 Commit 2). Build records via
// buildExceptionRecord before passing them in.
//
// Concurrency: last-write-wins. This is a single-user, machine-local store in
// ~/.scd/ — the same race profile as findings.jsonl, a deliberate choice (no
// multi-writer coordination), not an oversight.
function writeExceptions(repoRoot, records) {
  const target = exceptionsPath(repoRoot);   // creates the store dir at 0o700
  writeJsonlAtomic(target, Array.isArray(records) ? records : []);
}

// ── Mapping: config.yml exception → jsonl record ─────────────────────────────

// `created_date` is a date-only string ("YYYY-MM-DD"). Upgrade to UTC ISO-8601 by
// pinning it to midnight UTC of that date — the original wrote no time component,
// so midnight UTC is the accepted approximation (§2.1).
function createdDateToUtcIso(d) {
  if (d == null || d === '') return new Date().toISOString();
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(d));
  if (m) return `${m[1]}-${m[2]}-${m[3]}T00:00:00.000Z`;
  // Already a full timestamp? Normalize through Date if parseable; else fall back.
  const t = Date.parse(String(d));
  if (!isNaN(t)) return new Date(t).toISOString();
  return new Date().toISOString();
}

// Canonical store-record builder (DESIGN §2.1). The single place the on-disk
// exception shape is defined — both the bootstrap mapper and (Run 2 Commit 2's)
// create-writer construct records through here, so the shape can never diverge.
//
// `fields` are already in store-format: `created_at` is UTC ISO-8601 (NOT the
// config-format `created_date` — callers normalize that before calling).
// Emit rules:
//   - line_hash included ONLY when present (omitted for redacted/hashless).
//   - finding_id NEVER stored (the latent isByFindingId gatekeeper branch stays
//     dormant); created_date never stored (config-format only). Both are
//     destructured out so a caller passing them does not leak them via `extra`.
//   - reserved fields (branch, archived_at/archive_reason, expires/review_date)
//     are not emitted by us — they ride through `extra` only if a caller
//     supplies them (E1b/E1c.2/E1c.3 forward-compat), never null-written.
//   - sync-augmented fields (db_id/reviewed_by/review_comment) present only when
//     supplied.
// Field order is fixed for stable, byte-comparable output.
function buildExceptionRecord(fields) {
  const {
    finding_id,                           // never stored (§2.1)
    created_date,                         // config-format only; store uses created_at
    id, type, tag, status, rule, file, line, line_hash, reason, created_at,
    db_id, reviewed_by, review_comment,
    archived_at, archive_reason,          // E1c.2 lifecycle terminal state
    ...extra                              // forward-compat: future/reserved fields preserved
  } = fields;

  const rec = { id: String(id) };
  if (type != null) rec.type = type;
  if (tag  != null) rec.tag  = tag;          // optional — omitted, never null-written
  if (status != null) rec.status = status;
  rec.rule = rule;
  rec.file = file;
  if (line != null) rec.line = line;
  if (line_hash != null) rec.line_hash = line_hash;   // optional (redacted findings omit it)
  if (reason != null) rec.reason = reason;
  rec.created_at = created_at != null ? created_at : createdDateToUtcIso(null);
  if (db_id != null) rec.db_id = db_id;
  if (reviewed_by != null) rec.reviewed_by = reviewed_by;
  if (review_comment != null) rec.review_comment = review_comment;
  if (archived_at != null) rec.archived_at = archived_at;          // E1c.2 — terminal
  if (archive_reason != null) rec.archive_reason = archive_reason;

  // Forward-compatibility: preserve any unrecognized fields verbatim. Reserved
  // names land here once their sub-tracks ship; finding_id and created_date were
  // destructured out above, so they never reach here.
  for (const [k, v] of Object.entries(extra)) {
    if (v != null) rec[k] = v;
  }

  return rec;
}

// Returns a jsonl record, or null when the config entry lacks the identity fields
// required to migrate it (id + rule + file). A null is NOT silently dropped: it
// produces a count mismatch that fails the verification gate, so an unmigratable
// entry blocks removal of the config block rather than losing data.
//
// Normalizes config-format fields (created_date → created_at) and delegates the
// canonical shape to buildExceptionRecord — one shape, two callers.
function mapConfigExceptionToRecord(ex) {
  if (!ex || !ex.id || !ex.rule || !ex.file) return null;

  const { created_date, ...rest } = ex;
  return buildExceptionRecord({
    ...rest,
    created_at: createdDateToUtcIso(created_date),
  });
}

// ── Verification gate (§2.2) ─────────────────────────────────────────────────

// All three checks must hold before config.yml is touched. `jsonlRecords` is the
// set re-read from disk after the atomic write, so a parse/write failure surfaces
// here as a count or identity mismatch (check 3 is implicit in the re-read).
function verifyBootstrapGate(jsonlRecords, configExceptions) {
  // 1. Count — nothing dropped (an unmigratable entry shows up as a shortfall).
  if (jsonlRecords.length !== configExceptions.length) {
    return { ok: false, reason: `count mismatch (jsonl ${jsonlRecords.length} vs config ${configExceptions.length})` };
  }

  // 2. Per-record identity intact — right content, not just right count.
  const byId = new Map(jsonlRecords.map(r => [r.id, r]));
  for (const ce of configExceptions) {
    const r = byId.get(ce.id != null ? String(ce.id) : ce.id);
    if (!r) return { ok: false, reason: `missing record for id ${ce.id}` };
    if (r.rule !== ce.rule || r.file !== ce.file) {
      return { ok: false, reason: `identity drift for id ${ce.id}` };
    }
    const ceHash = ce.line_hash != null ? ce.line_hash : null;
    const rHash  = r.line_hash  != null ? r.line_hash  : null;
    if (ceHash !== rHash) return { ok: false, reason: `line_hash drift for id ${ce.id}` };
  }

  // 3. Parseable / atomic write completed — guaranteed by jsonlRecords being the
  //    re-read of the file (a corrupt line would have been skipped → count fails).
  return { ok: true };
}

// ── Config rewrite: surgical block removal + marker (§2.2) ────────────────────

// Removes the `exceptions:` block and appends the migration marker in ONE write.
// Every other key is preserved verbatim — this is block-removal + marker-add on
// existing content, never a regenerate-from-scratch. Block lines are the
// `exceptions:` header plus all immediately-following indented lines; a blank or a
// top-level key ends the block.
function stripExceptionsBlockAndMark(repoRoot) {
  const cfgPath = configPath(repoRoot);
  const content = fs.readFileSync(cfgPath, 'utf8');
  const lines   = content.split('\n');
  const out     = [];

  let i = 0;
  while (i < lines.length) {
    if (/^exceptions:\s*$/.test(lines[i])) {
      i++;                                            // drop the 'exceptions:' header
      while (i < lines.length && /^\s/.test(lines[i])) i++;  // drop indented block lines
      continue;
    }
    out.push(lines[i]);
    i++;
  }

  // Trim trailing whitespace/newlines left by the removal, then append the marker
  // as a top-level key (single trailing newline). Key/value content is untouched.
  let body = out.join('\n').replace(/\s+$/, '');
  body += `\n${MIGRATION_MARKER}: true\n`;
  fs.writeFileSync(cfgPath, body, 'utf8');
}

// ── Bootstrap-on-read ─────────────────────────────────────────────────────────

/**
 * Read exceptions with bootstrap-on-read.
 *
 * Returns { records, bootstrapped, gateFailed? }.
 *
 *   - Marker set → migration already done → read exceptions.jsonl directly.
 *   - Marker absent + no config exceptions → nothing to migrate → read jsonl
 *     (empty for a fresh repo; surfaces a stray jsonl if one exists).
 *   - Marker absent + config has exceptions → bootstrap (or re-bootstrap after a
 *     crash): materialize jsonl, run the gate, and only on pass strip the config
 *     block + set the marker in one write. On gate failure the partial jsonl is
 *     removed and config is left intact, so the next read re-bootstraps cleanly.
 */
function loadExceptionsWithBootstrap(repoRoot) {
  const { loadConfig } = require('./config');
  const cfg = loadConfig(repoRoot);

  if (cfg[MIGRATION_MARKER] === true) {
    return { records: loadExceptions(repoRoot), bootstrapped: false };
  }

  const configExceptions = Array.isArray(cfg.exceptions) ? cfg.exceptions : [];
  if (configExceptions.length === 0) {
    return { records: loadExceptions(repoRoot), bootstrapped: false };
  }

  // Bootstrap / re-bootstrap.
  const mapped = configExceptions.map(mapConfigExceptionToRecord).filter(Boolean);
  const target = exceptionsPath(repoRoot);   // creates the store dir at 0o700
  writeJsonlAtomic(target, mapped);

  // Re-read from disk so the gate verifies what actually landed.
  const onDisk = loadExceptions(repoRoot);
  const gate   = verifyBootstrapGate(onDisk, configExceptions);

  if (!gate.ok) {
    try { fs.unlinkSync(target); } catch { /* best-effort */ }
    process.stderr.write(
      `${YELLOW}[WARN]${RESET} exceptions bootstrap verification failed ` +
      `(${gate.reason}); config.yml left intact, will retry on next read\n`
    );
    return { records: mapped, bootstrapped: false, gateFailed: true };
  }

  stripExceptionsBlockAndMark(repoRoot);
  return { records: onDisk, bootstrapped: true };
}

module.exports = {
  loadExceptions,
  loadExceptionsWithBootstrap,
  // Store write API (dormant — no live caller until Run 2 Commit 2):
  writeExceptions,
  buildExceptionRecord,
  // Exported for unit tests and potential Run 2 reuse:
  mapConfigExceptionToRecord,
  verifyBootstrapGate,
  MIGRATION_MARKER,
};
