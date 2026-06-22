'use strict';
// lib/exception-gatekeeper.js
//
// Single reconciling reader for finding ↔ exception status (design E1c.1).
//
// `excepted` is DERIVED at read time and NEVER persisted on a finding: detection
// truth (findings) and decision truth (exceptions) merge in exactly ONE place.
// Every finding read — scan-time and read-time — goes through reconcileException,
// so no code path can show a finding without knowing its exception status. This
// replaces the previously scattered isExcepted callsites (the Fix-1 two-readers /
// two-sources bug class, 2026-06-14).
//
// Contract:
//   reconcileException(finding, exceptions) → { excepted, exception, expired, rejected }
//
// - Derives from scratch. Never reads an incoming `finding.excepted`.
// - Takes the exceptions LIST directly (not a config object), decoupling it from
//   config.yml ahead of the machine-local store move (E1a).
// - code_hash is the primary match; ALL legacy fallbacks are preserved (32-char
//   exact, 16-char prefix, sha256 lineHash, rule+file+line, file+line_range).
//   Switching to a finding_id key is a separate later track — not here.
// - `lineContent` is NOT a parameter. It is only needed for the legacy sha256
//   lineHash branch and is derived internally from finding.snippet: hashLine
//   normalises (trim + collapse whitespace + quotes), so a trimmed snippet hashes
//   identically to the raw line, and a redacted secret snippet yields null — which
//   reproduces the prior read-time behaviour (rule+file+line fallback then applies).
// - Knows NOTHING about `blocks`. The caller computes blocking from status + policy.

const crypto = require('crypto');

// Legacy line hash (format 3): "sha256:{16hex}" of the normalised line. Only the
// legacy lineHash branch consumes it; modern exceptions match on code_hash.
function hashLine(rawLine) {
  const normalized = rawLine
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/"/g, "'");
  return 'sha256:' + crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

const PENDING_TTL_DAYS = 14;

// The instant an exception stops applying (E1c.3). An explicit `expires` wins;
// otherwise a PENDING exception gets a default TTL from created_at — pending
// expires tighter to force a decision rather than float indefinitely. Approved or
// legacy exceptions without an explicit `expires` never auto-expire. Returns a
// Date, or null = never expires.
function effectiveExpiry(exc) {
  if (exc.expires) {
    const d = new Date(exc.expires);
    return isNaN(d.getTime()) ? null : d;
  }
  if (exc.status === 'pending' && exc.created_at) {
    const c = new Date(exc.created_at);
    if (!isNaN(c.getTime())) return new Date(c.getTime() + PENDING_TTL_DAYS * 86400000);
  }
  return null;
}

// Verdict for an exception whose identity ALREADY matches the finding. Order:
// expired → rejected → approved → pending/unknown. Only `approved` excepts (§7,
// E1c.4): an un-approved acceptance must NOT silently suppress its finding — it
// stays valid/blocking until a team-lead approves it.
function matchVerdict(exc) {
  const expiry = effectiveExpiry(exc);
  if (expiry && expiry < new Date()) {
    return { excepted: false, exception: exc, expired: true, rejected: false };
  }
  if (exc.status === 'rejected') {
    return { excepted: false, exception: exc, expired: false, rejected: true };
  }
  if (exc.status === 'approved') {
    return { excepted: true, exception: exc, expired: false, rejected: false };
  }
  return { excepted: false, exception: exc, expired: false, rejected: false, pending: true };
}

function reconcileException(finding, exceptions) {
  // lineContent is needed only for the legacy sha256 lineHash branch. Derive it
  // from the finding's snippet; a redacted secret ('[REDACTED]') has no usable
  // content → null (the rule+file+line fallback then applies, as before).
  const lineContent = (finding.snippet && finding.snippet !== '[REDACTED]') ? finding.snippet : null;
  const lineHash    = lineContent ? hashLine(lineContent) : null;

  for (const exc of exceptions || []) {
    if (exc.rule !== finding.ruleId) continue;

    // Archived exceptions are terminal (E1c.2): they never except — the finding is
    // valid again. The archive_reason is retained on the record for traceability,
    // but it plays no part in the live excepted/rejected decision.
    if (exc.archived_at) continue;

    // Expiry is checked per-match (matchVerdict), AFTER identity is confirmed —
    // never before, so an expired exception for a different file cannot mislabel
    // an unrelated finding as expired.

    // Normalise file paths for comparison
    const ne = exc.file         ? exc.file.replace(/\\/g, '/').replace(/^\.\//, '')         : null;
    const nf = finding.filePath ? finding.filePath.replace(/\\/g, '/').replace(/^\.\//, '') : null;
    const fileMatches = ne && nf && (nf === ne || nf.endsWith('/' + ne));

    // Hash match — three formats supported:
    // 1. codeHash (32-char hex): stored by addExceptionById — exact match against finding.codeHash
    // 2. Legacy 16-char hex: old addException computed sha256.slice(0,16) from file content.
    //    These are a prefix of finding.codeHash (which is sha256.slice(0,32) of the same content).
    // 3. hashLine() format "sha256:{16hex}": stored by legacy addException path
    const codeHashMatches = exc.line_hash && finding.codeHash && (
      exc.line_hash === finding.codeHash ||                                        // format 1: exact 32-char
      (exc.line_hash.length === 16 && finding.codeHash.startsWith(exc.line_hash))  // format 2: legacy 16-char prefix
    );
    const lineHashMatches = exc.line_hash && lineHash &&
      exc.line_hash === lineHash;

    if ((codeHashMatches || lineHashMatches) && fileMatches) {
      return matchVerdict(exc);
    }

    // Fallback: line_hash exists in config but lineContent was empty (e.g. secrets rules
    // that redact lineRaw). Match on rule + file + line instead — the hash cannot be verified
    // but the finding is specific enough to match safely.
    if (exc.line_hash && !lineHash && fileMatches && exc.line != null && finding.line === exc.line) {
      return matchVerdict(exc);
    }

    // File + line_range match (no hash)
    if (!exc.line_hash && fileMatches) {
      if (Array.isArray(exc.line_range) && finding.line != null) {
        const [from, to] = exc.line_range;
        if (finding.line >= from && finding.line <= to) {
          return matchVerdict(exc);
        }
        continue;
      }
      return matchVerdict(exc);
    }
  }

  return { excepted: false, exception: null, expired: false, rejected: false };
}

module.exports = { reconcileException, effectiveExpiry, PENDING_TTL_DAYS };
