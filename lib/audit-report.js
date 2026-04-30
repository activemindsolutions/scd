/**
 * audit-report.js
 * Human-readable terminal report of the audit log.
 * Shows findings history, exceptions, expired exceptions.
 */

const { readAuditLog, EVENTS } = require('./audit');

const RESET = '\x1b[0m';
const BOLD  = '\x1b[1m';
const DIM   = '\x1b[90m';
const RED   = '\x1b[31m';
const GREEN = '\x1b[32m';
const CYAN  = '\x1b[36m';
const YELLOW = '\x1b[33m';

async function showAuditReport(repoRoot, limit = 50) {
  const events = readAuditLog(repoRoot, 500);

  if (events.length === 0) {
    console.log('\n\x1b[90m No audit log found yet.\x1b[0m\n');
    return;
  }

  console.log(`\n${CYAN}${BOLD}╔══════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}${BOLD}║     Secure Code by Design – Audit Report  ║${RESET}`);
  console.log(`${CYAN}${BOLD}╚══════════════════════════════════════════╝${RESET}\n`);

  // ── Stats ────────────────────────────────────────────────────────────────
  const scans     = events.filter(e => e.event === EVENTS.SCAN_STARTED);
  const blocked   = events.filter(e => e.event === EVENTS.FINDING_BLOCKED);
  const warned    = events.filter(e => e.event === EVENTS.FINDING_WARNED);
  const excepted  = events.filter(e => e.event === EVENTS.FINDING_EXCEPTED);
  const expired   = events.filter(e => e.event === EVENTS.FINDING_EXCEPTION_EXPIRED);
  const scanBlocked = events.filter(e => e.event === EVENTS.SCAN_BLOCKED);

  console.log(`${BOLD}Summary${RESET}`);
  console.log(`  Total scans:              ${scans.length}`);
  console.log(`  Blocked scans:            ${RED}${scanBlocked.length}${RESET}`);
  console.log(`  Blocked findings:         ${RED}${blocked.length}${RESET}`);
  console.log(`  Warned findings:          ${YELLOW}${warned.length}${RESET}`);
  console.log(`  Excepted findings:        ${DIM}${excepted.length}${RESET}`);

  if (expired.length > 0) {
    console.log(`  ${RED}${BOLD}Expired exceptions:        ${expired.length} – action required!${RESET}`);
  }

  // ── Expired exceptions – these need immediate attention ──────────────────
  if (expired.length > 0) {
    console.log(`\n${RED}${BOLD}⚠️  Expired exceptions – immediate action required${RESET}`);
    console.log(`${RED}${'─'.repeat(50)}${RESET}`);
    for (const e of expired.slice(-10)) {
      console.log(`  ${e.timestamp.slice(0, 10)}  ${e.rule_id}  ${e.file}:${e.line}`);
      console.log(`  ${DIM}Exception approved by: ${e.exception_by || 'unknown'}${RESET}`);
    }
  }

  // ── Recent blocked findings ───────────────────────────────────────────────
  if (blocked.length > 0) {
    console.log(`\n${BOLD}Recent blocked findings${RESET}`);
    console.log(`${'─'.repeat(50)}`);
    for (const e of blocked.slice(-10)) {
      const date = e.timestamp.slice(0, 16).replace('T', ' ');
      console.log(`  ${DIM}${date}${RESET}  ${RED}${e.severity}${RESET}  ${e.rule_id}`);
      console.log(`  ${DIM}${e.file}:${e.line}  [${e.git_user}]${RESET}`);
    }
  }

  // ── Active exceptions ─────────────────────────────────────────────────────
  if (excepted.length > 0) {
    console.log(`\n${BOLD}Active exceptions (recent runs)${RESET}`);
    console.log(`${'─'.repeat(50)}`);

    // Deduplicate by rule+file
    const seen = new Set();
    for (const e of excepted.slice(-20)) {
      const key = `${e.rule_id}:${e.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const date = e.timestamp.slice(0, 10);
      console.log(`  ${DIM}${date}${RESET}  ${YELLOW}${e.rule_id}${RESET}  ${e.file}`);
      console.log(`  ${DIM}Approved by: ${e.exception_by || 'not specified'}${RESET}`);
    }
    console.log(`\n  ${DIM}Run 'scd approve --list' for full list${RESET}`);
  }

  // ── Recent scan history ───────────────────────────────────────────────────
  console.log(`\n${BOLD}Recent scans${RESET}`);
  console.log(`${'─'.repeat(50)}`);
  for (const e of scans.slice(-5)) {
    const date = e.timestamp.slice(0, 16).replace('T', ' ');
    const outcome = scanBlocked.find(b => b.session_id === e.session_id);
    const icon = outcome ? `${RED}🚫${RESET}` : `${GREEN}✅${RESET}`;
    console.log(`  ${icon}  ${DIM}${date}${RESET}  ${e.hook}  ${e.files_count} file(s)  [${e.git_user}]`);
  }

  console.log('');
}

module.exports = { showAuditReport };
