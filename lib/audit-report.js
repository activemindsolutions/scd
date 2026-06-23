const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('./output-constants');
/**
 * audit-report.js
 * Human-readable terminal report of the audit log.
 * Shows findings history, exceptions, expired exceptions.
 */

const { readAuditLog, EVENTS } = require('./audit');
const { formatLocalTime, formatLocalDate } = require('./format-time');

async function showAuditReport(repoRoot, limit = 50) {
  const events = readAuditLog(repoRoot, 500);

  if (events.length === 0) {
    console.log(DIM + '\n No audit log found yet.' + RESET + '\n');
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
    console.log(`\n${RED}${BOLD}⚠  Expired exceptions – immediate action required${RESET}`);
    console.log(`${RED}${'─'.repeat(50)}${RESET}`);
    for (const e of expired.slice(-10)) {
      console.log(`  ${formatLocalDate(e.timestamp)}  ${e.rule_id}  ${e.file}:${e.line}`);
      console.log(`  ${DIM}Exception approved by: ${e.exception_by || 'unknown'}${RESET}`);
    }
  }

  // ── Recent blocked findings ───────────────────────────────────────────────
  if (blocked.length > 0) {
    console.log(`\n${BOLD}Recent blocked findings${RESET}`);
    console.log(`${'─'.repeat(50)}`);
    for (const e of blocked.slice(-10)) {
      const date = formatLocalTime(e.timestamp);
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
      const date = formatLocalDate(e.timestamp);
      console.log(`  ${DIM}${date}${RESET}  ${YELLOW}${e.rule_id}${RESET}  ${e.file}`);
      console.log(`  ${DIM}Approved by: ${e.exception_by || 'not specified'}${RESET}`);
    }
    console.log(`\n  ${DIM}Run 'scd exceptions' for full list${RESET}`);
  }

  // ── Recent scan history ───────────────────────────────────────────────────
  console.log(`\n${BOLD}Recent scans${RESET}`);
  console.log(`${'─'.repeat(50)}`);
  for (const e of scans.slice(-5)) {
    const date = formatLocalTime(e.timestamp);
    const outcome = scanBlocked.find(b => b.session_id === e.session_id);
    const icon = outcome ? `${RED}✗${RESET}` : `${GREEN}✓${RESET}`;
    console.log(`  ${icon}  ${DIM}${date}${RESET}  ${e.hook}  ${e.files_count} file(s)  [${e.git_user}]`);
  }

  console.log('');
}

module.exports = { showAuditReport };
