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
    console.log('\n\x1b[90m Ingen audit-logg hittad ännu.\x1b[0m\n');
    return;
  }

  console.log(`\n${CYAN}${BOLD}╔══════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}${BOLD}║     Security Copilot – Audit Report      ║${RESET}`);
  console.log(`${CYAN}${BOLD}╚══════════════════════════════════════════╝${RESET}\n`);

  // ── Stats ────────────────────────────────────────────────────────────────
  const scans     = events.filter(e => e.event === EVENTS.SCAN_STARTED);
  const blocked   = events.filter(e => e.event === EVENTS.FINDING_BLOCKED);
  const warned    = events.filter(e => e.event === EVENTS.FINDING_WARNED);
  const excepted  = events.filter(e => e.event === EVENTS.FINDING_EXCEPTED);
  const expired   = events.filter(e => e.event === EVENTS.FINDING_EXCEPTION_EXPIRED);
  const scanBlocked = events.filter(e => e.event === EVENTS.SCAN_BLOCKED);

  console.log(`${BOLD}Sammanfattning${RESET}`);
  console.log(`  Totalt antal scanningar:     ${scans.length}`);
  console.log(`  Blockerade scanningar:       ${RED}${scanBlocked.length}${RESET}`);
  console.log(`  Blockerade findings:         ${RED}${blocked.length}${RESET}`);
  console.log(`  Varnade findings:            ${YELLOW}${warned.length}${RESET}`);
  console.log(`  Undantagna findings:         ${DIM}${excepted.length}${RESET}`);

  if (expired.length > 0) {
    console.log(`  ${RED}${BOLD}Utgångna undantag:           ${expired.length} – kräver åtgärd!${RESET}`);
  }

  // ── Expired exceptions – these need immediate attention ──────────────────
  if (expired.length > 0) {
    console.log(`\n${RED}${BOLD}⚠️  Utgångna undantag – kräver omedelbar åtgärd${RESET}`);
    console.log(`${RED}${'─'.repeat(50)}${RESET}`);
    for (const e of expired.slice(-10)) {
      console.log(`  ${e.timestamp.slice(0, 10)}  ${e.rule_id}  ${e.file}:${e.line}`);
      console.log(`  ${DIM}Undantag godkänt av: ${e.exception_by || 'okänd'}${RESET}`);
    }
  }

  // ── Recent blocked findings ───────────────────────────────────────────────
  if (blocked.length > 0) {
    console.log(`\n${BOLD}Senaste blockerade findings${RESET}`);
    console.log(`${'─'.repeat(50)}`);
    for (const e of blocked.slice(-10)) {
      const date = e.timestamp.slice(0, 16).replace('T', ' ');
      console.log(`  ${DIM}${date}${RESET}  ${RED}${e.severity}${RESET}  ${e.rule_id}`);
      console.log(`  ${DIM}${e.file}:${e.line}  [${e.git_user}]${RESET}`);
    }
  }

  // ── Active exceptions ─────────────────────────────────────────────────────
  if (excepted.length > 0) {
    console.log(`\n${BOLD}Aktiva undantag (senaste körningarna)${RESET}`);
    console.log(`${'─'.repeat(50)}`);

    // Deduplicate by rule+file
    const seen = new Set();
    for (const e of excepted.slice(-20)) {
      const key = `${e.rule_id}:${e.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const date = e.timestamp.slice(0, 10);
      console.log(`  ${DIM}${date}${RESET}  ${YELLOW}${e.rule_id}${RESET}  ${e.file}`);
      console.log(`  ${DIM}Godkänt av: ${e.exception_by || 'ej angiven'}${RESET}`);
    }
    console.log(`\n  ${DIM}Kör 'security-copilot approve --list' för fullständig lista${RESET}`);
  }

  // ── Recent scan history ───────────────────────────────────────────────────
  console.log(`\n${BOLD}Senaste scanningar${RESET}`);
  console.log(`${'─'.repeat(50)}`);
  for (const e of scans.slice(-5)) {
    const date = e.timestamp.slice(0, 16).replace('T', ' ');
    const outcome = scanBlocked.find(b => b.session_id === e.session_id);
    const icon = outcome ? `${RED}🚫${RESET}` : `${GREEN}✅${RESET}`;
    console.log(`  ${icon}  ${DIM}${date}${RESET}  ${e.hook}  ${e.files_count} fil(er)  [${e.git_user}]`);
  }

  console.log('');
}

module.exports = { showAuditReport };
