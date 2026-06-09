'use strict';
// lib/commands/queue.js
//
// `scd queue` — inspect and recover the offline-first push queue.
//
//   scd queue            default action = list
//   scd queue list       show both delivery channels
//   scd queue list --stale   only stale event entries
//   scd queue reset      make the whole queue deliverable again + try delivery
//
// Actions are subcommands; filters are flags (future filters like --type /
// --older-than hang off `list` later — not added here). The full stale-handling
// redesign (error-class taxonomy, doctor visibility with cause, `clear`) is a
// separate round; this file delivers the minimal recovery tooling only.

const { RESET, BOLD, DIM, GREEN, YELLOW, CYAN, OK } = require('../output-constants');

const SEP = '─'.repeat(72);
// Above this many deliverable (healthy) entries, list them as a count summary
// instead of one line each. Stale entries are ALWAYS shown in full — they are
// the actionable ones.
const HEALTHY_LINE_CAP = 20;

module.exports = { register, renderList, runReset };

// ── Helpers ──────────────────────────────────────────────────────────────────

// Storage stays UTC ISO-8601; human output shows local time. No shared
// formatLocalTime helper exists yet — a minimal inline local format is used
// here rather than printing raw UTC.
function fmtLocal(iso) {
  try { return new Date(iso).toLocaleString('en-SE'); } catch { return String(iso); }
}

function notConfigured(verb) {
  console.log('\n' + YELLOW + '  No central server configured' + RESET +
    DIM + ' — nothing ' + verb + ' without one.' + RESET);
  console.log(DIM + '    scd configure --central-url https://your-server:3000' + RESET + '\n');
}

function entryLine(e) {
  const type    = (e.event && e.event.type) || 'unknown';
  const marker  = e.stale ? (YELLOW + '⚠' + RESET) : (GREEN + OK + RESET);
  const staleTag = e.stale ? '  ' + YELLOW + 'stale: ' + e.reason + RESET : '';
  return '  ' + marker + '  ' +
    type.padEnd(18) +
    DIM + fmtLocal(e.ts).padEnd(22) + RESET +
    'attempts: ' + e.attempts +
    staleTag;
}

// ── list ─────────────────────────────────────────────────────────────────────

function renderList(opts = {}) {
  const { getCentralUrl } = require('../global-config');
  const centralUrl = getCentralUrl();
  if (!centralUrl) { notConfigured('queues'); return; }   // exit 0

  const pq           = require('../push-queue');
  const { cacheAge } = require('../scan-cache');
  const staleOnly    = !!opts.stale;

  const entries     = pq.listEntries();
  const deliverable = entries.filter(e => !e.stale);
  const stale       = entries.filter(e => e.stale);

  console.log('\n' + BOLD + 'Push queue' + RESET + '  ' + DIM + pq.QUEUE_PATH + RESET);
  console.log(DIM + 'Central URL: ' + RESET + CYAN + centralUrl + RESET);
  console.log(DIM + SEP + RESET);

  // ── Events channel ──
  if (entries.length === 0) {
    console.log('  ' + GREEN + OK + RESET + ' Events queue empty — all events synced.');
  } else {
    const oldest = entries.reduce((min, e) => (e.ts < min ? e.ts : min), entries[0].ts);
    console.log('  Events: ' + BOLD + entries.length + RESET + ' total  ' +
      DIM + '(' + RESET + GREEN + deliverable.length + ' deliverable' + RESET +
      DIM + ', ' + RESET + (stale.length ? YELLOW : DIM) + stale.length + ' stale' + RESET +
      DIM + ')' + RESET);
    console.log('  Oldest: ' + DIM + cacheAge(oldest) + RESET);
    console.log(DIM + SEP + RESET);

    if (staleOnly) {
      if (stale.length === 0) {
        console.log('  ' + GREEN + OK + RESET + ' No stale entries — queue is healthy.');
      } else {
        stale.forEach(e => console.log(entryLine(e)));
      }
    } else {
      // Stale entries always shown in full; healthy entries summarised when large.
      stale.forEach(e => console.log(entryLine(e)));
      if (deliverable.length <= HEALTHY_LINE_CAP) {
        deliverable.forEach(e => console.log(entryLine(e)));
      } else {
        console.log('  ' + GREEN + OK + RESET + '  ' + deliverable.length +
          ' deliverable event(s)' + DIM + ' (not listed individually)' + RESET);
      }
    }
  }

  // ── Exception channel (per-repo; no stale concept of its own) ──
  // Skipped in --stale mode, which is a focused view of stale events.
  if (!staleOnly) {
    try {
      const { getRepoRoot } = require('../config');
      const store    = require('../store');
      const repoRoot = getRepoRoot();
      if (store.isRepoKnown(repoRoot)) {
        const tracker = require('../exceptions-push-tracker');
        const pending = tracker.pendingCount(repoRoot);
        console.log(DIM + SEP + RESET);
        if (pending > 0) {
          const oldest = tracker.oldestQueuedAt(repoRoot);
          const age    = oldest ? cacheAge(oldest) : 'unknown';
          console.log('  Exceptions awaiting delivery: ' + BOLD + pending + RESET +
            DIM + '  (oldest: ' + age + ')' + RESET);
        } else {
          console.log('  ' + GREEN + OK + RESET + ' No exceptions awaiting delivery.');
        }
      }
    } catch { /* non-fatal — events channel already shown */ }
  }

  console.log('');
}

// ── reset ────────────────────────────────────────────────────────────────────

async function runReset() {
  const { getCentralUrl } = require('../global-config');
  if (!getCentralUrl()) { notConfigured('to reset'); return; }   // exit 0

  const pq = require('../push-queue');
  const { total, wereStale, ageStaleRemaining } = pq.resetAttempts();

  console.log('');
  if (total === 0) {
    console.log('  ' + GREEN + OK + RESET + ' Push queue is empty — nothing to reset.\n');
    return;
  }

  console.log('  ' + GREEN + OK + RESET + ' Reset ' + BOLD + total + RESET +
    ' event' + (total !== 1 ? 's' : '') +
    DIM + ' (' + wereStale + ' ' + (wereStale === 1 ? 'was' : 'were') + ' stale)' + RESET);

  if (ageStaleRemaining > 0) {
    console.log('  ' + YELLOW + '⚠' + RESET + '  ' + ageStaleRemaining + ' event' +
      (ageStaleRemaining !== 1 ? 's' : '') + ' still stale by age (> ' + pq.STALE_DAYS +
      ' days) — resetting attempts does not change age; these remain excluded.');
  }

  // One immediate, silent delivery attempt — the events-only flush primitive,
  // which also enforces the "events first" delivery order. repoRoot (when known)
  // lets flush echo the sync_exceptions ack token; null is fine standalone.
  let repoRoot = null;
  try {
    const { getRepoRoot } = require('../config');
    const store = require('../store');
    const r = getRepoRoot();
    if (store.isRepoKnown(r)) repoRoot = r;
  } catch { /* non-fatal — flush without repo context */ }

  const status = await pq.flushEvents(repoRoot);
  if (status === 'sent') {
    console.log('  ' + GREEN + OK + RESET + ' Delivered queued event(s) to central.\n');
  } else if (status === 'empty') {
    console.log('  ' + DIM + 'Nothing to deliver.' + RESET + '\n');
  } else {
    console.log('  ' + DIM + 'Server unreachable — queue kept, retried at next scan/sync/doctor.' + RESET + '\n');
  }
}

// ── Registration ─────────────────────────────────────────────────────────────

function register(program) {
  const { Command } = require('commander');

  const queueListCmd = new Command('list')
    .description('List events and exceptions waiting for the central server')
    .option('--stale', 'Show only stale event entries')
    .action((opts) => renderList(opts));

  const queueResetCmd = new Command('reset')
    .description('Reset delivery attempts on all queued events and retry delivery')
    .action(async () => { await runReset(); });

  const queueCmd = new Command('queue')
    .description('Inspect and recover the push queue')
    .action(() => renderList({}));   // default action = list

  queueCmd.addCommand(queueListCmd);
  queueCmd.addCommand(queueResetCmd);
  program.addCommand(queueCmd);
}
