'use strict';
const { RESET, DIM, YELLOW } = require('./output-constants');
/**
 * cli-helpers.js — Shared CLI utilities used across multiple commands.
 *
 * Extracted from bin/scd.js during Phase 3 refactoring.
 * All functions were previously defined inline at the top of bin/scd.js.
 */

/**
 * Print a version warning if the local CLI is below the server's minimum
 * required version. Reads from cached value — no network call.
 * Non-fatal: only shown when a central URL is configured.
 * opts.toStderr — write to stderr instead of stdout (for hook mode)
 */
function warnIfOutdated(opts = {}) {
  try {
    // Only warn when a server is configured — not in standalone mode
    const globalCfg = require('./global-config');
    const url = globalCfg.getCentralUrl();
    if (!url) return;

    // Two mirror warnings: CLI too old (server's min_cli_version) and server too
    // old (CLI's MIN_SERVER_VERSION). Both read cached values — no network call.
    const { getVersionWarning, getServerVersionWarning } = require('./version-check');
    const out = opts.toStderr ? process.stderr : process.stdout;
    for (const warn of [getVersionWarning(), getServerVersionWarning()]) {
      if (warn) out.write('\n' + YELLOW + warn + RESET + '\n');
    }
  } catch { /* never break a command */ }
}

/**
 * Handles platform differences correctly:
 *   macOS  → open
 *   Linux  → xdg-open
 *   Windows → start with empty title arg to avoid new terminal window
 */
function openInBrowser(target) {
  const { spawn } = require('child_process');
  if (process.platform === 'darwin') {
    spawn('open', [target], { detached: true, stdio: 'ignore' }).unref();
  } else if (process.platform === 'win32') {
    // 'start' requires shell:true and empty string as window title
    // to avoid opening a new terminal window instead of the browser
    spawn('cmd', ['/c', 'start', '', target], { detached: true, stdio: 'ignore', shell: false }).unref();
  } else {
    spawn('xdg-open', [target], { detached: true, stdio: 'ignore' }).unref();
  }
}

/**
 * Awaitable push-queue flush — called before process.exit() in scan commands.
 * Non-blocking: resolves immediately if no central URL or empty queue.
 * opts.noSync — skip flush entirely (--no-sync flag)
 */
async function tryFlush(opts = {}) {
  if (opts.noSync) return;  // --no-sync: skip push to scd-server
  try {
    const { getCentralUrl } = require('./global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;
    const { flush } = require('./push-queue');

    const repoRoot = (() => {
      try { return require('./config').getRepoRoot(); } catch { return null; }
    })();

    // 1. Events queue flush FIRST. Events register the repo (and findings
    //    context) on the server that exceptions FK-reference — pushing an
    //    exception before the repo exists yields a first-contact 500
    //    (FOREIGN KEY constraint failed). See fix(delivery-order).
    //    (E1d) Always flush, even with an empty queue: pullDecisions makes the
    //    empty contact POST so server decisions (sync_exceptions) and cached
    //    version info reach the CLI without the user running `scd sync`. Queued
    //    events are preserved if the server is unreachable.
    const status = await flush(centralUrl, { repoRoot, pullDecisions: true });
    if (status === 'license_invalid') {
      console.log(YELLOW + '  ⚠  Server license invalid — scan data queued locally.' + RESET);
      console.log(DIM + '     Data will sync automatically when the license is restored.' + RESET);
      console.log(DIM + '     Contact your scd-server administrator.' + RESET);
    } else if (status === 'auth_failed') {
      // #67: a rejected token used to fail silently — surface it now.
      console.log(YELLOW + '  ⚠  Queued, but the server is rejecting your token — delivery is blocked.' + RESET);
      console.log(DIM + '     Re-create the token on the server, then: scd configure --token <token>' + RESET);
    }

    // 2. Exception tracker push/retry SECOND — the repo now exists server-side.
    //    Cheap when nothing is pending. Never throws into us — same
    //    offline-first philosophy as the event push queue.
    if (repoRoot) {
      try { await require('./exception-manager').pushPendingExceptions(repoRoot); }
      catch { /* quiet retry */ }
    }
  } catch { /* non-fatal */ }
}

module.exports = { warnIfOutdated, openInBrowser, tryFlush };
