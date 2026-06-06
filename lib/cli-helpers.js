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

    const { getVersionWarning } = require('./version-check');
    const warn = getVersionWarning();
    if (warn) {
      const out = opts.toStderr ? process.stderr : process.stdout;
      out.write('\n' + YELLOW + warn + RESET + '\n');
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
    const { getCentralUrl, getCentralToken, getMinCliVersion, setServerVersionInfo } = require('./global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;
    const { flush, queueSize } = require('./push-queue');

    const repoRoot = (() => {
      try { return require('./config').getRepoRoot(); } catch { return null; }
    })();

    // 1. Events queue flush FIRST. Events register the repo (and findings
    //    context) on the server that exceptions FK-reference — pushing an
    //    exception before the repo exists yields a first-contact 500
    //    (FOREIGN KEY constraint failed). See fix(delivery-order).
    if (queueSize() > 0) {
      const status = await flush(centralUrl, { repoRoot });
      if (status === 'license_invalid') {
        console.log(YELLOW + '  ⚠  Server license invalid — scan data queued locally.' + RESET);
        console.log(DIM + '     Data will sync automatically when the license is restored.' + RESET);
        console.log(DIM + '     Contact your scd-server administrator.' + RESET);
      }
    } else if (!getMinCliVersion()) {
      // Queue empty — fetch version info if not yet cached. Fire-and-forget:
      // never blocks or throws.
      const token   = getCentralToken();
      const baseUrl = centralUrl.replace(/\/$/, '');
      const http    = baseUrl.startsWith('https') ? require('https') : require('http');
      new Promise((resolve) => {
        const req = http.get(
          baseUrl + '/api/v1/health',
          { headers: token ? { 'Authorization': `Bearer ${token}` } : {}, timeout: 4000 },
          (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
              try {
                const body = JSON.parse(data);
                if (body.version || body.min_cli_version) {
                  setServerVersionInfo(body.version || null, body.min_cli_version || null);
                }
              } catch { /* ignore */ }
              resolve();
            });
          }
        );
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.on('error', () => resolve());
      }).catch(() => {});
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
