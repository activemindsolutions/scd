'use strict';

/**
 * version-check.js
 * Compares the local scd version against the server's minimum required version.
 * Used by interactive commands to warn when the CLI needs upgrading.
 *
 * The server's min_cli_version is cached in ~/.scd/config after each successful
 * batch flush or health check — no extra network call needed at command time.
 */

const pkg = require('../package.json');

// The oldest scd-server this CLI is built to interoperate with — the mirror of the
// server's MIN_CLI_VERSION. The server warns when the CLI is too old; the CLI warns
// when the server is too old. This is a WARNING, not a hard block: the CLI still
// degrades gracefully against an older server, but flags that some features
// (e.g. the full sync_exceptions contract) may not work until it is upgraded.
const MIN_SERVER_VERSION = '1.3.0';

function semverLt(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0, nb = pb[i] || 0;
    if (na < nb) return true;
    if (na > nb) return false;
  }
  return false; // equal
}

/**
 * Returns a warning string if the local CLI version is below the server's
 * minimum required version, or null if everything is fine or no server info
 * is cached yet.
 */
function getVersionWarning() {
  try {
    const { getMinCliVersion, getServerVersion } = require('./global-config');
    const minVer = getMinCliVersion();
    if (!minVer) return null;                          // no server info cached yet
    if (!semverLt(pkg.version, minVer)) return null;  // up to date

    const serverVer = getServerVersion();
    const serverPart = serverVer ? ` (server: v${serverVer})` : '';
    return `⚠  scd v${pkg.version} is outdated — scd-server requires v${minVer} or later${serverPart}.\n` +
           `   Run: npm install -g @activemind/scd`;
  } catch {
    return null; // never let this break a command
  }
}

/**
 * Returns a warning string if the cached scd-server version is below the minimum
 * this CLI expects (MIN_SERVER_VERSION), or null if the server is new enough or no
 * server version is cached yet. Mirror of getVersionWarning (CLI-too-old).
 */
function getServerVersionWarning() {
  try {
    const { getServerVersion } = require('./global-config');
    const serverVer = getServerVersion();
    if (!serverVer) return null;                              // no server info cached yet
    if (!semverLt(serverVer, MIN_SERVER_VERSION)) return null; // server new enough

    return `⚠  scd-server v${serverVer} is older than this scd (v${pkg.version}) expects ` +
           `(v${MIN_SERVER_VERSION}+).\n` +
           `   Some features may not work fully until scd-server is upgraded.`;
  } catch {
    return null; // never let this break a command
  }
}

module.exports = { getVersionWarning, getServerVersionWarning, MIN_SERVER_VERSION };
