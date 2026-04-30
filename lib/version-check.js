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

module.exports = { getVersionWarning };
