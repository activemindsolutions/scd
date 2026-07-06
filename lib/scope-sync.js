'use strict';

/**
 * scope-sync.js
 * Push the repo's current scope to scd-server so it can shed / suppress the
 * findings the CLI now excludes (#239).
 *
 * We send the scope RULES (patterns + rule ids, with their audit fields), never a
 * resolved file list — the server matches its own findings against them (the v6
 * datamodel work showed resolved-list payloads blow up on large scans). The server
 * persists the scope (repo_config) and returns how many findings it scoped /
 * un-scoped.
 *
 * Offline-first and quiet on error — same philosophy as the exception push queue:
 * a missing server / bad token must never break a local `scd repo scope` edit.
 */

function pushScope(repoRoot) {
  const result = { sent: false, scoped: 0, unscoped: 0 };

  let centralUrl, token;
  try {
    const { getCentralUrl, getCentralToken } = require('./global-config');
    centralUrl = getCentralUrl();
    if (!centralUrl) return Promise.resolve(result);   // standalone — nothing to sync
    token = getCentralToken();
    if (!token) return Promise.resolve(result);
  } catch {
    return Promise.resolve(result);
  }

  let repoId, scope;
  try {
    repoId = require('./store').getRepoId(repoRoot);
    const { loadScope } = require('./scope');
    scope = loadScope(repoRoot) || { file_excludes: [], rule_excludes: [] };
  } catch {
    return Promise.resolve(result);
  }

  // Push what the CLI itself authored (repo + global) — not scope the server sent
  // down (scope-server.yml), to avoid echoing the server's own rules back at it.
  const notServer = (e) => !e || e._source !== 'server';
  const body = JSON.stringify({
    file_excludes: (scope.file_excludes || []).filter(e => e && e.pattern && notServer(e)).map(e => ({
      pattern: e.pattern, reason: e.reason || null, added_by: e.added_by || null, added_at: e.added_at || null,
    })),
    rule_excludes: (scope.rule_excludes || []).filter(e => e && e.rule && notServer(e)).map(e => ({
      rule: e.rule, files: e.files || undefined, reason: e.reason || null, added_by: e.added_by || null, added_at: e.added_at || null,
    })),
  });

  const url = centralUrl.replace(/\/$/, '') + '/api/v1/repos/' + encodeURIComponent(repoId) + '/scope';
  return postJson(url, body, token)
    .then((response) => {
      result.sent     = true;
      result.scoped   = Number(response.scoped)   || 0;
      result.unscoped = Number(response.unscoped) || 0;
      return result;
    })
    .catch((err) => {
      result.error = err.message || 'network';
      return result;   // quiet — offline-first
    });
}

// Minimal JSON POST — resolves with the parsed 2xx body, rejects otherwise.
function postJson(url, body, token) {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith('https');
    const http    = isHttps ? require('https') : require('http');
    const parsed  = new (require('url').URL)(url);
    const req = http.request({
      hostname: parsed.hostname,
      port:     parsed.port || (isHttps ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
        Authorization:   'Bearer ' + token,
      },
      timeout: 8000,
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(data ? JSON.parse(data) : {}); }
          catch { reject(new Error('bad_json')); }
        } else {
          reject(new Error('http_' + res.statusCode));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.write(body);
    req.end();
  });
}

module.exports = { pushScope };
