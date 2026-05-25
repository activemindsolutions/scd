/**
 * global-config.js
 * Manages the global (user-level) Secure Code by Design configuration.
 *
 * Location: ~/.scd/config.yml  (never inside a repo)
 * Format:   YAML key: value  (simple, no external deps)
 *
 * Migration: if config.yml does not exist but the legacy key=value file
 * config does, it is read, converted to YAML, and saved as config.yml.
 * The old file is renamed to config.old (kept as a silent backup).
 *
 * Security notes:
 *   - File is created with mode 0600 (owner read/write only)
 *   - API key is never printed in full – always masked
 *   - scd configure --show reveals only first 12 chars
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const GLOBAL_DIR  = path.join(os.homedir(), '.scd');
const CONFIG_PATH = path.join(GLOBAL_DIR, 'config.yml');
const CONFIG_OLD  = path.join(GLOBAL_DIR, 'config');       // legacy key=value
const CONFIG_BAK  = path.join(GLOBAL_DIR, 'config.old');   // backup after migration
const FILE_MODE   = 0o600;

// ── YAML helpers ───────────────────────────────────────────────────────────

function parseYaml(content) {
  const result = {};
  for (const raw of content.split('\n')) {
    const line = raw.replace(/\r$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const val = line.slice(colonIdx + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key && val !== '') result[key] = val;
  }
  return result;
}

function serializeYaml(obj) {
  const lines = [
    '# Secure Code by Design – global configuration',
    '# Managed by: scd configure',
    '# NEVER share this file – it contains API keys',
    '',
  ];
  for (const [key, value] of Object.entries(obj)) {
    lines.push(`${key}: ${value}`);
  }
  return lines.join('\n') + '\n';
}

// ── Migration ──────────────────────────────────────────────────────────────

function migrateIfNeeded() {
  if (fs.existsSync(CONFIG_PATH)) return;   // already on new format
  if (!fs.existsSync(CONFIG_OLD))  return;  // fresh install — nothing to migrate

  // Read old key=value format
  const old = {};
  try {
    const lines = fs.readFileSync(CONFIG_OLD, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      if (key && val) old[key] = val;
    }
  } catch {
    return; // can't read old file — skip migration
  }

  // Write YAML and rename old file to config.old
  try {
    fs.writeFileSync(CONFIG_PATH, serializeYaml(old), { mode: FILE_MODE, encoding: 'utf8' });
    fs.renameSync(CONFIG_OLD, CONFIG_BAK);
    process.stderr.write(
      `[scd] Migrated config to YAML format: ~/.scd/config → ~/.scd/config.yml\n` +
      `[scd] Old config preserved as ~/.scd/config.old\n`
    );
  } catch {
    // Migration failed — non-fatal, old file still readable as fallback
  }
}

// Run once at module load
migrateIfNeeded();

// ── Read/write ─────────────────────────────────────────────────────────────

function ensureDir() {
  if (!fs.existsSync(GLOBAL_DIR)) {
    fs.mkdirSync(GLOBAL_DIR, { recursive: true, mode: 0o700 });
  }
}

function readRaw() {
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      return parseYaml(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch {
      return {};
    }
  }
  // Fallback: config.old exists (migration ran but config.yml was deleted)
  if (fs.existsSync(CONFIG_BAK)) {
    try {
      return parseYaml(fs.readFileSync(CONFIG_BAK, 'utf8'));
    } catch {
      return {};
    }
  }
  return {};
}

function writeRaw(data) {
  ensureDir();
  fs.writeFileSync(CONFIG_PATH, serializeYaml(data), { mode: FILE_MODE, encoding: 'utf8' });
  try { fs.chmodSync(CONFIG_PATH, FILE_MODE); } catch { /* ignore on Windows */ }
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Get a value from global config.
 * Returns undefined if not set.
 */
function get(key) {
  return readRaw()[key];
}

/**
 * Set a key in global config.
 */
function set(key, value) {
  const data = readRaw();
  data[key] = value;
  writeRaw(data);
}

/**
 * Remove a key from global config.
 * Returns true if the key existed and was removed.
 */
function remove(key) {
  const data = readRaw();
  if (!(key in data)) return false;
  delete data[key];
  writeRaw(data);
  return true;
}

/**
 * Get the configured central server URL.
 * Returns null if not set.
 */
function getCentralUrl() {
  return get('CENTRAL_URL') || null;
}

/**
 * Set the central server URL.
 */
function setCentralUrl(url) {
  // Normalize localhost → 127.0.0.1 to avoid IPv6 resolution issues.
  // On macOS with Node 18, localhost resolves to ::1 but Express listens
  // on IPv4 by default — resulting in ECONNREFUSED. Using 127.0.0.1 is
  // always correct and avoids the ambiguity.
  const normalized = url.replace(/\/\//g, '//').replace('//localhost', '//127.0.0.1').replace(/\/$/, '');
  set('CENTRAL_URL', normalized);
}

/**
 * Remove the central server URL (disables push queue).
 */
function removeCentralUrl() {
  return remove('CENTRAL_URL');
}

/**
 * Get the configured central server API token.
 * Returns null if not set.
 */
function getCentralToken() {
  return get('CENTRAL_TOKEN') || null;
}

/**
 * Set the central server API token.
 */
function setCentralToken(token) {
  set('CENTRAL_TOKEN', token.trim());
}

/**
 * Remove the central server API token.
 */
function removeCentralToken() {
  return remove('CENTRAL_TOKEN');
}

// ── Timeout configuration ─────────────────────────────────────────────────

const TIMEOUT_DEFAULTS = {
  SERVER_TIMEOUT_MS: 30000,     // 30 seconds — regular API calls
  DEEP_TIMEOUT_MS:   1200000,   // 20 minutes — Ollama can be slow on CPU hardware
};

/**
 * Parse human-readable timeout values: '30s', '5m', '1200000' (ms as string).
 */
function parseTimeoutArg(value) {
  if (typeof value === 'number') return value;
  const str = String(value).trim().toLowerCase();
  if (str.endsWith('m')) {
    const n = parseInt(str, 10);
    if (isNaN(n)) throw new Error(`Invalid timeout value: ${value}`);
    return n * 60 * 1000;
  }
  if (str.endsWith('s')) {
    const n = parseInt(str, 10);
    if (isNaN(n)) throw new Error(`Invalid timeout value: ${value}`);
    return n * 1000;
  }
  const n = parseInt(str, 10);
  if (isNaN(n)) throw new Error(`Invalid timeout value: ${value}`);
  return n;
}

function getServerTimeout() {
  const val = get('SERVER_TIMEOUT_MS');
  const n   = val ? parseInt(val, 10) : NaN;
  return isNaN(n) ? TIMEOUT_DEFAULTS.SERVER_TIMEOUT_MS : n;
}

function setServerTimeout(ms) {
  set('SERVER_TIMEOUT_MS', String(ms));
}

function getDeepTimeout() {
  const val = get('DEEP_TIMEOUT_MS');
  const n   = val ? parseInt(val, 10) : NaN;
  return isNaN(n) ? TIMEOUT_DEFAULTS.DEEP_TIMEOUT_MS : n;
}

function setDeepTimeout(ms) {
  set('DEEP_TIMEOUT_MS', String(ms));
}

// ── Scan trace ────────────────────────────────────────────────────────────
// When enabled, every finding (active and suppressed) carries a _trace object
// in all scan-JSON files. Never shown in terminal output or reports.
// Set manually: SCAN_TRACE: true in ~/.scd/config.yml
// Not exposed via scd configure — internal debug tool only.

function getScanTrace() {
  return get('SCAN_TRACE') === 'true';
}

function setScanTrace(enabled) {
  set('SCAN_TRACE', enabled ? 'true' : 'false');
}

// ── Server version cache ──────────────────────────────────────────────────
// Cached from health endpoint and batch responses.
// Lets CLI warn about version mismatch without an extra network call.

function getServerVersion() {
  return get('SERVER_VERSION') || null;
}

function getMinCliVersion() {
  return get('MIN_CLI_VERSION') || null;
}

function setServerVersionInfo(serverVersion, minCliVersion) {
  if (serverVersion)  set('SERVER_VERSION',  serverVersion);
  if (minCliVersion)  set('MIN_CLI_VERSION', minCliVersion);
}

module.exports = {
  get, set, remove,
  getCentralUrl, setCentralUrl, removeCentralUrl,
  getCentralToken, setCentralToken, removeCentralToken,
  getServerTimeout, setServerTimeout,
  getDeepTimeout, setDeepTimeout,
  getScanTrace, setScanTrace,
  getServerVersion, getMinCliVersion, setServerVersionInfo,
  parseTimeoutArg,
  GLOBAL_CONFIG: CONFIG_PATH,
  GLOBAL_DIR,
};
