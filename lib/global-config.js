/**
 * global-config.js
 * Manages the global (user-level) Secure Code by Design configuration.
 *
 * Location: ~/.scd/config  (never inside a repo)
 * Format:   KEY=VALUE  (simple, no external deps)
 *
 * Stored settings:
 *   (extensible for future global settings)
 *
 * Security notes:
 *   - File is created with mode 0600 (owner read/write only)
 *   - API key is never printed in full – always masked
 *   - scd configure --show reveals only first 12 + last 4 chars
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const GLOBAL_DIR      = path.join(os.homedir(), '.scd');
const GLOBAL_CONFIG   = path.join(GLOBAL_DIR, 'config');
const FILE_MODE       = 0o600;

// ── Read/write helpers ─────────────────────────────────────────────────────

function ensureDir() {
  if (!fs.existsSync(GLOBAL_DIR)) {
    fs.mkdirSync(GLOBAL_DIR, { recursive: true, mode: 0o700 });
  }
}

function readRaw() {
  if (!fs.existsSync(GLOBAL_CONFIG)) return {};
  try {
    const lines = fs.readFileSync(GLOBAL_CONFIG, 'utf8').split('\n');
    const result = {};
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      result[key] = val;
    }
    return result;
  } catch {
    return {};
  }
}

function writeRaw(data) {
  ensureDir();
  const lines = [
    '# Secure Code by Design – global configuration',
    '# Managed by: scd configure',
    '# NEVER share this file – it contains API keys',
    '',
    ...Object.entries(data).map(([k, v]) => `${k}=${v}`),
    '',
  ];
  fs.writeFileSync(GLOBAL_CONFIG, lines.join('\n'), { mode: FILE_MODE, encoding: 'utf8' });
  // Enforce permissions even if file already existed
  try { fs.chmodSync(GLOBAL_CONFIG, FILE_MODE); } catch { /* ignore on Windows */ }
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

module.exports = {
  get, set, remove,
  getCentralUrl, setCentralUrl, removeCentralUrl,
  getCentralToken, setCentralToken, removeCentralToken,
  getServerTimeout, setServerTimeout,
  getDeepTimeout, setDeepTimeout,
  parseTimeoutArg,
  GLOBAL_CONFIG, GLOBAL_DIR,
};
