/**
 * global-config.js
 * Manages the global (user-level) Secure Code by Design configuration.
 *
 * Location: ~/.scd/config  (never inside a repo)
 * Format:   KEY=VALUE  (simple, no external deps)
 *
 * Stored settings:
 *   ANTHROPIC_API_KEY  – used by --deep analysis
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
 * Return the effective Anthropic API key.
 * Priority: environment variable > global config
 */
function getApiKey() {
  return process.env.ANTHROPIC_API_KEY || get('ANTHROPIC_API_KEY') || null;
}

/**
 * Mask an API key for display: show first 16 + last 4 chars.
 * sk-ant-api03-AbCdEf... → sk-ant-api03-AbCd············Wxyz
 */
function maskApiKey(key) {
  if (!key) return '(not set)';
  if (key.length <= 20) return key.slice(0, 4) + '·'.repeat(key.length - 4);
  return key.slice(0, 16) + '·'.repeat(Math.max(4, key.length - 20)) + key.slice(-4);
}

/**
 * Return a summary object for scd configure --show
 */
function showConfig() {
  const raw    = readRaw();
  const apiKey = getApiKey();
  const source = process.env.ANTHROPIC_API_KEY ? 'environment variable'
               : raw.ANTHROPIC_API_KEY         ? `global config (${GLOBAL_CONFIG})`
               : null;

  return {
    configPath: GLOBAL_CONFIG,
    exists:     fs.existsSync(GLOBAL_CONFIG),
    apiKey:     maskApiKey(apiKey),
    apiKeySource: source || '(not set)',
    raw,
  };
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
  // Normalise – strip trailing slash
  set('CENTRAL_URL', url.replace(/\/$/, ''));
}

/**
 * Remove the central server URL (disables push queue).
 */
function removeCentralUrl() {
  return remove('CENTRAL_URL');
}

module.exports = { get, set, remove, getApiKey, maskApiKey, showConfig, getCentralUrl, setCentralUrl, removeCentralUrl, GLOBAL_CONFIG, GLOBAL_DIR };
