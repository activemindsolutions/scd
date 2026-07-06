'use strict';

/**
 * Regression: `scd configure` must apply ALL setter options given in one call.
 *
 * Each setter block used to end with process.exit(0), so a combined call like
 * `configure --central-url X --token Y` set only the first option and silently
 * dropped the rest. The blocks now mark `handled` and exit once at the end.
 *
 * Run: node --test tests/unit/configure-multi-option.test.js
 */

const { test }      = require('node:test');
const assert        = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');

const SCD = path.resolve(__dirname, '..', '..', 'bin', 'scd.js');

test('configure applies --central-url AND --token in a single call', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'scd-cfg-'));
  try {
    execFileSync(
      process.execPath,
      [SCD, 'configure', '--central-url', 'http://127.0.0.1:3000', '--token', 'scd-testtoken'],
      { env: { ...process.env, HOME: home }, stdio: 'pipe' },
    );
    const cfg = fs.readFileSync(path.join(home, '.scd', 'config.yml'), 'utf8');
    assert.match(cfg, /CENTRAL_URL: http:\/\/127\.0\.0\.1:3000/, 'central URL set');
    assert.match(cfg, /CENTRAL_TOKEN: scd-testtoken/,
      'token set in the SAME call — a setter no longer exits before the next runs');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
