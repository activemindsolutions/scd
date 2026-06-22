/**
 * version-check.test.js
 * E1h:min-server-version — the CLI warns when the connected scd-server is older
 * than MIN_SERVER_VERSION (mirror of the server's min_cli_version → CLI warning).
 *
 * Run: node --test tests/unit/version-check.test.js
 */

'use strict';

const { test, describe, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const path   = require('path');

const root = path.resolve(__dirname, '../..');
const gc = require(path.join(root, 'lib/global-config'));
const vc = require(path.join(root, 'lib/version-check'));

const realGetServerVersion = gc.getServerVersion;
const realGetMinCliVersion = gc.getMinCliVersion;
afterEach(() => {
  gc.getServerVersion = realGetServerVersion;
  gc.getMinCliVersion = realGetMinCliVersion;
});

function withServerVersion(v) { gc.getServerVersion = () => v; }

describe('getServerVersionWarning (E1h)', () => {

  test('no server version cached → no warning', () => {
    withServerVersion(null);
    assert.equal(vc.getServerVersionWarning(), null);
  });

  test('server older than MIN_SERVER_VERSION → warns', () => {
    withServerVersion('1.2.1');   // older than 1.3.0
    const w = vc.getServerVersionWarning();
    assert.ok(w && /older than this scd/.test(w), 'warns when server is too old');
    assert.match(w, new RegExp(`v${vc.MIN_SERVER_VERSION.replace(/\./g, '\\.')}`), 'names the minimum');
  });

  test('server equal to MIN_SERVER_VERSION → no warning', () => {
    withServerVersion(vc.MIN_SERVER_VERSION);
    assert.equal(vc.getServerVersionWarning(), null);
  });

  test('server newer than MIN_SERVER_VERSION → no warning', () => {
    withServerVersion('99.0.0');
    assert.equal(vc.getServerVersionWarning(), null);
  });

  test('the two checks are independent — server-too-old fires even when the CLI is current', () => {
    gc.getMinCliVersion = () => null;   // server has no min_cli_version → CLI-too-old silent
    withServerVersion('1.0.0');
    assert.equal(vc.getVersionWarning(), null, 'CLI-too-old stays silent');
    assert.ok(vc.getServerVersionWarning(), 'server-too-old still fires');
  });
});
