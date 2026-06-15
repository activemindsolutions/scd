#!/usr/bin/env node
/**
 * scd – CLI entry point
 * Config-aware with audit logging
 */

const { Command } = require('commander');

const { warnIfOutdated, openInBrowser, tryFlush } = require('../lib/cli-helpers');
const { loadConfig, getRepoRoot } = require('../lib/config');

const program = new Command();

const pkg = require('../package.json');


program
  .name('scd')
  .description('Secure Code by Design – automated security scanning');

// Handle --version / -V before Commander parses — shows scd version output
// identical to `scd version`, instead of Commander's default single-line format.
if (process.argv.includes('--version') || process.argv.includes('-V')) {
  require('../lib/commands/version').showVersion();
  process.exit(0);
}

require('../lib/commands/scan').register(program);


require('../lib/commands/install').register(program);
require('../lib/commands/uninstall').register(program);

require('../lib/commands/doctor').register(program);

require('../lib/commands/accept').register(program);

require('../lib/commands/ignore').register(program);

require('../lib/commands/findings').register(program);


require('../lib/commands/sync').register(program);

require('../lib/commands/queue').register(program);

require('../lib/commands/exceptions').register(program);

require('../lib/commands/init').register(program);

require('../lib/commands/remove').register(program);

require('../lib/commands/report').register(program);

require('../lib/commands/audit').register(program);
require('../lib/commands/insights').register(program);

require('../lib/commands/configure').register(program);
require('../lib/commands/scope').register(program);


require('../lib/commands/repo').register(program);

require('../lib/commands/version').register(program);
require('../lib/commands/list').register(program);
require('../lib/commands/rules').register(program);

require('../lib/commands/export-findings').register(program);


// ── scd review-rules (Activemind-internal, hidden from scd --help) ───────────
{
  const { Command } = require('commander');
  const reviewCmd = new Command('review-rules');
  reviewCmd
    .description('Export findings with rule internals for Activemind rule quality review')
    .option('--scan <id>',        'Scan ID to export (default: latest scan)')
    .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
    .option('--rule <id>',        'Filter to a specific rule ID')
    .option('--deep-only',        'Export only findings that have a deep analysis result')
    .option('--output <path>',    'Output file path (default: ~/.scd/repos/{id}/exports/scd-review-{scanId}.json)')
    .action(async (opts) => {
      const path  = require('path');
      const store = require('../lib/store');
      const { exportFindings } = require('../lib/export-findings');
      const { loadCache } = require('../lib/scan-cache');
      const repoRoot = getRepoRoot();

      let resolvedScanId = opts.scan || null;
      if (!resolvedScanId) {
        const latest = loadCache(repoRoot);
        if (latest) resolvedScanId = latest.scanId;
      }

      const defaultName = 'scd-review-' + (resolvedScanId || 'scan') + '.json';
      const outputPath  = opts.output
        ? path.resolve(process.cwd(), opts.output)
        : store.exportPath(repoRoot, defaultName);

      await exportFindings({
        repoRoot,
        scanId:               opts.scan     || null,
        severity:             opts.severity || null,
        rule:                 opts.rule     || null,
        deepOnly:             !!opts.deepOnly,
        outputPath,
        includeRuleInternals: true,
        command:              'review-rules',
      });
    });

  program.addCommand(reviewCmd, { hidden: true });
}


program.parse(process.argv);

// ── Push worker – trigger after every command ─────────────────────────────
// Non-blocking: runs after the CLI command completes.
// Only active when a central URL is configured.
// Failures are silent – never affect CLI output or exit code.
setImmediate(() => {
  try {
    const { getCentralUrl } = require('../lib/global-config');
    const centralUrl = getCentralUrl();
    if (!centralUrl) return;

    const { flush, queueSize } = require('../lib/push-queue');
    if (queueSize() === 0) return;

    // Pass repoRoot so meta includes repo and installation identity
    const repoRoot = (() => {
      try { return require('../lib/config').getRepoRoot(); } catch { return null; }
    })();

    flush(centralUrl, { repoRoot }).catch(() => {});
  } catch {
    // Non-fatal
  }
});
