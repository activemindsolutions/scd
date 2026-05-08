'use strict';
// lib/commands/export-findings.js

module.exports = { register };

function register(program) {
  program
    .command('export-findings')
    .description('Export findings from a scan for external review')
    .option('--scan <id>',        'Scan ID to export (default: latest scan)')
    .option('--severity <level>', 'Filter by severity: critical, high, medium, exposure')
    .option('--rule <id>',        'Filter to a specific rule ID')
    .option('--deep-only',        'Export only findings that have a deep analysis result')
    .option('--output <path>',    'Output file path (default: ~/.scd/repos/{id}/exports/scd-findings-{scanId}.json)')
    .action(async (opts) => {
      const path  = require('path');
      const store = require('../store');
      const { exportFindings } = require('../export-findings');
      const { loadCache }      = require('../scan-cache');
      const { getRepoRoot }    = require('../config');
      const repoRoot = getRepoRoot();

      // Resolve scan ID first so we can use it in the default filename
      let resolvedScanId = opts.scan || null;
      if (!resolvedScanId) {
        const latest = loadCache(repoRoot);
        if (latest) resolvedScanId = latest.scanId;
      }

      const defaultName = 'scd-findings-' + (resolvedScanId || 'scan') + '.json';
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
        includeRuleInternals: false,
        command:              'export-findings',
      });
    });
}
