'use strict';
// lib/commands/rules.js

module.exports = { register };

function register(program) {
  program
    .command('rules')
    .description('List, search and inspect security rules')
    .option('--lang <langs>',     'Filter by language (js, ts, py, php, cs, aspx, all) — comma-separated')
    .option('--severity <level>', 'Filter by severity (critical, high, medium, exposure)')
    .option('--id <id>',          'Show full detail for a specific rule ID (e.g. INFRA-001)')
    .option('--search <query>',   'Free-text search in ID, name, category, why, fix')
    .option('--stats',            'Show rule counts by severity, language and category')
    .option('--format <fmt>',     'Output format: table (default) | json')
    .action((opts) => {
      const { queryRules, getStats, getRegistry, SEV_ORDER } = require('../rule-registry');

      const SEV_COLOR = {
        CRITICAL: '\x1b[31m',  // red
        HIGH:     '\x1b[33m',  // yellow
        MEDIUM:   '\x1b[34m',  // blue
        EXPOSURE: '\x1b[36m',  // cyan
        LOW:      '\x1b[90m',  // dim
      };
      const RESET = '\x1b[0m';
      const BOLD  = '\x1b[1m';
      const DIM   = '\x1b[90m';

      const colorSev = (s) => (SEV_COLOR[s] || '') + s.padEnd(8) + RESET;

      // ── JSON output ──────────────────────────────────────────────────────
      if (opts.format === 'json') {
        const rules = queryRules({ lang: opts.lang, severity: opts.severity,
                                    id: opts.id, search: opts.search });
        if (opts.stats) {
          console.log(JSON.stringify(getStats(rules), null, 2));
        } else {
          console.log(JSON.stringify(rules, null, 2));
        }
        return;
      }

      // ── Stats view ───────────────────────────────────────────────────────
      if (opts.stats) {
        const rules = queryRules({ lang: opts.lang, severity: opts.severity, search: opts.search });
        const s = getStats(rules);
        console.log('\n' + BOLD + 'Secure Code by Design – Rule stats' + RESET);
        console.log(DIM + '─'.repeat(50) + RESET + '\n');
        console.log('  Total rules: ' + BOLD + s.total + RESET + '\n');

        console.log('  By severity:');
        for (const [sev, n] of Object.entries(s.bySeverity).sort((a,b) => (SEV_ORDER[a[0]]??9)-(SEV_ORDER[b[0]]??9))) {
          console.log('    ' + colorSev(sev) + '  ' + n);
        }

        console.log('\n  By language:');
        const langEntries = Object.entries(s.byLanguage).sort((a,b) => b[1]-a[1]);
        for (const [lang, n] of langEntries) {
          console.log('    ' + lang.padEnd(12) + DIM + n + RESET);
        }

        console.log('\n  By category:');
        const catEntries = Object.entries(s.byCategory).sort((a,b) => b[1]-a[1]);
        for (const [cat, n] of catEntries) {
          const short = cat.replace(/\s*\(OWASP.*?\)/,'').trim();
          console.log('    ' + short.padEnd(40) + DIM + n + RESET);
        }
        console.log();
        return;
      }

      // ── Detail view (--id) ───────────────────────────────────────────────
      if (opts.id) {
        const rules = queryRules({ id: opts.id });
        if (rules.length === 0) {
          console.log('\n\x1b[33m Rule not found: ' + opts.id + RESET);
          console.log(DIM + ' Use scd rules --search <term> to find rules.\n' + RESET);
          process.exit(1);
        }
        const r = rules[0];
        const sev = SEV_COLOR[r.severity] || '';
        console.log('\n' + BOLD + r.id + RESET + '  ' + sev + r.severity + RESET);
        console.log(DIM + '─'.repeat(60) + RESET);
        console.log(BOLD + r.name + RESET + '\n');
        console.log('  Category:  ' + r.category);
        console.log('  Languages: ' + r.languages.join(', '));
        console.log('  Match:     ' + r.matchMode);

        if (r.why) {
          console.log('\n' + BOLD + 'Why this matters' + RESET);
          console.log(wordWrap(r.why, 70, '  '));
        }
        if (r.scenario) {
          console.log('\n' + BOLD + 'Attack scenario' + RESET);
          console.log(wordWrap(r.scenario, 70, '  '));
        }
        if (r.fix) {
          console.log('\n' + BOLD + 'How to fix' + RESET);
          console.log(wordWrap(r.fix, 70, '  '));
        }
        if (r.checklist && r.checklist.length) {
          console.log('\n' + BOLD + 'Verification checklist' + RESET);
          for (const item of r.checklist) {
            console.log('  ☐ ' + item);
          }
        }
        console.log();
        return;
      }

      // ── List view (default) ──────────────────────────────────────────────
      const rules = queryRules({ lang: opts.lang, severity: opts.severity, search: opts.search });

      if (rules.length === 0) {
        console.log('\n' + DIM + ' No rules match the given filters.\n' + RESET);
        return;
      }

      const title = buildTitle(opts);
      console.log('\n' + BOLD + 'Secure Code by Design – Rules' + (title ? '  ' + DIM + title + RESET : '') + RESET);
      console.log(DIM + '─'.repeat(90) + RESET);

      // Column widths
      const ID_W = 16, SEV_W = 10, LANG_W = 18, CAT_W = 32;
      console.log(
        DIM +
        'ID'.padEnd(ID_W) +
        'Severity'.padEnd(SEV_W) +
        'Languages'.padEnd(LANG_W) +
        'Category'.padEnd(CAT_W) +
        'Name' +
        RESET
      );
      console.log(DIM + '─'.repeat(90) + RESET);

      // Group by category for readability
      const byCategory = {};
      for (const r of rules) {
        const cat = r.category.replace(/\s*\(OWASP.*?\)/,'').trim();
        if (!byCategory[cat]) byCategory[cat] = [];
        byCategory[cat].push(r);
      }

      for (const [cat, catRules] of Object.entries(byCategory)) {
        for (const r of catRules) {
          const id   = r.id.padEnd(ID_W);
          const sev  = (SEV_COLOR[r.severity]||'') + r.severity.padEnd(SEV_W - 1) + RESET + ' ';
          const langs = r.languages.join(',').slice(0, LANG_W - 1).padEnd(LANG_W);
          const category = cat.slice(0, CAT_W - 1).padEnd(CAT_W);
          const name = r.name.slice(0, 46) + (r.name.length > 46 ? '…' : '');
          console.log(id + sev + DIM + langs + RESET + DIM + category + RESET + name);
        }
      }

      console.log(DIM + '─'.repeat(90) + RESET);
      console.log('  ' + rules.length + ' rule' + (rules.length !== 1 ? 's' : '') +
        (rules.length < getRegistry().length ? ' (filtered from ' + getRegistry().length + ' total)' : ' total') + '\n');
      console.log(DIM +
        '  scd rules --id <ID>          full detail for a rule\n' +
        '  scd rules --lang php         filter by language\n' +
        '  scd rules --severity critical filter by severity\n' +
        '  scd rules --search <term>    free-text search\n' +
        '  scd rules --stats            counts by severity / language / category\n' +
        RESET);
    });
}

function wordWrap(text, width, indent) {
  const words = text.split(' ');
  const lines = [];
  let line = '';
  for (const word of words) {
    if ((line + word).length > width) { lines.push(indent + line.trim()); line = ''; }
    line += word + ' ';
  }
  if (line.trim()) lines.push(indent + line.trim());
  return lines.join('\n');
}

function buildTitle(opts) {
  const parts = [];
  if (opts.lang)     parts.push('lang=' + opts.lang);
  if (opts.severity) parts.push('severity=' + opts.severity);
  if (opts.search)   parts.push('search="' + opts.search + '"');
  return parts.join('  ');
}
