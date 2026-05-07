'use strict';
const { RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN } = require('../output-constants');
// lib/commands/scope.js
// scd scope — manage global scan scope exclusions (~/.scd/scope.yml)
// For repo-level scope, use: scd repo scope

module.exports = { register, appendToScope, buildFileEntry, buildRuleEntry, removeFromScope };

function register(program) {
  const { Command } = require('commander');

  const scopeCmd = new Command('scope')
    .description('Manage global scan scope exclusions (~/.scd/scope.yml)')
    .addHelpText('after', `
Examples:
  scd scope --show
  scd scope --add-file "tests/fixtures/" --reason "Test fixtures with intentional vulns"
  scd scope --add-rule INFRA-001 --reason "Cloud-managed infrastructure"
  scd scope --add-rule JS-ERR-002 --files "lib/rules/,**/*.test.js" --reason "Rule definition files"

  For repo-level scope: scd repo scope --show`)
    .option('--show',              'Show active global scope exclusions')
    .option('--add-file <pattern>','Add a file/directory exclusion pattern')
    .option('--add-rule <ruleId>', 'Add a rule exclusion')
    .option('--files <globs>',     'Comma-separated file globs to scope a rule exclusion (use with --add-rule)')
    .option('--reason <text>',     'Reason for the exclusion (required with --add-file and --add-rule)')
    .option('--remove-file <pattern>','Remove a file exclusion by pattern')
    .option('--remove-rule <ruleId>', 'Remove a rule exclusion by rule ID')
    .action((opts) => {
      const fs    = require('fs');
      const os    = require('os');
      const path  = require('path');
      const store = require('../store');
      const { loadScope, validateScope, summariseScope } = require('../scope');


      const scopeFile = store.globalScopePath();

      // ── --show ──────────────────────────────────────────────────────────────
      if (opts.show || (!opts.addFile && !opts.addRule && !opts.removeFile && !opts.removeRule)) {
        if (!fs.existsSync(scopeFile)) {
          console.log(`\n${DIM}  No global scope.yml found.${RESET}`);
          console.log(`${DIM}  Use ${RESET}${CYAN}scd scope --add-file${RESET}${DIM} or ${RESET}${CYAN}scd scope --add-rule${RESET}${DIM} to create one.${RESET}\n`);
          return;
        }

        const scope = loadScope(null);   // global only — no repoRoot
        const warnings = validateScope(scope);
        const summary = summariseScope(scope);

        console.log(`\n${BOLD}Global scope exclusions${RESET}  ${DIM}(~/.scd/scope.yml)${RESET}\n`);

        if (!summary.hasExclusions) {
          console.log(`${DIM}  No active exclusions.${RESET}\n`);
          return;
        }

        if (summary.fileLines.length > 0) {
          console.log(`${BOLD}  File exclusions:${RESET}`);
          for (const line of summary.fileLines) console.log(`  ${line.trim()}`);
          console.log();
        }

        if (summary.ruleLines.length > 0) {
          console.log(`${BOLD}  Rule exclusions:${RESET}`);
          for (const line of summary.ruleLines) console.log(`  ${line.trim()}`);
          console.log();
        }

        if (warnings.length > 0) {
          console.log(`${YELLOW}  ⚠ Incomplete entries (missing required fields):${RESET}`);
          for (const w of warnings) {
            console.log(`${YELLOW}    ${w.identifier}: missing ${w.missing.join(', ')}${RESET}`);
          }
          console.log();
        }
        return;
      }

      // ── --add-file / --add-rule: require --reason ────────────────────────────
      if (!opts.reason) {
        console.error(`\n${RED}✗ --reason is required.${RESET}`);
        console.error(`  Every scope exclusion must have a documented reason.\n`);
        process.exit(1);
      }

      // ── Build entry ──────────────────────────────────────────────────────────
      const { getMachineFingerprint } = require('../store');
      const installId  = getMachineFingerprint() || 'unknown';
      const addedAt    = new Date().toLocaleString('sv-SE', {
        timeZone: 'Europe/Stockholm', year: 'numeric', month: '2-digit',
        day: '2-digit', hour: '2-digit', minute: '2-digit',
      }).replace(',', '');

      // ── --add-file ───────────────────────────────────────────────────────────
      if (opts.addFile) {
        const entry = buildFileEntry(opts.addFile, opts.reason, installId, addedAt);
        appendToScope(scopeFile, 'file_excludes', entry);
        console.log(`\n${GREEN}✓ File exclusion added to global scope.yml${RESET}`);
        console.log(`  ${DIM}Pattern : ${opts.addFile}${RESET}`);
        console.log(`  ${DIM}Reason  : ${opts.reason}${RESET}`);
        console.log(`  ${DIM}Added by: ${installId}${RESET}\n`);
        console.log(`${YELLOW}  ⚠ Active file exclusions are visible in every scan output.${RESET}\n`);
        return;
      }

      // ── --add-rule ───────────────────────────────────────────────────────────
      if (opts.addRule) {
        const files = opts.files
          ? opts.files.split(',').map(s => s.trim()).filter(Boolean)
          : null;
        const entry = buildRuleEntry(opts.addRule, files, opts.reason, installId, addedAt);
        appendToScope(scopeFile, 'rule_excludes', entry);
        const scopeDesc = files ? files.join(', ') : 'all files';
        console.log(`\n${GREEN}✓ Rule exclusion added to global scope.yml${RESET}`);
        console.log(`  ${DIM}Rule    : ${opts.addRule}${RESET}`);
        console.log(`  ${DIM}Scope   : ${scopeDesc}${RESET}`);
        console.log(`  ${DIM}Reason  : ${opts.reason}${RESET}`);
        console.log(`  ${DIM}Added by: ${installId}${RESET}\n`);
        console.log(`${YELLOW}  ⚠ Active rule exclusions are visible in every scan output.${RESET}\n`);
        return;
      }

      // ── --remove-file ─────────────────────────────────────────────────────────
      if (opts.removeFile) {
        const removed = removeFromScope(scopeFile, 'file_excludes', 'pattern', opts.removeFile);
        if (removed.length === 0) {
          console.log(`\n${YELLOW}  No file exclusion found matching: ${opts.removeFile}${RESET}\n`);
        } else {
          console.log(`\n${GREEN}✓ Removed ${removed.length} file exclusion(s) from global scope.yml${RESET}`);
          for (const r of removed) {
            console.log(`  ${DIM}Pattern : ${r.pattern}${RESET}`);
            console.log(`  ${DIM}Reason  : ${r.reason || '(none)'}${RESET}`);
            console.log(`  ${DIM}Added by: ${r.added_by || '(unknown)'}  ${r.added_at || ''}${RESET}`);
          }
          console.log();
        }
        return;
      }

      // ── --remove-rule ─────────────────────────────────────────────────────────
      if (opts.removeRule) {
        const removed = removeFromScope(scopeFile, 'rule_excludes', 'rule', opts.removeRule);
        if (removed.length === 0) {
          console.log(`\n${YELLOW}  No rule exclusion found matching: ${opts.removeRule}${RESET}\n`);
        } else {
          console.log(`\n${GREEN}✓ Removed ${removed.length} rule exclusion(s) from global scope.yml${RESET}`);
          for (const r of removed) {
            const scopeDesc = r.files && r.files.length ? r.files.join(', ') : 'all files';
            console.log(`  ${DIM}Rule    : ${r.rule} (${scopeDesc})${RESET}`);
            console.log(`  ${DIM}Reason  : ${r.reason || '(none)'}${RESET}`);
            console.log(`  ${DIM}Added by: ${r.added_by || '(unknown)'}  ${r.added_at || ''}${RESET}`);
          }
          console.log();
        }
        return;
      }
    });

  program.addCommand(scopeCmd);
}

// ── Helpers ───────────────────────────────────────────────────────────────

function buildFileEntry(pattern, reason, addedBy, addedAt) {
  return [
    `  - pattern: ${pattern}`,
    `    reason: "${reason}"`,
    `    added_by: ${addedBy}`,
    `    added_at: "${addedAt}"`,
  ].join('\n');
}

function buildRuleEntry(rule, files, reason, addedBy, addedAt) {
  const lines = [
    `  - rule: ${rule}`,
  ];
  if (files && files.length) {
    lines.push(`    files:`);
    for (const f of files) lines.push(`      - ${f}`);
  }
  lines.push(`    reason: "${reason}"`);
  lines.push(`    added_by: ${addedBy}`);
  lines.push(`    added_at: "${addedAt}"`);
  return lines.join('\n');
}


/**
 * Remove all entries from a section in scope.yml that match a key/value.
 * Parses the YAML as text — uses the scope parser to identify entries,
 * then removes their line ranges from the raw file.
 *
 * Returns an array of removed entries (for display).
 */
function removeFromScope(scopeFile, section, matchKey, matchValue) {
  const fs = require('fs');
  const { parseScope } = require('../scope');

  if (!fs.existsSync(scopeFile)) return [];

  const content  = fs.readFileSync(scopeFile, 'utf8');
  const parsed   = parseScope(content);
  const entries  = parsed[section] || [];

  // Find entries that match
  const toRemove = entries.filter(e => e[matchKey] === matchValue);
  if (toRemove.length === 0) return [];

  // Remove by rebuilding the section without matched entries
  const remaining = entries.filter(e => e[matchKey] !== matchValue);

  // Rebuild file: replace section content
  const lines = content.split('\n');
  const newLines = [];
  let inSection  = false;
  let inEntry    = false;
  let skipEntry  = false;
  let entryLines = [];

  // Two-pass: collect entry line ranges, then rebuild
  // Simpler approach: regenerate the section from remaining entries
  const otherSection = section === 'file_excludes' ? 'rule_excludes' : 'file_excludes';
  const otherEntries = parsed[otherSection] || [];

  let result = rebuildScopeFile(content, section, remaining, otherSection, otherEntries);
  fs.writeFileSync(scopeFile, result, { encoding: 'utf8', mode: 0o600 });

  return toRemove;
}

/**
 * Rebuild scope.yml content preserving header comments and both sections.
 * Regenerates section entries from parsed data.
 */
function rebuildScopeFile(original, changedSection, changedEntries, otherSection, otherEntries) {
  const lines   = original.split('\n');
  const result  = [];
  let inSection = null;
  let skipUntilNextSection = false;

  for (const line of lines) {
    // Detect top-level section headers
    if (/^file_excludes\s*:/.test(line)) {
      inSection = 'file_excludes';
      skipUntilNextSection = true;
      result.push(line);
      // Inject entries for this section
      const entries = inSection === changedSection ? changedEntries : otherEntries;
      for (const e of (changedSection === 'file_excludes' ? changedEntries : otherEntries)) {
        result.push(buildFileEntry(e.pattern, e.reason || '', e.added_by || '', e.added_at || ''));
      }
      continue;
    }
    if (/^rule_excludes\s*:/.test(line)) {
      inSection = 'rule_excludes';
      skipUntilNextSection = true;
      result.push(line);
      for (const e of (changedSection === 'rule_excludes' ? changedEntries : otherEntries)) {
        result.push(buildRuleEntry(e.rule, e.files || null, e.reason || '', e.added_by || '', e.added_at || ''));
      }
      continue;
    }

    // Skip existing entry lines inside a section
    if (skipUntilNextSection && inSection) {
      // A line that is not indented and not empty and not a comment = new top-level key
      if (line.length > 0 && !line.startsWith(' ') && !line.startsWith('\t') && !line.startsWith('#')) {
        skipUntilNextSection = false;
        inSection = null;
        result.push(line);
      }
      // Otherwise skip — entries were already injected above
      continue;
    }

    result.push(line);
  }

  return result.join('\n');
}

/**
 * Append a new entry to the correct section in scope.yml.
 * Creates the file with header if it does not exist.
 * Appends to existing section if present, adds section header if not.
 */
function appendToScope(scopeFile, section, entryYaml) {
  const fs   = require('fs');
  const path = require('path');
  const os   = require('os');

  // Ensure ~/.scd/ exists
  const dir = path.dirname(scopeFile);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  if (!fs.existsSync(scopeFile)) {
    // Create file with header and both section stubs
    const header = [
      `# scope.yml — global scan scope exclusions`,
      `# Managed by: scd scope`,
      `# Every entry requires reason, added_by, and added_at.`,
      `# Missing fields produce a warning in scan output and audit log.`,
      `#`,
      `# Documentation: https://docs.securecodebydesign.com/scope`,
      ``,
      `file_excludes:`,
      section === 'file_excludes' ? entryYaml : '',
      ``,
      `rule_excludes:`,
      section === 'rule_excludes' ? entryYaml : '',
      ``,
    ].join('\n');
    fs.writeFileSync(scopeFile, header, { encoding: 'utf8', mode: 0o600 });
    return;
  }

  let content = fs.readFileSync(scopeFile, 'utf8');

  // Section already exists — append after the section header
  const sectionRe = new RegExp(`^(${section}\\s*:[ \\t]*)$`, 'm');
  if (sectionRe.test(content)) {
    // Find the section and append entry before the next top-level key or EOF
    const lines = content.split('\n');
    const sectionIdx = lines.findIndex(l => new RegExp(`^${section}\\s*:`).test(l));
    // Find end of section: next line that is a top-level key (no leading space) and not a comment
    let insertIdx = sectionIdx + 1;
    while (insertIdx < lines.length) {
      const line = lines[insertIdx];
      if (line.length > 0 && !line.startsWith(' ') && !line.startsWith('\t') && !line.startsWith('#')) break;
      insertIdx++;
    }
    lines.splice(insertIdx, 0, entryYaml);
    content = lines.join('\n');
  } else {
    // Section does not exist — append to end of file
    content = content.trimEnd() + `\n\n${section}:\n${entryYaml}\n`;
  }

  fs.writeFileSync(scopeFile, content, { encoding: 'utf8', mode: 0o600 });
}
