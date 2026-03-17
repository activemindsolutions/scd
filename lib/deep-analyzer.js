/**
 * deep-analyzer.js
 * Claude API-driven deep analysis of security findings from sc scan --deep.
 *
 * Design:
 *   - Grupperar findings per fil → en API-call per fil
 *   - Skickar kodens kontext (relevanta rader runt varje finding)
 *   - Returns confirmation, attack scenario and concrete fix code
 *   - Interactive cost estimate if scope is broad (>5 files)
 *
 * Kostnadsmodell (Sonnet 4.6):
 *   Input:  $3.00 / 1M tokens
 *   Output: $15.00 / 1M tokens
 *   Typisk finding-grupp: ~800 input + ~600 output tokens ≈ $0.011/fil
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Konstanter ─────────────────────────────────────────────────────────────

const MODEL          = 'claude-sonnet-4-6';
const MAX_TOKENS     = 4096;   // per API call – must fit all findings with full analysis
const CONTEXT_LINES  = 8;      // rader kodbas runt varje finding
const MAX_FINDINGS_PER_CALL = 3; // max findings per API call – keeps response within token budget

// Estimated tokens per file group (used for cost estimation)
const EST_INPUT_TOKENS_PER_FILE  = 900;
const EST_OUTPUT_TOKENS_PER_FILE = 650;

// Priser i USD per 1M tokens (Sonnet 4.6)
const PRICE_INPUT_PER_M  = 3.00;
const PRICE_OUTPUT_PER_M = 15.00;

// Thresholds for interactive warning
const INTERACTIVE_THRESHOLD_FILES    = 5;
const INTERACTIVE_THRESHOLD_FINDINGS = 15;

// Retry settings for rate limit (429) errors
const RETRY_MAX_ATTEMPTS = 4;
const RETRY_BASE_DELAY_MS = 15000;  // 15s base – doubles: 15s, 30s, 60s, 120s

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Read code lines around a finding (context window).
 */
function extractContext(filePath, lineNum, lines = CONTEXT_LINES) {
  try {
    const abs     = path.resolve(process.cwd(), filePath);
    const content = fs.readFileSync(abs, 'utf8').split('\n');
    const start   = Math.max(0, lineNum - lines - 1);
    const end     = Math.min(content.length, lineNum + lines);
    return content
      .slice(start, end)
      .map((l, i) => `${start + i + 1}: ${l}`)
      .join('\n');
  } catch {
    return '(source not available)';
  }
}

/**
 * Estimate cost in USD for a number of files.
 */
function estimateCost(fileCount) {
  const inputCost  = (fileCount * EST_INPUT_TOKENS_PER_FILE  / 1_000_000) * PRICE_INPUT_PER_M;
  const outputCost = (fileCount * EST_OUTPUT_TOKENS_PER_FILE / 1_000_000) * PRICE_OUTPUT_PER_M;
  return (inputCost + outputCost).toFixed(4);
}

/**
 * Interaktiv ja/nej-prompt i terminalen.
 * Returnerar Promise<boolean>.
 */
function promptYesNo(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.once('data', data => {
      process.stdin.pause();
      const answer = data.toString().trim().toLowerCase();
      resolve(answer === 'j' || answer === 'y' || answer === 'ja' || answer === 'yes');
    });
  });
}

/**
 * Gruppera findings per fil.
 */
function groupByFile(findings) {
  const groups = new Map();
  for (const f of findings) {
    if (!groups.has(f.filePath)) groups.set(f.filePath, []);
    groups.get(f.filePath).push(f);
  }
  return groups;
}

// ── System-prompt ──────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are an expert in application security and penetration testing.
You analyse security findings from an automated scanning tool and provide concrete,
actionable advice in English.

For each finding respond with a JSON object with exactly this structure:
{
  "ruleId": "<rule ID from input>",
  "line": <radnummer>,
  "confirmed": true/false,
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "false_positive_reason": "<explanation if confirmed=false, otherwise null>",
  "attack_scenario": "<concrete attack scenario in 2-3 sentences, specific to this code>",
  "fix_code": "<concrete fix code in the same language as the original, with comment>",
  "fix_explanation": "<brief explanation of why this fix approach is correct>"
}

ALWAYS respond with a JSON array, even for a single finding: [{...}, {...}]
No markdown backticks, no preamble — raw JSON only.`;

// ── API call ──────────────────────────────────────────────────────────────

/**
 * Retry wrapper with exponential backoff for rate limit (429) errors.
 */
async function withRetry(fn, context) {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      const is429 = err.status === 429
        || (err.message && err.message.includes('429'))
        || (err.message && err.message.includes('rate_limit'));

      attempt++;
      if (!is429 || attempt >= RETRY_MAX_ATTEMPTS) throw err;

      const delayMs  = RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
      const delaySec = Math.round(delayMs / 1000);
      process.stderr.write(
        `\x1b[33m   [deep] Rate limit hit${context ? ' (' + context + ')' : ''} – ` +
        `retrying in ${delaySec}s (attempt ${attempt}/${RETRY_MAX_ATTEMPTS - 1})...\x1b[0m\n`
      );
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

/**
 * Analyse a group of findings for a file.
 * Returns array of analysis results.
 */
async function analyzeFileFindings(filePath, findings, apiKey) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client    = new Anthropic({ apiKey });

  // Build context snippets for each finding
  const findingDescriptions = findings.map(f => ({
    ruleId:   f.ruleId,
    name:     f.name,
    severity: f.severity,
    line:     f.line,
    snippet:  f.snippet,
    context:  extractContext(f.filePath, f.line),
    problem:  f.description,
    scenario: f.scenario,
  }));

  const userMessage = `Analyse these security findings in the file "${filePath}":

${JSON.stringify(findingDescriptions, null, 2)}

Provide your analysis as a JSON array with one object per finding.`;

  const response = await withRetry(
    () => client.messages.create({
      model:      MODEL,
      max_tokens: MAX_TOKENS,
      system:     SYSTEM_PROMPT,
      messages:   [{ role: 'user', content: userMessage }],
    }),
    filePath
  );

  const raw = response.content[0]?.text ?? '[]';

  // Strip any markdown backticks the model may include
  // Strippa alla former av markdown-wrapping som modellen kan returnera
  const cleaned = raw
    .replace(/^```(?:json)?\s*/im, '')
    .replace(/```\s*$/m, '')
    .trim();

  try {
    const parsed = JSON.parse(cleaned);
    // Ensure we always return an array
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (parseErr) {
    // Log raw response to stderr for debugging without polluting stdout
    process.stderr.write(`\x1b[33m   [deep] JSON parse-fel: ${parseErr.message}\x1b[0m\n`);
    process.stderr.write(`\x1b[90m   [deep] Raw response: ${raw.slice(0, 300)}\x1b[0m\n`);
    return [];
  }
}

// ── Huvud-export ───────────────────────────────────────────────────────────

/**
 * Run deep analysis on a list of findings.
 *
 * @param {Array}  findings  - From scanFull()
 * @param {Object} opts      - { apiKey, interactive, verbose }
 * @returns {Map}  filePath → [analysresultat]
 */
async function deepAnalyze(findings, opts = {}) {
  const { apiKey, interactive = true, verbose = false, delayMs = 0 } = opts;

  if (!apiKey) {
    throw new Error(
      'ANTHROPIC_API_KEY missing. Set the key in environment or run: sc configure --api-key sk-ant-...'
    );
  }

  // Ensure findings is a plain array (scanFull may attach _timedOut as a property)
  const allFindings = Array.from(findings);

  // Diagnostics – log what we actually received
  if (verbose) {
    const sevCounts = allFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
    }, {});
    process.stderr.write(`\x1b[90m   [deep] ${allFindings.length} findings in: ${JSON.stringify(sevCounts)}\x1b[0m\n`);
  }

  // Filter to CRITICAL and HIGH only – EXPOSURE/MEDIUM are not worth the API cost
  const eligible = allFindings.filter(f =>
    f.severity === 'CRITICAL' || f.severity === 'HIGH'
  );

  if (eligible.length === 0) {
    if (verbose) process.stderr.write('\x1b[90m   [deep] Inga CRITICAL/HIGH findings – avslutar.\x1b[0m\n');
    return new Map();
  }

  const byFile   = groupByFile(eligible);
  const fileCount = byFile.size;
  const estCost  = estimateCost(fileCount);

  // Interactive warning if scope is broad
  if (interactive && (fileCount > INTERACTIVE_THRESHOLD_FILES || eligible.length > INTERACTIVE_THRESHOLD_FINDINGS)) {
    const YELLOW = '\x1b[33m', RESET = '\x1b[0m', BOLD = '\x1b[1m', DIM = '\x1b[90m';
    console.log(`\n${YELLOW}${BOLD}⚠️  --deep scope is broad${RESET}`);
    console.log(`${DIM}   ${eligible.length} findings i ${fileCount} filer → uppskattad kostnad: ~$${estCost} USD${RESET}`);
    console.log(`${DIM}   Tip: narrow scope with --rule PHP-INJ-002 or --severity critical${RESET}\n`);

    const confirmed = await promptYesNo(`   Continue with deep analysis of all ${fileCount} files? [y/N] `);
    if (!confirmed) {
      console.log(`\n\x1b[90m   Deep analysis aborted. Run again with a narrower scope.\x1b[0m\n`);
      return new Map();
    }
    console.log('');
  }

  // Run analysis file by file, in batches if the file has many findings
  const results = new Map();
  let fileIndex = 0;

  for (const [filePath, fileFindings] of byFile) {
    fileIndex++;

    if (verbose) {
      process.stdout.write(
        `\x1b[90m   [${fileIndex}/${fileCount}] Analysing ${filePath}...\x1b[0m\r`
      );
    }

    try {
      // Split into batches of MAX_FINDINGS_PER_CALL – keeps each response within token budget
      const allAnalyses = [];
      for (let i = 0; i < fileFindings.length; i += MAX_FINDINGS_PER_CALL) {
        const batch    = fileFindings.slice(i, i + MAX_FINDINGS_PER_CALL);
        const analyses = await analyzeFileFindings(filePath, batch, apiKey);
        allAnalyses.push(...analyses);
      }
      results.set(filePath, allAnalyses);
    } catch (err) {
      // API error for individual file – mark as error, continue with the rest
      results.set(filePath, [{ _error: err.message }]);
    }

    // Inter-file delay to avoid rate limiting (configurable via --delay or config deep_delay_ms)
    if (delayMs > 0 && fileIndex < fileCount) {
      if (verbose) {
        process.stdout.write(
          `\x1b[90m   [${fileIndex}/${fileCount}] Waiting ${delayMs}ms before next file...\x1b[0m\r`
        );
      }
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  if (verbose) {
    process.stdout.write('\x1b[2K'); // Rensa progress-rad
  }

  return results;
}

// ── Output-formattering ────────────────────────────────────────────────────

const SEV_COLORS = {
  CRITICAL: '\x1b[31m',
  HIGH:     '\x1b[33m',
};

/**
 * Format the deep analysis section for terminal output.
 * Called from output-terminal.js or directly from the CLI.
 *
 * @param {Array} findings    - Ursprungliga findings
 * @param {Map}   deepResults - From deepAnalyze()
 * @returns {string}
 */
function formatDeepSection(findings, deepResults) {
  if (!deepResults || deepResults.size === 0) return '';

  const RESET  = '\x1b[0m';
  const BOLD   = '\x1b[1m';
  const DIM    = '\x1b[90m';
  const GREEN  = '\x1b[32m';
  const RED    = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const CYAN   = '\x1b[36m';

  const lines = [];
  lines.push('');
  lines.push('─'.repeat(60));
  lines.push(`  ${CYAN}${BOLD}↓  Claude deep analysis (--deep)  ↓${RESET}`);
  lines.push('─'.repeat(60));

  for (const [filePath, analyses] of deepResults) {
    if (!Array.isArray(analyses) || analyses.length === 0) continue;

    // API error for this file
    if (analyses[0]?._error) {
      lines.push(`\n  ${RED}❌ ${filePath}${RESET}`);
      lines.push(`     ${DIM}API-fel: ${analyses[0]._error}${RESET}`);
      continue;
    }

    for (const analysis of analyses) {
      // Find original finding – match on ruleId + line (filePath format may differ)
      const original = findings.find(f =>
        f.ruleId === analysis.ruleId &&
        f.line   === analysis.line   &&
        (f.filePath === filePath || f.filePath.endsWith(filePath) || filePath.endsWith(f.filePath))
      );
      const sev      = original?.severity ?? 'HIGH';
      const color    = SEV_COLORS[sev] ?? YELLOW;
      const sevIcon  = sev === 'CRITICAL' ? '🔴' : '🟠';

      lines.push('');
      lines.push(`  ${color}${BOLD}${sevIcon} ${analysis.ruleId} · ${filePath}:${analysis.line}${RESET}`);

      // Assessment
      if (analysis.confirmed === false) {
        lines.push(`     ${GREEN}${BOLD}✓ Likely false positive${RESET}  ${DIM}(confidence: ${analysis.confidence})${RESET}`);
        if (analysis.false_positive_reason) {
          lines.push(`     ${DIM}${analysis.false_positive_reason}${RESET}`);
        }
        continue; // No attack/fix for false positives
      }

      const confColor = analysis.confidence === 'HIGH' ? RED
                      : analysis.confidence === 'MEDIUM' ? YELLOW : DIM;
      lines.push(`     ${BOLD}Assessment:${RESET} ${RED}✗ Confirmed vulnerability${RESET}  ${DIM}confidence: ${confColor}${analysis.confidence}${RESET}`);

      // Attack-scenario
      if (analysis.attack_scenario) {
        lines.push('');
        lines.push(`     ${BOLD}Attack:${RESET}`);
        // Wrap long lines at ~80 chars
        const words = analysis.attack_scenario.split(' ');
        let currentLine = '     ';
        for (const word of words) {
          if (currentLine.length + word.length > 82) {
            lines.push(`${DIM}${currentLine}${RESET}`);
            currentLine = '     ' + word + ' ';
          } else {
            currentLine += word + ' ';
          }
        }
        if (currentLine.trim()) lines.push(`${DIM}${currentLine}${RESET}`);
      }

      // Fix-kod
      if (analysis.fix_code) {
        lines.push('');
        lines.push(`     ${BOLD}Fix:${RESET}`);
        const fixLines = analysis.fix_code.split('\n');
        for (const fl of fixLines) {
          lines.push(`     ${GREEN}${fl}${RESET}`);
        }
      }

      // Fix explanation
      if (analysis.fix_explanation) {
        lines.push(`     ${DIM}↳ ${analysis.fix_explanation}${RESET}`);
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}

module.exports = { deepAnalyze, formatDeepSection, estimateCost };
