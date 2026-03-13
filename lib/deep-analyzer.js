/**
 * deep-analyzer.js
 * Claude API-driven djupanalys av säkerhetsfynd från sc scan --deep.
 *
 * Design:
 *   - Grupperar findings per fil → en API-call per fil
 *   - Skickar kodens kontext (relevanta rader runt varje finding)
 *   - Returnerar bekräftelse, attack-scenario och konkret fix-kod
 *   - Interaktiv kostnadsuppskattning om scope är brett (>5 filer)
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
const MAX_TOKENS     = 4096;   // per API-call – måste rymma alla findings med full analys
const CONTEXT_LINES  = 8;      // rader kodbas runt varje finding
const MAX_FINDINGS_PER_CALL = 3; // max findings per API-call – håller svaret inom token-budget

// Uppskattade tokens per fil-grupp (används för kostnadsuppskattning)
const EST_INPUT_TOKENS_PER_FILE  = 900;
const EST_OUTPUT_TOKENS_PER_FILE = 650;

// Priser i USD per 1M tokens (Sonnet 4.6)
const PRICE_INPUT_PER_M  = 3.00;
const PRICE_OUTPUT_PER_M = 15.00;

// Trösklar för interaktiv varning
const INTERACTIVE_THRESHOLD_FILES    = 5;
const INTERACTIVE_THRESHOLD_FINDINGS = 15;

// ── Hjälpfunktioner ────────────────────────────────────────────────────────

/**
 * Läs kodrader runt ett finding (kontext-fönster).
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
    return '(kodbas ej tillgänglig)';
  }
}

/**
 * Uppskatta kostnad i USD för ett antal filer.
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

const SYSTEM_PROMPT = `Du är en expert på applikationssäkerhet och penetrationstestning. 
Du analyserar säkerhetsfynd från ett automatiserat skanningsverktyg och ger konkreta, 
handlingsbara råd på svenska.

För varje fynd ska du svara med ett JSON-objekt med exakt denna struktur:
{
  "ruleId": "<regel-id från input>",
  "line": <radnummer>,
  "confirmed": true/false,
  "confidence": "HÖG" | "MEDEL" | "LÅG",
  "false_positive_reason": "<förklaring om confirmed=false, annars null>",
  "attack_scenario": "<konkret attack-scenario på 2-3 meningar, specifikt för denna kod>",
  "fix_code": "<konkret fix-kod i samma språk som originalet, med kommentar>",
  "fix_explanation": "<kort förklaring av varför fixens approach är rätt>"
}

Svara ALLTID med ett JSON-array, även om det bara är ett fynd: [{...}, {...}]
Inga markdown-backticks, inget preamble – bara rå JSON.`;

// ── API-anrop ──────────────────────────────────────────────────────────────

/**
 * Analysera en grupp findings för en fil.
 * Returnerar array med analysresultat.
 */
async function analyzeFileFindings(filePath, findings, apiKey) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client    = new Anthropic({ apiKey });

  // Bygg kontext-snippets för varje finding
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

  const userMessage = `Analysera dessa säkerhetsfynd i filen "${filePath}":

${JSON.stringify(findingDescriptions, null, 2)}

Ge din analys som ett JSON-array med ett objekt per fynd.`;

  const response = await client.messages.create({
    model:      MODEL,
    max_tokens: MAX_TOKENS,
    system:     SYSTEM_PROMPT,
    messages:   [{ role: 'user', content: userMessage }],
  });

  const raw = response.content[0]?.text ?? '[]';

  // Strippa eventuella markdown-backticks om modellen ändå skickar dem
  // Strippa alla former av markdown-wrapping som modellen kan returnera
  const cleaned = raw
    .replace(/^```(?:json)?\s*/im, '')
    .replace(/```\s*$/m, '')
    .trim();

  try {
    const parsed = JSON.parse(cleaned);
    // Säkerställ att vi alltid returnerar en array
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch (parseErr) {
    // Logga råsvaret till stderr så vi kan debugga utan att störa stdout
    process.stderr.write(`\x1b[33m   [deep] JSON parse-fel: ${parseErr.message}\x1b[0m\n`);
    process.stderr.write(`\x1b[90m   [deep] Råsvar: ${raw.slice(0, 300)}\x1b[0m\n`);
    return [];
  }
}

// ── Huvud-export ───────────────────────────────────────────────────────────

/**
 * Kör djupanalys på en lista findings.
 *
 * @param {Array}  findings  - Från scanFull()
 * @param {Object} opts      - { apiKey, interactive, verbose }
 * @returns {Map}  filePath → [analysresultat]
 */
async function deepAnalyze(findings, opts = {}) {
  const { apiKey, interactive = true, verbose = false } = opts;

  if (!apiKey) {
    throw new Error(
      'ANTHROPIC_API_KEY saknas. Sätt nyckeln i miljön eller kör: sc configure --api-key sk-ant-...'
    );
  }

  // Säkerställ att findings är en ren array (scanFull lägger _timedOut som property)
  const allFindings = Array.from(findings);

  // Diagnostik – logga vad vi faktiskt fått in
  if (verbose) {
    const sevCounts = allFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
    }, {});
    process.stderr.write(`\x1b[90m   [deep] ${allFindings.length} findings in: ${JSON.stringify(sevCounts)}\x1b[0m\n`);
  }

  // Filtrera bara CRITICAL och HIGH – EXPOSURE/MEDIUM är inte värda API-kostnaden
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

  // Interaktiv varning om scope är brett
  if (interactive && (fileCount > INTERACTIVE_THRESHOLD_FILES || eligible.length > INTERACTIVE_THRESHOLD_FINDINGS)) {
    const YELLOW = '\x1b[33m', RESET = '\x1b[0m', BOLD = '\x1b[1m', DIM = '\x1b[90m';
    console.log(`\n${YELLOW}${BOLD}⚠️  --deep scope är brett${RESET}`);
    console.log(`${DIM}   ${eligible.length} findings i ${fileCount} filer → uppskattad kostnad: ~$${estCost} USD${RESET}`);
    console.log(`${DIM}   Tips: avgränsa med --rule PHP-INJ-002 eller --severity critical${RESET}\n`);

    const confirmed = await promptYesNo(`   Fortsätt med djupanalys av alla ${fileCount} filer? [j/N] `);
    if (!confirmed) {
      console.log(`\n\x1b[90m   Djupanalys avbruten. Kör igen med ett smalare scope.\x1b[0m\n`);
      return new Map();
    }
    console.log('');
  }

  // Kör analys fil för fil, i batchar om filen har många findings
  const results = new Map();
  let fileIndex = 0;

  for (const [filePath, fileFindings] of byFile) {
    fileIndex++;

    if (verbose) {
      process.stdout.write(
        `\x1b[90m   [${fileIndex}/${fileCount}] Analyserar ${filePath}...\x1b[0m\r`
      );
    }

    try {
      // Dela upp i batchar om MAX_FINDINGS_PER_CALL – håller varje svar inom token-budget
      const allAnalyses = [];
      for (let i = 0; i < fileFindings.length; i += MAX_FINDINGS_PER_CALL) {
        const batch    = fileFindings.slice(i, i + MAX_FINDINGS_PER_CALL);
        const analyses = await analyzeFileFindings(filePath, batch, apiKey);
        allAnalyses.push(...analyses);
      }
      results.set(filePath, allAnalyses);
    } catch (err) {
      // API-fel för enskild fil – markera som fel, fortsätt med resten
      results.set(filePath, [{ _error: err.message }]);
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
 * Formatera djupanalys-sektionen för terminal-output.
 * Anropas från output-terminal.js eller direkt från CLI.
 *
 * @param {Array} findings    - Ursprungliga findings
 * @param {Map}   deepResults - Från deepAnalyze()
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
  lines.push(`  ${CYAN}${BOLD}↓  Claude djupanalys (--deep)  ↓${RESET}`);
  lines.push('─'.repeat(60));

  for (const [filePath, analyses] of deepResults) {
    if (!Array.isArray(analyses) || analyses.length === 0) continue;

    // API-fel för denna fil
    if (analyses[0]?._error) {
      lines.push(`\n  ${RED}❌ ${filePath}${RESET}`);
      lines.push(`     ${DIM}API-fel: ${analyses[0]._error}${RESET}`);
      continue;
    }

    for (const analysis of analyses) {
      // Hitta ursprungligt finding – matcha på ruleId + line (filePath kan skilja i format)
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

      // Bekräftelse
      if (analysis.confirmed === false) {
        lines.push(`     ${GREEN}${BOLD}✓ Trolig false positive${RESET}  ${DIM}(konfidens: ${analysis.confidence})${RESET}`);
        if (analysis.false_positive_reason) {
          lines.push(`     ${DIM}${analysis.false_positive_reason}${RESET}`);
        }
        continue; // Ingen attack/fix för false positives
      }

      const confColor = analysis.confidence === 'HÖG' ? RED
                      : analysis.confidence === 'MEDEL' ? YELLOW : DIM;
      lines.push(`     ${BOLD}Bekräftelse:${RESET} ${RED}✗ Verkligt problem${RESET}  ${DIM}konfidens: ${confColor}${analysis.confidence}${RESET}`);

      // Attack-scenario
      if (analysis.attack_scenario) {
        lines.push('');
        lines.push(`     ${BOLD}Attack:${RESET}`);
        // Bryt långa rader vid ~80 tecken
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

      // Fix-förklaring
      if (analysis.fix_explanation) {
        lines.push(`     ${DIM}↳ ${analysis.fix_explanation}${RESET}`);
      }
    }
  }

  lines.push('');
  return lines.join('\n');
}

module.exports = { deepAnalyze, formatDeepSection, estimateCost };
