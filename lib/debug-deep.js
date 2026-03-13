// Kör direkt mot API:et med samma logik som deep-analyzer
// Sätt ANTHROPIC_API_KEY i miljön innan du kör detta

const fs   = require('fs');
const path = require('path');

const MODEL = 'claude-sonnet-4-6';

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

async function run() {
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  const mockFindings = [
    { ruleId: 'PHP-INJ-002', line: 14, severity: 'CRITICAL',
      snippet: "$result = sqlsrv_query($link, $SQL, array($_POST['id']));",
      description: 'SQL-injection via direktinterpolering',
      context: '12: $SQL = "DELETE FROM filter WHERE id = " . $_POST["id"];\n13: \n14: $result = sqlsrv_query($link, $SQL, array($_POST[\'id\']));'
    }
  ];

  const userMessage = `Analysera dessa säkerhetsfynd i filen "WS_deleteFilter.php":

${JSON.stringify(mockFindings, null, 2)}

Ge din analys som ett JSON-array med ett objekt per fynd.`;

  console.log('Skickar till API...');
  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 1500,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userMessage }],
  });

  const raw = response.content[0]?.text ?? '[]';
  console.log('\n=== RAW API RESPONSE ===');
  console.log(raw);
  console.log('========================\n');

  const cleaned = raw.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
  try {
    const parsed = JSON.parse(cleaned);
    console.log('✅ JSON parsad OK:', JSON.stringify(parsed, null, 2));
  } catch (e) {
    console.log('❌ JSON parse-fel:', e.message);
    console.log('Cleaned string:', cleaned);
  }
}

run().catch(console.error);
