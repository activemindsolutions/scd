/**
 * scanner-secrets.js
 * Fast secrets detection for pre-commit hook.
 * Now config-aware and audit-logged.
 */

const { isExcepted, getRuleAction } = require('./config');

const RULES = [
  {
    id: 'SECRET-001',
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL',
    why: 'AWS Access Keys ger direkt åtkomst till era molntjänster.',
    scenario: 'En angripare som hittar nyckeln kan starta servrar, läsa S3-buckets och ta bort data på er räkning.',
    fix: 'Använd environment-variabler eller AWS IAM roles. Rotera nyckeln omedelbart via AWS Console.',
  },
  {
    id: 'SECRET-002',
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    severity: 'CRITICAL',
    why: 'En OpenAI-nyckel i koden kan användas av vem som helst som läser repot.',
    scenario: 'Angripare scrapar GitHub efter dessa nycklar automatiskt inom minuter efter publicering.',
    fix: 'Spara i .env-fil (lägg .env i .gitignore) eller i er plattforms secret manager.',
  },
  {
    id: 'SECRET-003',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'CRITICAL',
    why: 'GitHub-tokens ger åtkomst till era repositories och organisationsinställningar.',
    scenario: 'Med en giltig token kan en angripare läsa privat kod eller injectera skadlig kod.',
    fix: 'Använd GitHub Secrets för CI/CD. Rotera token direkt via github.com/settings/tokens.',
  },
  {
    id: 'SECRET-004',
    name: 'Generic API Key (hårdkodad)',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
    severity: 'HIGH',
    why: 'Hårdkodade API-nycklar exponeras för alla som kan läsa källkoden.',
    scenario: 'Om repot läcker eller delas med en konsult har den personen tillgång till er externa tjänst.',
    fix: 'Flytta till environment-variabel: process.env.API_KEY eller motsvarande för ert språk.',
  },
  {
    id: 'SECRET-005',
    name: 'Hardcoded password',
    // Matches: password = "secret123", pwd: 'abc123', passwd="x"
    // Excludes:
    //   - jQuery/DOM selectors: $("input[name='password']"), getElementById('password')
    //   - input attributes: name='password', type='password'
    //   - process.env, getenv, os.environ – correct env var handling
    //   - C# typed declarations caught by CS-SECRET-002: string adminPassword = "..."
    //   - URL-encoded POST bodies: postdata="...password="+var+"..." (dynamic, not hardcoded)
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]/gi,
    antipattern: /input\[|\.val\(\)|getElementById|querySelector|getenv|process\.env|os\.environ|name\s*=\s*['"]password|type\s*=\s*['"]password|password=["']\s*\+\s*\w|&password=["']\s*\+|(?:string|var|const|let)\s+\w*[Pp]assword/i,
    lookahead: 80,
    severity: 'HIGH',
    why: 'Hardcoded passwords in source code are one of the most common vulnerabilities in AI-generated code. They end up in version control history permanently — even after deletion.',
    scenario: 'An AI coding tool fills in a sample password that gets committed and forgotten. Anyone with repository access — including future contributors — can see it forever in git history.',
    fix: 'Use environment variables or a secrets manager. Ensure .env is in .gitignore. For .NET: use Web.config encrypted sections or environment variables via ConfigurationManager.',
  },
  {
    id: 'SECRET-006',
    name: 'Privat nyckel (PEM-format)',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    why: 'En privat nyckel i koden kompromissar hela er kryptografiska infrastruktur.',
    scenario: 'SSL-certifikat, SSH-åtkomst och signerade tokens kan alla förfalskas.',
    fix: 'Privata nycklar ska aldrig finnas i källkod. Använd en secrets manager eller HSM.',
  },
  {
    id: 'SECRET-007',
    name: 'JWT-hemlighet hårdkodad',
    pattern: /jwt[_-]?secret\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'CRITICAL',
    why: 'JWT-hemligheten används för att signera och verifiera alla inloggningstoken.',
    scenario: 'Den som känner till hemligheten kan skapa giltiga JWT-tokens för vilken användare som helst.',
    fix: 'Generera en stark slumpmässig hemlighet (min 256 bit) och spara i environment-variabel.',
  },
  {
    id: 'SECRET-008',
    name: 'Stripe Secret Key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'CRITICAL',
    why: 'Stripe live-nycklar ger full åtkomst till era betalningar och kundkortsdata.',
    scenario: 'En angripare kan initiera utbetalningar eller komma åt kortinformation.',
    fix: 'Använd aldrig live-nycklar i kod. Spara i server-side environment-variabel.',
  },
];

async function scanSecrets(files, config = null) {
  const findings = [];

  for (const { filePath, content } of files) {
    const lines = content.split('\n');

    for (const rule of RULES) {
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];
        const matches = [...line.matchAll(new RegExp(rule.pattern.source, rule.pattern.flags))];

        for (const match of matches) {
          // Antipattern-check: om regeln har antipattern, kolla matchad rad + lookahead
          if (rule.antipattern) {
            const lookahead  = rule.lookahead || 80;
            const windowEnd  = Math.min(lines.length, lineIndex + Math.ceil(lookahead / 80) + 1);
            const window     = lines.slice(lineIndex, windowEnd).join('\n');
            if (rule.antipattern.test(window)) continue; // trolig false positive – skippa
          }

          const redacted = line.trim().replace(match[0], '[REDACTED]');

          const finding = {
            ruleId:   rule.id,
            name:     rule.name,
            severity: rule.severity,
            filePath,
            line:     lineIndex + 1,
            snippet:  redacted,
            why:      rule.why,
            scenario: rule.scenario,
            fix:      rule.fix,
            hook:     'pre-commit',
          };

          if (config) {
            const excResult = isExcepted(config, finding, line);
            finding.excepted          = excResult.excepted;
            finding.exception_expired = excResult.expired;
            finding.exception         = excResult.exception;
            const action = getRuleAction(config, rule.id, rule.severity);
            finding.action = action;
            finding.blocks = !excResult.excepted && action === 'block';
          } else {
            finding.excepted = false;
            finding.action   = rule.severity === 'CRITICAL' ? 'block' : 'warn';
            finding.blocks   = rule.severity === 'CRITICAL';
          }

          findings.push(finding);
        }
      }
    }
  }

  return findings;
}

module.exports = { scanSecrets, RULES };
