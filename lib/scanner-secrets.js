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
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'AWS Access Keys grant direct access to your cloud services and resources.',
    scenario: 'An attacker who finds the key can launch servers, read S3 buckets, and delete data on your behalf — charges and breaches may go unnoticed for days.',
    fix: 'Use environment variables or AWS IAM roles instead. Rotate the key immediately via the AWS Console and audit CloudTrail for unauthorized usage.',
  },
  {
    id: 'SECRET-002',
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'An OpenAI API key in source code can be used by anyone who reads the repository — including forks and search engine caches.',
    scenario: 'Automated scanners harvest OpenAI keys from GitHub within minutes of a push. Usage costs can reach thousands of dollars before the key is revoked.',
    fix: 'Store in a .env file (with .env in .gitignore) or in your platform\'s secret manager. Revoke the exposed key at platform.openai.com/api-keys.',
  },
  {
    id: 'SECRET-003',
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'GitHub tokens grant access to your repositories and organization settings, scoped to whatever permissions were granted at creation.',
    scenario: 'With a valid token, an attacker can read private code, push commits, create webhooks, or inject malicious code into your repository.',
    fix: 'Use GitHub Actions secrets for CI/CD: ${{ secrets.MY_TOKEN }}. Revoke the exposed token immediately at github.com/settings/tokens.',
  },
  {
    id: 'SECRET-004',
    name: 'Generic API Key (hardcoded)',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]/gi,
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'Hardcoded API keys are exposed to everyone who can read the source code — including all contributors, contractors, and anyone who gains repository access.',
    scenario: 'If the repository is shared with a consultant or accidentally made public, the API key is immediately exposed to external parties.',
    fix: 'Move to an environment variable: process.env.API_KEY or the equivalent for your language. Store the value in a .env file excluded from git, or use a secrets manager.',
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
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'Hardcoded passwords in source code are one of the most common vulnerabilities in AI-generated code. They end up in version control history permanently — even after deletion.',
    scenario: 'An AI coding tool fills in a sample password that gets committed and forgotten. Anyone with repository access — including future contributors — can see it forever in git history.',
    fix: 'Use environment variables or a secrets manager. Ensure .env is in .gitignore. For .NET: use Web.config encrypted sections or environment variables via ConfigurationManager.',
  },
  {
    id: 'SECRET-006',
    name: 'Private key (PEM format)',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    why: 'A private key in source code compromises your entire cryptographic infrastructure — SSL certificates, SSH access, and signed tokens can all be forged.',
    scenario: 'The committed private key is used to decrypt TLS traffic captured by an attacker, or to sign malicious code as if it came from your organisation.',
    fix: 'Private keys must never appear in source code. Store in a secrets manager or HSM. Revoke and reissue the affected certificate or key pair immediately.',
  },
  {
    id: 'SECRET-007',
    name: 'Hardcoded JWT secret',
    pattern: /jwt[_-]?secret\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'CRITICAL',
    category: 'Broken Authentication (OWASP A07)',
    why: 'The JWT signing secret is used to sign and verify all authentication tokens. Exposing it allows an attacker to forge valid sessions for any user.',
    scenario: 'An attacker who knows the secret creates a JWT with admin: true and any user ID, bypassing all authentication checks in your application.',
    fix: 'Generate a strong random secret (minimum 256 bits) and store it in an environment variable. Rotate the secret and invalidate all existing sessions immediately.',
  },
  {
    id: 'SECRET-008',
    name: 'Stripe Secret Key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    why: 'Stripe live keys grant full programmatic access to your payment account, including initiating payouts, refunds, and reading card data.',
    scenario: 'An attacker uses the exposed key to initiate payouts to an external account or enumerate customer payment methods.',
    fix: 'Never use live keys in source code. Store in a server-side environment variable only. Revoke the exposed key immediately in the Stripe Dashboard and audit recent API activity.',
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
            if (rule.antipattern.test(window)) continue; // likely false positive – skip
          }

          const redacted = line.trim().replace(match[0], '[REDACTED]');

          const finding = {
            ruleId:   rule.id,
            name:     rule.name,
            severity: rule.severity,
            category: rule.category,
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
