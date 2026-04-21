/**
 * rules-sensitive-files.js
 * Security rules for sensitive file types: config files, secrets, logs, scripts, and data files.
 * Covers: .env, .sql, .yml/.yaml, .json, .xml, .properties, .ini, .cfg, .sh, .ps1, .bat, .bak
 * Also: filename-only rules for binary secret files (.pem, .key, .pfx, .sqlite, .db)
 *
 * Rule categories:
 *   FILENAME  – the file itself should not exist / be in this location
 *   CONTENT   – dangerous content pattern found inside the file
 */

// ── .env files ────────────────────────────────────────────────────────────────

const ENV_RULES = [
  {
    id: 'ENV-001',
    name: 'Hardcoded secret in .env file committed to repository',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches .env lines where the variable name contains a sensitive keyword
    // Covers: DB_PASSWORD, API_KEY, MY_API_KEY, JWT_SECRET, STRIPE_SECRET_KEY etc.
    pattern: /^[A-Z0-9_]*(?:PASSWORD|PASSWD|_SECRET|_TOKEN|_KEY|API_KEY|API_SECRET|ACCESS_KEY|CLIENT_SECRET|PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|STRIPE|TWILIO|SENDGRID|AWS_SECRET|AZURE_SECRET|GCP_KEY|GITHUB_TOKEN|GITLAB_TOKEN)[A-Z0-9_]*\s*=\s*\S.{3,}/gim,
    antipattern: /=\s*(?:your_|change_|replace_|example_|test_|<|>|\$\{|%\(|placeholder)/i,
    lookahead: 5,
    why: '.env files are designed to keep secrets OUT of source code — but committing the .env file itself defeats that purpose entirely. Any secret in a committed .env file is as exposed as if it were hardcoded.',
    scenario: 'Developer runs git add . and commits .env along with other files. The repository now stores DB_PASSWORD, API_KEY, and JWT_SECRET in its history forever — including after deletion.',
    fix: 'Add .env to .gitignore immediately. Rotate all exposed secrets. Commit only .env.example with placeholder values. Use CI/CD secrets management (GitHub Secrets, Azure Key Vault) for deployment environments.',
    fileTypes: ['env'],
  },
  {
    id: 'ENV-002',
    name: 'Production .env file with credentials (.env.production, .env.prod)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    matchMode: 'filename',
    // Matches filenames containing .env.prod, .env.production, .env.staging etc.
    filenamePattern: /\.env\.(?:prod(?:uction)?|staging|live|release|deploy)/i,
    why: 'Production environment files contain live credentials for databases, payment systems, and third-party APIs. A single exposure can result in immediate breach of production systems.',
    scenario: '.env.production is pushed to a public repository. Automated scrapers find it within minutes. Production database, payment API keys, and email service credentials are compromised.',
    fix: 'Remove from repository immediately (use git filter-branch or BFG Repo Cleaner to purge history). Rotate all credentials. Use environment-specific secrets management — never store production secrets in files.',
    fileTypes: ['env'],
  },
];

// ── SQL dump files ────────────────────────────────────────────────────────────

const SQL_RULES = [
  {
    id: 'SQL-001',
    name: 'SQL dump file in repository or web-accessible location',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    matchMode: 'filename',
    filenamePattern: /(?:dump|backup|export|full|prod|database|db).*\.sql$|\.sql\.(?:gz|bak|zip)$/i,
    why: 'SQL dump files contain the complete database schema and often production data including user records, hashed passwords, PII, and transaction history. They are frequently created for migration and left in accessible locations.',
    scenario: 'Developer creates database.sql for migration, forgets to delete it. File is reachable at https://company.com/database.sql. Attacker downloads the entire production database including user emails and password hashes.',
    fix: 'Remove SQL dumps from web-accessible directories and version control. Store backups outside the web root in access-controlled storage. Use .gitignore patterns: *.sql, *.dump.',
    fileTypes: ['sql'],
  },
  {
    id: 'SQL-002',
    name: 'Hardcoded credentials in SQL file (CREATE USER / ALTER USER)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: CREATE USER 'user'@'host' IDENTIFIED BY 'password'
    // Also: ALTER USER ... IDENTIFIED BY, GRANT ... IDENTIFIED BY (MySQL legacy)
    pattern: /(?:CREATE|ALTER)\s+USER\s+[^;]{0,100}IDENTIFIED\s+BY\s+['"][^'"]{1,80}['"]/gi,
    why: 'SQL scripts that create database users often include plaintext passwords for the initial setup. These scripts end up in version control and are rarely updated when passwords are rotated.',
    scenario: 'setup.sql contains CREATE USER app_user IDENTIFIED BY "ProductionPass123". The script is committed to a private repository that later becomes public. The database account is compromised.',
    fix: 'Never include passwords in SQL scripts. Use IDENTIFIED BY <EXTERNAL> and manage passwords separately, or use SQL scripts that read from environment variables via shell wrappers.',
    fileTypes: ['sql'],
  },
  {
    id: 'SQL-003',
    name: 'Personal data (PII) columns in SQL dump',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches INSERT statements with PII-indicative column names
    // Common in exports/dumps of user tables
    pattern: /INSERT\s+INTO\s+\w+\s*\([^)]{0,200}(?:personnummer|ssn|social_security|passport|national_id|credit_card|card_number)[^)]{0,200}\)/gi,
    why: 'SQL dumps containing PII such as social security numbers, passport numbers or payment card data in version control or web-accessible locations constitute a data breach under GDPR and PCI-DSS.',
    scenario: 'Developer exports users table for testing, commits users_export.sql. The file contains 50,000 records with personnummer (Swedish SSN) and email addresses. GDPR breach notification is now required.',
    fix: 'Never commit real user data to version control. Use anonymized/synthetic test data. If a dump is required for debugging, strip PII first using a data masking tool.',
    fileTypes: ['sql'],
  },
];

// ── YAML / YML files ──────────────────────────────────────────────────────────

const YAML_RULES = [
  {
    id: 'YAML-001',
    name: 'Hardcoded password in YAML config file',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: password: "value", passwd: value, db_pass: 'value'
    // Excludes env var references: ${PASSWORD}, ${{ secrets.PASSWORD }}
    pattern: /(?:password|passwd|pwd|secret|api_key|api_secret|token|private_key)\s*:\s*(?!.*\$\{)(?!.*\$\{\{)['"]?[^\s'"#\n$%{]{6,}['"]?/gi,
    antipattern: /\$\{|\$\{\{|<[A-Z_]+>|YOUR_|CHANGE_ME|PLACEHOLDER|example|test123/i,
    lookahead: 5,
    why: 'YAML configuration files (Docker Compose, Kubernetes, CI/CD pipelines, application configs) are frequently committed to version control with hardcoded credentials that should be injected at runtime.',
    scenario: 'docker-compose.yml contains POSTGRES_PASSWORD: "ProductionPass" and is committed. Anyone with repository access — including contractors, junior devs, and CI/CD systems — has the production database password.',
    fix: 'Use environment variable references: password: ${DB_PASSWORD}. For Kubernetes: use Secrets objects. For GitHub Actions: use ${{ secrets.MY_SECRET }}. Never put literal credentials in YAML files.',
    fileTypes: ['yml', 'yaml'],
  },
  {
    id: 'YAML-002',
    name: 'CI/CD pipeline with hardcoded secret (GitHub Actions / GitLab CI)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: env: MY_SECRET: "hardcoded" patterns in workflow files
    pattern: /(?:env|environment)\s*:\s*\n(?:\s+[A-Z][A-Z0-9_]+\s*:\s*['"]?[^\s'"#\n$]{8,}['"]?\s*\n){1,}/gm,
    antipattern: /\$\{\{|\$\{|secrets\.|vault\./i,
    lookahead: 10,
    why: 'CI/CD pipeline files (.github/workflows/*.yml, .gitlab-ci.yml) are version controlled. Hardcoded secrets in these files are exposed to everyone with repository read access, including forks.',
    scenario: 'GitHub Actions workflow hardcodes AWS_SECRET_ACCESS_KEY. A contributor forks the repository for a PR. The fork now contains production AWS credentials with potential for cloud resource abuse.',
    fix: 'Use secrets references exclusively: ${{ secrets.AWS_SECRET_KEY }}. Configure secrets in repository settings, not in workflow files. Audit pipeline files in code review for credential leaks.',
    fileTypes: ['yml', 'yaml'],
  },
];

// ── JSON files ────────────────────────────────────────────────────────────────

const JSON_RULES = [
  {
    id: 'JSON-001',
    name: 'Hardcoded API key or secret in JSON config file',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: "apiKey": "AIza...", "secret": "sk-...", "token": "ghp_..."
    // Common in: Firebase config, appsettings.json, config.json
    pattern: /"(?:apiKey|api_key|apiSecret|api_secret|clientSecret|client_secret|accessToken|access_token|secretKey|secret_key|privateKey|private_key|authToken|auth_token)"\s*:\s*"([^"]{8,})"/gi,
    antipattern: /YOUR_|CHANGE|EXAMPLE|PLACEHOLDER|<[A-Z]|^:[a-zA-Z]/i,
    lookahead: 5,

    // Dynamic confidence based on the matched value's entropy and format.
    // HIGH:   known secret formats (sk-, ghp_, AKIA, base64 blocks, hex 32+)
    // MEDIUM: high entropy ASCII, looks random
    // LOW:    natural language, non-ASCII (i18n labels), or very short
    confidence: (match, lineRaw) => {
      if (!match) return 'MEDIUM';
      // Extract the value from the match (capture group 1)
      const full = match[0] || '';
      const valueMatch = full.match(/":\s*"([^"]+)"/);
      const value = valueMatch ? valueMatch[1] : '';

      if (!value) return 'MEDIUM';

      // LOW: contains non-ASCII characters (i18n/translation files)
      if (/[^ -]/.test(value)) return 'LOW';

      // LOW: looks like natural language — contains spaces, short readable text
      if (/\s/.test(value)) return 'LOW';

      // LOW: route parameter pattern (:paramName)
      if (/^:/.test(value)) return 'LOW';

      // LOW: no digits at all — real secrets always contain numbers.
      // Natural language words (e.g. "Client-Geheimnis", "Klienthemmelighet") never do.
      if (!/\d/.test(value)) return 'LOW';

      // HIGH: known secret format prefixes
      if (/^(?:sk-|ghp_|ghs_|gho_|github_pat_|xoxb-|xoxp-|xoxa-|AKIA|AIza|ya29\.|eyJ)/.test(value)) return 'HIGH';

      // HIGH: long hex string (32+ hex chars)
      if (/^[0-9a-f]{32,}$/i.test(value)) return 'HIGH';

      // HIGH: looks like base64 (long, no spaces, valid base64 charset)
      if (/^[A-Za-z0-9+/]{32,}={0,2}$/.test(value)) return 'HIGH';

      // MEDIUM: high entropy — random-looking mix of chars, 16+ length
      if (value.length >= 16 && /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value)) return 'MEDIUM';

      // LOW: short or simple values unlikely to be real secrets
      if (value.length < 12) return 'LOW';

      return 'MEDIUM';
    },

    why: 'JSON configuration files committed to version control expose API keys, OAuth secrets, and access tokens. These are particularly dangerous in frontend projects where appsettings or firebase configs contain service credentials.',
    scenario: 'appsettings.json contains "ConnectionString": "...Password=prod123..." and is committed. Azure DevOps build log shows the file. Production database credentials are now in build history.',
    fix: 'Use appsettings.{Environment}.json with environment-specific files excluded from git. For .NET: use User Secrets (dotnet user-secrets) for local dev and Key Vault for production. Never commit appsettings.Production.json.',
    fileTypes: ['json'],
  },
  {
    id: 'JSON-002',
    name: 'Firebase / GCP service account key file',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: GCP/Firebase service account JSON structure
    pattern: /"type"\s*:\s*"service_account"[^}]{0,500}"private_key"\s*:\s*"-----BEGIN/gi,
    why: 'GCP and Firebase service account JSON files contain private keys that grant programmatic access to cloud services. These files are frequently downloaded for local development and accidentally committed.',
    scenario: 'firebase-service-account.json is committed to a repository. Automated scanners (GitGuardian, TruffleHog) detect it within minutes. Attacker gains full Firebase admin access including reading all user data.',
    fix: 'Add *service-account*.json and *-credentials.json to .gitignore. Use Workload Identity Federation or mounted secrets in production. For local dev, store outside the repository directory.',
    fileTypes: ['json'],
  },
];

// ── XML files ─────────────────────────────────────────────────────────────────

const XML_RULES = [
  {
    id: 'XML-001',
    name: 'Hardcoded credentials in XML config (Maven settings, Spring, NuGet)',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: <password>value</password> in XML config files
    pattern: /<(?:password|passwd|secret|apiKey|api-key|accessKey|access-key|token)>(?!.*\$\{)[^<]{4,80}<\/(?:password|passwd|secret|apiKey|api-key|accessKey|access-key|token)>/gi,
    antipattern: /\$\{|\$ENV|CHANGE_ME|YOUR_PASSWORD|example/i,
    lookahead: 5,
    why: 'XML configuration files (Maven settings.xml, Spring applicationContext.xml, NuGet.config) are frequently committed with hardcoded credentials for package repositories, databases, and external services.',
    scenario: 'Maven settings.xml contains <password>nexus-prod-pass</password> for the internal Nexus repository. Developer commits it. Attacker gains access to internal build artifacts and can inject malicious dependencies.',
    fix: 'Use property references: <password>${env.NEXUS_PASSWORD}</password>. For Maven: use server credentials via CI/CD environment injection. For Spring: use @Value("${db.password}") bound to environment variables.',
    fileTypes: ['xml'],
  },
  {
    id: 'XML-002',
    name: 'Connection string with password in XML config',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: connectionString="...Password=..." in XML (Web.config, app.config patterns)
    pattern: /connectionString\s*=\s*["'][^"']{0,200}Password\s*=[^;"']{1,80}/gi,
    why: 'Connection strings with embedded passwords in XML config files (Web.config, app.config, ApplicationHost.config) are a systemic issue in .NET applications. They are rarely encrypted and frequently committed.',
    scenario: 'Web.config contains connectionString="...Password=SqlServerProd123". The file is in the repository for all team members. It also exists on the server — readable by any user who gains file system access.',
    fix: 'Encrypt Web.config connectionStrings section using aspnet_regiis -pe "connectionStrings". For new projects: use environment variables or Azure App Service connection string settings which override Web.config at runtime.',
    fileTypes: ['xml', 'config'],
  },
];

// ── .properties files ─────────────────────────────────────────────────────────

const PROPERTIES_RULES = [
  {
    id: 'PROP-001',
    name: 'Hardcoded password in .properties file',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: db.password=value, spring.datasource.password=value
    pattern: /^[a-zA-Z][\w.\-]{2,60}(?:password|passwd|secret|api[_.]?key|token|credential)\s*=\s*(?!\$\{)(?!ENC\()(?!your|change|example)[^\s#\n]{4,}/gim,
    antipattern: /=\s*\$\{|=\s*ENC\(|#\s*example|=\s*<|=\s*YOUR/i,
    lookahead: 5,
    why: 'Java .properties files (Spring Boot application.properties, Hibernate, JDBC config) are often committed with real credentials. Spring Boot\'s externalized configuration is designed to override these at runtime — but only if developers know to use it.',
    scenario: 'spring.datasource.password=ProductionDBPass123 in application.properties. Committed to git. All 12 developers and the CI/CD system have the production database password. One disgruntled employee or compromised account leads to breach.',
    fix: 'Use Spring profiles: application-prod.properties excluded from git, loaded via SPRING_PROFILES_ACTIVE. Or use environment variable binding: spring.datasource.password=${DB_PASSWORD}. Jasypt can encrypt values: ENC(encryptedValue).',
    fileTypes: ['properties'],
  },
];

// ── .ini / .cfg files ─────────────────────────────────────────────────────────

const INI_RULES = [
  {
    id: 'INI-001',
    name: 'Hardcoded credentials in INI or CFG config file',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: password = value, passwd=value, secret=value in INI format
    pattern: /^(?:password|passwd|pwd|secret|api_key|db_pass|db_password|token)\s*=\s*(?!\$\{)(?!your_|change_|example)[^\s#\n]{4,}/gim,
    antipattern: /^\s*#|\$\{|<[A-Z]|your_password|change_me/i,
    lookahead: 5,
    why: 'INI and CFG files are the classic configuration format for Python applications (Django, Flask via configparser), PHP (php.ini), and many legacy systems. They often contain database credentials and API keys committed alongside application code.',
    scenario: 'config.cfg contains password = FlaskProdSecret committed by a junior developer who followed a tutorial. The tutorial used a real-looking password that the developer never changed.',
    fix: 'Read sensitive values from environment variables in the config loader: password = %(DB_PASSWORD)s using configparser interpolation, or os.environ["DB_PASSWORD"] in application startup code.',
    fileTypes: ['ini', 'cfg', 'conf'],
  },
];

// ── Shell scripts (.sh, .bash) ────────────────────────────────────────────────

const SHELL_RULES = [
  {
    id: 'SH-001',
    name: 'Hardcoded secret in shell script (export or variable assignment)',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: export API_KEY="value", PASSWORD="value", TOKEN='value'
    pattern: /(?:export\s+)?[A-Z][A-Z0-9_]{2,40}(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS|_PWD|_API)\s*=\s*["'][^"'\n]{6,}["']/g,
    antipattern: /\$\{|\$\(|read\s+-s|getpass|vault|secrets/i,
    lookahead: 5,
    why: 'Shell scripts with hardcoded secrets are a common finding in DevOps and infrastructure repositories. They are often written as quick one-offs and then committed, or used in CI/CD pipelines where environment injection was not configured.',
    scenario: 'deploy.sh contains export DB_PASSWORD="ProductionPass123". It is committed as part of the deployment tooling. Every team member, contractor, and CI/CD system with repository access has the production password.',
    fix: 'Read secrets from environment: DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD not set}". The :? syntax causes the script to fail loudly if the variable is not set. For CI/CD, inject via pipeline secret management.',
    fileTypes: ['sh', 'bash'],
  },
  {
    id: 'SH-002',
    name: 'Hardcoded credentials in curl or wget command',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: curl -H "Authorization: Bearer token", --user user:password
    pattern: /(?:curl|wget)[^#\n]{0,200}(?:-H\s+["']Authorization:\s+(?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{8,}|--user\s+\w+:[^\s'"]{4,}|--password\s+["'][^"'\n]{4,}["'])/gi,
    antipattern: /\$\{|\$[A-Z_]|read\s+-s/i,
    lookahead: 5,
    why: 'Shell scripts that make authenticated API calls often hardcode credentials in curl/wget commands. These commands may also appear in shell history, process listings, and log files.',
    scenario: 'backup.sh uses curl with a hardcoded Bearer token for a cloud storage API. The token has write access. An attacker who reads this script can exfiltrate or overwrite all backed-up data.',
    fix: 'Use environment variables: curl -H "Authorization: Bearer ${API_TOKEN}". Store the token in a secrets manager and inject it at runtime. Never pass credentials as literal strings in command-line arguments.',
    fileTypes: ['sh', 'bash'],
  },
];

// ── PowerShell (.ps1) ─────────────────────────────────────────────────────────

const PS_RULES = [
  {
    id: 'PS-001',
    name: 'Hardcoded credential in PowerShell script',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: $password = "value", $apiKey = 'value', ConvertTo-SecureString "value"
    pattern: /\$(?:password|passwd|apiKey|api_key|secret|token|credential|pass)\s*=\s*["'][^"'\n]{4,}["']|ConvertTo-SecureString\s+["'][^"'\n]{4,}["']/gi,
    antipattern: /Read-Host|Get-Secret|ConvertTo-SecureString\s+\$|KeyVault|SecretManagement/i,
    lookahead: 10,
    why: 'PowerShell scripts are common in Windows/.NET environments for deployment, database maintenance, and administration tasks. Hardcoded credentials in these scripts are a frequent finding in ASP.NET project repositories.',
    scenario: '$password = "SqlAdmin123!" is used to construct a SqlConnection in a database migration script. The script is in the repository. SQL Server admin credentials are now accessible to all developers.',
    fix: 'Use Read-Host -AsSecureString for interactive scripts, or inject via environment: $password = $env:DB_PASSWORD. For automation, use the SecretManagement module or Azure Key Vault PowerShell module.',
    fileTypes: ['ps1'],
  },
];

// ── Windows batch (.bat, .cmd) ────────────────────────────────────────────────

const BATCH_RULES = [
  {
    id: 'BAT-001',
    name: 'Hardcoded password in Windows batch script',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: SET PASSWORD=value, SET DB_PASS=value, SET API_KEY=value
    pattern: /SET\s+(?:[A-Z][A-Z0-9_]{2,40})?(?:PASSWORD|PASSWD|API_KEY|SECRET|TOKEN|DB_PASS)\s*=\s*(?!%)[^\s%\n]{4,}/gi,
    antipattern: /SET\s+\w+=\s*%\w+%|SET\s+\/P/i,
    lookahead: 5,
    why: 'Windows batch scripts (.bat, .cmd) in ASP.NET and legacy Windows server environments frequently use SET to assign credentials for database connections, FTP uploads, and service calls.',
    scenario: 'deploy.bat contains SET DB_PASSWORD=Prod@2024 for use in sqlcmd commands. The script is part of the release process and lives in the repository. Every team member has the production SQL Server password.',
    fix: 'Read from environment: SET DB_PASSWORD=%DB_PASSWORD%. Inject the variable value via CI/CD pipeline variables (Azure DevOps pipeline variables, TeamCity parameters) which are never stored in source control.',
    fileTypes: ['bat', 'cmd'],
  },
];

// ── Backup files ──────────────────────────────────────────────────────────────

const BACKUP_RULES = [
  {
    id: 'BAK-001',
    name: 'Backup file in repository or web-accessible location',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    matchMode: 'filename',
    filenamePattern: /\.(?:bak|old|orig|backup|tmp|temp|copy|swp|~)$|~$|\.bak\d*$/i,
    why: 'Backup files are created by editors, deployment tools, and manual copy operations. They often contain older versions of configuration files with credentials, or copies of source files with sensitive logic exposed.',
    scenario: 'Web.config.bak is created during a failed deployment and left in the web root. It is accessible at https://app.com/Web.config.bak and contains the production connection string with credentials.',
    fix: 'Add backup file patterns to .gitignore: *.bak, *.old, *.orig, *.tmp, *~. Audit web root for these files. Configure web server to deny access to common backup extensions.',
    fileTypes: ['bak', 'old', 'orig', 'tmp', 'swp'],
  },
];

// ── Binary secret files (filename-only) ──────────────────────────────────────

const BINARY_SECRET_RULES = [
  {
    id: 'BINSEC-001',
    name: 'Private key file (.pem, .key) in repository',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    matchMode: 'filename',
    filenamePattern: /(?:^|[/\\])(?!.*(?:public|\.pub$)).*\.(?:pem|key|p8)$/i,
    why: 'PEM and KEY files contain private cryptographic material: SSL/TLS private keys, SSH private keys, code signing keys. A single committed private key can compromise an entire PKI infrastructure.',
    scenario: 'ssl.pem is committed for "convenience" during development. The same certificate is used in production. Attacker clones the repository, extracts the private key, and can perform HTTPS man-in-the-middle attacks or decrypt recorded traffic.',
    fix: 'Remove immediately using git filter-branch or BFG Repo Cleaner. Revoke and reissue the certificate. Add *.pem, *.key to .gitignore. Use certificate management services (Let\'s Encrypt, ACM) that never expose private keys.',
    fileTypes: ['pem', 'key', 'p8'],
  },
  {
    id: 'BINSEC-002',
    name: 'PKCS#12 certificate bundle (.pfx, .p12) in repository',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    matchMode: 'filename',
    filenamePattern: /\.(?:pfx|p12)$/i,
    why: 'PFX/P12 files bundle a certificate with its private key, protected only by a password. If the file is committed, attackers need only crack or find the password (often in nearby config files) to extract the private key.',
    scenario: 'app-cert.pfx is committed alongside its password in appsettings.json. Attacker extracts the private key, signs malicious code with the organization\'s code signing certificate, or decrypts TLS traffic.',
    fix: 'Never commit PFX/P12 files. Store them in a hardware security module (HSM), Azure Key Vault, or a secrets manager. For local development use, store outside the repository and reference by absolute path.',
    fileTypes: ['pfx', 'p12'],
  },
  {
    id: 'BINSEC-003',
    name: 'SQLite database file in repository',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    matchMode: 'filename',
    filenamePattern: /\.(?:sqlite|sqlite3|db|sdb)$/i,
    why: 'SQLite database files committed to version control may contain user data, password hashes, session tokens, or application secrets stored as database records. The entire database is readable by anyone with repository access.',
    scenario: 'app.db is committed as part of the initial project setup. It contains a seeded admin user with a bcrypt hash that is crackable offline. Attacker recovers the admin password and gains application access.',
    fix: 'Add *.sqlite, *.sqlite3, *.db to .gitignore. Use migration scripts to define schema — never commit the database file itself. For test fixtures, use SQL seed scripts with synthetic data only.',
    fileTypes: ['sqlite', 'sqlite3', 'db', 'sdb'],
  },
];

// ── Log file content rules ────────────────────────────────────────────────────

const LOG_RULES = [
  {
    id: 'LOG-001',
    name: 'Connection string with credentials found in log file',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches connection strings logged during errors or startup
    // Uses [^\n] (not [^;]) because semicolons appear between key-value pairs
    pattern: /(?:Server|Data Source|Host)\s*=[^\n]{0,200}(?:Password|PWD)\s*=[^;\n"']{1,60}/gi,
    why: 'Applications that log connection strings (during startup, connection errors, or debug output) expose database credentials in log files. Log files are often stored insecurely, forwarded to log aggregation services, or accessible to more people than intended.',
    scenario: 'An application logs the full connection string when database connection fails. Error log is shipped to an ELK stack accessible to all developers. The production DB password is visible in Kibana to 40 people.',
    fix: 'Never log connection strings. Use structured logging and explicitly exclude sensitive fields. Implement a log sanitizer that redacts patterns matching credentials before writing to log output.',
    fileTypes: ['log', 'txt'],
  },
  {
    id: 'LOG-002',
    name: 'Password or secret value found in log file',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches logged values that look like passwords in log output
    pattern: /(?:password|passwd|pwd|secret|api[_\s]?key|token|credential)\s*[=:]\s*["']?[^\s"'#\n]{6,}/gi,
    antipattern: /redacted|\*{3,}|<hidden>|\[FILTERED\]|\[REDACTED\]/i,
    lookahead: 10,
    why: 'Log files that contain passwords or secrets represent a secondary exposure vector. Logs are often retained longer than necessary, backed up to insecure storage, or sent to external services without proper filtering.',
    scenario: 'Login attempt logging includes the submitted password for debugging. Logs are shipped to a third-party log service. User passwords (including those reused from other services) are now stored by a third party.',
    fix: 'Implement log sanitization that redacts sensitive parameter names before output. Never log request bodies that may contain passwords. Audit logging pipelines for credential leakage.',
    fileTypes: ['log', 'txt'],
  },
  {
    id: 'LOG-003',
    name: 'Swedish personal identity number (personnummer) in log file',
    severity: 'HIGH',
    category: 'Sensitive Data Exposure / GDPR',
    // Matches Swedish personnummer: YYYYMMDDXXXX or YYYYMMDD-XXXX (dash optional in logs)
    pattern: /\b(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?\d{4}\b|\b\d{6}-?\d{4}\b/g,
    why: 'Swedish personnummer (personal identity numbers) in log files constitutes processing of sensitive personal data under GDPR Article 9 and the Swedish Personal Data Act. Logging PII without legal basis or proper safeguards triggers notification obligations.',
    scenario: 'Application logs user identifiers as personnummer for debugging. Logs are retained for 2 years and accessible to operations staff. A log server compromise exposes 10,000 users\' personal identity numbers — a notifiable GDPR breach.',
    fix: 'Replace personnummer with internal user IDs in all log output. If logging is required for audit purposes, pseudonymize: log a hash of the personnummer, not the value itself. Review log retention policy.',
    fileTypes: ['log', 'txt'],
  },
  {
    id: 'LOG-004',
    name: 'Email addresses in bulk in log file',
    severity: 'MEDIUM',
    category: 'Sensitive Data Exposure / GDPR',
    // Matches multiple email addresses — threshold approach (flag if file contains >5 emails)
    pattern: /[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}/g,
    minMatches: 5,
    why: 'Log files containing many email addresses represent a bulk PII exposure. Email addresses are personal data under GDPR. Log files are often less protected than databases and more likely to be shared or forwarded.',
    scenario: 'Application logs each user\'s email on login for audit purposes. Log file grows to 200MB with 85,000 unique email addresses. Developer copies the log file to their laptop for troubleshooting. GDPR breach.',
    fix: 'Hash or truncate email addresses in logs: log user_id or a hash(email) instead. Review what constitutes necessary audit logging versus debug logging that should be disabled in production.',
    fileTypes: ['log', 'txt'],
  },
];

// ── Exports ───────────────────────────────────────────────────────────────────

const ALL_RULES = [
  ...ENV_RULES,
  ...SQL_RULES,
  ...YAML_RULES,
  ...JSON_RULES,
  ...XML_RULES,
  ...PROPERTIES_RULES,
  ...INI_RULES,
  ...SHELL_RULES,
  ...PS_RULES,
  ...BATCH_RULES,
  ...BACKUP_RULES,
  ...BINARY_SECRET_RULES,
  ...LOG_RULES,
];

// Filename-only rules (checked by filename, not content)
const FILENAME_RULES = ALL_RULES.filter(r => r.matchMode === 'filename');

// Content rules (scanned line by line)
const CONTENT_RULES = ALL_RULES.filter(r => !r.matchMode);

module.exports = { ALL_RULES, FILENAME_RULES, CONTENT_RULES };
