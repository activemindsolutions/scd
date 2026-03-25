/**
 * rules-infra-leakage.js
 * Rules for detecting internal infrastructure references that should never
 * appear in code or config files deployed to public/production environments.
 *
 * This is OSINT-risk territory: individually these are rarely critical, but
 * together they give an attacker a map of your internal network before they
 * even have access to it.
 *
 * Severity rationale:
 *   HIGH      – direct connection strings / credentials with internal address
 *   EXPOSURE  – reference alone (no credentials), informational leak
 *
 * False-positive strategy:
 *   antipattern  – skip if nearby context clearly signals dev/test/example
 *   fileFilter   – entire file skipped if name matches test/example pattern
 *                  (handled in scanner-full, not here)
 *
 * Rule IDs:
 *   INFRA-001–009   Localhost / loopback
 *   INFRA-010–019   RFC 1918 private addresses
 *   INFRA-020–029   Internal hostnames in URLs
 *   INFRA-030–039   Internal service ports in URL context
 *   INFRA-040–049   Comments containing internal addresses
 *   INFRA-050–059   Internal addresses in connection strings (HIGH)
 */

'use strict';

// ── Shared antipatterns ────────────────────────────────────────────────────
// These indicate the reference is expected/intentional in a dev context

const DEV_CONTEXT = /(?:example|sample|placeholder|TODO|FIXME|NOTE|demo|mock|fake|dummy|test|spec|localhost_only|dev.only|development.only)/i;
const LINK_EXAMPLE = /(?:example\.com|example\.org|example\.net|your[-_]?(?:host|domain|server|url)|<host>|<server>|\[host\]|\[server\])/i;
const ENV_VAR_REF  = /(?:process\.env|os\.environ|getenv|System\.getenv|\$\{|\$[A-Z_]+\b)/;

// Patterns that indicate an address is being used as data/validation, not as config.
// Covers: equality checks, function args in validation code, comment explanations.
const ADDR_AS_DATA = /(?:==\s*['"`]|!=\s*['"`]|\.startswith\s*\(|netloc\s*==|\.host\s*==|is_loopback|is_private|is_reserved|_has_ipv6|check.*local|local.*check|returns\s+(?:True|False)\s+if|e\.g\.|i\.e\.|for\s+example|#.*if\s+ip\s*=|#.*ip\s*=|log\.(debug|info|warning|error|critical)\s*\()/i;


// ── INFRA-001–009: Localhost / loopback ───────────────────────────────────

const LOCALHOST_RULES = [
  {
    id: 'INFRA-001',
    name: 'Hardcoded localhost reference in non-test file',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches: "localhost", "localhost:PORT", http://localhost etc.
    // Excludes matches that are part of a longer word (e.g. localhostname)
    pattern: /(?:["'`\s(=,]|^|\/{2}[^\n]*?)(?:https?:\/\/)?localhost(?::\d{2,5})?(?:[/"'\s),]|$)/gim,
    antipattern: /(?:example|sample|placeholder|TODO|FIXME|demo|mock|fake|dummy|test|spec|getenv|process\.env|os\.environ|System\.getenv|\$_ENV|\$_SERVER|\)\s*[?:?]{1,2}\s*['"].*localhost|\|\|\s*['"].*localhost|,\s*['"]localhost['"]|,\s*default\s*=\s*['"]localhost|fallback|==\s*['"]localhost|!=\s*['"]localhost|netloc|is_loopback|log\.(debug|info|warning|error)|e\.g\.|i\.e\.)/i,
    why: 'Hardcoded localhost references indicate code written against a local development environment. If this reaches a production build or public repository, it reveals that a service is expected to run locally — and can cause silent failures in production when the service is unreachable.',
    scenario: 'A frontend config file contains `apiUrl: "http://localhost:3000"`. The build is deployed to production. The app silently fails for all users, and anyone inspecting the source bundle now knows your backend runs on port 3000 locally.',
    fix: 'Replace hardcoded localhost with an environment variable: `process.env.API_URL` / `os.environ["API_URL"]`. Use .env files locally and CI/CD secrets for production. Never hardcode host references in source code.',
  },
  {
    id: 'INFRA-002',
    name: 'Hardcoded 127.0.0.1 loopback address',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    pattern: /(?:["'`\s(=,]|\/\/[^\n]*?)127\.0\.0\.1(?::\d{2,5})?/gim,
    antipattern: new RegExp(DEV_CONTEXT.source + '|' + ADDR_AS_DATA.source, 'i'),
    lookahead: 120,
    why: 'The loopback address 127.0.0.1 is an explicit reference to the local machine. In source code it signals a service binding or local dependency that was never abstracted for different environments.',
    scenario: 'A Python Flask app has `REDIS_HOST = "127.0.0.1"` hardcoded. The production Redis is on a different host. The app fails silently, and the commit history now permanently records that Redis was expected locally.',
    fix: 'Use environment variables for all host/address configuration. `REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")` is acceptable for local fallback — but never commit production addresses.',
  },
  {
    id: 'INFRA-003',
    name: 'IPv6 loopback address (::1)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Require active use context. Skip documentation lines where ::1 is mentioned as example.
    // Note: antipattern checks forward from match – for backward context we rely on the
    // pattern itself: only match ::1 inside a string delimiter or assignment, not in prose.
    pattern: /(?:=\s*["'`]|["'`])[^\n]{0,30}::1(?::\d{2,5})?["'`]/gim,
    antipattern: /(?:e\.g\.|i\.e\.|must include|not just|example|documentation|note:|see also|_has_ipv6|is_loopback|is_reserved|==|!=)/i,
    lookahead: 150,
    why: 'The IPv6 loopback address ::1 reveals that the system runs IPv6 internally — useful intelligence for an attacker mapping your infrastructure.',
    scenario: 'An nginx config committed to a public repo contains `listen [::1]:8080`. This tells an attacker both the port and that IPv6 is active internally.',
    fix: 'Move host/port bindings to environment configuration. Never commit network binding details to source control.',
  },
];


// ── INFRA-010–019: RFC 1918 private IP addresses ──────────────────────────

const RFC1918_RULES = [
  {
    id: 'INFRA-010',
    name: 'Hardcoded 10.x.x.x private network address',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches 10.0.0.0/8 range: 10. followed by 3 octets
    pattern: /["'`\s(=:/,]10\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?::\d{2,5})?(?:["'`\s)/,]|$)/gim,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'RFC 1918 addresses (10.0.0.0/8) are private internal network addresses. Their presence in source code reveals your internal network topology — subnet layout, server locations, and service architecture — to anyone who can read the code.',
    scenario: 'A deployment script contains `DB_HOST=10.0.1.45`. An attacker who gains any level of access (even read-only to the repo) now knows an internal database server IP. Combined with other findings, this helps plan lateral movement.',
    fix: 'Never hardcode private IP addresses. Use DNS names with environment-specific resolution, or environment variables. Internal service discovery (Consul, Kubernetes DNS) should handle routing.',
  },
  {
    id: 'INFRA-011',
    name: 'Hardcoded 172.16–31.x.x private network address',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches 172.16.0.0/12 range: 172.16.x.x – 172.31.x.x
    pattern: /["'`\s(=:/,]172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?::\d{2,5})?(?:["'`\s)/,]|$)/gim,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'The 172.16.0.0/12 range is a private address block commonly used for Docker networks, VPNs, and internal subnets. Exposure reveals network segmentation details.',
    scenario: 'A Docker Compose file references `172.20.0.5` as a service IP. This reveals your Docker subnet configuration and makes container network enumeration easier if an attacker gains a foothold.',
    fix: 'Use Docker service names or Kubernetes service DNS names instead of static IPs. Let orchestration handle IP assignment.',
  },
  {
    id: 'INFRA-012',
    name: 'Hardcoded 192.168.x.x private network address',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Requires assignment or URL context to avoid matching IPs in docstrings/examples
    pattern: /(?:[=:\s(]\s*["'`]|https?:\/\/|["'`]\s*[+]\s*|\$\{)192\.168\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?::\d{2,5})?(?:["'`\s)/,]|$)/gim,
    antipattern: new RegExp(DEV_CONTEXT.source + '|' + ADDR_AS_DATA.source, 'i'),
    lookahead: 150,
    why: '192.168.x.x is the most common private address range for office and home networks. References in code often come from local development and signal that proper environment abstraction is missing.',
    scenario: 'A PHP config file has `$db_host = "192.168.1.10"` — likely a developer\'s local machine IP. If deployed, the application fails in production and exposes local network details to anyone reading the code.',
    fix: 'Use environment variables or service discovery. If this is truly a local-only value, ensure it is in .env (which must be gitignored) rather than in committed config files.',
  },
];


// ── INFRA-020–029: Internal hostnames in URLs ─────────────────────────────

const INTERNAL_HOSTNAME_RULES = [
  {
    id: 'INFRA-020',
    name: 'Internal hostname pattern in URL (dev/staging/internal subdomain)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches URLs with internal-sounding subdomains but NOT known public domains
    // e.g. http://dev.w3.org, http://dev.mozilla.org, http://test.example.com are excluded
    pattern: /https?:\/\/(?:dev|staging|stage|test|uat|qa|preprod|internal|intranet|corp|local|private|admin|backend|api-internal|int)\.(?!(?:w3|mozilla|ietf|whatwg|github|google|microsoft|apple|amazon|cloudflare|fastly|example|jquery|npmjs|nodejs)\b)/gi,
    antipattern: /(?:w3\.org|mozilla\.org|ietf\.org|whatwg\.org|example\.com|jquery\.com|draft\.csswg|spec\.)/i,
    lookahead: 80,
    why: 'Internal subdomain names in source code reveal your environment structure, naming conventions, and potentially accessible internal services. This is valuable OSINT for an attacker.',
    scenario: 'A frontend config has `API_BASE: "https://api-internal.company.com"`. An attacker now knows an internal API endpoint exists, its naming convention, and can probe it for access controls.',
    fix: 'Use environment variables for all base URLs. The running environment should inject the correct URL — source code should never know whether it is dev, staging, or production.',
  },
  {
    id: 'INFRA-021',
    name: 'Non-public TLD in hardcoded URL (.local, .internal, .corp, .lan)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches URLs using non-public TLDs reserved for internal use
    pattern: /https?:\/\/[a-z0-9.-]+\.(?:local|internal|corp|intranet|lan|priv|home|localdomain)(?::\d{2,5})?(?:\/[^\s"'`]*)?/gi,
    antipattern: LINK_EXAMPLE,
    lookahead: 80,
    why: 'Non-public TLDs (.local, .internal, .corp) are exclusively used for internal DNS resolution. Their presence in code reveals internal naming conventions and network architecture.',
    scenario: 'A Kubernetes manifest references `http://redis.internal:6379`. This exposes the internal DNS name and port of your Redis service to anyone reading the manifest in a public repo.',
    fix: 'Replace internal DNS names with Kubernetes service names (e.g. `redis:6379`) or inject via environment variables. Avoid committing any .internal / .local / .corp hostnames.',
  },
  {
    id: 'INFRA-022',
    name: 'Possible internal server hostname (short hostname without TLD)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches URL-like references to bare hostnames (no TLD) that look like internal server names
    // e.g. http://dbserver/, http://appserver:8080, mongodb://mongo01/
    pattern: /(?:mongodb|postgres|mysql|redis|amqp|http|https):\/\/[a-z][a-z0-9-]{2,20}(?::\d{2,5})?\/(?![\/])/gi,
    antipattern: /(?:localhost|127\.0\.0|example|sample|placeholder|e\.g\.|i\.e\.|for\s+example)/i,
    lookahead: 100,
    why: 'Bare hostnames in connection strings or URLs (without a domain) indicate internal server names used within a private network. These names reveal infrastructure naming conventions.',
    scenario: 'A Node.js app config has `MONGO_URI: "mongodb://mongo01/mydb"`. The hostname "mongo01" reveals that MongoDB servers follow a numbered naming convention, helping an attacker enumerate infrastructure.',
    fix: 'Use environment variables for all connection strings. Never commit internal server names to source control.',
  },
];


// ── INFRA-030–039: Internal service ports in URL context ──────────────────

const INTERNAL_PORT_RULES = [
  {
    id: 'INFRA-030',
    name: 'Database port hardcoded in connection string (PostgreSQL 5432)',
    severity: 'HIGH',
    category: 'Infrastructure Leakage',
    // Port in a connection string context, not just any mention
    pattern: /(?:postgres(?:ql)?|jdbc:postgresql):\/\/[^"'\s]{3,}:5432/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 200,
    why: 'A hardcoded PostgreSQL connection string exposes both the server address and confirms PostgreSQL is used. Combined with other findings, this provides enough information to target the database directly.',
    scenario: 'A connection string `postgresql://10.0.1.45:5432/production_db` is found in a config file. An attacker now has the server IP, port, database type, and database name — everything needed for a targeted attack.',
    fix: 'Store the entire connection string in an environment variable: `DATABASE_URL=os.environ["DATABASE_URL"]`. Never hardcode any part of a production connection string.',
  },
  {
    id: 'INFRA-031',
    name: 'Database port hardcoded in connection string (MySQL/MariaDB 3306)',
    severity: 'HIGH',
    category: 'Infrastructure Leakage',
    pattern: /(?:mysql|mariadb|jdbc:mysql):\/\/[^"'\s]{3,}:3306/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 200,
    why: 'MySQL/MariaDB connection strings with hardcoded hosts and ports reveal database infrastructure. Port 3306 is the default and well-known; its presence confirms the database type.',
    scenario: 'CI/CD pipeline config contains `mysql://admin:pass@192.168.1.20:3306/app`. This exposes credentials, internal IP, and confirms MySQL — a complete attack package.',
    fix: 'Use environment variables for all database connection details. Treat any committed connection string as fully compromised.',
  },
  {
    id: 'INFRA-032',
    name: 'Redis port hardcoded in connection string (6379)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    pattern: /(?:redis(?:s)?):\/\/[^"'\s]{3,}:6379/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'Redis on its default port is a common target for attacks when exposed. Hardcoded Redis connection strings reveal server location and confirm caching/session infrastructure.',
    scenario: 'A session config has `REDIS_URL = "redis://10.0.2.10:6379"`. An attacker who gains network access now has a direct target for session hijacking attacks.',
    fix: 'Store Redis connection details in environment variables. Ensure Redis requires authentication (`requirepass`) and is not exposed outside the internal network.',
  },
  {
    id: 'INFRA-033',
    name: 'MongoDB port hardcoded in connection string (27017)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    pattern: /mongodb(?:\+srv)?:\/\/[^"'\s]{3,}:27017/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'MongoDB on port 27017 has historically been a target for mass scanning attacks due to open instances. Revealing the host and port in source code increases targeted attack risk.',
    scenario: 'An app config has `MONGO_URI = "mongodb://mongo.internal:27017/users"`. This reveals both the internal hostname and that MongoDB stores user data — a high-value target.',
    fix: 'Use environment variable `MONGODB_URI`. Ensure MongoDB requires authentication and bind to non-public interfaces only.',
  },
  {
    id: 'INFRA-034',
    name: 'Elasticsearch port hardcoded (9200/9300)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    pattern: /https?:\/\/[^"'\s]{3,}:(?:9200|9300)(?:[/"'\s]|$)/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'Elasticsearch is frequently misconfigured with no authentication. Exposing the host and port in source code makes it trivially easy to attempt direct data access.',
    scenario: 'A search service config has `ES_HOST = "http://10.0.3.15:9200"`. An attacker with network access can directly query Elasticsearch for indexed data.',
    fix: 'Use environment variables. Enable Elasticsearch X-Pack security and authentication. Bind to non-public interfaces.',
  },
  {
    id: 'INFRA-035',
    name: 'RabbitMQ/AMQP port hardcoded (5672/15672)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    pattern: /amqps?:\/\/[^"'\s]{3,}:(?:5672|15672)/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'Message queue servers are critical infrastructure. Exposing AMQP connection details reveals queue topology and provides a target for message injection or eavesdropping attacks.',
    scenario: 'A worker service config has `AMQP_URL = "amqp://user:pass@10.0.4.20:5672"`. An attacker can now inject malicious messages into the queue, potentially triggering unintended actions.',
    fix: 'Store AMQP connection strings in environment variables. Use TLS (amqps://) and rotate credentials if exposed.',
  },
  {
    id: 'INFRA-036',
    name: 'Internal admin/management port hardcoded (8080, 8443, 9090, 9443)',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Port in URL context with an internal-looking host
    pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^"'\s]*:(?:8080|8443|9090|9443|4848|8161|8888)(?:[/"'\s]|$)/gi,
    antipattern: /(?:example|sample|placeholder|TODO|FIXME|NOTE|demo|mock|fake|dummy|test|spec|localhost_only|dev.only|development.only|log\.(debug|info|warning|error|critical)\s*\(|e\.g\.|i\.e\.)/i,
    lookahead: 150,
    why: 'Management and admin ports (8080, 8443, 9090 etc.) are often less protected than primary application ports. Their exposure in source code, combined with an internal IP, reveals management interfaces.',
    scenario: 'A monitoring config contains `http://10.0.1.5:9090/metrics`. This reveals a Prometheus endpoint on an internal server — useful for mapping the monitoring infrastructure.',
    fix: 'Move all admin/management URLs to environment variables. Restrict management interfaces to specific network segments.',
  },
];


// ── INFRA-040–049: Infrastructure references in comments ──────────────────

const COMMENT_RULES = [
  {
    id: 'INFRA-040',
    name: 'Internal IP address in code comment',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Matches IP addresses in comments (// # <!-- /* style)
    // Negative lookbehind for : prevents matching // inside URLs (http://...)
    pattern: /(?<!:)(?:\/\/|#|<!--|\/\*)[^\n]*(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)/gim,
    antipattern: /(?:example|sample|placeholder|demo|mock|fake|dummy|returns\s+(?:True|False)|e\.g\.|i\.e\.|for\s+example|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,  // two IPs on same line = example range
    lookahead: 200,
    why: 'Comments containing internal IP addresses are often left-over notes from development ("// works on 10.0.1.5 – ask ops team"). They are never sanitised by minifiers or build processes and persist in git history forever.',
    scenario: 'A JavaScript file has `// TODO: update endpoint – currently points to 10.0.1.45:3000 on prod`. This comment is in the production bundle, visible to anyone who opens DevTools.',
    fix: 'Remove all infrastructure references from comments before committing. Use ticket references (e.g. "// See INFRA-1234") instead of IP addresses or server names.',
  },
  {
    id: 'INFRA-041',
    name: 'Internal hostname or server name in code comment',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Comments mentioning server names, internal URLs, or internal domains
    pattern: /(?:\/\/|#|<!--|\/\*)[^\n]*https?:\/\/(?:dev|staging|internal|intranet|corp|local|admin|backend)\.[a-z0-9.-]+/gim,
    antipattern: /(?:w3\.org|mozilla\.org|ietf\.org|whatwg\.org|csswg|draft\.|spec\.|rfc\d|standards\.)/i,
    lookahead: 500,
    why: 'Internal URLs in comments reveal the same information as hardcoded strings, but are often overlooked because they are "just comments". They survive minification, transpilation, and stay in git history.',
    scenario: 'A comment says `// old API was at http://internal.company.com/api/v1`. The internal API hostname is now visible to anyone reading the committed file.',
    fix: 'Treat comments the same as code for sensitive information. Remove server names, internal URLs, and IP addresses from all comments.',
  },
  {
    id: 'INFRA-042',
    name: 'Port number with server context in comment',
    severity: 'EXPOSURE',
    category: 'Infrastructure Leakage',
    // Comments that reference specific ports in a connection context
    pattern: /(?:\/\/|#|<!--|\/\*)[^\n]{0,200}(?:port\s+\d{4,5}|(?:running on|listens on|connects to|forwarded to)[^\n]{0,80}:\d{4,5})/gim,
    antipattern: DEV_CONTEXT,
    lookahead: 150,
    why: 'Comments describing service ports and connections are developer notes that expose network architecture. They are typically accurate because developers write them as reminders.',
    scenario: '`// proxy forwards to backend running on port 8080` — this comment tells an attacker exactly what to look for when they gain access to the network.',
    fix: 'Remove connection and port descriptions from comments. Architecture documentation belongs in internal wikis, not in code comments.',
  },
];


// ── INFRA-050–059: Connection strings with internal addresses (HIGH) ───────

const CONNECTION_STRING_RULES = [
  {
    id: 'INFRA-050',
    name: 'Database connection string with internal IP address',
    severity: 'HIGH',
    category: 'Infrastructure Leakage',
    // Full connection string pattern with internal IP
    pattern: /(?:jdbc:|mongodb(?:\+srv)?:|postgresql:|mysql:|redis:|amqp:)\/\/[^"'\s]*(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})[^"'\s]*/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 250,
    why: 'A complete connection string with an internal IP address reveals: the database type, exact server location, port, and potentially database name — the complete information needed to attempt a direct attack if any network access is obtained.',
    scenario: 'A JDBC connection string `jdbc:postgresql://10.0.1.20:5432/production` is found in a config file. An attacker who gains any internal network access (VPN compromise, insider, cloud misconfiguration) can immediately target this server.',
    fix: 'This is HIGH severity. Store the entire connection string as a single environment variable. Audit git history for this value and rotate all credentials. Consider this information compromised.',
  },
  {
    id: 'INFRA-051',
    name: 'Generic URL with internal IP (non-database services)',
    severity: 'HIGH',
    category: 'Infrastructure Leakage',
    // HTTP/S URLs with internal IPs — broader catch for APIs, services, etc.
    pattern: /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{2,5})?(?:\/[^\s"'`]*)?/gi,
    antipattern: DEV_CONTEXT,
    lookahead: 200,
    why: 'A full URL with an internal IP address exposes not just the IP but also the path structure and API layout of internal services. This is immediately actionable intelligence for an attacker.',
    scenario: 'A frontend config has `INTERNAL_API: "http://10.0.2.30:8080/api/v2/admin"`. This reveals the internal admin API location, its version, and that it runs on port 8080.',
    fix: 'Replace with an environment variable. Audit all configurations for similar patterns. Treat the internal service location as potentially known to attackers.',
  },
];


// ── Aggregate exports ──────────────────────────────────────────────────────

const ALL_INFRA_RULES = [
  ...LOCALHOST_RULES,
  ...RFC1918_RULES,
  ...INTERNAL_HOSTNAME_RULES,
  ...INTERNAL_PORT_RULES,
  ...COMMENT_RULES,
  ...CONNECTION_STRING_RULES,
];

module.exports = {
  ALL_INFRA_RULES,
  LOCALHOST_RULES,
  RFC1918_RULES,
  INTERNAL_HOSTNAME_RULES,
  INTERNAL_PORT_RULES,
  COMMENT_RULES,
  CONNECTION_STRING_RULES,
};
