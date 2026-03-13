/**
 * rules-ts.js
 * Security rules specific to TypeScript.
 * Applied IN ADDITION to rules-js.js on .ts and .tsx files.
 *
 * Covers patterns where TypeScript's type system is bypassed or suppressed,
 * creating blind spots that allow unsafe data to reach sensitive operations.
 * These patterns are particularly common in AI-generated TypeScript code.
 */

// ── Type assertion bypasses ───────────────────────────────────────────────────

const TYPE_ASSERTION_RULES = [
  {
    id: 'TS-TYPE-001',
    name: 'Type assertion (as any) disables type safety on potentially unsafe value',
    severity: 'MEDIUM',
    category: 'Injection (OWASP A03)',
    // Matches: req.params.x as any, req.body as any, request.query.x as any
    // Also catches the double-cast pattern: as unknown as SomeType
    pattern: /(?:req|request|ctx|context)\s*(?:\.\s*\w+)+\s+as\s+any\b|as\s+unknown\s+as\s+(?!never\b)\w+/g,
    why: 'Casting request-derived values to "any" silences the TypeScript compiler for all downstream usage. Any injection, traversal, or auth bypass that the type system would have caught is now invisible — both to the compiler and to code reviewers.',
    scenario: 'AI generates const userId = req.params.id as any to resolve a type error quickly. userId flows into a SQL query. The compiler no longer warns when it is used in string concatenation, because "any" propagates silently through expressions.',
    fix: 'Parse and validate at the boundary instead of asserting: const userId = z.string().uuid().parse(req.params.id). Use a validation library (Zod, Valibot, io-ts) and derive the type from the schema rather than asserting it.',
    fileTypes: ['ts', 'tsx'],
  },
  {
    id: 'TS-TYPE-002',
    name: 'Non-null assertion (!) applied directly to request input',
    severity: 'MEDIUM',
    category: 'Injection (OWASP A03)',
    // Matches: req.body.email!, req.params.id!, req.query.search!
    // The ! tells TypeScript "I guarantee this is not null/undefined" — no runtime check
    pattern: /(?:req|request|ctx|context)\s*\.\s*(?:body|params|query|headers)\s*(?:\.\s*\w+|\[['"][^'"]+['"]\])\s*!/g,
    why: 'The non-null assertion operator (!) removes null and undefined from the type without performing any runtime check. If the value is actually absent or malformed, the application throws at runtime — or worse, proceeds with undefined in a security-sensitive context.',
    scenario: 'AI writes const token = req.headers.authorization!.split(" ")[1] to satisfy the compiler. If Authorization is absent, this throws "Cannot read properties of undefined" — potentially triggering a different error handler that leaks stack trace details.',
    fix: 'Check explicitly: const auth = req.headers.authorization; if (!auth) return res.status(401).json({ error: "Unauthorized" }); const token = auth.split(" ")[1];',
    fileTypes: ['ts', 'tsx'],
  },
];

// ── Compiler suppression ──────────────────────────────────────────────────────

const COMPILER_SUPPRESSION_RULES = [
  {
    id: 'TS-SUPPRESS-001',
    name: '@ts-ignore or @ts-expect-error suppressing a type error in security-sensitive context',
    severity: 'HIGH',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: // @ts-ignore or // @ts-expect-error on the line before sensitive operations
    // Uses lookahead window: if the next ~150 chars contain query/exec/auth/password etc.
    pattern: /\/\/\s*@ts-(?:ignore|expect-error)[^\n]*\n[^\n]{0,150}(?:query|exec|eval|password|token|secret|auth|cookie|session|sql|mongo|redis|fetch|axios|http)/gi,
    why: '@ts-ignore and @ts-expect-error tell the compiler to skip type checking for the next line. When placed before database calls, authentication logic, or HTTP requests, they hide exactly the type errors that would reveal unsafe data flow — often the same errors that signal an injection or auth bypass.',
    scenario: 'AI adds // @ts-ignore above db.query("SELECT * FROM users WHERE id=" + userId) to suppress "Argument of type string | undefined is not assignable to parameter of type string". The suppression hides that userId might be undefined or attacker-controlled.',
    fix: 'Fix the underlying type error instead of suppressing it. If the suppression is hiding an "X | undefined" error, add a null check. If it is hiding an incompatible type, add validation. @ts-ignore should never appear near data access or authentication code.',
    fileTypes: ['ts', 'tsx'],
  },
  {
    id: 'TS-SUPPRESS-002',
    name: 'TypeScript strict mode disabled in tsconfig',
    severity: 'MEDIUM',
    category: 'Security Misconfiguration (OWASP A05)',
    // Matches: "strict": false in tsconfig.json
    // Also catches individual flags that strict enables: strictNullChecks, noImplicitAny
    pattern: /"(?:strict|strictNullChecks|noImplicitAny|strictFunctionTypes)"\s*:\s*false/g,
    why: 'Disabling strict mode (or its constituent checks) means the compiler no longer warns about implicit any types, unchecked null/undefined access, or unsafe function signatures. These are the exact checks that catch unsafe handling of user input at compile time.',
    scenario: 'Project has "strict": false in tsconfig. AI generates code freely using implicit any throughout request handlers. A security review finds SQL injection in five places — all would have been type errors under strict mode, flagged before the code was ever committed.',
    fix: 'Enable "strict": true in tsconfig.json and fix the resulting type errors. For existing codebases, enable checks incrementally: start with "strictNullChecks": true as it catches the most security-relevant issues.',
    fileTypes: ['ts'],
  },
];

// ── Runtime validation gaps ───────────────────────────────────────────────────

const VALIDATION_RULES = [
  {
    id: 'TS-VALID-001',
    name: 'Request body cast to typed interface without runtime validation',
    severity: 'HIGH',
    category: 'Injection (OWASP A03)',
    // Matches: req.body as UserInput, req.body as LoginRequest etc.
    // TypeScript interfaces are erased at runtime — casting provides zero validation
    pattern: /(?:req|request|ctx)\s*\.\s*body\s+as\s+(?!any\b|unknown\b)[A-Z]\w+/g,
    why: 'TypeScript interfaces and type aliases are compile-time constructs only — they are completely erased in the emitted JavaScript. Casting req.body to an interface performs no runtime validation whatsoever. The actual request body can contain any shape, any types, any extra fields.',
    scenario: 'AI generates: const input = req.body as CreateUserDto. The interface requires email: string, but the runtime value could be { email: { $gt: "" } } — a NoSQL injection payload. TypeScript is satisfied; the database is not.',
    fix: 'Always validate at the runtime boundary using a schema library: const input = CreateUserSchema.parse(req.body). Zod, Valibot, and class-validator all provide both runtime validation and TypeScript type inference from the same schema definition.',
    fileTypes: ['ts', 'tsx'],
  },
];

// ── Exports ───────────────────────────────────────────────────────────────────

const ALL_RULES = [
  ...TYPE_ASSERTION_RULES,
  ...COMPILER_SUPPRESSION_RULES,
  ...VALIDATION_RULES,
];

module.exports = { ALL_RULES };
