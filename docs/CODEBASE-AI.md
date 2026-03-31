# Secure Code by Design – AI Codebase Reference (scd-ai)

_This document covers files and modules specific to the scd-ai layer.
For the full codebase reference, see CODEBASE.md.
For architecture and design decisions, see ARCHITECTURE-AI.md._

---

## scd CLI — AI-related files

### bin/scd.js additions

The `--deep` flag invocation checks for scd-server configuration before
proceeding. If no central URL is configured, or if the server responds
without the `deep_analysis` entitlement, the CLI prints the teaser message
and exits cleanly.

```
scd scan --deep
  → global-config.js: getCentralUrl() — is server configured?
  → If not: print teaser message, exit 0
  → If yes: proceed with scan, collect findings
  → deep-analyzer.js: analyzeFindings(findings, opts)
      → POST /api/v1/deep/analyze to scd-server
      → Receive structured results
      → Merge into scan output
  → audit.js: logScan() — deep_source recorded in audit.log
  → scan-cache.js: saveCache() — deep results stored in scan file
```

### lib/deep-analyzer.js (updated)

Previously sent findings directly to Anthropic API. Now acts as a thin
client that routes to scd-server. The actual AI pipeline runs server-side.

| Behaviour | Before | After |
|---|---|---|
| Analysis target | Anthropic API | scd-server `/api/v1/deep/analyze` |
| What CLI sends | Findings + code context | Findings + code context |
| What CLI knows about AI | Provider, model | Nothing — server decides |
| `trust_level` enforcement | CLI-side | Server-side (authoritative) |
| `deep_source` tagging | Partial | Full — returned by server |

**Key principle:** The CLI is a transport layer for deep analysis.
All AI logic, KB lookup, and provider selection lives in scd-server.

---

## scd-server — AI engine

### New files

```
lib/
  ai-engine.js          ← Orchestrator. Assembles prompt, calls Ollama,
  │                       parses response, stores result.
  │                       Exports: analyzeFindings(findings, repoId, opts)
  │
  ai-kb.js              ← KB access layer.
  │                       Layer 1: getKbForRule(ruleId) — deterministic lookup
  │                       Layer 2: getSemanticContext(embedding, topK) — vec search
  │                       Exports: buildKbContext(finding, opts)
  │
  ai-kb-store.js        ← Vector store abstraction.
  │                       Backend: sqlite-vec (scd-kb.db)
  │                       Exports: indexDocument(doc), search(embedding, topK),
  │                                getStats(), isIndexed()
  │
  ai-providers/
  │  local.js           ← Ollama HTTP client.
  │                       generate(prompt, opts) → string
  │                       embed(text) → float[]
  │                       checkHealth() → { model, available, ... }
  │
  │  anthropic.js       ← Existing Claude API client (moved here from CLI).
  │                       Same interface as local.js.
  │
  ai-live-context.js    ← Pulls repo-specific context from scd.db.
  │                       getRepoContext(repoId, ruleId) →
  │                         { finding_count, accepted_exceptions,
  │                           owasp_trend, top_rules }
  │
  routes-ai.js          ← Express routes for AI endpoints.
                          POST /api/v1/deep/analyze (Bearer)
                          GET  /api/v1/ai/health   (JWT admin)
                          POST /admin/api/ai/index-kb (JWT admin)
```

### lib/ai-engine.js

Core orchestrator. Called by `routes-ai.js` once per analysis request.

```javascript
// Simplified flow
async function analyzeFindings(findings, repoId, opts) {
  const results = [];

  for (const finding of findings) {
    // Layer 1: deterministic rule KB
    const ruleKb = await aiKb.getKbForRule(finding.ruleId);

    // Layer 2: semantic KB
    const findingEmbedding = await provider.embed(JSON.stringify(finding));
    const semanticDocs = await aiKbStore.search(findingEmbedding, 3);

    // Live context from scd.db
    const liveCtx = await aiLiveContext.getRepoContext(repoId, finding.ruleId);

    // Assemble prompt
    const prompt = buildPrompt(finding, ruleKb, semanticDocs, liveCtx);

    // Pass 1
    let result = await provider.generate(prompt, { temperature: 0.1 });
    let parsed = parseJsonResponse(result);

    // Pass 2 if confidence is low
    if (parsed.confidence === 'LOW' || needsMoreContext(parsed)) {
      const expandedPrompt = buildExpandedPrompt(finding, ruleKb, semanticDocs, liveCtx);
      result = await provider.generate(expandedPrompt, { temperature: 0.1 });
      parsed = parseJsonResponse(result);
    }

    // Tag with deep_source
    parsed.deep_source = buildDeepSource(opts.provider, opts.model, opts.endpoint);

    results.push(parsed);
  }

  return results;
}
```

### lib/ai-kb.js

Manages the two-layer KB. Layer 1 is loaded from `lib/ai-kb/` at startup
and cached in memory. Layer 2 queries `scd-kb.db` at request time.

```javascript
// Layer 1 — always retrieved, deterministic
function getKbForRule(ruleId) {
  // Returns: { rule, fix, teaching, verification } or partial if not all exist
  return {
    rule: ruleIndex[ruleId]?.rule || null,
    fix: ruleIndex[ruleId]?.fix || null,
    teaching: ruleIndex[ruleId]?.teaching || null,
    verification: ruleIndex[ruleId]?.verification || null,
  };
}

// Layer 2 — semantic retrieval
async function getSemanticContext(embedding, topK = 3) {
  return await aiKbStore.search(embedding, topK);
  // Returns: [{ path, content, score }, ...]
}
```

### lib/ai-kb-store.js

Vector store abstraction. Wraps `sqlite-vec` via `better-sqlite3`.
The interface is backend-agnostic — replacing `scd-kb.db` with Postgres
pgvector requires only a new implementation of this module.

```javascript
// Key exports
indexDocument(doc)          // Embeds and stores a KB document
search(embedding, topK)     // Returns top-K similar documents
getStats()                  // { doc_count, indexed_at, embed_model }
isIndexed()                 // boolean — has index-kb been run?
rebuildIndex()              // Re-embeds all documents (after KB update)
```

**Database:** `data/scd-kb.db` — separate from `data/scd.db`.
Initialized on first `index-kb` run. Never contains customer code.

### lib/ai-providers/local.js

Thin HTTP client for Ollama. No SDK dependency — plain `fetch`.

```javascript
// Ollama endpoints used
POST /api/generate    ← text generation (stream: false)
POST /api/embed       ← embedding generation
GET  /api/tags        ← model availability check
```

All calls use configurable `timeout_ms` (default 120s) to handle slow
hardware without hanging the request.

### lib/ai-live-context.js

Queries `scd.db` for repo-specific intelligence to include in the prompt.
This is the data that no static KB can provide.

```javascript
getRepoContext(repoId, ruleId) → {
  finding_count_90d,    // How many times this rule fired in this repo last 90 days
  accepted_exceptions,  // Exceptions accepted for this rule, with reasons
  owasp_trend,          // OWASP category trend for this repo (improving/stable/worsening)
  repo_top_rules,       // Top 5 rules by frequency in this repo
}
```

Example prompt contribution:
```
Repository context:
- PHP-INJ-002 has triggered 47 times in the last 90 days in this repository.
- 2 accepted exceptions exist for this rule. Reasons: "Input validated upstream
  via allowlist (confirmed in code review)", "Internal tool, no external input".
- OWASP A03 (Injection) trend: worsening (+12% vs previous 90 days).
```

This context directly informs the model's confidence and false-positive
assessment — it is aware of the codebase's history with this finding type.

### lib/routes-ai.js

```
POST /api/v1/deep/analyze
  Auth: Bearer token (same as events batch)
  Body: { repoId, findings: [...], trust_level }
  → Validates trust_level (refuses if maximum_privacy and provider != local)
  → ai-engine.js: analyzeFindings()
  → Returns: { results: [...], analyzed_at }

GET /api/v1/ai/health
  Auth: JWT (admin or viewer)
  → ai-providers/local.js: checkHealth()
  → ai-kb-store.js: getStats()
  → Returns: full health object (see ARCHITECTURE-AI.md)

POST /admin/api/ai/index-kb
  Auth: JWT (admin only)
  → ai-kb-store.js: rebuildIndex()
  → Returns: { doc_count, duration_ms }
  → Also available as CLI: scd-server index-kb
```

---

## scd-server — Database additions

### scd.db new tables

```sql
-- Deep analysis results, linked to scans
deep_results
  id            INTEGER PRIMARY KEY
  scan_id       TEXT NOT NULL          -- references scans.session_id
  repo_id       TEXT NOT NULL
  rule_id       TEXT NOT NULL
  file          TEXT NOT NULL
  line          INTEGER NOT NULL
  confirmed     INTEGER NOT NULL       -- 0/1
  confidence    TEXT NOT NULL          -- HIGH | MEDIUM | LOW
  false_positive_reason TEXT
  attack_scenario       TEXT
  fix_code              TEXT
  fix_explanation       TEXT
  teaching_explanation  TEXT
  prevention_tips       TEXT           -- JSON array
  verification_steps    TEXT           -- JSON array
  kb_sources            TEXT           -- JSON array of KB doc paths used
  deep_source           TEXT NOT NULL  -- JSON: provider, model, code_left_environment, ...
  analyzed_at           TEXT NOT NULL

-- AI configuration (persisted across restarts)
ai_config
  key   TEXT PRIMARY KEY
  value TEXT
  -- Keys: ollama_url, model, embed_model, kb_indexed_at, kb_doc_count,
  --       provider (local|anthropic)
```

### scd-kb.db schema

```sql
-- KB document metadata
kb_documents
  id          INTEGER PRIMARY KEY
  layer       INTEGER NOT NULL        -- 1 (structured) or 2 (semantic)
  category    TEXT                    -- owasp, framework, rule, fix, teaching, etc.
  rule_id     TEXT                    -- nullable; set for Layer 1 rule-specific docs
  path        TEXT NOT NULL           -- relative path in lib/ai-kb/
  content     TEXT NOT NULL
  created_at  TEXT NOT NULL

-- Vector index (sqlite-vec virtual table)
kb_vectors
  rowid       -- references kb_documents.id
  embedding   float[768]              -- nomic-embed-text dimensions
```

---

## KB directory structure

```
lib/ai-kb/
  rules/
    PHP-INJ-002.json        ← { ruleId, interpretation, strong_signals,
    JS-INJ-001.json             false_positive_patterns, remediation_approach }
    PY-INJ-001.json
    ...                     (one file per rule, Layer 1)
  fixes/
    sql-injection-php.json  ← { language, pattern, safe_example, explanation }
    sql-injection-js.json
    ...                     (Layer 1)
  teaching/
    sql-injection.json      ← { concept, why_dangerous, mental_model, examples }
    jwt-verification.json
    ...                     (Layer 1)
  verification/
    injection-generic.json  ← { how_to_confirm, test_payloads, tools }
    ...                     (Layer 1)
  owasp/
    A01-broken-access.md    (Layer 2 — semantic)
    A03-injection.md
    ...
  frameworks/
    laravel-security.md     (Layer 2 — semantic)
    express-security.md
    django-security.md
    aspnet-security.md
    ...
  cra/
    article-13-overview.md  (Layer 2 — semantic)
    sdlc-requirements.md
  nis2/
    article-21-measures.md  (Layer 2 — semantic)
  playbooks/
    sql-injection-pentest.md  (Layer 2 — semantic; curated Activemind content)
    jwt-attacks.md
    ...
```

**Layer 1 files are JSON** — structured for deterministic lookup.
**Layer 2 files are Markdown** — indexed via embedding for semantic retrieval.

---

## scd-server — config.yml additions

```yaml
# Existing configuration unchanged above this section

ai:
  provider: local                    # local | anthropic
  ollama_url: http://localhost:11434 # Ollama base URL (local provider only)
  model: qwen2.5-coder:14b           # Generation model
  embed_model: nomic-embed-text      # Embedding model (local provider only)
  timeout_ms: 120000                 # Per-request timeout
  top_k_semantic: 3                  # Layer 2 docs retrieved per finding
  pass2_enabled: true                # Enable conditional re-analysis pass
```

---

## scd-server — Admin UI additions

New section in `/admin`: **AI Status**

Displays:
- Provider (local / anthropic)
- Model name and availability
- KB index status (indexed / not indexed, doc count, last indexed timestamp)
- "Re-index KB" button (triggers `POST /admin/api/ai/index-kb`)
- Link to `/api/v1/ai/health` JSON

Deep analysis results are visible in existing dashboard drill-down views:
- `/dashboard/rule/:id` — shows AI confirmation rate for this rule
- `/dashboard/repo/:id` — shows deep analysis coverage for this repo
- Scan detail modal — shows `deep_source.code_left_environment` badge

---

## scd CLI — doctor additions

`scd doctor` checks AI configuration when a central URL is configured:

```
✓  scd-server reachable
✓  License valid (Professional + Deep Analysis Pack)
✓  AI provider: local (qwen2.5-coder:14b via Ollama)
✓  Ollama reachable, model available
✓  KB indexed (47 documents, last indexed 2026-03-31)
```

If AI is not configured or the entitlement is missing:

```
ℹ  Deep Analysis Pack not active on this license.
   Contact Activemind to add scd-ai to your subscription.
```

---

## Key design rules (AI-specific)

- **No AI logic in the CLI.** The CLI sends findings and receives results.
  Provider selection, KB lookup, and prompt construction are server-side.
- **Layer 1 before Layer 2.** Rule-specific KB is always retrieved first.
  Semantic retrieval is a complement, not a replacement.
- **Low temperature always.** `temperature: 0.1` for all generation calls.
  Structured JSON output requires determinism. Never use default temperature.
- **Validate JSON before storing.** Parse and validate the model's JSON
  response before writing to `deep_results`. Store raw response in a
  `raw_response` debug field if parsing fails — never silently discard.
- **deep_source is mandatory.** Every stored result must have `deep_source`.
  A result without provenance cannot be used for compliance purposes.
- **KB files are English only.** Same as rule text and CLI output.
- **scd-kb.db is never customer data.** It contains only KB documents
  embedded by Activemind or the customer's admin. Never store findings,
  code, or scan results in scd-kb.db.
