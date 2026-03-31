# Secure Code by Design – AI Architecture (scd-ai)

_This document covers the design and architecture of the scd-ai layer.
For the overall product architecture, see ARCHITECTURE.md._

---

## Purpose and positioning

scd-ai is the local AI analysis layer of Secure Code by Design. It enables
AI-powered deep analysis of security findings without sending customer code
outside their own infrastructure.

scd-ai is a **commercial add-on** that requires scd-server. It is not part
of the open source CLI. The `--deep` flag exists in the CLI as a feature
preview — without a valid scd-server connection and scd-ai entitlement, it
returns a clear message directing the user to their subscription.

### Why local AI matters

`scd scan --deep` with an external provider (Anthropic API) sends code
fragments outside the customer's environment. For security-conscious customers
— fintech, healthtech, public sector — this is a blocker regardless of how
little is sent.

scd-ai resolves this completely: AI analysis runs inside the customer's own
infrastructure, using a local model served by Ollama. No code fragments leave
the network. This is documented per-finding via the `deep_source` field,
providing an auditable trail for CRA/NIS2 compliance purposes.

---

## Commercial model

scd-ai maps to the **Deep Analysis Pack** add-on in the pricing model.
Two variants:

| Variant | Provider | Code leaves environment |
|---|---|---|
| Deep Analysis – Cloud | Anthropic API (Claude) | Yes — code fragments only |
| Deep Analysis – Local (scd-ai) | Local model via Ollama | Never |

The Local variant is positioned specifically at customers with data
sovereignty requirements or regulatory constraints. It is a unique market
differentiator — no comparable self-hosted SAST tool offers this combination.

---

## System overview

```
Developer machine
  scd CLI
    scd scan --deep
        │
        │  POST /api/v1/deep/analyze
        ▼
  scd-server (customer infrastructure)
    lib/ai-engine.js
        ├── Layer 1: KB lookup (rule registry → static KB)
        ├── Layer 2: Semantic KB (sqlite-vec embeddings)
        ├── Live context: scd.db (repo history, exceptions, top rules)
        └── Ollama API (http://localhost:11434 or configured URL)
                │
                ▼
          Local model (e.g. qwen2.5-coder:14b)
                │
                ▼
    Structured JSON response
    → stored in scd.db (deep_results table)
    → returned to CLI
    → visible in dashboard
```

The CLI has no direct knowledge of Ollama. It sends findings to scd-server
and receives structured analysis back. scd-server owns the entire AI pipeline.

---

## trust_level integration

`trust_level` in `securityagent.yml` controls which deep analysis provider
is permitted for a given repository:

```
maximum_privacy   → local provider only; external API calls blocked
balanced          → local provider preferred; cloud provider available as
                    explicit opt-in per scan
maximum_analysis  → cloud provider (Anthropic API); maximum findings
```

`maximum_privacy` is the recommended setting for scd-ai customers. It
provides a hard guarantee: no external calls, verifiable in audit output.

---

## deep_source — audit trail

Every deep analysis result carries a `deep_source` object. This is stored
in scd.db, included in the CLI scan file, and visible in the HTML report.

```json
"deep_source": {
  "provider": "local",
  "model": "qwen2.5-coder:14b",
  "endpoint": "http://scd-server.internal:3000",
  "code_left_environment": false,
  "analyzed_at": "2026-03-31T09:14:22Z"
}
```

`code_left_environment` is always `false` for local provider, `true` for
cloud provider. This field is the auditable evidence that privacy was
maintained — suitable for CRA Article 13 manufacturer accountability and
NIS2 Article 21 security measure documentation.

---

## Knowledge Base (KB) design

The KB is what makes local AI analysis useful despite the quality gap
between local and cloud models. It provides structured, domain-specific
context that generic models lack — particularly for security analysis.

### Layer 1 — Structured rule KB (deterministic)

Static, rule-indexed knowledge stored as JSON alongside the server binary.
Retrieved by exact `ruleId` match — no embedding needed, no latency.

```
lib/ai-kb/
  rules/          ← one file per rule: interpretation, strong signals,
  │               false-positive patterns, remediation approach
  fixes/          ← secure code examples per language per rule
  teaching/       ← pedagogical explanations (why this pattern is dangerous)
  verification/   ← how to confirm a finding is genuine, not a false positive
```

Layer 1 is always retrieved first and always included in the model prompt.
It is the authoritative source for rule-specific guidance.

### Layer 2 — Semantic KB (embedding-based retrieval)

Broader security knowledge retrieved via vector similarity search.
Enriches the prompt with context the rule-specific KB does not cover.

```
lib/ai-kb/
  owasp/          ← OWASP category explanations, attack patterns
  frameworks/     ← framework-specific security guidance (Laravel, Express,
  │               Django, ASP.NET, Spring)
  cra/            ← EU Cyber Resilience Act context
  nis2/           ← NIS2 Article 21 security requirements
  playbooks/      ← Activemind pentest playbooks (curated subset)
```

Layer 2 documents are embedded once (on `scd-server ai index-kb`) and
stored in `data/scd-kb.db` using `sqlite-vec`. At analysis time, the
finding is embedded and the top-k most similar documents are retrieved
and appended to the prompt.

### KB separation principle

Layer 1 and Layer 2 are kept deliberately separate:

- Layer 1 is **deterministic**: same ruleId always retrieves the same content.
  Easy to update, easy to audit, easy to version.
- Layer 2 is **semantic**: retrieved by similarity. Quality depends on KB
  content and embedding model. Can degrade silently if KB content is poor.

This separation makes debugging straightforward: if the analysis is wrong
about a specific rule, the problem is in Layer 1. If it lacks broader
security context, the problem is in Layer 2.

---

## Database design

scd-ai uses two SQLite databases to keep concerns separate and enable
future migration of the vector store independently of application data.

```
data/
  scd.db      ← Application data (unchanged from existing schema)
                New tables: deep_results, ai_config
  scd-kb.db   ← KB embeddings only (sqlite-vec)
                Tables: kb_documents, kb_vectors
```

### scd.db additions

```sql
deep_results    scan_id, repo_id, rule_id, file, line,
                confirmed, confidence, false_positive_reason,
                attack_scenario, fix_code, fix_explanation,
                teaching_explanation, prevention_tips (JSON),
                verification_steps (JSON), deep_source (JSON),
                analyzed_at

ai_config       key/value: ollama_url, model, embed_model,
                kb_indexed_at, kb_doc_count
```

### scd-kb.db

```sql
kb_documents    id, layer (1|2), category, rule_id (nullable),
                path, content, created_at

kb_vectors      rowid → kb_documents.id, embedding (float[N])
                (sqlite-vec virtual table)
```

**Migration path:** `scd-kb.db` can be replaced with a Postgres database
using `pgvector` without touching `scd.db` or application logic. The
abstraction layer in `lib/ai-kb-store.js` handles both backends.

---

## Analysis flow

### Pass 1 — Primary analysis

```
Findings received (per file, grouped)
    │
    ├── Layer 1 lookup: ruleId → rule KB (always)
    ├── Layer 2 retrieval: embed finding → top-3 semantic KB docs
    ├── Live context from scd.db:
    │     - Finding count for this rule in this repo (last 90 days)
    │     - Accepted exceptions for this rule in this repo (with reasons)
    │     - OWASP category trend for this repo
    │
    └── Prompt assembled → Ollama API → structured JSON response
```

### Pass 2 — Conditional re-analysis

Triggered automatically when Pass 1 returns `confidence: "LOW"` or
`confirmed: false` with no `false_positive_reason`.

Pass 2 adds expanded context:
- More surrounding lines from the original finding (up to 20 lines)
- Additional Layer 2 KB documents (top-5 instead of top-3)
- Explicit instruction to resolve the confidence question

Pass 2 results replace Pass 1 results in storage if confidence improves.

### Output schema

```json
{
  "ruleId": "PHP-INJ-002",
  "line": 3,
  "confirmed": true,
  "confidence": "HIGH",
  "false_positive_reason": null,
  "attack_scenario": "...",
  "technical_reasoning": ["...", "..."],
  "fix_code": "...",
  "fix_explanation": "...",
  "teaching_explanation": "...",
  "prevention_tips": ["...", "..."],
  "verification_steps": ["...", "..."],
  "kb_sources": ["rules/PHP-INJ-002.json", "fixes/sql-injection-php.json"],
  "deep_source": {
    "provider": "local",
    "model": "qwen2.5-coder:14b",
    "endpoint": "http://scd-server.internal:3000",
    "code_left_environment": false,
    "analyzed_at": "2026-03-31T09:14:22Z"
  }
}
```

`kb_sources` lists which KB documents were used. This supports KB quality
improvement over time: if the model produces poor output, kb_sources shows
which documents contributed.

---

## Ollama integration

scd-server communicates with Ollama via its HTTP API. No Ollama SDK or
native bindings — plain HTTP, consistent with scd's no-unnecessary-dependencies
principle.

### Configuration (config.yml)

```yaml
ai:
  provider: local                          # local | anthropic
  ollama_url: http://localhost:11434       # Ollama API base URL
  model: qwen2.5-coder:14b                # Generation model
  embed_model: nomic-embed-text           # Embedding model
  kb_path: ./lib/ai-kb                    # KB document directory
  temperature: 0.1                        # Low = deterministic output
  timeout_ms: 120000                      # 2 min timeout for slow hardware
```

### Health check

```
GET /api/v1/ai/health
→ {
    "ollama": "ok" | "unreachable",
    "model": "qwen2.5-coder:14b",
    "model_available": true,
    "embed_model": "nomic-embed-text",
    "embed_model_available": true,
    "kb_indexed": true,
    "kb_doc_count": 47,
    "kb_indexed_at": "2026-03-31T08:00:00Z"
  }
```

Exposed in the scd-server admin UI. `scd doctor` also checks AI health
when `ai.provider: local` is configured.

---

## Model recommendations

### Recommended: qwen2.5-coder:14b

Best balance of code analysis quality and hardware requirements for the
SMB target market.

- License: Apache 2.0 — fully commercial use permitted
- RAM: ~12 GB (fits 16 GB server)
- Context window: 128K tokens
- Strengths: multi-language code, structured JSON output, security reasoning

### Minimum: qwen2.5-coder:7b

For constrained environments (developer machine, low-RAM server).

- License: Apache 2.0
- RAM: ~6 GB (fits 8 GB machine)
- Quality: acceptable for CRITICAL/HIGH findings; weaker on subtle issues

### Embedding model: nomic-embed-text

- License: Apache 2.0
- Embedding dimensions: 768
- Well-supported in Ollama, consistent quality for code/security text

### Models to avoid

- Qwen2.5 3B / 72B — not Apache 2.0; requires separate license review
- Llama 3.x — Meta Community License; requires "Built with Llama" attribution
  in product UI if distributed or made available to others
- Stability AI models — non-commercial license only

---

## Open source boundary

The `--deep` flag is present in the open source CLI. When invoked without
a configured scd-server, or when the license does not include the scd-ai
entitlement, the CLI outputs:

```
ℹ  Deep analysis requires scd-server with the Deep Analysis Pack.
   See https://activemind.se/scd for subscription options.
```

This is the intentional "teaser" behaviour — the feature is discoverable,
the path to unlock it is clear, and no functionality is gated behind
undocumented walls.

---

## Future directions

The architecture is designed to accommodate these extensions without
structural changes:

**Whole-repository analysis**
Rather than finding-driven analysis (regex detects, AI confirms), a future
`scd scan --ai` mode would pass complete files to the local model for
discovery-driven analysis — finding issues regex cannot detect: logic flaws,
IDOR via flow relationships, race conditions, insecure design patterns.
Context window size is the practical constraint; chunking strategies will
be required for large files.

**KB growth and curation**
Layer 2 KB content can grow independently of the codebase. Activemind can
publish KB updates as part of the scd-ai subscription — essentially a
continuously improving security knowledge base delivered to customer
infrastructure.

**Fine-tuning (long-term)**
High-quality confirmed findings with expert-verified deep analysis results
accumulate over time. This dataset is the natural foundation for LoRA
fine-tuning of the base model — improving analysis quality specifically for
the scd use case. This is a long-term direction, not near-term.

**Provider abstraction**
The `ai.provider` config key is the extension point. Adding a new provider
(e.g. a self-hosted vLLM instance, a future open model via a different
runtime) requires a new provider module in `lib/ai-providers/` without
touching the analysis engine or routes.

**AI-driven analytics**
The same AI engine that analyses individual findings can operate on
`scd.db` as its primary input rather than code context. This enables
reasoning over historical patterns, anomaly detection across teams and
repositories, and natural language queries against scan history.
New scd-server endpoints (e.g. `/api/v1/ai/insights`, `/api/v1/ai/query`)
would expose this capability. The `ai-live-context.js` module is the
natural starting point — it already reads the relevant tables; the
extension is letting AI reason over that data directly rather than
using it as prompt context only. No structural changes to the
architecture are required.

**Chained AI analysis — local reasoning escalated externally**
For complex patterns where local model confidence is insufficient, a
future "chained" mode would allow scd-server to escalate reasoning to
an external AI — but with a strict separation between what constitutes
*code* and what constitutes *data*. Aggregated statistics, OWASP trends,
finding counts, and behavioural patterns contain no customer code and
represent a qualitatively different category of information.

This requires a more granular trust model than today's binary
code/no-code distinction:

```
What may leave the environment?
  Level 1: Nothing              → maximum_privacy
  Level 2: Aggregated data only → analytics may escalate externally
  Level 3: Code fragments       → deep analysis via cloud provider
  Level 4: Unrestricted         → maximum_analysis
```

Everything transmitted externally — regardless of level — would be
logged to disk and `scd.db` with full metadata: timestamp, destination,
payload type, and size. This provides complete auditability for CRA
and NIS2 compliance purposes. The `deep_source` schema would be extended
with two separate fields: `code_left_environment` (existing) and
`data_left_environment` (new), keeping the audit trail precise and
machine-readable.

The boundary between code and data requires careful formal definition
before implementation — findings that contain code snippets sit in a
grey zone that must be resolved explicitly. This is a conceptual
direction that needs to mature before it is designed in detail.

**Malicious code and supply chain attack detection**
Regex-based rules can identify known dangerous patterns in vendor code
and dependencies, but AI reasoning enables a qualitatively different
capability: detecting *intent*. This includes obfuscated strings that
reconstruct at runtime, unexpected network calls embedded in npm packages,
dependency code that mimics legitimate APIs while exfiltrating data, and
subtle backdoors introduced via compromised upstream repositories or
typosquatting attacks.

This builds directly on existing foundations: `scd scan --vendor-only`
already targets dependency code specifically, and `scd deps` (planned)
covers known CVEs via OSV. AI-powered supply chain analysis is the next
layer — reasoning over vendor code the same way a security researcher
would when auditing a suspicious package. The local provider is
particularly well-suited here, since vendor code (often including
third-party proprietary code) should not leave the customer's environment
under any circumstances.
