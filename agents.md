# LLM Security Check — Agent Context

This file gives a future Claude Code session everything it needs to continue building this project without re-reading the original brief. Keep it updated as the project evolves.

---

## What this project is

**LLM Security Check** is a passive, read-only web scanner that crawls the public surface of a developer's app and reports LLM-specific security mistakes in plain English. The primary user is a developer who built an AI-assisted ("vibe coded") app and wants to know if they accidentally exposed secrets or made common LLM architecture mistakes.

The tool is NOT an attack tool. It detects and explains. It never exploits, never tests discovered keys against providers, and never sends any prompt to a discovered endpoint.

---

## Tech stack (pinned — do not add dependencies without asking)

| Layer | Choice |
|-------|--------|
| Backend | FastAPI + Pydantic v2 |
| Server | Uvicorn, single process, async |
| HTTP client | httpx (AsyncClient) |
| HTML parsing | BeautifulSoup4 + lxml |
| Detection | Python re + entropy scoring |
| Frontend | One index.html, vanilla JS, plain CSS — NO React, NO npm |
| Static serving | FastAPI StaticFiles |
| Packaging | uv (fall back to pip + requirements.txt) |
| Tests | pytest + pytest-asyncio + respx |
| Lint/format | ruff |
| Container | Dockerfile, python:3.12-slim, non-root user |

Python version: **3.12**. Type hints on every function. Code must pass `ruff check`.

---

## Project structure

```
llm-security-check/
├── pyproject.toml
├── README.md
├── Dockerfile
├── .dockerignore
├── .env.example
├── fly.toml                            # Fly.io single-instance deploy
├── app/
│   ├── main.py                         # FastAPI app, routes, StaticFiles mount
│   ├── config.py                       # pydantic-settings Settings
│   ├── models.py                       # Pydantic v2 request/response models
│   ├── store.py                        # In-memory scan store, TTL, concurrency cap
│   ├── scanner.py                      # Orchestrator: collect → detect → classify → report
│   ├── net/
│   │   ├── safe_fetch.py               # SSRF-guarded httpx wrapper (ALL network I/O goes here)
│   │   └── crawler.py                  # Page discovery, asset collection, source maps
│   ├── detect/
│   │   ├── rules.py                    # Rule definitions as Python dict (data only, no logic)
│   │   ├── redact.py                   # Redaction: called at detection time, before any object
│   │   ├── entropy.py                  # Shannon entropy scorer
│   │   ├── secrets.py                  # Group 1 (provider keys) + Group 2 (generic secrets)
│   │   ├── architecture.py             # Group 3 (LLM-specific antipatterns)
│   │   └── headers.py                  # CORS, CSP, rate-limit header checks
│   ├── knowledge/
│   │   └── attacks.py                  # Static attack knowledge base — NO LLM calls ever
│   └── report.py                       # Scoring (0–100), grading (A–F), Markdown renderer
├── static/
│   └── index.html                      # Entire frontend ≤600 lines
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── vulnerable_app/             # Deliberately leaky static site (FAKE keys only)
    │   └── clean_app/                  # No secrets, baseline for negative tests
    ├── test_safe_fetch.py
    ├── test_secrets.py
    ├── test_redaction.py
    ├── test_architecture.py
    ├── test_scanner_e2e.py
    └── test_api.py
```

---

## Non-negotiable safety rules

These must be implemented before detection logic and must have tests. Do not skip or soften them.

1. **Passive only.** GET and HEAD only. Never POST. Never submit a form. Never send input to an endpoint.

2. **Never validate a discovered key.** Do not call OpenAI, Anthropic, Google, or any provider. Validity is format-only. The report must say so explicitly.

3. **Redact everywhere.** Format: `prefix…last4` (e.g. `sk-ant-api03-…f2a9`). Redaction happens in `detect/redact.py` at the moment of detection, before the `Finding` object is constructed. No raw secret ever enters a log, a model field, or a serialised response. A test must assert this.

4. **SSRF defence on every fetch.** `net/safe_fetch.py` is the only place httpx is called. Rules:
   - Only http/https schemes
   - Resolve hostname, check every IP against: loopback, RFC-1918 (10/8, 172.16/12, 192.168/16), link-local 169.254/16 (covers cloud metadata), unique-local IPv6, ::1, 0.0.0.0/8
   - Reject `localhost` and `*.localhost` by name
   - Max 3 redirects; re-run IP check on every hop
   - 10s per-request timeout, 120s per-scan budget
   - 5 MB response body cap (stream and abort)
   - Allowed ports: 80, 443, 3000, 5173, 8000, 8080

5. **Scope discipline.** Stay on the submitted origin (scheme + host + port). Never follow off-origin links. Third-party script CDN fetching requires explicit user opt-in checkbox.

6. **Politeness.** Send `User-Agent: LLMSecurityCheck/1.0 (+<repo url>)`. Fetch and obey robots.txt. Max 2 concurrent requests per target. Max 20 pages + 30 assets per scan.

7. **Ownership attestation.** POST /api/scan requires `owns_target: true`. Reject with 400 otherwise. UI has unchecked-by-default checkbox.

8. **No persistence.** Reports expire on TTL (default 30 min). Nothing written to disk. Raw page content never stored — only short redacted snippets ≤80 chars.

---

## Detection groups

### Group 1 — LLM provider credentials (Critical severity)
Regex + validity heuristic. Covered providers: OpenAI (sk-, sk-proj-), Anthropic (sk-ant-api03-), Google AI/Gemini (AIza, 39 chars), Groq (gsk_), Mistral, Cohere, Perplexity (pplx-), Together, Fireworks, DeepSeek, xAI (xai-), Hugging Face (hf_), Replicate (r8_), OpenRouter (sk-or-v1-), ElevenLabs, AssemblyAI, Deepgram, LangSmith (ls__ / lsv2_), Pinecone/Weaviate/Qdrant, AWS access key ID (AKIA/ASIA), Azure OpenAI (32-hex near *.openai.azure.com).

Placeholder detection: keys that match the format but contain sk-xxx, your-api-key, REPLACE_ME, repeated characters, or appear inside comments/examples get `confidence: low` — severity stays Critical, they are never silently dropped.

### Group 2 — Generic secret exposure (High severity)
High-entropy strings (Shannon > 4.0, length ≥ 24) assigned to secret-ish key names. JWTs in client code. .env served over HTTP. Firebase/Supabase service-role keys. Source maps exposing server-side files.

### Group 3 — LLM architecture antipatterns
1. Browser calls provider API directly (api.openai.com, api.anthropic.com, etc. in frontend code)
2. System prompt in frontend (long strings near model params, instruction language)
3. Model/parameters/tool schemas exposed in client code
4. Unauthenticated LLM proxy path reachable (HEAD + OPTIONS only — never send a prompt)
5. Permissive CORS on API paths
6. Missing security headers (CSP, X-Content-Type-Options, Referrer-Policy)
7. No visible rate limiting headers
8. Debug surface (stack traces, /docs, /openapi.json on production)

---

## Architecture decisions (do not reverse without a reason)

- **`safe_fetch.py` is the sole network entry point.** No code elsewhere calls httpx directly.
- **Redaction is a detector responsibility.** `redact()` is called before the `Finding` is constructed. The `Finding` model never holds a raw secret.
- **Rules are data, detectors are interpreters.** `detect/rules.py` is a dict. Detectors iterate over it. Adding a new rule means adding a dict entry, not touching control flow.
- **Knowledge base is static authored text.** `attacks.py` is a plain Python dict. Zero LLM calls at runtime, ever. The `how_it_applies_here` field is a Python format string taking `provider` and `location` kwargs.
- **In-memory store, single instance.** `store.py` is a module-level dict with TTL. README must explain the scaling limitation (Redis required for horizontal scale).
- **Rate limiting is a hand-rolled in-memory dict** (keyed by client IP), not slowapi, to minimise dependencies and maximise auditability.

---

## API surface

| Method | Path | Purpose |
|--------|------|---------|
| POST | /api/scan | Start scan. Body: `{target_url, owns_target, include_third_party?}`. Returns 202 `{scan_id, status}` |
| GET | /api/scan/{scan_id} | Poll status / fetch report |
| GET | /api/scan/{scan_id}/stream | SSE: stage progress + findings as detected |
| GET | /api/scan/{scan_id}/report.md | Markdown report |
| DELETE | /api/scan/{scan_id} | Drop from memory early |
| GET | /api/rules | Detection catalog |
| GET | /api/health | Liveness |
| GET | / | Single-page frontend |

---

## Finding response shape

```json
{
  "id": "uuid",
  "rule_id": "exposed_key_anthropic",
  "title": "Anthropic API key in client-side JavaScript",
  "severity": "critical",
  "confidence": "high",
  "category": "exposed_credential",
  "evidence": {
    "location": "https://example.com/assets/index-a1b2.js",
    "line": 1420,
    "redacted_value": "sk-ant-api03-…f2a9",
    "context": "const client = new Anthropic({ apiKey: \"sk-ant-…f2a9\" })"
  },
  "why_it_matters": "...",
  "attacks": [
    {"id": "billing_drain", "name": "...", "what_it_is": "...", "how_it_applies_here": "...", "impact": "..."}
  ],
  "remediation": ["Rotate this key now in the Anthropic console", "..."],
  "references": [{"label": "OWASP LLM02: Sensitive Information Disclosure", "url": "..."}]
}
```

Status values: `queued`, `running`, `complete`, `failed`, `rejected`.

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| PORT | 8000 | Listen port |
| MAX_PAGES | 20 | Crawl page cap |
| MAX_ASSETS | 30 | Asset fetch cap |
| SCAN_TIMEOUT_SECONDS | 120 | Whole-scan budget |
| REQUEST_TIMEOUT_SECONDS | 10 | Per-request timeout |
| SCAN_TTL_MINUTES | 30 | Report retention |
| RATE_LIMIT_PER_HOUR | 5 | Scans per client IP |
| ALLOW_PRIVATE_TARGETS | false | Local dev only — logs a loud WARNING when true |
| USER_AGENT | LLMSecurityCheck/1.0 (+repo url) | Scanner identification |

---

## Testing rules

- **No real network calls.** All httpx calls in unit tests mocked with respx. The only real HTTP traffic is to `tests/fixtures/` apps served locally by pytest fixtures.
- **Every SSRF rule has its own test** asserting the fetch was refused.
- **Every detection rule has a positive + negative test** against the fixture apps.
- **Redaction test:** generate synthetic key → full scan → serialise report to JSON → assert full key string absent from JSON and captured log output.
- **Attestation test:** POST without `owns_target: true` → 400.
- **Rate limit test:** sixth scan from one IP in an hour → rejected.
- **Fixture keys must carry a comment** marking them as synthetic/fake and formatted to match patterns but never resembling a real issued credential.

---

## Scoring and grading

- Score 0–100 based on weighted severity counts.
- Letter grade A–F.
- **A single Critical finding caps the grade at F**, regardless of score.
- The headline sentence names the most severe finding specifically.

---

## Build phases (current status: Phase 0 — PLAN complete, awaiting review)

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Complete | PLAN.md written, awaiting review |
| 1 | Not started | Skeleton: pyproject.toml, FastAPI, /api/health, placeholder index.html, ruff, pytest |
| 2 | Not started | safe_fetch.py + test_safe_fetch.py |
| 3 | Not started | Fixture apps (vulnerable + clean) |
| 4 | Not started | crawler.py |
| 5 | Not started | Detectors: redact, entropy, secrets, architecture, headers |
| 6 | Not started | attacks.py, report.py, models.py |
| 7 | Not started | API routes, SSE, store, rate limiting, attestation |
| 8 | Not started | Frontend (static/index.html) |
| 9 | ✅ Complete | Dockerfile, README, .env.example, fly.toml, deploy |
| 10 | ✅ Complete | Hardening pass |

**Rule:** finish and test each phase before starting the next. Run pytest after every phase and paste the summary line. Do not move on with a red suite.

**Phase 10 final:** `195 passed, 0 failed` — `ruff check` clean.

---

## Acceptance criteria (all must hold before the build is "done")

- [ ] Scanning vulnerable fixture finds: Anthropic key, OpenAI key, direct provider call, leaked system prompt, exposed config.json, source map, permissive CORS header
- [ ] Scanning clean fixture → zero critical or high findings + honest "what we could not check" list
- [ ] Every finding renders all four blocks: what, why, attacks, fix
- [ ] No raw secret in any API response, log line, or the DOM — proven by test
- [ ] Every SSRF case refused — proven by tests including redirect-to-private
- [ ] Scan without ownership attestation → 400
- [ ] `ruff check` passes clean
- [ ] `pytest` passes clean
- [ ] `docker build` succeeds, container runs
- [ ] Deployed URL completes a scan of a real public site within timeout
- [ ] README states what the tool cannot detect

---

## What this tool will never do

- Call any LLM or AI API at runtime (knowledge base is static text)
- Validate a discovered key against its provider
- Write findings to disk
- POST to any discovered endpoint
- Follow off-origin links (without explicit user opt-in for CDN scripts)
- Store raw page content (only ≤80-char redacted snippets)
- Provide authentication, user accounts, or analytics
