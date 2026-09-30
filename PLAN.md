# LLM Security Check — Phase 0 Plan

**Author:** Safia Habib  
**Date:** 2026-09-29  
**Status:** Awaiting review before Phase 1 begins

---

## Interpretation of the Brief

### What this product is

A passive, read-only web scanner that crawls the public surface of a developer's app and reports LLM-specific security mistakes — primarily secrets exposed in frontend code. It never attacks, never validates keys against providers, and never sends any prompt to a discovered endpoint. Findings are explained in plain English with concrete attack scenarios drawn from a static knowledge base.

### What makes it distinct from generic secret scanners

- Domain-specific: covers LLM provider key formats, LLM architecture antipatterns (client-side calls, exposed system prompts, tool schemas), and LLM-specific attack scenarios.
- Explanation-first: every finding is paired with authored attack descriptions, not just pattern matches.
- Safety-first design: SSRF defence, redaction-before-storage, no key validation, ownership attestation, scope discipline, and politeness are all first-class requirements — not afterthoughts.

---

## File Plan

All files to be created. Paths relative to `llm-security-check/`.

```
llm-security-check/
├── pyproject.toml                      # uv/pip project, ruff config, pytest config
├── README.md                           # Usage, limitations, authorised-use policy
├── Dockerfile                          # python:3.12-slim, non-root user, HEALTHCHECK
├── .dockerignore
├── .env.example                        # All env vars documented
├── fly.toml                            # Fly.io deployment config (single instance)
│
├── app/
│   ├── __init__.py
│   ├── main.py                         # FastAPI app + route registration + StaticFiles
│   ├── config.py                       # pydantic-settings Settings class
│   ├── models.py                       # All Pydantic v2 request/response models
│   ├── store.py                        # In-memory scan store, TTL, concurrency cap
│   ├── scanner.py                      # Orchestrator: collect → detect → classify → report
│   │
│   ├── net/
│   │   ├── __init__.py
│   │   ├── safe_fetch.py               # SSRF-guarded httpx.AsyncClient wrapper
│   │   └── crawler.py                  # Page discovery, asset collection, source maps
│   │
│   ├── detect/
│   │   ├── __init__.py
│   │   ├── rules.py                    # Rule definitions as a Python dict (data, not logic)
│   │   ├── redact.py                   # Redaction: prefix + last-4, applied at detection time
│   │   ├── entropy.py                  # Shannon entropy scorer
│   │   ├── secrets.py                  # Group 1 (provider keys) + Group 2 (generic secrets)
│   │   ├── architecture.py             # Group 3 (LLM architecture antipatterns)
│   │   └── headers.py                  # CORS, CSP, rate-limit header checks
│   │
│   ├── knowledge/
│   │   └── attacks.py                  # Static attack knowledge base (dict, no LLM calls)
│   │
│   └── report.py                       # Scoring (0–100), grading (A–F), Markdown renderer
│
├── static/
│   └── index.html                      # Entire frontend: HTML + CSS + JS, ≤600 lines
│
└── tests/
    ├── conftest.py                     # pytest fixtures: app client, fixture-app server
    ├── fixtures/
    │   ├── vulnerable_app/             # Deliberately leaky static site for testing
    │   │   ├── index.html
    │   │   ├── assets/
    │   │   │   ├── index.js            # Synthetic keys, system prompt, direct API call
    │   │   │   └── index.js.map        # Source map with sourcesContent
    │   │   ├── config.json             # Exposed config with fake key
    │   │   └── .env                    # Served at /.env — triggers critical on its own
    │   └── clean_app/                  # No secrets, baseline for negative test cases
    │       ├── index.html
    │       └── assets/index.js
    │
    ├── test_safe_fetch.py              # SSRF rules, all cases
    ├── test_secrets.py                 # Group 1 + 2 detectors: true positives + negatives
    ├── test_redaction.py               # Proves no full key reaches serialised output or logs
    ├── test_architecture.py            # Group 3 checks
    ├── test_scanner_e2e.py             # Full scan against vulnerable_app and clean_app
    └── test_api.py                     # API endpoints, attestation, rate limiting, errors
```

**Total Python files:** ~18  
**Total test files:** 6  
**Frontend:** 1 HTML file

---

## Phase-by-Phase Build Order

| Phase | Deliverable | Checkpoint |
|-------|-------------|------------|
| 0 | PLAN.md (this file) | Review before Phase 1 |
| 1 | pyproject.toml, main.py, config.py, /api/health, placeholder index.html, ruff + pytest wired | App runs, health endpoint answers |
| 2 | safe_fetch.py, test_safe_fetch.py | All SSRF tests pass; no crawling exists yet |
| 3 | tests/fixtures/vulnerable_app/ and clean_app/ | Can serve locally, visually inspectable |
| 4 | crawler.py | Collector run against fixture yields expected artefact inventory |
| 5 | redact.py, entropy.py, secrets.py, architecture.py, headers.py, all detect tests | Redaction test proves no full key in serialised report |
| 6 | attacks.py, report.py, models.py updated | Generated Markdown report is readable end to end |
| 7 | store.py, API routes, SSE, rate limiting, attestation | test_api.py green including rejections |
| 8 | static/index.html | Browser scan of fixture shows full report |
| 9 | Dockerfile, README, .env.example, fly.toml, deployed URL | Live URL completes a real scan |
| 10 | Hardening pass | Report on anything not fully satisfiable |

---

## Key Design Decisions

### safe_fetch.py is a single entry point for all network I/O
Every outbound request — page fetches, asset fetches, robots.txt, source map fetches, well-known probes — goes through one `safe_fetch(url, ...)` async function. No code elsewhere calls `httpx` directly. This makes the SSRF boundary auditable in one file.

### Redaction is a detector responsibility, not a report responsibility
`redact.py` exports a single `redact(value: str) -> str` function. Every detector calls it immediately on match, before the `Finding` object is constructed. The `Finding` model holds only the redacted form. There is no post-processing step and no way to accidentally log a raw key through structured logging of a `Finding`.

### Rules are data, detectors are interpreters
`detect/rules.py` defines a `RULES` dict keyed by rule ID. Each entry carries `id`, `title`, `category`, `severity`, `patterns` (list of compiled regexes), `confidence_modifiers` (for placeholder detection), and `attack_ids`. The detector functions in `secrets.py`, `architecture.py`, and `headers.py` iterate over applicable rules and apply the patterns — they contain no rule-specific logic. Adding a new provider key pattern means adding one dict entry to `RULES`.

### Knowledge base is static authored text
`attacks.py` is a plain Python dict. No LLM call, no template engine, no network request. The `how_it_applies_here` field is a Python format string that takes `provider` and `location` keyword arguments. This is deterministic, auditable, and has no runtime dependencies.

### SSE + polling fallback
The scan stream endpoint (`GET /api/scan/{scan_id}/stream`) emits server-sent events. The frontend also polls `GET /api/scan/{scan_id}` every 2 seconds as a fallback for environments that block SSE. Both paths produce the same data; SSE is just faster.

### Single-instance, in-memory only
`store.py` is a module-level `dict` with per-entry expiry timestamps and a `MAX_CONCURRENT_SCANS` cap (default 10). No Redis, no SQLite. The README explains the consequence: restarting the process drops all in-progress scan results, and horizontal scaling requires a shared store. The .env.example documents the TTL and concurrency vars.

---

## Questions and Potential Issues

### 1. Source map fetching scope
The brief says source maps should be fetched "only if the user opts in with an explicit checkbox" for third-party scripts, but source maps for same-origin JS are clearly in scope. I will fetch same-origin source maps unconditionally and apply the third-party opt-in only to cross-origin script src attributes. If that interpretation is wrong, let me know.

### 2. /.env returning 200 as a critical finding
The brief says "treat a 200 on /.env as critical on its own." I will implement this as a standalone rule with no pattern matching — the presence of a 200 response on that path is the finding, and the body will be scanned for additional secrets on top of that. This means the /.env finding can appear alongside other findings from the same file rather than replacing them.

### 3. Port allowlist vs. non-standard ports
The brief's SSRF spec says "reject non-standard ports by default, with an allowlist of 80, 443, 3000, 5173, 8000, 8080." Port 5173 is Vite's dev default, so this is appropriate for scanning vibe-coded apps that may be deployed on non-80 ports. I'll make the allowlist configurable via an env var so operators can extend it.

### 4. Placeholder key confidence
The brief says placeholder keys (sk-xxx, sk-proj-REPLACE_ME, repeated chars, in example/comment) should be detected at "low confidence, not high." I will define confidence as: `high` = format-valid, no placeholder markers; `medium` = format-valid but in a comment or near words like "example", "placeholder", "replace"; `low` = format matches but contains repeated chars, all-x body, or an obvious placeholder string. Severity stays Critical regardless; confidence is a separate field. This matches the brief's intent.

### 5. "Unauthenticated LLM proxy" detection via HEAD/OPTIONS only
The brief explicitly says to detect this by "HEAD or OPTIONS only — check for the route's existence and whether CORS is wide open. Never send a prompt to it." I will send HEAD to candidate paths, then OPTIONS to check CORS, and report "possible open relay — verify manually" at High severity. I will never send a body or a GET with query parameters that look like a prompt.

### 6. Rate limiting implementation
The brief suggests `slowapi` or a simple in-memory limiter. I will use a simple in-memory dict keyed by client IP (from `request.client.host` or `X-Forwarded-For` when behind a proxy). SlowAPI adds a dependency; rolling it myself is ~30 lines and is more auditable for a security tool. If you'd prefer slowapi, say so.

### 7. `ALLOW_PRIVATE_TARGETS` env var
The brief says this must "default to false and be loudly logged when true." I'll implement it as a startup check: if `ALLOW_PRIVATE_TARGETS=true`, the app logs a `WARNING` level message on every startup and on every scan, and the health endpoint includes `"allow_private_targets": true` in its response body so it's visible in monitoring.

### 8. `ruff check` scope
I'll configure ruff to check all files under `app/` and `tests/`. The fixture files under `tests/fixtures/` will be excluded since they contain deliberately bad patterns (fake keys as string literals) that might trip secret-detection linters.

---

## Acceptance Criteria Cross-Check

| Criterion | Implementation approach |
|-----------|------------------------|
| Finds Anthropic key in fixture | Group 1 detector, `exposed_key_anthropic` rule |
| Finds OpenAI key in fixture | Group 1 detector, `exposed_key_openai` rule |
| Finds direct provider call | Group 3 `browser_direct_call` check in architecture.py |
| Finds leaked system prompt | Group 3 `system_prompt_in_frontend` check |
| Finds exposed config.json | Well-known path probe + Group 1/2 scan of contents |
| Finds source map | Source map fetch + Group 1/2 scan of sourcesContent |
| Finds permissive CORS | headers.py CORS check |
| Clean fixture → zero critical/high | Negative test cases in test_scanner_e2e.py |
| All four finding blocks present | models.py + report.py + frontend render |
| No raw secret in API/logs/DOM | test_redaction.py |
| All SSRF cases refused | test_safe_fetch.py |
| No attestation → 400 | test_api.py |
| ruff + pytest clean | CI check in Dockerfile build |
| docker build succeeds | Phase 9 |
| Live URL completes scan within timeout | Phase 9 deploy |
| README states limitations | Phase 9 README |

---

## What I Will Not Build

- Any LLM call at runtime (explanations are static text)
- Any database or persistent storage
- Authentication or user accounts
- Any write operation to a target (passive only)
- Any attempt to validate discovered keys against providers
- React, npm, or a build step for the frontend
