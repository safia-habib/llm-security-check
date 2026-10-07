# LLM Security Check

A passive, read-only web scanner that crawls the public surface of your app and reports
LLM-specific security mistakes in plain English — exposed API keys, system prompts in
client code, direct provider calls from the browser, misconfigured CORS, and more.

Designed for developers who built an AI-assisted app and want to catch common mistakes
before attackers do.

---

## What it detects

| Group | Examples |
|-------|---------|
| **Provider credentials** (Critical) | OpenAI, Anthropic, Google Gemini, Groq, AWS, Hugging Face, xAI, Replicate, Perplexity, OpenRouter, LangSmith keys in JS bundles, `.env` files, source maps, or `config.json` |
| **Generic secrets** (High) | JWTs in client code, `.env` served over HTTP, source maps exposing server-side files, high-entropy strings assigned to secret-like names |
| **LLM architecture mistakes** (High/Medium) | Browser calling provider API directly, system prompt in frontend, model parameters or tool schemas exposed, unauthenticated LLM proxy path, permissive `Access-Control-Allow-Origin: *`, missing `Content-Security-Policy` |

Each finding includes:
- **What it is** — plain-English description
- **Why it matters** — the specific risk in context
- **Attack scenarios** — concrete abuse paths an attacker would follow
- **Remediation steps** — ordered list of actions to fix it

---

## What it cannot detect

This tool has deliberate, hard limits. A clean report is **not** a guarantee of security.

- **Authentication and authorisation on discovered endpoints** — would require sending
  credentials, which is outside the tool's passive scope.
- **Whether discovered API keys are currently valid** — the tool never calls any provider
  API to test credentials. Key rotation is always recommended regardless.
- **Dynamic content generated after JavaScript execution** — the scanner does not run
  a headless browser; client-side rendered content may be missed.
- **Private or authenticated routes** — only publicly reachable pages are crawled.
- **Backend-side code** not exposed through source maps or configuration files.
- **Runtime LLM behaviour** — the tool never sends prompts to any discovered AI endpoint.
- **Rate limiting beyond what is visible in HTTP response headers.**
- **Indirect prompt injection** through third-party content the app retrieves at runtime.
- **Supply-chain attacks** in dependencies — this is not a dependency auditor.
- **Infrastructure misconfigurations** not visible at the HTTP layer.

---

## Quick start

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Install and run

```bash
# Clone the repo
git clone https://github.com/placeholder/llm-security-check
cd llm-security-check

# Install with uv
uv pip install .

# Or with pip
pip install .

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

### Environment variables

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `8000` | Listen port |
| `MAX_PAGES` | `20` | Page crawl cap |
| `MAX_ASSETS` | `30` | Asset fetch cap |
| `SCAN_TIMEOUT_SECONDS` | `120` | Per-scan budget |
| `REQUEST_TIMEOUT_SECONDS` | `10` | Per-request timeout |
| `SCAN_TTL_MINUTES` | `30` | Report retention in memory |
| `RATE_LIMIT_PER_HOUR` | `5` | Scans per client IP per hour |
| `ALLOW_PRIVATE_TARGETS` | `false` | **Development only.** Allows scanning localhost. Logs a loud warning. Never enable in a shared deployment. |
| `USER_AGENT` | `LLMSecurityCheck/1.0 (…)` | Scanner identification header |

---

## Docker

```bash
# Build
docker build -t llm-security-check .

# Run
docker run -p 8000:8000 llm-security-check
```

To override settings:

```bash
docker run -p 8000:8000 \
  -e RATE_LIMIT_PER_HOUR=10 \
  -e SCAN_TTL_MINUTES=60 \
  llm-security-check
```

---

## Deploy to Fly.io

```bash
# Install the Fly CLI: https://fly.io/docs/hands-on/install-flyctl/
fly auth login

# First deploy (creates the app)
fly launch

# Subsequent deploys
fly deploy
```

The `fly.toml` configures a single shared-CPU machine with 512 MB RAM.
Machines auto-stop when idle and auto-start on incoming requests.

> **Scaling note:** The scan store is held in-process memory. A single machine is
> the only supported topology without additional work. Horizontal scaling requires
> replacing `app/store.py` with a shared backend such as Redis.

---

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Start a scan. Body: `{"target_url": "…", "owns_target": true}` → 202 `{scan_id, status}` |
| `GET` | `/api/scan/{id}` | Poll status or fetch the complete report |
| `GET` | `/api/scan/{id}/stream` | SSE stream: stage progress and findings as detected |
| `GET` | `/api/scan/{id}/report.md` | Download the Markdown report |
| `DELETE` | `/api/scan/{id}` | Remove a scan from memory |
| `GET` | `/api/rules` | Detection rule catalog |
| `GET` | `/api/health` | Liveness check |
| `GET` | `/` | Web UI |

`owns_target` must be `true` — the scanner rejects requests without ownership
attestation. Scan only apps you own or have written permission to test.

---

## Development

```bash
# Install with dev extras
uv pip install ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Run with auto-reload
uvicorn app.main:app --reload
```

### Project structure

```
app/
  main.py           FastAPI app, routes
  config.py         pydantic-settings Settings
  models.py         Pydantic request/response models
  store.py          In-memory scan store (TTL, concurrency cap)
  scanner.py        Scan orchestrator (crawl → detect → enrich → report)
  net/
    safe_fetch.py   SSRF-guarded httpx wrapper (sole network entry point)
    crawler.py      Page discovery and asset collection
  detect/
    rules.py        Detection rules as a plain Python dict
    redact.py       Secret redaction (prefix…last4)
    entropy.py      Shannon entropy scorer
    secrets.py      Group 1+2: provider keys and generic secrets
    architecture.py Group 3: LLM architecture antipatterns
    headers.py      CORS and CSP header checks
  knowledge/
    attacks.py      Static attack knowledge base (no LLM calls)
  report.py         Scoring, grading, Markdown renderer
static/
  index.html        Single-page frontend (vanilla JS, no build step)
tests/
  fixtures/
    vulnerable_app/ Deliberately leaky static site (fake keys only)
    clean_app/      Baseline negative-test app
```

---

## Security model

- **Passive only.** GET and HEAD requests only. No forms submitted, no data sent to
  discovered endpoints.
- **Keys are never tested.** Discovered credentials are redacted to `prefix…last4` at
  detection time and never sent to any provider API.
- **No persistence.** Reports live in memory for up to `SCAN_TTL_MINUTES` minutes, then
  expire. Nothing is written to disk.
- **SSRF protection.** Every outbound request is validated against scheme, hostname,
  resolved IP, and port allowlists before it is sent. Redirect chains are re-validated
  at each hop.
- **Scope discipline.** The crawler stays within the submitted origin. Off-origin links
  are not followed unless the user opts in to third-party script scanning.
- **robots.txt respected.** The scanner fetches and obeys `robots.txt` before crawling.

---

## Licence

MIT
