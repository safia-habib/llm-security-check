"""
Detection rule definitions.

Rules are pure data — a dict of dicts. No compiled regexes, no functions.
Detectors import RULES and compile patterns at call time.

Each rule has:
    title           Human-readable finding title
    severity        "critical" | "high" | "medium" | "low" | "info"
    confidence      "high" | "medium" | "low"
    category        Short slug describing the finding class
    group           1 = provider keys, 2 = generic secrets, 3 = architecture
    pattern         Regex string (None for structural/header checks)
    why_it_matters  ≤3 sentences explaining the risk
    attack_ids      IDs into the attacks knowledge base (app/knowledge/attacks.py)
    remediation     Ordered list of actionable steps
    references      list[{"label": str, "url": str}]
"""

from __future__ import annotations

RULES: dict[str, dict] = {
    # ──────────────────────────────────────────────────────────────────────────
    # Group 1 — LLM Provider Credentials (Critical)
    # ──────────────────────────────────────────────────────────────────────────
    "exposed_key_openai": {
        "title": "OpenAI API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "why_it_matters": (
            "An OpenAI API key in client-side code can be extracted by any visitor from "
            "page source or the browser's network tab. Attackers use stolen keys to "
            "generate completions and drain your billing quota at no cost to them."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate the key immediately in the OpenAI dashboard (platform.openai.com → API keys).",
            "Move all OpenAI API calls to a server-side proxy that authenticates your users first.",
            "Store the new key only in a server-side environment variable, never in source code.",
            "Set spend limits and usage alerts in the OpenAI billing dashboard.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
            {
                "label": "OpenAI API Key Best Practices",
                "url": "https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety",
            },
        ],
    },
    "exposed_key_openai_proj": {
        "title": "OpenAI project API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"sk-proj-[A-Za-z0-9\-_]{50,}",
        "why_it_matters": (
            "OpenAI project keys are scoped to a single project but still grant full "
            "access to its models and quota. Exposure lets attackers consume your project "
            "budget and access any data the project can reach."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate the key immediately in the OpenAI dashboard under the affected project.",
            "Proxy all API calls through your backend; never reference the key in frontend code.",
            "Restrict project key permissions to the minimum required scopes.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "exposed_key_anthropic": {
        "title": "Anthropic API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"sk-ant-api03-[A-Za-z0-9]{60,120}",
        "why_it_matters": (
            "An Anthropic API key in client code lets any visitor make Claude API calls at "
            "your expense. Prompt injection attacks are trivial when the model can be "
            "called directly from the browser without any server-side validation."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access", "prompt_injection"],
        "remediation": [
            "Rotate the key immediately at console.anthropic.com → API Keys.",
            "Move Claude API calls to a server-side proxy; validate all user input there.",
            "Never expose the Anthropic key in any file that is bundled into the frontend.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "Anthropic API Key Management",
                "url": "https://docs.anthropic.com/en/api/getting-started",
            },
        ],
    },
    "exposed_key_gemini": {
        "title": "Google Gemini API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"AIza[A-Za-z0-9\-_]{35}",
        "why_it_matters": (
            "Google API keys beginning with AIza grant access to all enabled Google Cloud "
            "services, not just Gemini. An attacker can use the key to incur charges across "
            "Maps, Vision, Translation, and other APIs, or exfiltrate your data."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate or delete the key in the Google Cloud Console → APIs & Services → Credentials.",
            "Add API key restrictions: limit the key to specific APIs and your production domain.",
            "Use a backend proxy for Gemini calls; never embed the key in frontend bundles.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "Google: Best Practices for Managing API Keys",
                "url": "https://cloud.google.com/docs/authentication/api-keys#best_practices",
            },
        ],
    },
    "exposed_key_groq": {
        "title": "Groq API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"gsk_[A-Za-z0-9]{50,70}",
        "why_it_matters": (
            "A Groq API key in client code can be extracted and used immediately to access "
            "Groq's ultra-fast inference at your expense. Exposure may also reveal which "
            "models and prompts you are using."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate the key in the Groq console (console.groq.com → API Keys).",
            "Proxy all Groq calls through your server-side backend.",
            "Set rate limits and monitor usage for anomalies.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "exposed_key_aws_access_key": {
        "title": "AWS access key ID exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        "why_it_matters": (
            "AWS access key IDs are typically paired with a secret access key in the same "
            "source file or environment. Together they grant programmatic access to your AWS "
            "account, potentially including S3 buckets, SageMaker, Bedrock, and IAM."
        ),
        "attack_ids": ["unauthorized_access", "data_exfiltration"],
        "remediation": [
            "Immediately deactivate the key in the AWS IAM console and check CloudTrail "
            "for unauthorised API calls.",
            "Rotate or delete the key pair; use IAM roles with least-privilege permissions.",
            "For frontend AWS interactions, use Amazon Cognito identity pools with "
            "temporary credentials — never long-lived key pairs.",
        ],
        "references": [
            {
                "label": "AWS: Best Practices for Managing AWS Access Keys",
                "url": "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
            },
            {
                "label": "CWE-798: Use of Hard-coded Credentials",
                "url": "https://cwe.mitre.org/data/definitions/798.html",
            },
        ],
    },
    "exposed_key_huggingface": {
        "title": "Hugging Face API token exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"hf_[A-Za-z0-9]{30,}",
        "why_it_matters": (
            "Hugging Face tokens may have write access, allowing an attacker to modify or "
            "delete your models and datasets. Read tokens expose private models and "
            "inference endpoints billed to your account."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access", "model_theft"],
        "remediation": [
            "Revoke the token at huggingface.co/settings/tokens.",
            "Create a new read-only or fine-grained token with the minimum required scope.",
            "Keep Hugging Face tokens server-side only; proxy all inference through your backend.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "Hugging Face: User Access Tokens",
                "url": "https://huggingface.co/docs/hub/security-tokens",
            },
        ],
    },
    "exposed_key_openrouter": {
        "title": "OpenRouter API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"sk-or-v1-[A-Za-z0-9]{60,}",
        "why_it_matters": (
            "OpenRouter keys provide access to dozens of LLM providers through a single "
            "API, multiplying the blast radius of a single key exposure. Attackers can "
            "route expensive model calls through your key and drain your credits."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Revoke the key in the OpenRouter dashboard (openrouter.ai/keys).",
            "Proxy all OpenRouter calls through your backend.",
            "Set per-model spend limits on your OpenRouter account.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "exposed_key_xai": {
        "title": "xAI (Grok) API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"xai-[A-Za-z0-9]{50,}",
        "why_it_matters": (
            "An xAI API key found in client code can be used to make Grok API calls at "
            "your expense. Exposure reveals your model usage patterns and lets attackers "
            "exploit your account's quota and rate limits."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate the key in the xAI console.",
            "Move all Grok API calls to a server-side proxy.",
            "Monitor your xAI usage dashboard for unexpected activity.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "exposed_key_replicate": {
        "title": "Replicate API token exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"r8_[A-Za-z0-9]{37,}",
        "why_it_matters": (
            "Replicate tokens grant access to GPU-backed model inference, which can be "
            "extremely expensive. An attacker can run large image or video models at your "
            "cost, generating content that violates your terms of service."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Revoke the token at replicate.com/account/api-tokens.",
            "Create a new token and store it only in server-side environment variables.",
            "Proxy all Replicate calls through your backend.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "exposed_key_perplexity": {
        "title": "Perplexity API key exposed in client-side code",
        "severity": "critical",
        "confidence": "high",
        "category": "exposed_credential",
        "group": 1,
        "pattern": r"pplx-[A-Za-z0-9]{48}",
        "why_it_matters": (
            "A Perplexity API key in client code lets attackers perform web-grounded "
            "searches and chat completions at your expense. It also reveals that your "
            "application uses Perplexity's online models, which can guide further attacks."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Rotate the key in the Perplexity developer console.",
            "Proxy all Perplexity API calls through your server-side backend.",
            "Set rate limits and monitor usage dashboards regularly.",
        ],
        "references": [
            {
                "label": "OWASP LLM02: Sensitive Information Disclosure",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # Group 2 — Generic Secret Exposure (High)
    # ──────────────────────────────────────────────────────────────────────────
    "env_file_publicly_accessible": {
        "title": ".env file publicly accessible over HTTP",
        "severity": "high",
        "confidence": "high",
        "category": "sensitive_file_exposure",
        "group": 2,
        "pattern": None,
        "why_it_matters": (
            ".env files typically contain database credentials, API keys, and service "
            "secrets. Serving one over HTTP exposes every secret it contains in a single "
            "unauthenticated request to any visitor or automated scanner."
        ),
        "attack_ids": ["unauthorized_access", "data_exfiltration"],
        "remediation": [
            "Block access to .env files in your web server or CDN configuration.",
            "Rotate every credential found in the exposed file immediately.",
            "Move secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, "
            "Doppler) and reference them by name, not value, in your app.",
            "Add .env to .gitignore and verify it was never committed to your repository.",
        ],
        "references": [
            {
                "label": "OWASP WSTG: Testing for Sensitive Data in HTTP Responses",
                "url": "https://owasp.org/www-project-web-security-testing-guide/",
            },
            {
                "label": "CWE-538: File and Directory Information Exposure",
                "url": "https://cwe.mitre.org/data/definitions/538.html",
            },
        ],
    },
    "source_map_in_production": {
        "title": "JavaScript source map exposed in production",
        "severity": "high",
        "confidence": "high",
        "category": "source_disclosure",
        "group": 2,
        "pattern": None,
        "why_it_matters": (
            "Source maps reconstruct original pre-bundled source code, including file "
            "paths, comments, and any secrets that were present before bundling. Exposing "
            "them in production makes reverse-engineering your application trivial."
        ),
        "attack_ids": ["model_theft", "data_exfiltration"],
        "remediation": [
            "Configure your bundler to omit sourceMappingURL comments in production builds.",
            "If source maps are needed for error tracking, upload them privately to your "
            "error monitoring service (Sentry, Datadog) and block public access.",
            "Audit the original source files for hardcoded secrets before the next build.",
        ],
        "references": [
            {
                "label": "OWASP WSTG: Map Execution Paths Through Application",
                "url": "https://owasp.org/www-project-web-security-testing-guide/",
            },
            {
                "label": "CWE-540: Inclusion of Sensitive Information in Source Code",
                "url": "https://cwe.mitre.org/data/definitions/540.html",
            },
        ],
    },
    "jwt_in_client_code": {
        "title": "JSON Web Token (JWT) found in client-side code",
        "severity": "high",
        "confidence": "medium",
        "category": "exposed_credential",
        "group": 2,
        "pattern": (
            r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}"
        ),
        "why_it_matters": (
            "A hardcoded JWT in client code may be a long-lived service account token "
            "or admin credential. Unlike short-lived user JWTs, hardcoded tokens cannot "
            "be revoked without a code change and deployment."
        ),
        "attack_ids": ["unauthorized_access", "data_exfiltration"],
        "remediation": [
            "Revoke or rotate the JWT signing key to immediately invalidate the token.",
            "Never hardcode JWTs in source code; issue short-lived tokens at runtime.",
            "Inspect the JWT payload (jwt.io) to understand what access it grants and "
            "audit recent usage in your auth provider's logs.",
        ],
        "references": [
            {
                "label": "OWASP: JSON Web Token Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            },
            {
                "label": "CWE-798: Use of Hard-coded Credentials",
                "url": "https://cwe.mitre.org/data/definitions/798.html",
            },
        ],
    },
    # ──────────────────────────────────────────────────────────────────────────
    # Group 3 — LLM Architecture Antipatterns
    # ──────────────────────────────────────────────────────────────────────────
    "direct_provider_api_call": {
        "title": "Direct LLM provider API call from browser JavaScript",
        "severity": "high",
        "confidence": "high",
        "category": "insecure_llm_architecture",
        "group": 3,
        "pattern": (
            r"https?://api\.(?:openai|anthropic|groq|mistral|cohere|perplexity)\.(?:com|ai)"
        ),
        "why_it_matters": (
            "Calling an LLM provider directly from the browser exposes your API key to "
            "every visitor, lets users observe your prompts and model settings via the "
            "network tab, and bypasses any server-side validation or rate limiting."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access", "prompt_injection"],
        "remediation": [
            "Create a thin backend proxy endpoint (e.g. POST /api/chat) that forwards "
            "requests to the LLM provider using a server-side secret.",
            "Validate and sanitise user input on the server before forwarding.",
            "Implement authentication, rate limiting, and usage tracking on the proxy.",
        ],
        "references": [
            {
                "label": "OWASP LLM07: Insecure Plugin Design",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-603: Use of Client-Side Authentication",
                "url": "https://cwe.mitre.org/data/definitions/603.html",
            },
        ],
    },
    "gemini_direct_api_call": {
        "title": "Direct Google Gemini API call from browser JavaScript",
        "severity": "high",
        "confidence": "high",
        "category": "insecure_llm_architecture",
        "group": 3,
        "pattern": r"generativelanguage\.googleapis\.com",
        "why_it_matters": (
            "Calling the Gemini API directly from the browser exposes your Google API "
            "key and reveals your model configuration to any visitor. Server-side "
            "proxying is required to protect credentials and control usage."
        ),
        "attack_ids": ["billing_drain", "unauthorized_access"],
        "remediation": [
            "Route all Gemini calls through a server-side proxy; remove the direct URL "
            "from frontend code.",
            "Restrict your Google API key to specific server-side origins and APIs.",
            "Monitor Google Cloud usage dashboards for unexpected spikes.",
        ],
        "references": [
            {
                "label": "Google: Best Practices for Managing API Keys",
                "url": "https://cloud.google.com/docs/authentication/api-keys#best_practices",
            },
            {
                "label": "OWASP LLM07: Insecure Plugin Design",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
        ],
    },
    "system_prompt_in_frontend": {
        "title": "System prompt reference found in client-side code",
        "severity": "high",
        "confidence": "medium",
        "category": "prompt_disclosure",
        "group": 3,
        "pattern": r"(?i)\bsystem[_-]?prompt\b",
        "why_it_matters": (
            "A system prompt found in client code is readable by any user, allowing them "
            "to understand your AI's constraints, find guardrail loopholes, and craft "
            "inputs that bypass safety rules or extract your proprietary instructions."
        ),
        "attack_ids": ["prompt_injection", "model_theft"],
        "remediation": [
            "Move the system prompt to the server; send only the user-visible "
            "conversation history to the frontend.",
            "Never store the system prompt in a JavaScript variable, a data attribute, "
            "or a client-accessible API endpoint.",
            "Treat your system prompt as a trade secret and apply the same access "
            "controls as any other sensitive server-side configuration.",
        ],
        "references": [
            {
                "label": "OWASP LLM07: System Prompt Leakage",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "OWASP LLM01: Prompt Injection",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
        ],
    },
    "model_params_in_frontend": {
        "title": "LLM model parameters exposed in client-side code",
        "severity": "medium",
        "confidence": "medium",
        "category": "configuration_disclosure",
        "group": 3,
        "pattern": (
            r"(?i)\b(?:temperature|maxTokens|max_tokens)\s*[:=]\s*[\d.]+"
        ),
        "why_it_matters": (
            "Exposing model parameters such as temperature and token limits reveals your "
            "AI configuration and may let users manipulate these values via modified "
            "requests if your backend does not re-validate them."
        ),
        "attack_ids": ["prompt_injection", "unauthorized_access"],
        "remediation": [
            "Define model parameters in server-side code only; accept only the "
            "user-provided message from the client.",
            "Validate and clamp any parameters that must come from the client (e.g. "
            "max response length) against safe server-side bounds.",
        ],
        "references": [
            {
                "label": "OWASP LLM07: Insecure Plugin Design",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            },
            {
                "label": "CWE-200: Exposure of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/200.html",
            },
        ],
    },
    "permissive_cors_wildcard": {
        "title": "Permissive CORS wildcard (Access-Control-Allow-Origin: *)",
        "severity": "high",
        "confidence": "high",
        "category": "insecure_configuration",
        "group": 3,
        "pattern": None,
        "why_it_matters": (
            "A wildcard CORS header lets any website make cross-origin requests to your "
            "API and read the responses. Combined with a user's existing session, this "
            "enables data theft from authenticated endpoints without the user's knowledge."
        ),
        "attack_ids": ["cors_bypass", "data_exfiltration"],
        "remediation": [
            "Replace the wildcard with an explicit allowlist of trusted origins "
            "(e.g. Access-Control-Allow-Origin: https://yourapp.com).",
            "If your API serves only unauthenticated public data, a wildcard is acceptable "
            "but you must ensure no cookies or auth headers are reflected.",
            "Test your CORS configuration with a CORS scanner after every deployment.",
        ],
        "references": [
            {
                "label": "OWASP: CORS Misconfiguration",
                "url": "https://owasp.org/www-project-web-security-testing-guide/",
            },
            {
                "label": "MDN: CORS — Access-Control-Allow-Origin",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
            },
        ],
    },
    "missing_csp_header": {
        "title": "Content-Security-Policy header absent",
        "severity": "info",
        "confidence": "high",
        "category": "missing_security_header",
        "group": 3,
        "pattern": None,
        "why_it_matters": (
            "Without a Content-Security-Policy header, browsers allow inline scripts and "
            "arbitrary resource loading, which significantly increases the impact of any "
            "cross-site scripting (XSS) vulnerability found in your application."
        ),
        "attack_ids": ["prompt_injection"],
        "remediation": [
            "Add a Content-Security-Policy header; start with a restrictive policy and "
            "widen it as needed: Content-Security-Policy: default-src 'self'.",
            "Use nonces or hashes for any inline scripts rather than 'unsafe-inline'.",
            "Test your CSP at csp-evaluator.withgoogle.com before deploying.",
        ],
        "references": [
            {
                "label": "OWASP: Content Security Policy Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            },
            {
                "label": "MDN: Content-Security-Policy",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            },
        ],
    },
}
