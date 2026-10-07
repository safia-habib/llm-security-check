"""
Static attack knowledge base.

Each entry describes an attack class that LLM-specific security mistakes enable.
No LLM calls are made at runtime — this is authored text, not generated content.

Format of how_it_applies_here:
  A Python format string that accepts keyword arguments:
    {provider}  — the specific provider name (e.g. "OpenAI", "Anthropic")
    {location}  — the URL / file where the issue was found
"""

from __future__ import annotations

ATTACKS: dict[str, dict[str, str]] = {
    # ------------------------------------------------------------------
    "billing_drain": {
        "id": "billing_drain",
        "name": "API Quota Drain",
        "what_it_is": (
            "An attacker uses your exposed API key to make high-volume API calls, "
            "exhausting your usage quota and generating unexpected charges before the "
            "key is revoked. Automated scripts can send thousands of requests per minute, "
            "and many providers bill in real time with no hard spending cap by default."
        ),
        "how_it_applies_here": (
            "Your {provider} key is visible at {location}. "
            "Anyone who loads that page can copy the key and immediately run scripted "
            "requests at scale — typical quota drain attacks generate hundreds of dollars "
            "of charges within minutes of a key being discovered."
        ),
        "impact": (
            "Direct financial loss from unexpected API charges; service disruption when "
            "your quota is exhausted; potential account suspension if the provider "
            "detects unusual usage patterns."
        ),
    },
    # ------------------------------------------------------------------
    "unauthorized_access": {
        "id": "unauthorized_access",
        "name": "Unauthorised API Access",
        "what_it_is": (
            "With a valid API key, an attacker gains the same level of access to the "
            "provider's API as your application. This includes calling any model the key "
            "has permission to use, reading fine-tuned model metadata, and — for keys with "
            "admin scopes — managing other keys on the account."
        ),
        "how_it_applies_here": (
            "The {provider} key found at {location} can be used directly in API calls with "
            "no further authentication. An attacker simply substitutes it into their own "
            "requests and inherits your application's full API permissions."
        ),
        "impact": (
            "Unauthorised use of paid AI services; potential access to fine-tuned models, "
            "assistants, or files stored in the provider account; risk of the attacker "
            "impersonating your application's AI interactions."
        ),
    },
    # ------------------------------------------------------------------
    "prompt_injection": {
        "id": "prompt_injection",
        "name": "Prompt Injection",
        "what_it_is": (
            "When a system prompt or model configuration is visible in client-side code, "
            "users can craft inputs designed to override, leak, or subvert those "
            "instructions. Indirect prompt injection extends this to any content the model "
            "retrieves or processes, such as documents or web pages."
        ),
        "how_it_applies_here": (
            "The system prompt or instructions exposed at {location} tell an attacker "
            "exactly what constraints have been applied to the {provider} model. "
            "That knowledge makes it far easier to craft inputs that cause the model "
            "to ignore its instructions, reveal sensitive context, or behave maliciously."
        ),
        "impact": (
            "Model jailbreaking; exfiltration of confidential business logic embedded in "
            "the system prompt; manipulation of AI output to harm users or third parties; "
            "social engineering attacks targeting users who trust the AI's responses."
        ),
    },
    # ------------------------------------------------------------------
    "data_exfiltration": {
        "id": "data_exfiltration",
        "name": "Data Exfiltration via Exposed Credentials",
        "what_it_is": (
            "Credentials found in exposed configuration files often have access to more "
            "than just the LLM API. Database URLs, cloud credentials, and storage keys "
            "co-located with AI keys in .env files or source maps give attackers a path "
            "to your application's stored data."
        ),
        "how_it_applies_here": (
            "The file at {location} contains credentials that may include {provider} "
            "secrets alongside other service credentials. An attacker who can read this "
            "file can attempt to use every credential it contains, not just the AI key."
        ),
        "impact": (
            "Breach of user data stored in databases or cloud storage; regulatory exposure "
            "under GDPR, CCPA, or HIPAA; reputational damage from a confirmed data breach."
        ),
    },
    # ------------------------------------------------------------------
    "model_theft": {
        "id": "model_theft",
        "name": "Intellectual Property Disclosure via Source Maps",
        "what_it_is": (
            "Production source maps reconstruct your application's original source code, "
            "including server-side files that were accidentally bundled before build. "
            "Attackers can use source map tooling to download and read proprietary business "
            "logic, prompt engineering, and security controls."
        ),
        "how_it_applies_here": (
            "The source map at {location} contains original source files for your "
            "{provider}-connected application. This may expose your system prompts, "
            "tool definitions, data-processing logic, and any secrets that were present "
            "in the source at build time."
        ),
        "impact": (
            "Disclosure of proprietary prompt engineering and AI configuration; "
            "exposure of business logic that should be server-side only; "
            "potential secrets embedded in pre-bundle source files."
        ),
    },
    # ------------------------------------------------------------------
    "cors_bypass": {
        "id": "cors_bypass",
        "name": "Cross-Origin Request Forgery via Permissive CORS",
        "what_it_is": (
            "When an API endpoint responds with Access-Control-Allow-Origin: *, any "
            "website on the internet can make credentialed requests to it from a visitor's "
            "browser. This bypasses the same-origin policy that normally isolates "
            "authenticated API calls from third-party pages."
        ),
        "how_it_applies_here": (
            "The {provider} API endpoint at {location} returns a wildcard CORS header. "
            "A malicious website can trick logged-in users into making requests to your "
            "API — including LLM queries — from the attacker's domain, without the user "
            "realising it."
        ),
        "impact": (
            "Cross-site request forgery against authenticated LLM API paths; "
            "exfiltration of user data through AI-mediated responses; "
            "quota exhaustion via forged user sessions."
        ),
    },
}
