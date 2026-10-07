"""
Secret redaction — called at detection time, before any Finding object is built.

Format: prefix…last4  (e.g. sk-ant-api03-…f2a9)

The known-prefix list is ordered longest-first so the most specific prefix wins.
"""

from __future__ import annotations

_KNOWN_PREFIXES: tuple[str, ...] = (
    "sk-ant-api03-",  # Anthropic (longest / most specific first)
    "sk-or-v1-",      # OpenRouter
    "sk-proj-",       # OpenAI project keys
    "sk-",            # OpenAI legacy
    "AIza",           # Google Gemini
    "gsk_",           # Groq
    "xai-",           # xAI
    "hf_",            # Hugging Face
    "r8_",            # Replicate
    "pplx-",          # Perplexity
    "AKIA",           # AWS IAM access key
    "ASIA",           # AWS STS session key
    "ls__",           # LangSmith
    "lsv2_",          # LangSmith v2
    "eyJ",            # JWT header
)


def redact(secret: str) -> str:
    """Return a redacted representation of *secret*.

    Keeps the provider-identifying prefix and the last 4 characters.
    Always returns a string safe to log and store.
    """
    if len(secret) <= 8:
        return "***"
    for prefix in _KNOWN_PREFIXES:
        if secret.startswith(prefix):
            return f"{prefix}…{secret[-4:]}"
    # Generic fallback: first 6 characters
    return f"{secret[:6]}…{secret[-4:]}"
