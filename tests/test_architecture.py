"""
Tests for app.detect.architecture.detect_architecture and
app.detect.headers.detect_headers — Group 3 antipattern detector.
"""

from __future__ import annotations

from app.detect.architecture import detect_architecture
from app.detect.headers import detect_headers
from app.net.crawler import Artifact, ArtifactKind

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _art(
    content: str,
    kind: ArtifactKind = ArtifactKind.SCRIPT_EXTERNAL,
    url: str = "http://test.example.com/app.js",
    source_url: str = "http://test.example.com/",
) -> Artifact:
    return Artifact(
        url=url,
        source_url=source_url,
        kind=kind,
        content=content.encode("utf-8"),
    )


# ---------------------------------------------------------------------------
# Direct provider API call detection
# ---------------------------------------------------------------------------


def test_detects_direct_openai_call() -> None:
    snippet = 'fetch("https://api.openai.com/v1/chat/completions", { method: "POST" })'
    findings = detect_architecture([_art(snippet)], {})
    assert any(f.rule_id == "direct_provider_api_call" for f in findings)


def test_detects_direct_anthropic_call() -> None:
    snippet = 'const url = "https://api.anthropic.com/v1/messages";'
    findings = detect_architecture([_art(snippet)], {})
    assert any(f.rule_id == "direct_provider_api_call" for f in findings)


def test_detects_gemini_direct_call() -> None:
    snippet = 'const endpoint = "https://generativelanguage.googleapis.com/v1beta/models";'
    findings = detect_architecture([_art(snippet)], {})
    assert any(f.rule_id == "gemini_direct_api_call" for f in findings)


# ---------------------------------------------------------------------------
# System prompt and model parameter detection
# ---------------------------------------------------------------------------


def test_detects_system_prompt() -> None:
    snippet = 'const systemPrompt = "You are a helpful assistant.";'
    findings = detect_architecture([_art(snippet)], {})
    assert any(f.rule_id == "system_prompt_in_frontend" for f in findings)


def test_detects_model_params() -> None:
    snippet = "const opts = { temperature: 0.7, max_tokens: 1000 };"
    findings = detect_architecture([_art(snippet)], {})
    assert any(f.rule_id == "model_params_in_frontend" for f in findings)


# ---------------------------------------------------------------------------
# Negative tests (clean code should produce no findings)
# ---------------------------------------------------------------------------


def test_no_provider_call_in_clean_js() -> None:
    snippet = 'fetch("/api/chat", { method: "POST", body: JSON.stringify({ message }) })'
    findings = detect_architecture([_art(snippet)], {})
    provider_findings = [f for f in findings if f.rule_id == "direct_provider_api_call"]
    assert not provider_findings


def test_no_system_prompt_in_clean_js() -> None:
    snippet = "function sendMessage(text) { return fetch('/api/chat', { body: text }); }"
    findings = detect_architecture([_art(snippet)], {})
    prompt_findings = [f for f in findings if f.rule_id == "system_prompt_in_frontend"]
    assert not prompt_findings


# ---------------------------------------------------------------------------
# CORS wildcard detection
# ---------------------------------------------------------------------------


def test_detects_permissive_cors() -> None:
    headers = {"http://test.example.com/": {"access-control-allow-origin": "*"}}
    findings = detect_architecture([], headers)
    assert any(f.rule_id == "permissive_cors_wildcard" for f in findings)


def test_no_cors_finding_strict_origin() -> None:
    headers = {
        "http://test.example.com/": {
            "access-control-allow-origin": "https://trusted.example.com",
        }
    }
    findings = detect_architecture([], headers)
    cors_findings = [f for f in findings if f.rule_id == "permissive_cors_wildcard"]
    assert not cors_findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_deduplicates_provider_call_same_origin() -> None:
    # Two artifacts from the same origin, both referencing api.openai.com.
    snippet = 'const u = "https://api.openai.com/v1/chat/completions";'
    art1 = _art(snippet, url="http://test.example.com/a.js")
    art2 = _art(snippet, url="http://test.example.com/b.js")
    findings = detect_architecture([art1, art2], {})
    provider_findings = [f for f in findings if f.rule_id == "direct_provider_api_call"]
    assert len(provider_findings) == 1, (
        "Two artifacts from the same origin should produce only one finding per rule"
    )


# ---------------------------------------------------------------------------
# detect_headers wrapper
# ---------------------------------------------------------------------------


def test_detect_headers_cors_wildcard() -> None:
    headers = {"http://test.example.com/": {"access-control-allow-origin": "*"}}
    findings = detect_headers(headers)
    assert any(f.rule_id == "permissive_cors_wildcard" for f in findings)


def test_detect_headers_no_cors_finding_strict() -> None:
    headers = {
        "http://test.example.com/": {
            "access-control-allow-origin": "https://myapp.example.com",
        }
    }
    findings = detect_headers(headers)
    cors_findings = [f for f in findings if f.rule_id == "permissive_cors_wildcard"]
    assert not cors_findings
