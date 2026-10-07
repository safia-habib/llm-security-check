"""
Tests for app.detect.redact and the key security property:
no raw secret may appear in any serialised Finding.
"""

from __future__ import annotations

import json

from app.detect.redact import redact
from app.detect.secrets import detect_secrets
from app.net.crawler import Artifact, ArtifactKind

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _art(content: str, url: str = "http://test.example.com/app.js") -> Artifact:
    return Artifact(
        url=url,
        source_url="http://test.example.com/",
        kind=ArtifactKind.SCRIPT_EXTERNAL,
        content=content.encode("utf-8"),
    )


# ---------------------------------------------------------------------------
# redact() unit tests
# ---------------------------------------------------------------------------


def test_redact_anthropic() -> None:
    raw = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopQRST"
    result = redact(raw)
    assert result.startswith("sk-ant-api03-")
    assert result.endswith(f"…{raw[-4:]}")
    assert raw not in result


def test_redact_openai() -> None:
    raw = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    result = redact(raw)
    assert result.startswith("sk-")
    assert result.endswith(f"…{raw[-4:]}")
    assert raw not in result


def test_redact_gemini() -> None:
    raw = "AIza" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"
    result = redact(raw)
    assert result.startswith("AIza")
    assert result.endswith(f"…{raw[-4:]}")
    assert raw not in result


def test_redact_groq() -> None:
    raw = "gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234"
    result = redact(raw)
    assert result.startswith("gsk_")
    assert result.endswith(f"…{raw[-4:]}")
    assert raw not in result


def test_redact_aws() -> None:
    raw = "AKIA" + "ABCDEFGHIJKLMNOP"
    result = redact(raw)
    assert result.startswith("AKIA")
    assert result.endswith(f"…{raw[-4:]}")
    assert raw not in result


def test_redact_short_string() -> None:
    assert redact("abc") == "***"
    assert redact("12345") == "***"


def test_redact_preserves_last4() -> None:
    raw = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    result = redact(raw)
    assert result.endswith(raw[-4:])


# ---------------------------------------------------------------------------
# Key security property: no raw secret in serialised Finding JSON
# ---------------------------------------------------------------------------


def test_raw_key_absent_from_finding_json() -> None:
    # 48 alphanumeric chars after "sk-" — matches exposed_key_openai pattern.
    raw_key = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    artifact = _art(f'const client = new OpenAI({{ apiKey: "{raw_key}" }});')

    findings = detect_secrets([artifact])

    assert len(findings) >= 1, "Expected at least one finding for the exposed key"

    serialised = json.dumps([f.model_dump() for f in findings])
    assert raw_key not in serialised, (
        "Raw API key must not appear anywhere in the serialised findings JSON"
    )
