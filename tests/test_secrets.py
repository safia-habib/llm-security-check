"""
Tests for app.detect.secrets.detect_secrets — Group 1 and Group 2 detector.
"""

from __future__ import annotations

from app.detect.secrets import detect_secrets
from app.models import Confidence, Severity
from app.net.crawler import Artifact, ArtifactKind

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _art(
    content: str,
    kind: ArtifactKind = ArtifactKind.SCRIPT_EXTERNAL,
    url: str = "http://test.example.com/app.js",
) -> Artifact:
    return Artifact(
        url=url,
        source_url="http://test.example.com/",
        kind=kind,
        content=content.encode("utf-8"),
    )


# ---------------------------------------------------------------------------
# Group 1 — Provider credential detection
# ---------------------------------------------------------------------------


def test_detects_openai_key() -> None:
    # 48 alphanumeric chars after "sk-" — matches exposed_key_openai.
    key = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    findings = detect_secrets([_art(f'apiKey: "{key}"')])
    assert any(f.rule_id == "exposed_key_openai" for f in findings)
    match = next(f for f in findings if f.rule_id == "exposed_key_openai")
    assert match.severity == Severity.critical


def test_detects_anthropic_key() -> None:
    # 70 alphanumeric chars after "sk-ant-api03-" — matches exposed_key_anthropic.
    key = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjK"
    findings = detect_secrets([_art(f'const key = "{key}";')])
    assert any(f.rule_id == "exposed_key_anthropic" for f in findings)


def test_detects_gemini_key() -> None:
    # AIza + 35 alphanumeric/dash/underscore chars (39 total).
    key = "AIza" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj"
    findings = detect_secrets([_art(f'const apiKey = "{key}";')])
    assert any(f.rule_id == "exposed_key_gemini" for f in findings)


def test_detects_aws_key() -> None:
    # AKIA + 16 uppercase/digit chars (20 total).
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    findings = detect_secrets([_art(f'accessKeyId: "{key}"')])
    assert any(f.rule_id == "exposed_key_aws_access_key" for f in findings)


def test_fixture_keys_low_confidence() -> None:
    # Key contains "FAKE" — should be detected but flagged as low confidence.
    key = "sk-FAKE00000000000000000000000000000000000000000FAKE"
    findings = detect_secrets([_art(f'apiKey: "{key}"')])
    # Finding must be present (severity stays critical for awareness).
    assert findings, "Expected a finding for a placeholder-format key"
    # All findings for this key should have low confidence.
    key_findings = [f for f in findings if f.evidence.redacted_value is not None]
    assert all(f.confidence == Confidence.low for f in key_findings)


# ---------------------------------------------------------------------------
# Group 2 — Generic secret detection
# ---------------------------------------------------------------------------


def test_env_artifact_fires_finding() -> None:
    art = _art("DB_PASSWORD=hunter2\nSECRET_KEY=abc123", kind=ArtifactKind.ENV)
    findings = detect_secrets([art])
    assert any(f.rule_id == "env_file_publicly_accessible" for f in findings)


def test_source_map_artifact_fires_finding() -> None:
    art = _art('{"version":3,"sources":["app.js"]}', kind=ArtifactKind.SOURCE_MAP)
    findings = detect_secrets([art])
    assert any(f.rule_id == "source_map_in_production" for f in findings)


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------


def test_no_findings_clean_js() -> None:
    content = 'fetch("/api/chat", { method: "POST", body: JSON.stringify({ message }) })'
    findings = detect_secrets([_art(content)])
    # No provider keys or secrets in this clean snippet.
    assert not findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_deduplicates_same_key_in_two_artifacts() -> None:
    key = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    art1 = _art(f'const k1 = "{key}";', url="http://test.example.com/a.js")
    art2 = _art(f'const k2 = "{key}";', url="http://test.example.com/b.js")
    findings = detect_secrets([art1, art2])
    openai_findings = [f for f in findings if f.rule_id == "exposed_key_openai"]
    assert len(openai_findings) == 1, (
        "The same redacted key value should not produce duplicate findings"
    )


# ---------------------------------------------------------------------------
# Third-party filtering
# ---------------------------------------------------------------------------


def test_third_party_artifact_skipped() -> None:
    key = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    art = Artifact(
        url="https://cdn.example.com/vendor.js",
        source_url="http://test.example.com/",
        kind=ArtifactKind.SCRIPT_EXTERNAL,
        content=f'apiKey="{key}"'.encode(),
        is_third_party=True,
    )
    findings = detect_secrets([art])
    assert not findings, "Third-party artifacts must be skipped by detect_secrets"


# ---------------------------------------------------------------------------
# Inline artifact location
# ---------------------------------------------------------------------------


def test_evidence_location_inline() -> None:
    key = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
    art = Artifact(
        url="inline:http://test.example.com/:0",
        source_url="http://test.example.com/",
        kind=ArtifactKind.SCRIPT_INLINE,
        content=f'apiKey="{key}"'.encode(),
    )
    findings = detect_secrets([art])
    assert findings, "Expected at least one finding for the inline artifact"
    # The evidence location must be the source_url, not the synthetic inline: URL.
    openai = next((f for f in findings if f.rule_id == "exposed_key_openai"), None)
    assert openai is not None
    assert openai.evidence.location == "http://test.example.com/"
