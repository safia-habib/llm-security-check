"""Phase 7 API integration tests."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app import store as scan_store
from app.main import _rate_limits
from app.models import (
    Confidence,
    Evidence,
    Finding,
    ScanReport,
    ScanStatus,
    ScanSummary,
    Severity,
    SeverityCounts,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_state() -> None:
    """Clear scan store and rate-limit history before each test."""
    scan_store.clear_all()
    _rate_limits.clear()


def _valid_payload(**kwargs) -> dict:
    base = {"target_url": "https://example.com", "owns_target": True}
    base.update(kwargs)
    return base


def _dummy_finding() -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        rule_id="exposed_key_openai",
        title="Test finding",
        severity=Severity.critical,
        confidence=Confidence.high,
        category="exposed_credential",
        evidence=Evidence(location="https://example.com/app.js", redacted_value="sk-…1234"),
        why_it_matters="Test.",
        attacks=[],
        remediation=["Rotate the key."],
        references=[],
    )


def _complete_report(scan_id: str) -> ScanReport:
    return ScanReport(
        scan_id=scan_id,
        status=ScanStatus.complete,
        target_url="https://example.com",
        started_at="2026-09-29T12:00:00Z",
        duration_seconds=3.5,
        summary=ScanSummary(
            score=70,
            grade="F",
            headline="Critical issue: Test finding (1 finding total: 1 critical).",
            counts=SeverityCounts(critical=1),
        ),
        findings=[_dummy_finding()],
        pages_crawled=2,
        assets_scanned=5,
    )


# ---------------------------------------------------------------------------
# POST /api/scan
# ---------------------------------------------------------------------------


def test_start_scan_returns_202(client: TestClient) -> None:
    resp = client.post("/api/scan", json=_valid_payload())
    assert resp.status_code == 202
    body = resp.json()
    assert "scan_id" in body
    assert body["status"] == "queued"


def test_start_scan_missing_attestation_rejected(client: TestClient) -> None:
    resp = client.post("/api/scan", json={"target_url": "https://example.com"})
    assert resp.status_code == 422


def test_start_scan_false_attestation_rejected(client: TestClient) -> None:
    resp = client.post(
        "/api/scan",
        json={"target_url": "https://example.com", "owns_target": False},
    )
    assert resp.status_code == 422


def test_start_scan_stores_entry(client: TestClient) -> None:
    resp = client.post("/api/scan", json=_valid_payload())
    scan_id = resp.json()["scan_id"]
    entry = scan_store.get(scan_id)
    assert entry is not None
    assert entry.scan_id == scan_id


def test_start_scan_invalid_json_returns_400(client: TestClient) -> None:
    resp = client.post(
        "/api/scan",
        content=b"not-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def test_rate_limit_fifth_scan_allowed(client: TestClient) -> None:
    """Exactly at the limit (5 of 5) should still be accepted."""
    ip = "192.0.2.1"
    headers = {"X-Forwarded-For": ip}
    for _ in range(5):
        resp = client.post("/api/scan", json=_valid_payload(), headers=headers)
        assert resp.status_code == 202


def test_rate_limit_sixth_scan_rejected(client: TestClient) -> None:
    """6th scan from the same IP within an hour must be rejected with 429."""
    ip = "192.0.2.2"
    headers = {"X-Forwarded-For": ip}
    for _ in range(5):
        client.post("/api/scan", json=_valid_payload(), headers=headers)
    resp = client.post("/api/scan", json=_valid_payload(), headers=headers)
    assert resp.status_code == 429
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["reason"] == "rate_limited"


def test_rate_limit_different_ips_independent(client: TestClient) -> None:
    """Rate limit is per-IP; different IPs don't share quota."""
    for i in range(5):
        resp = client.post(
            "/api/scan",
            json=_valid_payload(),
            headers={"X-Forwarded-For": f"192.0.2.{i + 10}"},
        )
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}
# ---------------------------------------------------------------------------


def test_get_scan_not_found(client: TestClient) -> None:
    resp = client.get("/api/scan/does-not-exist")
    assert resp.status_code == 404


def test_get_scan_returns_status_queued(client: TestClient) -> None:
    start = client.post("/api/scan", json=_valid_payload())
    scan_id = start.json()["scan_id"]
    resp = client.get(f"/api/scan/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["status"] in ("queued", "running", "complete", "failed")


def test_get_scan_complete_returns_full_report(client: TestClient) -> None:
    """When a report is present in the store it is returned verbatim."""
    scan_id = str(uuid.uuid4())
    entry = scan_store.create(scan_id)
    entry.status = ScanStatus.complete
    entry.report = _complete_report(scan_id)

    resp = client.get(f"/api/scan/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "complete"
    assert body["summary"]["grade"] == "F"
    assert len(body["findings"]) == 1


# ---------------------------------------------------------------------------
# DELETE /api/scan/{scan_id}
# ---------------------------------------------------------------------------


def test_delete_scan_returns_204(client: TestClient) -> None:
    start = client.post("/api/scan", json=_valid_payload())
    scan_id = start.json()["scan_id"]
    resp = client.delete(f"/api/scan/{scan_id}")
    assert resp.status_code == 204


def test_delete_scan_removes_from_store(client: TestClient) -> None:
    start = client.post("/api/scan", json=_valid_payload())
    scan_id = start.json()["scan_id"]
    client.delete(f"/api/scan/{scan_id}")
    assert scan_store.get(scan_id) is None


def test_delete_scan_not_found(client: TestClient) -> None:
    resp = client.delete("/api/scan/does-not-exist")
    assert resp.status_code == 404


def test_delete_scan_then_get_returns_404(client: TestClient) -> None:
    start = client.post("/api/scan", json=_valid_payload())
    scan_id = start.json()["scan_id"]
    client.delete(f"/api/scan/{scan_id}")
    resp = client.get(f"/api/scan/{scan_id}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/scan/{scan_id}/report.md
# ---------------------------------------------------------------------------


def test_report_md_not_found(client: TestClient) -> None:
    resp = client.get("/api/scan/does-not-exist/report.md")
    assert resp.status_code == 404


def test_report_md_not_ready_returns_202(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    scan_store.create(scan_id)  # status=queued, report=None
    resp = client.get(f"/api/scan/{scan_id}/report.md")
    assert resp.status_code == 202


def test_report_md_complete_returns_markdown(client: TestClient) -> None:
    scan_id = str(uuid.uuid4())
    entry = scan_store.create(scan_id)
    entry.status = ScanStatus.complete
    entry.report = _complete_report(scan_id)

    resp = client.get(f"/api/scan/{scan_id}/report.md")
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "# LLM Security Check Report" in resp.text
    assert "Grade: F" in resp.text


# ---------------------------------------------------------------------------
# GET /api/rules
# ---------------------------------------------------------------------------


def test_list_rules_returns_200(client: TestClient) -> None:
    resp = client.get("/api/rules")
    assert resp.status_code == 200


def test_list_rules_has_rules_key(client: TestClient) -> None:
    body = client.get("/api/rules").json()
    assert "rules" in body
    assert isinstance(body["rules"], list)
    assert len(body["rules"]) > 0


def test_list_rules_entries_have_required_fields(client: TestClient) -> None:
    body = client.get("/api/rules").json()
    for rule in body["rules"]:
        assert "id" in rule
        assert "title" in rule
        assert "severity" in rule
        assert "category" in rule


def test_list_rules_includes_openai_rule(client: TestClient) -> None:
    body = client.get("/api/rules").json()
    ids = {r["id"] for r in body["rules"]}
    assert "exposed_key_openai" in ids


def test_list_rules_total_matches_count(client: TestClient) -> None:
    body = client.get("/api/rules").json()
    assert body["total"] == len(body["rules"])


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


def test_health_still_works(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# URL validation (Phase 10)
# ---------------------------------------------------------------------------


def test_invalid_scheme_ftp_rejected(client: TestClient) -> None:
    """ftp:// scheme must be rejected with 422."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "ftp://example.com", "owns_target": True},
    )
    assert resp.status_code == 422


def test_invalid_scheme_file_rejected(client: TestClient) -> None:
    """file:// scheme must be rejected with 422."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "file:///etc/passwd", "owns_target": True},
    )
    assert resp.status_code == 422


def test_no_scheme_rejected(client: TestClient) -> None:
    """URL without scheme must be rejected with 422."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "example.com", "owns_target": True},
    )
    assert resp.status_code == 422


def test_empty_url_rejected(client: TestClient) -> None:
    """Empty target_url must be rejected with 422."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "", "owns_target": True},
    )
    assert resp.status_code == 422


def test_http_url_accepted(client: TestClient) -> None:
    """http:// is a valid scheme."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "http://example.com", "owns_target": True},
    )
    assert resp.status_code == 202


def test_https_url_accepted(client: TestClient) -> None:
    """https:// is a valid scheme."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "https://example.com", "owns_target": True},
    )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# Security headers (Phase 10)
# ---------------------------------------------------------------------------


def test_security_headers_on_health(client: TestClient) -> None:
    """Security headers must be present on every response."""
    resp = client.get("/api/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "content-security-policy" in resp.headers


def test_security_headers_on_scan_post(client: TestClient) -> None:
    """Security headers must be injected on POST /api/scan responses too."""
    resp = client.post("/api/scan", json=_valid_payload())
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"


def test_security_headers_on_rules(client: TestClient) -> None:
    resp = client.get("/api/rules")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src" in csp
    assert "frame-ancestors" in csp
