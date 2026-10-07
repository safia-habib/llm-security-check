"""Phase 1 smoke test: /api/health returns expected shape."""

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "timestamp" in body
    assert "allow_private_targets" in body


def test_health_private_targets_default_false(client: TestClient) -> None:
    resp = client.get("/api/health")
    body = resp.json()
    assert body["allow_private_targets"] is False


def test_scan_without_attestation_rejected(client: TestClient) -> None:
    """Ownership attestation: owns_target=false must be refused with 422."""
    resp = client.post(
        "/api/scan",
        json={"target_url": "https://example.com", "owns_target": False},
    )
    assert resp.status_code == 422
