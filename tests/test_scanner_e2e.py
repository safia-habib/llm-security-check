"""End-to-end scanner tests against local fixture servers.

Each test spins a full run_scan() pipeline against the vulnerable_app and
clean_app fixture servers (served by conftest.py).  The `allow_private_targets`
fixture enables safe_fetch to reach 127.0.0.1 fixture servers.
"""

from __future__ import annotations

import pytest

from app import store as scan_store
from app.scanner import run_scan
from app.store import ScanEntry

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _run(base_url: str, include_third_party: bool = False) -> ScanEntry:
    scan_id = "test-e2e"
    # Clear any previous entry with this id.
    scan_store.delete(scan_id)
    entry = scan_store.create(scan_id)
    await run_scan(entry, base_url, include_third_party)
    return entry


# ---------------------------------------------------------------------------
# Vulnerable-app acceptance criteria
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vulnerable_finds_openai_key(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    assert entry.status.value == "complete"
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "exposed_key_openai" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_anthropic_key(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "exposed_key_anthropic" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_direct_provider_call(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "direct_provider_api_call" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_system_prompt(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "system_prompt_in_frontend" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_env_file(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "env_file_publicly_accessible" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_source_map(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "source_map_in_production" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_finds_cors_wildcard(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    rule_ids = {f.rule_id for f in entry.report.findings}
    assert "permissive_cors_wildcard" in rule_ids, f"rule_ids={rule_ids}"


@pytest.mark.asyncio
async def test_vulnerable_grade_is_f(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    assert entry.report.summary is not None
    assert entry.report.summary.grade == "F"


@pytest.mark.asyncio
async def test_vulnerable_findings_have_attacks_populated(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    # At least the critical findings should have attack entries
    critical = [f for f in entry.report.findings if f.severity.value == "critical"]
    assert critical, "Expected at least one critical finding"
    for f in critical:
        assert f.attacks, f"Finding {f.rule_id!r} has no attacks populated"


@pytest.mark.asyncio
async def test_vulnerable_not_checked_populated(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(vulnerable_server)
    assert entry.report.not_checked, "not_checked list must not be empty"


@pytest.mark.asyncio
async def test_vulnerable_no_raw_secret_in_api_response(
    vulnerable_server: str,
    allow_private_targets: None,
) -> None:
    """No full key string may appear in the serialised report JSON."""
    entry = await _run(vulnerable_server)
    report_json = entry.report.model_dump_json()

    raw_keys = [
        "sk-FAKE00000000000000000000000000000000000000000FAKE",
        "sk-ant-api03-FAKE0000000000000000000000000000000000000000000000000000000000000000FAKE",
        "AIzaFAKE000000000000000000000000FAKE000",
        "gsk_FAKE0000000000000000000000000000000000000000000000000000FAKE",
        "AKIAFAKEACCESSKEYID0",
    ]
    for raw in raw_keys:
        assert raw not in report_json, (
            f"Raw key {raw[:20]}… found in serialised report — redaction failed"
        )


# ---------------------------------------------------------------------------
# Clean-app negative tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_no_critical_findings(
    clean_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(clean_server)
    assert entry.status.value == "complete"
    critical = [f for f in entry.report.findings if f.severity.value == "critical"]
    assert not critical, f"Unexpected critical findings on clean app: {[f.rule_id for f in critical]}"


@pytest.mark.asyncio
async def test_clean_no_high_findings(
    clean_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(clean_server)
    high = [f for f in entry.report.findings if f.severity.value == "high"]
    assert not high, f"Unexpected high findings on clean app: {[f.rule_id for f in high]}"


@pytest.mark.asyncio
async def test_clean_not_checked_populated(
    clean_server: str,
    allow_private_targets: None,
) -> None:
    entry = await _run(clean_server)
    assert entry.report.not_checked, "not_checked must be populated even on clean scans"
