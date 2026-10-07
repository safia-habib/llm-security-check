"""Tests for app/report.py — scoring, grading, headline, enrichment, Markdown renderer."""

from __future__ import annotations

import uuid

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
from app.report import (
    _count_by_severity,
    enrich_with_attacks,
    grade,
    headline,
    render_markdown,
    score,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str = "exposed_key_openai",
    severity: Severity = Severity.critical,
    confidence: Confidence = Confidence.high,
    title: str = "Test finding",
    location: str = "https://example.com/app.js",
    redacted_value: str | None = "sk-…1234",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        category="exposed_credential",
        evidence=Evidence(
            location=location,
            line=42,
            redacted_value=redacted_value,
            context='const key = "sk-…1234"',
        ),
        why_it_matters="Exposed key enables abuse.",
        attacks=[],
        remediation=["Rotate the key.", "Move it server-side."],
        references=[],
    )


def _report(findings: list[Finding] | None = None, **kwargs) -> ScanReport:
    f = findings or []
    counts = SeverityCounts(
        critical=sum(1 for x in f if x.severity == Severity.critical),
        high=sum(1 for x in f if x.severity == Severity.high),
        medium=sum(1 for x in f if x.severity == Severity.medium),
        low=sum(1 for x in f if x.severity == Severity.low),
        info=sum(1 for x in f if x.severity == Severity.info),
    )
    summary = ScanSummary(
        score=score(f),
        grade=grade(f),
        headline=headline(f),
        counts=counts,
    )
    return ScanReport(
        scan_id=str(uuid.uuid4()),
        status=ScanStatus.complete,
        target_url="https://example.com",
        started_at="2026-09-29T12:00:00Z",
        duration_seconds=5.0,
        summary=summary,
        findings=f,
        pages_crawled=3,
        assets_scanned=7,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


def test_score_no_findings():
    assert score([]) == 100


def test_score_single_critical():
    assert score([_finding(severity=Severity.critical)]) == 70


def test_score_single_high():
    assert score([_finding(severity=Severity.high)]) == 85


def test_score_single_medium():
    assert score([_finding(severity=Severity.medium)]) == 95


def test_score_single_low():
    assert score([_finding(severity=Severity.low)]) == 98


def test_score_floors_at_zero():
    # 4 criticals = 120 deducted; must floor at 0
    findings = [_finding(severity=Severity.critical) for _ in range(4)]
    assert score(findings) == 0


def test_score_mixed():
    findings = [
        _finding(severity=Severity.critical),   # -30
        _finding(severity=Severity.high),        # -15
        _finding(severity=Severity.medium),      # -5
    ]
    assert score(findings) == 50


# ---------------------------------------------------------------------------
# grade()
# ---------------------------------------------------------------------------


def test_grade_no_findings():
    assert grade([]) == "A"


def test_grade_critical_always_f():
    f = _finding(severity=Severity.critical)
    assert grade([f]) == "F"


def test_grade_critical_even_with_high_score():
    # One critical makes it F even if hypothetically the score would be B-range.
    f = _finding(severity=Severity.critical)
    assert grade([f]) == "F"


def test_grade_b_range():
    # 1 high = score 85 → B
    assert grade([_finding(severity=Severity.high)]) == "B"


def test_grade_c_range():
    # 3 highs = 100 - 45 = 55 → D (not C)
    # 2 highs = 100 - 30 = 70 → C
    assert grade([_finding(severity=Severity.high), _finding(severity=Severity.high)]) == "C"


def test_grade_d_range():
    # 3 highs = 100 - 45 = 55 → D
    findings = [_finding(severity=Severity.high) for _ in range(3)]
    assert grade(findings) == "D"


def test_grade_f_no_critical():
    # 4 highs = 100 - 60 = 40 → F (no critical)
    findings = [_finding(severity=Severity.high) for _ in range(4)]
    assert grade(findings) == "F"


# ---------------------------------------------------------------------------
# headline()
# ---------------------------------------------------------------------------


def test_headline_no_findings():
    assert headline([]) == "No security issues were detected."


def test_headline_names_worst_finding():
    f = _finding(severity=Severity.critical, title="Anthropic key in client JS")
    result = headline([f])
    assert "Anthropic key in client JS" in result
    assert "Critical" in result


def test_headline_names_most_severe_when_mixed():
    findings = [
        _finding(severity=Severity.high, title="CORS wildcard"),
        _finding(severity=Severity.critical, title="OpenAI key exposed"),
        _finding(severity=Severity.medium, title="Missing CSP"),
    ]
    result = headline(findings)
    assert "OpenAI key exposed" in result


def test_headline_includes_total_count():
    findings = [_finding(severity=Severity.high) for _ in range(3)]
    result = headline(findings)
    assert "3 findings" in result


def test_headline_single_finding_singular():
    f = _finding(severity=Severity.high, title="CORS wildcard")
    result = headline([f])
    assert "1 finding" in result
    assert "findings" not in result.replace("1 finding", "")


# ---------------------------------------------------------------------------
# enrich_with_attacks()
# ---------------------------------------------------------------------------


def test_enrich_populates_attack_entries():
    f = _finding(rule_id="exposed_key_openai", location="https://example.com/app.js")
    enriched = enrich_with_attacks([f])
    assert len(enriched) == 1
    assert len(enriched[0].attacks) > 0


def test_enrich_formats_provider_name():
    f = _finding(rule_id="exposed_key_anthropic", location="https://example.com/app.js")
    enriched = enrich_with_attacks([f])
    # Every how_it_applies_here for this rule should mention Anthropic
    for attack in enriched[0].attacks:
        assert "Anthropic" in attack.how_it_applies_here


def test_enrich_formats_location():
    loc = "https://example.com/static/index.js"
    f = _finding(rule_id="exposed_key_openai", location=loc)
    enriched = enrich_with_attacks([f])
    for attack in enriched[0].attacks:
        assert loc in attack.how_it_applies_here


def test_enrich_unknown_rule_returns_no_attacks():
    f = _finding(rule_id="nonexistent_rule_id")
    enriched = enrich_with_attacks([f])
    assert enriched[0].attacks == []


def test_enrich_does_not_mutate_original():
    f = _finding(rule_id="exposed_key_openai")
    original_attacks = list(f.attacks)
    enrich_with_attacks([f])
    assert f.attacks == original_attacks


def test_enrich_attack_has_all_fields():
    f = _finding(rule_id="exposed_key_openai")
    enriched = enrich_with_attacks([f])
    for attack in enriched[0].attacks:
        assert attack.id
        assert attack.name
        assert attack.what_it_is
        assert attack.how_it_applies_here
        assert attack.impact


# ---------------------------------------------------------------------------
# render_markdown()
# ---------------------------------------------------------------------------


def test_markdown_contains_target_url():
    report = _report()
    md = render_markdown(report)
    assert "https://example.com" in md


def test_markdown_contains_grade_and_score():
    findings = [_finding(severity=Severity.critical)]
    report = _report(findings=findings)
    md = render_markdown(report)
    assert "Grade: F" in md
    assert "/100" in md


def test_markdown_all_four_blocks_present():
    """Every finding must render: evidence, why it matters, attacks, remediation."""
    f = _finding(rule_id="exposed_key_openai")
    enriched = enrich_with_attacks([f])
    report = _report(findings=enriched)
    md = render_markdown(report)
    assert "**Why it matters:**" in md
    assert "**Attack scenarios:**" in md
    assert "**Remediation:**" in md
    assert "**Location:**" in md


def test_markdown_finding_title_present():
    f = _finding(title="My special finding title")
    report = _report(findings=[f])
    md = render_markdown(report)
    assert "My special finding title" in md


def test_markdown_redacted_value_present():
    f = _finding(redacted_value="sk-…abcd")
    report = _report(findings=[f])
    md = render_markdown(report)
    assert "sk-…abcd" in md


def test_markdown_remediation_steps_present():
    f = _finding()
    report = _report(findings=[f])
    md = render_markdown(report)
    assert "Rotate the key." in md
    assert "Move it server-side." in md


def test_markdown_not_checked_section_present():
    report = _report()
    md = render_markdown(report)
    assert "What we could not check" in md
    assert "never calls provider APIs" in md


def test_markdown_no_findings_clean_message():
    report = _report(findings=[])
    md = render_markdown(report)
    assert "No findings" in md or "No security issues" in md


def test_markdown_footer_disclaimer():
    report = _report()
    md = render_markdown(report)
    assert "never validates discovered credentials" in md


def test_markdown_no_raw_secret_when_enriched():
    """Raw key must never appear in rendered Markdown — only the redacted form."""
    raw = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcd"
    f = _finding(redacted_value="sk-ant-api03-…abcd")
    report = _report(findings=[f])
    md = render_markdown(report)
    assert raw not in md


# ---------------------------------------------------------------------------
# _count_by_severity()  (internal helper)
# ---------------------------------------------------------------------------


def test_count_by_severity_empty():
    counts = _count_by_severity([])
    assert all(v == 0 for v in counts.values())


def test_count_by_severity_mixed():
    findings = [
        _finding(severity=Severity.critical),
        _finding(severity=Severity.critical),
        _finding(severity=Severity.high),
        _finding(severity=Severity.info),
    ]
    counts = _count_by_severity(findings)
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 0
    assert counts["low"] == 0
    assert counts["info"] == 1
