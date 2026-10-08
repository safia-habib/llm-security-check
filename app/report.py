"""
Scoring, grading, finding enrichment, and Markdown report renderer.

Public API
----------
enrich_with_attacks(findings, rules) -> list[Finding]
    Populate Finding.attacks from the knowledge base using rule attack_ids.

score(findings) -> int
    Return a 0–100 security score.

grade(findings) -> str
    Return a letter grade A–F.  A single Critical finding always yields F.

headline(findings) -> str
    One sentence naming the worst finding or confirming a clean scan.

render_markdown(report) -> str
    Full Markdown report ready to serve as report.md.
"""

from __future__ import annotations

from app.detect.rules import RULES
from app.knowledge.attacks import ATTACKS
from app.models import AttackEntry, Finding, ScanReport, Severity

# ---------------------------------------------------------------------------
# Severity weights for scoring
# ---------------------------------------------------------------------------

_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 2,
    "info": 0,
}

# Provider label inferred from rule_id — used to render how_it_applies_here.
_RULE_PROVIDER: dict[str, str] = {
    "exposed_key_openai": "OpenAI",
    "exposed_key_openai_proj": "OpenAI",
    "exposed_key_anthropic": "Anthropic",
    "exposed_key_gemini": "Google Gemini",
    "exposed_key_groq": "Groq",
    "exposed_key_aws_access_key": "AWS",
    "exposed_key_huggingface": "Hugging Face",
    "exposed_key_openrouter": "OpenRouter",
    "exposed_key_xai": "xAI (Grok)",
    "exposed_key_replicate": "Replicate",
    "exposed_key_perplexity": "Perplexity",
    "jwt_in_client_code": "JWT",
    "env_file_publicly_accessible": "the application",
    "source_map_in_production": "the application",
    "direct_provider_api_call": "the LLM provider",
    "gemini_direct_api_call": "Google Gemini",
    "system_prompt_in_frontend": "the LLM",
    "model_params_in_frontend": "the LLM",
    "permissive_cors_wildcard": "the API",
    "missing_csp_header": "the application",
}

# ---------------------------------------------------------------------------
# Finding enrichment
# ---------------------------------------------------------------------------


def enrich_with_attacks(
    findings: list[Finding], rules: dict[str, dict] | None = None
) -> list[Finding]:
    """Return copies of *findings* with the `attacks` field populated.

    For each finding, looks up `rules[rule_id]["attack_ids"]`, fetches each
    attack from the knowledge base, and formats `how_it_applies_here` with
    the specific provider name and evidence location.

    Args:
        findings: Raw findings from the detectors (attacks=[]).
        rules: The RULES dict; defaults to the imported RULES if None.
    """
    rule_registry = rules if rules is not None else RULES
    enriched: list[Finding] = []
    for finding in findings:
        rule = rule_registry.get(finding.rule_id, {})
        attack_ids: list[str] = rule.get("attack_ids", [])
        provider = _RULE_PROVIDER.get(finding.rule_id, "the provider")
        location = finding.evidence.location or "the exposed file"

        attack_entries: list[AttackEntry] = []
        for attack_id in attack_ids:
            attack = ATTACKS.get(attack_id)
            if attack is None:
                continue
            try:
                how = attack["how_it_applies_here"].format(
                    provider=provider, location=location
                )
            except (KeyError, IndexError):
                how = attack["how_it_applies_here"]
            attack_entries.append(
                AttackEntry(
                    id=attack["id"],
                    name=attack["name"],
                    what_it_is=attack["what_it_is"],
                    how_it_applies_here=how,
                    impact=attack["impact"],
                )
            )
        # Pydantic models are immutable; use model_copy to replace attacks field.
        enriched.append(finding.model_copy(update={"attacks": attack_entries}))
    return enriched


# ---------------------------------------------------------------------------
# Scoring and grading
# ---------------------------------------------------------------------------


def score(findings: list[Finding]) -> int:
    """Return a 0–100 security score (higher is better)."""
    deduction = sum(
        _SEVERITY_DEDUCTIONS.get(str(f.severity), 0) for f in findings
    )
    return max(0, 100 - deduction)


def grade(findings: list[Finding]) -> str:
    """Return a letter grade A–F.

    A single Critical finding always yields F regardless of the numeric score.
    """
    has_critical = any(f.severity == Severity.critical for f in findings)
    if has_critical:
        return "F"
    s = score(findings)
    if s >= 90:
        return "A"
    if s >= 75:
        return "B"
    if s >= 60:
        return "C"
    if s >= 45:
        return "D"
    return "F"


def headline(findings: list[Finding]) -> str:
    """Return one sentence naming the most severe finding, or a clean-scan message."""
    if not findings:
        return "No security issues were detected."
    # Sort by severity weight descending, then confidence descending
    _sev_order = {s: i for i, s in enumerate(
        ["critical", "high", "medium", "low", "info"]
    )}
    worst = min(findings, key=lambda f: _sev_order.get(str(f.severity), 99))
    counts = _count_by_severity(findings)
    severity_str = str(worst.severity).capitalize()
    total = len(findings)
    parts = [
        f"{v} {k}" for k, v in counts.items() if v
    ]
    summary = ", ".join(parts)
    return (
        f"{severity_str} issue: {worst.title} "
        f"({total} finding{'s' if total != 1 else ''} total: {summary})."
    )


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    order = ["critical", "high", "medium", "low", "info"]
    counts: dict[str, int] = {k: 0 for k in order}
    for f in findings:
        key = str(f.severity)
        if key in counts:
            counts[key] += 1
    return counts


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

_NOT_CHECKED: list[str] = [
    "Authentication and authorisation on discovered endpoints "
    "(would require sending credentials, which is outside this tool's scope).",
    "Rate limiting beyond what is visible in HTTP response headers.",
    "Dynamic content generated after JavaScript execution "
    "(this tool does not run JavaScript).",
    "Private or authenticated routes not reachable from the public internet.",
    "Backend-side code not exposed through source maps or configuration files.",
    "Runtime behaviour of discovered LLM integrations "
    "(this tool never sends prompts to any discovered endpoint).",
    "Whether discovered API keys are currently active "
    "(this tool never calls provider APIs to validate credentials).",
]


def render_markdown(report: ScanReport) -> str:
    """Render *report* as a Markdown string."""
    lines: list[str] = []
    _h = lines.append

    # Header
    _h("# LLM Security Check Report")
    _h("")
    _h(f"**Target:** {report.target_url}")
    _h(f"**Scan date:** {report.started_at}")
    if report.duration_seconds is not None:
        _h(f"**Duration:** {report.duration_seconds:.1f}s")
    _h(f"**Pages crawled:** {report.pages_crawled}  |  "
       f"**Assets scanned:** {report.assets_scanned}")
    _h("")

    # Grade + score
    if report.summary:
        g = report.summary.grade
        s = report.summary.score
        _h(f"## Grade: {g}  |  Score: {s}/100")
        _h("")
        _h(f"> {report.summary.headline}")
        _h("")

    # Severity summary bar
    if report.summary and report.findings:
        counts = _count_by_severity(report.findings)
        parts = [f"**{v} {k}**" for k, v in counts.items() if v]
        _h(f"Found {len(report.findings)} finding"
           f"{'s' if len(report.findings) != 1 else ''}: "
           + " · ".join(parts))
        _h("")

    _h("---")
    _h("")

    # Findings
    if report.findings:
        _h("## Findings")
        _h("")
        for finding in report.findings:
            _render_finding(finding, lines)
    else:
        _h("## Findings")
        _h("")
        _h("No findings. Great work — keep checking regularly as your app evolves.")
        _h("")

    # What we could not check
    _h("---")
    _h("")
    _h("## What we could not check")
    _h("")
    not_checked = report.not_checked if report.not_checked else _NOT_CHECKED
    for item in not_checked:
        _h(f"- {item}")
    _h("")

    # Footer
    _h("---")
    _h("")
    _h(
        "*Generated by [LLM Security Check](https://github.com/safia_habib/llm-security-check). "
        "This tool never validates discovered credentials against their providers and "
        "never sends prompts to any discovered endpoint.*"
    )

    return "\n".join(lines)


def _render_finding(finding: Finding, lines: list[str]) -> None:
    sev = str(finding.severity).upper()
    conf = str(finding.confidence).capitalize()
    lines.append(f"### [{sev}] {finding.title}")
    lines.append("")
    lines.append(
        f"**Confidence:** {conf}  |  **Category:** {finding.category}  |  "
        f"**Rule:** `{finding.rule_id}`"
    )
    lines.append("")

    # Evidence block
    ev = finding.evidence
    if ev.location:
        loc_str = ev.location
        if ev.line:
            loc_str += f" (line {ev.line})"
        lines.append(f"**Location:** {loc_str}")
    if ev.redacted_value:
        lines.append(f"**Detected value:** `{ev.redacted_value}`")
    if ev.context:
        lines.append("**Context:**")
        lines.append("```")
        lines.append(ev.context)
        lines.append("```")
    lines.append("")

    # Why it matters
    lines.append("**Why it matters:**")
    lines.append("")
    lines.append(finding.why_it_matters)
    lines.append("")

    # Attack scenarios
    if finding.attacks:
        lines.append("**Attack scenarios:**")
        lines.append("")
        for attack in finding.attacks:
            lines.append(f"#### {attack.name}")
            lines.append("")
            lines.append(attack.what_it_is)
            lines.append("")
            lines.append(f"*How it applies here:* {attack.how_it_applies_here}")
            lines.append("")
            lines.append(f"**Impact:** {attack.impact}")
            lines.append("")

    # Remediation
    lines.append("**Remediation:**")
    lines.append("")
    for i, step in enumerate(finding.remediation, 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    # References
    if finding.references:
        lines.append("**References:**")
        lines.append("")
        for ref in finding.references:
            lines.append(f"- [{ref.label}]({ref.url})")
        lines.append("")

    lines.append("---")
    lines.append("")
