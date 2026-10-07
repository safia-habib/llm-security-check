"""
Group 3 (LLM architecture antipatterns) detector.

Checks:
  - Code patterns in HTML, external scripts, inline scripts, and source map content
    (direct provider API calls, system prompt exposure, model parameter disclosure).
  - Response header checks: permissive CORS wildcard, missing CSP header.

Deduplication:
  - Code patterns: at most one finding per (rule_id, origin).
  - CORS: one finding per unique origin where the wildcard is present.
  - CSP: one finding per unique origin where the header is absent.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse

from app.detect.rules import RULES
from app.models import Confidence, Evidence, Finding, Reference, Severity
from app.net.crawler import Artifact, ArtifactKind

# Artifact kinds that are scanned for code patterns.
_SCANNABLE_KINDS: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.HTML,
        ArtifactKind.SCRIPT_EXTERNAL,
        ArtifactKind.SCRIPT_INLINE,
        ArtifactKind.SOURCE_MAP_CONTENT,
    }
)

# Artifact URL prefixes that indicate synthetic/inline content.
_INLINE_URL_PREFIXES: tuple[str, ...] = (
    "inline:",
    "inline_meta:",
    "source_map_content:",
)


def _url_origin(url: str) -> str:
    """Return scheme://hostname[:port] for *url*."""
    p = urlparse(url)
    port_part = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port_part}"


def _artifact_origin(artifact: Artifact) -> str:
    """Derive the origin from the artifact's source_url."""
    return _url_origin(artifact.source_url)


def _evidence_location(artifact: Artifact) -> str:
    """Return the evidence location URL for *artifact*.

    Synthetic/inline artifacts use source_url; fetched URLs use url.
    """
    if any(artifact.url.startswith(p) for p in _INLINE_URL_PREFIXES):
        return artifact.source_url
    return artifact.url


def _build_finding(
    *,
    rule_id: str,
    rule: dict,
    evidence: Evidence,
) -> Finding:
    """Construct a Finding from rule metadata and pre-built Evidence."""
    return Finding(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        title=rule["title"],
        severity=Severity(rule["severity"]),
        confidence=Confidence(rule["confidence"]),
        category=rule["category"],
        evidence=evidence,
        why_it_matters=rule["why_it_matters"],
        attacks=[],
        remediation=rule["remediation"],
        references=[Reference(label=r["label"], url=r["url"]) for r in rule["references"]],
    )


def detect_architecture(
    artifacts: list[Artifact],
    response_headers: dict[str, dict[str, str]],
) -> list[Finding]:
    """Detect Group 3 LLM architecture antipatterns.

    Args:
        artifacts: All artifacts collected by the crawler.
        response_headers: Mapping of URL → response header dict (lowercase keys).

    Returns:
        A deduplicated list of Finding objects.
    """
    findings: list[Finding] = []

    # ── Compile Group 3 code-pattern rules ────────────────────────────────────
    code_rules: list[tuple[str, re.Pattern[bytes], dict]] = []
    for rule_id, rule in RULES.items():
        if rule["group"] != 3:
            continue
        pat = rule.get("pattern")
        if pat is None:
            continue
        code_rules.append((rule_id, re.compile(pat.encode("utf-8")), rule))

    # Dedup: (rule_id, origin) — at most one finding per rule per origin.
    seen_code: set[tuple[str, str]] = set()

    # ── Scan artifacts for code patterns ─────────────────────────────────────
    for artifact in artifacts:
        if artifact.kind not in _SCANNABLE_KINDS:
            continue

        art_origin = _artifact_origin(artifact)
        location = _evidence_location(artifact)
        content = artifact.content

        for rule_id, pattern, rule in code_rules:
            dedup_key = (rule_id, art_origin)
            if dedup_key in seen_code:
                continue

            m = pattern.search(content)
            if m is None:
                continue

            seen_code.add(dedup_key)

            line = content[: m.start()].count(b"\n") + 1

            # Build context snippet (≤80 chars).
            start, end = m.start(), m.end()
            ctx_start = max(0, start - 20)
            ctx_end = min(len(content), end + 20)
            ctx = content[ctx_start:ctx_end].decode("utf-8", errors="replace")
            if len(ctx) > 80:
                ctx = ctx[:77] + "..."

            findings.append(
                _build_finding(
                    rule_id=rule_id,
                    rule=rule,
                    evidence=Evidence(
                        location=location,
                        line=line,
                        redacted_value=None,
                        context=ctx,
                    ),
                )
            )

    # ── CORS wildcard check ───────────────────────────────────────────────────
    cors_rule = RULES["permissive_cors_wildcard"]
    seen_cors_origins: set[str] = set()

    for url, headers in response_headers.items():
        acao = headers.get("access-control-allow-origin", "")
        if acao != "*":
            continue
        origin = _url_origin(url)
        if origin in seen_cors_origins:
            continue
        seen_cors_origins.add(origin)
        findings.append(
            _build_finding(
                rule_id="permissive_cors_wildcard",
                rule=cors_rule,
                evidence=Evidence(
                    location=url,
                    line=None,
                    redacted_value=None,
                    context="Access-Control-Allow-Origin: *",
                ),
            )
        )

    # ── Missing CSP check ─────────────────────────────────────────────────────
    csp_rule = RULES["missing_csp_header"]
    seen_csp_origins: set[str] = set()

    # Only check URLs that correspond to HTML pages.
    html_urls: set[str] = {art.url for art in artifacts if art.kind == ArtifactKind.HTML}

    for url, headers in response_headers.items():
        if url not in html_urls:
            continue
        origin = _url_origin(url)
        if origin in seen_csp_origins:
            continue
        if "content-security-policy" not in headers:
            seen_csp_origins.add(origin)
            findings.append(
                _build_finding(
                    rule_id="missing_csp_header",
                    rule=csp_rule,
                    evidence=Evidence(
                        location=url,
                        line=None,
                        redacted_value=None,
                        context="Content-Security-Policy header absent",
                    ),
                )
            )

    return findings
