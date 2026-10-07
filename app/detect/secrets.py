"""
Group 1 (LLM provider credentials) and Group 2 (generic secrets) detector.

Detection pipeline per artifact:
  1. Skip third-party artifacts.
  2. Run all Group 1+2 regex patterns on raw bytes via finditer.
  3. Redact each raw match immediately; build Evidence and Finding.
  4. Perform structural checks (ENV file, source map).
  5. Deduplicate: (rule_id, redacted_value) for regex findings;
     (rule_id, artifact.url) for structural findings.
"""

from __future__ import annotations

import re
import uuid

from app.detect.redact import redact
from app.detect.rules import RULES
from app.models import Confidence, Evidence, Finding, Reference, Severity
from app.net.crawler import Artifact, ArtifactKind

# Artifact URL prefixes that indicate synthetic/inline content.
# For these, use artifact.source_url as the evidence location.
_INLINE_URL_PREFIXES: tuple[str, ...] = (
    "inline:",
    "inline_meta:",
    "source_map_content:",
)

# Strings inside a matched value that indicate a placeholder / test credential.
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "FAKE",
    "fake",
    "TEST",
    "test",
    "0000",
    "1111",
    "REPLACE",
    "replace",
    "example",
    "xxx",
    "dummy",
    "your-api-key",
    "placeholder",
)


def _is_placeholder(value: str) -> bool:
    """Return True if *value* looks like a placeholder rather than a real secret."""
    return any(marker in value for marker in _PLACEHOLDER_MARKERS)


def _evidence_location(artifact: Artifact) -> str:
    """Return the evidence location URL for *artifact*.

    Inline/synthetic artifacts use source_url; real fetched URLs use url.
    """
    if any(artifact.url.startswith(p) for p in _INLINE_URL_PREFIXES):
        return artifact.source_url
    return artifact.url


def _build_finding(
    *,
    rule_id: str,
    rule: dict,
    evidence: Evidence,
    confidence: Confidence,
) -> Finding:
    """Construct a Finding from rule metadata and pre-built Evidence."""
    return Finding(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        title=rule["title"],
        severity=Severity(rule["severity"]),
        confidence=confidence,
        category=rule["category"],
        evidence=evidence,
        why_it_matters=rule["why_it_matters"],
        attacks=[],
        remediation=rule["remediation"],
        references=[Reference(label=r["label"], url=r["url"]) for r in rule["references"]],
    )


def detect_secrets(artifacts: list[Artifact]) -> list[Finding]:
    """Scan *artifacts* for Group 1 and Group 2 findings.

    Returns a deduplicated list of Finding objects. Raw secrets never appear
    in any returned object — redact() is called before Evidence is constructed.
    """
    # Compile all Group 1+2 patterns at call time (rules are data, not objects).
    compiled: list[tuple[str, re.Pattern[bytes], dict]] = []
    for rule_id, rule in RULES.items():
        if rule["group"] not in (1, 2):
            continue
        pat = rule.get("pattern")
        if pat is None:
            continue
        compiled.append((rule_id, re.compile(pat.encode("utf-8")), rule))

    findings: list[Finding] = []
    # Dedup sets: regex findings by (rule_id, redacted_value);
    # structural findings by (rule_id, artifact_url).
    seen_regex: set[tuple[str, str]] = set()
    seen_structural: set[tuple[str, str]] = set()

    for artifact in artifacts:
        if artifact.is_third_party:
            continue

        content = artifact.content
        location = _evidence_location(artifact)

        # ── Regex-based secret detection ──────────────────────────────────────
        for rule_id, pattern, rule in compiled:
            for m in pattern.finditer(content):
                raw_match = m.group(0).decode("utf-8", errors="replace")
                redacted_value = redact(raw_match)

                dedup_key = (rule_id, redacted_value)
                if dedup_key in seen_regex:
                    continue
                seen_regex.add(dedup_key)

                # Determine confidence: placeholder keys stay Critical but get low confidence.
                confidence = (
                    Confidence.low if _is_placeholder(raw_match) else Confidence.high
                )

                # Build context snippet (≤80 chars) with the raw value already redacted.
                start, end = m.start(), m.end()
                ctx_start = max(0, start - 20)
                ctx_end = min(len(content), end + 20)
                ctx_raw = content[ctx_start:ctx_end].decode("utf-8", errors="replace")
                ctx = ctx_raw.replace(raw_match, redacted_value)
                if len(ctx) > 80:
                    ctx = ctx[:77] + "..."

                line = content[: m.start()].count(b"\n") + 1

                evidence = Evidence(
                    location=location,
                    line=line,
                    redacted_value=redacted_value,
                    context=ctx,
                )
                findings.append(
                    _build_finding(
                        rule_id=rule_id,
                        rule=rule,
                        evidence=evidence,
                        confidence=confidence,
                    )
                )

        # ── Structural checks ─────────────────────────────────────────────────
        if artifact.kind == ArtifactKind.ENV:
            struct_key = ("env_file_publicly_accessible", artifact.url)
            if struct_key not in seen_structural:
                seen_structural.add(struct_key)
                rule = RULES["env_file_publicly_accessible"]
                findings.append(
                    _build_finding(
                        rule_id="env_file_publicly_accessible",
                        rule=rule,
                        evidence=Evidence(location=location, line=None, redacted_value=None),
                        confidence=Confidence(rule["confidence"]),
                    )
                )

        if artifact.kind == ArtifactKind.SOURCE_MAP:
            struct_key = ("source_map_in_production", artifact.url)
            if struct_key not in seen_structural:
                seen_structural.add(struct_key)
                rule = RULES["source_map_in_production"]
                findings.append(
                    _build_finding(
                        rule_id="source_map_in_production",
                        rule=rule,
                        evidence=Evidence(location=location, line=None, redacted_value=None),
                        confidence=Confidence(rule["confidence"]),
                    )
                )

    return findings
