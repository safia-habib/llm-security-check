"""
HTTP response header detector.

Thin wrapper around architecture.detect_architecture that performs only the
header-based checks (CORS wildcard and missing CSP). The scanner orchestrator
(Phase 7) can call this independently from the code-pattern scanner.
"""

from __future__ import annotations

from app.detect.architecture import detect_architecture
from app.models import Finding


def detect_headers(response_headers: dict[str, dict[str, str]]) -> list[Finding]:
    """Check response headers for security misconfigurations.

    Checks performed:
    - Access-Control-Allow-Origin: * (CORS wildcard)
    - Missing Content-Security-Policy on HTML pages

    Args:
        response_headers: Mapping of URL → response header dict (lowercase keys).

    Returns:
        A list of Finding objects for each misconfiguration detected.
    """
    # Delegate to detect_architecture with an empty artifacts list so only the
    # header checks run (no code-pattern scanning is performed).
    return detect_architecture([], response_headers)
