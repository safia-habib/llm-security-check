"""
Scan URL audit log.

A single rotating file records every scan target submitted and every URL
the crawler fetches.  The log is the authoritative record of what the
scanner touched on the network.

Usage
-----
Call ``setup_audit_log(path)`` once at startup (app lifespan).  Elsewhere
import and call the three log_* helpers — they are safe to call before
setup (messages are silently dropped if no file handler is configured).

Log format (one record per line)::

    2026-10-08 12:00:00 UTC SCAN_QUEUED  scan_id=… client_ip=… target=…
    2026-10-08 12:00:00 UTC FETCH        scan_id=… method=GET  url=… status=200
    2026-10-08 12:00:03 UTC SCAN_DONE    scan_id=… status=complete grade=F \
        findings=7 duration_s=3.21
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Per-task context: the scan_id of the currently-executing scan.
# Set by scanner.run_scan at the top of each task so all safe_fetch calls
# within that task can attach the right scan_id to their log entries.
# ---------------------------------------------------------------------------

current_scan_id: ContextVar[str] = ContextVar("current_scan_id", default="-")

# ---------------------------------------------------------------------------
# Dedicated audit logger — propagation disabled so entries never appear on
# stderr; they go only to the rotating file configured by setup_audit_log().
# ---------------------------------------------------------------------------

_audit = logging.getLogger("app.scan_audit")
_audit.propagate = False


def setup_audit_log(path: str) -> None:
    """Attach a rotating file handler to the audit logger.

    Safe to call more than once (duplicate handlers are avoided).
    10 MB per file, 5 backup files kept (~50 MB total maximum).
    """
    # Avoid adding a duplicate handler on hot-reload or repeated test setups.
    for h in _audit.handlers:
        if isinstance(h, RotatingFileHandler) and h.baseFilename.endswith(path):
            return

    handler = RotatingFileHandler(
        path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s UTC %(message)s"))
    _audit.addHandler(handler)
    _audit.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Log helpers
# ---------------------------------------------------------------------------


def log_scan_queued(scan_id: str, client_ip: str, target_url: str) -> None:
    """Record that a new scan was accepted and queued."""
    _audit.info(
        "SCAN_QUEUED  scan_id=%s client_ip=%s target=%s",
        scan_id,
        client_ip,
        target_url,
    )


def log_url_fetched(url: str, method: str, status_code: int) -> None:
    """Record a single outbound HTTP request made by the crawler."""
    _audit.info(
        "FETCH        scan_id=%s method=%-4s url=%s status=%s",
        current_scan_id.get(),
        method.upper(),
        url,
        status_code,
    )


def log_scan_done(
    scan_id: str,
    status: str,
    grade: str | None,
    findings: int,
    duration_s: float,
) -> None:
    """Record the final outcome of a scan."""
    _audit.info(
        "SCAN_DONE    scan_id=%s status=%s grade=%s findings=%d duration_s=%.2f",
        scan_id,
        status,
        grade or "-",
        findings,
        duration_s,
    )
