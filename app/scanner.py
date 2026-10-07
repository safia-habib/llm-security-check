"""
Scan orchestrator.

Pipeline: crawl → detect secrets → detect architecture → enrich → build report.

Progress is pushed to the ScanEntry's events list so the SSE endpoint can
stream it to connected clients.
"""

from __future__ import annotations

import asyncio
import datetime
import logging

from app import store as scan_store
from app.config import get_settings
from app.detect.architecture import detect_architecture
from app.detect.secrets import detect_secrets
from app.models import (
    Finding,
    ScanReport,
    ScanStatus,
    ScanSummary,
    Severity,
    SeverityCounts,
)
from app.net.crawler import crawl
from app.report import _NOT_CHECKED, enrich_with_attacks, grade, headline, score
from app.store import ScanEntry

logger = logging.getLogger(__name__)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _push(entry: ScanEntry, event_type: str, **data: object) -> None:
    scan_store.push_event(entry, {"type": event_type, **data})


async def run_scan(
    entry: ScanEntry,
    target_url: str,
    include_third_party: bool,
) -> None:
    """Execute the full scan pipeline and update *entry* in place."""
    settings = get_settings()
    started_at = _now()
    entry.status = ScanStatus.running
    _push(entry, "started", message=f"Scan started for {target_url}")

    try:
        # ------------------------------------------------------------------
        # Stage 1: Crawl
        # ------------------------------------------------------------------
        _push(entry, "stage", stage="crawling", message="Crawling target…")

        def _on_progress(stage: str, cur: int, total: int) -> None:
            _push(entry, "progress", stage=stage, message=f"{stage} {cur}/{total}")

        crawl_result = await asyncio.wait_for(
            crawl(
                target_url,
                include_third_party=include_third_party,
                on_progress=_on_progress,
            ),
            timeout=settings.scan_timeout_seconds,
        )

        _push(
            entry,
            "stage",
            stage="crawled",
            message=(
                f"Crawled {crawl_result.pages_crawled} page(s), "
                f"{crawl_result.assets_scanned} asset(s)"
            ),
        )

        # ------------------------------------------------------------------
        # Stage 2: Detect
        # ------------------------------------------------------------------
        _push(entry, "stage", stage="detecting", message="Running security detectors…")

        raw: list[Finding] = []
        raw.extend(detect_secrets(crawl_result.artifacts))
        raw.extend(
            detect_architecture(crawl_result.artifacts, crawl_result.response_headers)
        )

        # ------------------------------------------------------------------
        # Stage 3: Enrich and emit findings
        # ------------------------------------------------------------------
        enriched = enrich_with_attacks(raw)
        for finding in enriched:
            _push(entry, "finding", finding=finding.model_dump())

        # ------------------------------------------------------------------
        # Stage 4: Build report
        # ------------------------------------------------------------------
        _push(entry, "stage", stage="reporting", message="Building report…")

        duration = (_now() - started_at).total_seconds()
        counts = SeverityCounts(
            critical=sum(1 for f in enriched if f.severity == Severity.critical),
            high=sum(1 for f in enriched if f.severity == Severity.high),
            medium=sum(1 for f in enriched if f.severity == Severity.medium),
            low=sum(1 for f in enriched if f.severity == Severity.low),
            info=sum(1 for f in enriched if f.severity == Severity.info),
        )
        summary = ScanSummary(
            score=score(enriched),
            grade=grade(enriched),
            headline=headline(enriched),
            counts=counts,
        )
        report = ScanReport(
            scan_id=entry.scan_id,
            status=ScanStatus.complete,
            target_url=target_url,
            started_at=started_at.isoformat(),
            duration_seconds=duration,
            summary=summary,
            findings=enriched,
            not_checked=list(_NOT_CHECKED),
            pages_crawled=crawl_result.pages_crawled,
            assets_scanned=crawl_result.assets_scanned,
            errors=[f"{url}: {reason}" for url, reason in crawl_result.errors],
        )

        entry.report = report
        entry.status = ScanStatus.complete
        _push(
            entry,
            "complete",
            message=(
                f"Scan complete. Grade: {summary.grade}, "
                f"Score: {summary.score}/100, "
                f"Findings: {len(enriched)}"
            ),
            grade=summary.grade,
            score=summary.score,
            findings_count=len(enriched),
        )
        logger.info(
            "Scan %s complete: grade=%s score=%d findings=%d",
            entry.scan_id,
            summary.grade,
            summary.score,
            len(enriched),
        )

    except TimeoutError:
        entry.status = ScanStatus.failed
        _push(entry, "failed", message="Scan timed out")
        logger.warning("Scan %s timed out", entry.scan_id)

    except Exception:
        entry.status = ScanStatus.failed
        _push(entry, "failed", message="Scan failed due to an internal error")
        logger.exception("Scan %s failed", entry.scan_id)
