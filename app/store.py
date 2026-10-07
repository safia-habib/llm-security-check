"""
In-memory scan store with TTL expiry and concurrency cap.

All mutations happen in the asyncio event loop — no locks needed.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
from typing import Any

from app.models import ScanReport, ScanStatus

MAX_CONCURRENT_SCANS: int = 10


@dataclasses.dataclass
class ScanEntry:
    scan_id: str
    status: ScanStatus
    report: ScanReport | None
    events: list[dict[str, Any]]
    created_at: datetime.datetime
    task: asyncio.Task | None = dataclasses.field(default=None, repr=False)


_store: dict[str, ScanEntry] = {}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _prune(ttl_minutes: int) -> None:
    cutoff = _now() - datetime.timedelta(minutes=ttl_minutes)
    expired = [k for k, v in _store.items() if v.created_at < cutoff]
    for k in expired:
        entry = _store.pop(k, None)
        if entry and entry.task and not entry.task.done():
            entry.task.cancel()


def create(scan_id: str) -> ScanEntry:
    entry = ScanEntry(
        scan_id=scan_id,
        status=ScanStatus.queued,
        report=None,
        events=[],
        created_at=_now(),
    )
    _store[scan_id] = entry
    return entry


def get(scan_id: str, ttl_minutes: int = 30) -> ScanEntry | None:
    _prune(ttl_minutes)
    return _store.get(scan_id)


def delete(scan_id: str) -> bool:
    entry = _store.pop(scan_id, None)
    if entry is None:
        return False
    if entry.task and not entry.task.done():
        entry.task.cancel()
    return True


def running_count() -> int:
    return sum(1 for e in _store.values() if e.status == ScanStatus.running)


def push_event(entry: ScanEntry, event: dict[str, Any]) -> None:
    entry.events.append(event)


def clear_all() -> None:
    """Reset the store entirely — for use in tests only."""
    _store.clear()
