import asyncio
import datetime
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app import store as scan_store
from app.config import get_settings, warn_if_unsafe
from app.detect.rules import RULES
from app.models import (
    HealthResponse,
    RejectionResponse,
    ScanInitResponse,
    ScanReport,
    ScanRequest,
    ScanStatus,
)
from app.report import render_markdown
from app.scanner import run_scan

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Security-headers middleware (pure ASGI — does not buffer StreamingResponse)
# ---------------------------------------------------------------------------

_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (
        b"content-security-policy",
        (
            b"default-src 'self'; "
            b"script-src 'self' 'unsafe-inline'; "
            b"style-src 'self' 'unsafe-inline'; "
            b"connect-src 'self'; "
            b"object-src 'none'; "
            b"base-uri 'none'; "
            b"form-action 'self'; "
            b"frame-ancestors 'none';"
        ),
    ),
]


class _SecurityHeadersMiddleware:
    """Injects security headers into every HTTP response.

    Implemented as a pure ASGI middleware so that StreamingResponse (SSE)
    is never buffered — headers are injected at the http.response.start
    message level before any body chunks are sent.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(
        self, scope: dict[str, Any], receive: Any, send: Any
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extras = [(k, v) for k, v in _SECURITY_HEADERS if k not in existing]
                if extras:
                    message = {
                        **message,
                        "headers": list(message.get("headers", [])) + extras,
                    }
            await send(message)

        await self.app(scope, receive, _send_with_headers)


# ---------------------------------------------------------------------------
# Rate limiting — in-memory dict keyed by client IP
# ---------------------------------------------------------------------------

_rate_limits: dict[str, list[datetime.datetime]] = {}


def _check_rate_limit(client_ip: str, limit: int) -> bool:
    """Return True if the request is allowed; False if the client is rate-limited.

    Consumes one slot when returning True.
    """
    now = datetime.datetime.now(datetime.UTC)
    cutoff = now - datetime.timedelta(hours=1)
    history = _rate_limits.setdefault(client_ip, [])
    _rate_limits[client_ip] = [t for t in history if t > cutoff]
    if len(_rate_limits[client_ip]) >= limit:
        return False
    _rate_limits[client_ip].append(now)
    return True


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    warn_if_unsafe(settings)
    logger.info("LLM Security Check v%s starting on port %d", VERSION, settings.port)
    yield
    logger.info("LLM Security Check shutting down")


app = FastAPI(
    title="LLM Security Check",
    version=VERSION,
    description="Passive scanner for LLM-specific security mistakes in web applications",
    docs_url=None,
    redoc_url=None,
    lifespan=_lifespan,
)

app.add_middleware(_SecurityHeadersMiddleware)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again."},
    )


# ---------------------------------------------------------------------------
# API routes  (registered before StaticFiles so they take priority)
# ---------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=VERSION,
        timestamp=datetime.datetime.now(datetime.UTC).isoformat(),
        allow_private_targets=settings.allow_private_targets,
    )


@app.get("/api/rules")
async def list_rules() -> JSONResponse:
    rules_list = [
        {
            "id": rule_id,
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "category": rule["category"],
            "group": rule["group"],
            "why_it_matters": rule["why_it_matters"],
        }
        for rule_id, rule in RULES.items()
    ]
    return JSONResponse(status_code=200, content={"rules": rules_list, "total": len(rules_list)})


@app.post("/api/scan")
async def start_scan(request: Request) -> JSONResponse:
    settings = get_settings()

    # Parse body — return 422 on validation error (includes owns_target=false).
    try:
        body = await request.json()
        scan_req = ScanRequest(**body)
    except ValidationError as exc:
        return JSONResponse(status_code=422, content=json.loads(exc.json()))
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid request body"})

    # Ownership attestation — handled by Pydantic validator on ScanRequest,
    # so if we reach this point the field is True.  Belt-and-suspenders check:
    if not scan_req.owns_target:
        return JSONResponse(
            status_code=400,
            content=RejectionResponse(
                status=ScanStatus.rejected,
                reason="attestation_required",
                message="owns_target must be true to initiate a scan.",
            ).model_dump(),
        )

    # Rate limiting
    client_ip = _client_ip(request)
    if not _check_rate_limit(client_ip, settings.rate_limit_per_hour):
        return JSONResponse(
            status_code=429,
            content=RejectionResponse(
                status=ScanStatus.rejected,
                reason="rate_limited",
                message=(
                    f"Too many scans. Limit is {settings.rate_limit_per_hour} per hour."
                ),
            ).model_dump(),
        )

    # Concurrency cap
    if scan_store.running_count() >= scan_store.MAX_CONCURRENT_SCANS:
        return JSONResponse(
            status_code=503,
            content=RejectionResponse(
                status=ScanStatus.rejected,
                reason="server_busy",
                message="Maximum concurrent scans reached. Please retry shortly.",
            ).model_dump(),
        )

    # Create entry and launch background task
    scan_id = str(uuid.uuid4())
    entry = scan_store.create(scan_id)
    task = asyncio.create_task(
        run_scan(entry, scan_req.target_url, scan_req.include_third_party)
    )
    entry.task = task

    return JSONResponse(
        status_code=202,
        content=ScanInitResponse(
            scan_id=scan_id, status=ScanStatus.queued
        ).model_dump(),
    )


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> JSONResponse:
    settings = get_settings()
    entry = scan_store.get(scan_id, ttl_minutes=settings.scan_ttl_minutes)
    if entry is None:
        return JSONResponse(status_code=404, content={"detail": "Scan not found"})

    if entry.report is not None:
        return JSONResponse(status_code=200, content=entry.report.model_dump())

    # Scan still in progress — return minimal status payload
    partial = ScanReport(
        scan_id=scan_id,
        status=entry.status,
        target_url="",
        started_at=entry.created_at.isoformat(),
    )
    return JSONResponse(status_code=200, content=partial.model_dump())


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str, request: Request) -> StreamingResponse:
    settings = get_settings()

    async def _sse() -> AsyncGenerator[str, None]:
        cursor = 0
        while True:
            entry = scan_store.get(scan_id, ttl_minutes=settings.scan_ttl_minutes)
            if entry is None:
                yield _sse_event("error", {"message": "scan not found"})
                return

            # Emit any new events since cursor
            batch = entry.events[cursor:]
            for event in batch:
                yield _sse_event(event.get("type", "event"), event)
            cursor += len(batch)

            # Exit once scan is terminal
            if entry.status in (ScanStatus.complete, ScanStatus.failed):
                return

            # Check client disconnect
            if await request.is_disconnected():
                return

            await asyncio.sleep(0.25)

    return StreamingResponse(
        _sse(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scan/{scan_id}/report.md")
async def get_report_md(scan_id: str) -> PlainTextResponse:
    settings = get_settings()
    entry = scan_store.get(scan_id, ttl_minutes=settings.scan_ttl_minutes)
    if entry is None:
        return PlainTextResponse("Scan not found", status_code=404)
    if entry.report is None:
        return PlainTextResponse(
            f"Report not ready yet (status: {entry.status})", status_code=202
        )
    return PlainTextResponse(render_markdown(entry.report), media_type="text/markdown")


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str) -> JSONResponse:
    deleted = scan_store.delete(scan_id)
    if not deleted:
        return JSONResponse(status_code=404, content={"detail": "Scan not found"})
    return JSONResponse(status_code=204, content=None)


# ---------------------------------------------------------------------------
# Static file serving — must come last so API routes take priority
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory="static", html=True), name="static")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sse_event(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
