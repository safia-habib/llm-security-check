import datetime
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings, warn_if_unsafe
from app.models import HealthResponse, RejectionResponse, ScanStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    warn_if_unsafe(settings)
    logger.info("LLM Security Check v%s starting on port %d", VERSION, settings.port)
    yield
    logger.info("LLM Security Check shutting down")


app = FastAPI(
    title="LLM Security Check",
    version=VERSION,
    description="Passive scanner for LLM-specific security mistakes in web applications",
    docs_url=None,   # hide /docs in production; expose via /api/rules instead
    redoc_url=None,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": "Not found"})


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    # Never leak internal details
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again."},
    )


# ---------------------------------------------------------------------------
# API routes — must be registered BEFORE the StaticFiles mount
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


@app.post("/api/scan")
async def start_scan_placeholder() -> JSONResponse:
    """Placeholder — implemented in Phase 7."""
    return JSONResponse(
        status_code=501,
        content=RejectionResponse(
            status=ScanStatus.rejected,
            reason="not_implemented",
            message="Scan endpoint not yet available.",
        ).model_dump(),
    )


@app.get("/api/rules")
async def list_rules_placeholder() -> JSONResponse:
    """Placeholder — implemented in Phase 6."""
    return JSONResponse(status_code=200, content={"rules": []})


# ---------------------------------------------------------------------------
# Static file serving — must come last so API routes take priority
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory="static", html=True), name="static")
