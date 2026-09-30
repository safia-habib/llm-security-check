import http.server
import os
import threading
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient  # noqa: F401 — re-exported for tests

from app.main import app

# ---------------------------------------------------------------------------
# FastAPI test client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
async def async_client() -> AsyncClient:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Local fixture app servers
#
# Both servers run on localhost (127.0.0.1) so scanner tests must set
# ALLOW_PRIVATE_TARGETS=true via the `allow_private_targets` fixture below.
#
# Ports 8001/8002 are intentionally outside the safe_fetch allowlist so
# that tests with ALLOW_PRIVATE_TARGETS=false still prove the port check works.
# Tests that scan these servers use the `allow_private_targets` fixture which
# bypasses both the IP and port checks for the duration of the test session.
# ---------------------------------------------------------------------------


def _make_handler_class(directory: str) -> type[http.server.SimpleHTTPRequestHandler]:
    """Return a SimpleHTTPRequestHandler subclass rooted at *directory*."""
    abs_dir = os.path.abspath(directory)

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, directory=abs_dir, **kwargs)

        def end_headers(self) -> None:
            # Permissive CORS on the vulnerable server (realistic misconfiguration)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            super().end_headers()

        def log_message(self, *args: object, **kwargs: object) -> None:
            pass  # suppress HTTP log noise during tests

    return _Handler


def _start_server(directory: str, port: int) -> http.server.HTTPServer:
    handler_cls = _make_handler_class(directory)
    server = http.server.HTTPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture(scope="session")
def vulnerable_server() -> Generator[str, None, None]:
    """Serve tests/fixtures/vulnerable_app on port 8001. Yields base URL."""
    server = _start_server("tests/fixtures/vulnerable_app", 8001)
    yield "http://127.0.0.1:8001"
    server.shutdown()


@pytest.fixture(scope="session")
def clean_server() -> Generator[str, None, None]:
    """Serve tests/fixtures/clean_app on port 8002. Yields base URL."""
    server = _start_server("tests/fixtures/clean_app", 8002)
    yield "http://127.0.0.1:8002"
    server.shutdown()


# ---------------------------------------------------------------------------
# ALLOW_PRIVATE_TARGETS helper
#
# Scanner / crawler tests need safe_fetch to reach 127.0.0.1.
# This fixture sets the env var for the session and clears the Settings cache.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def allow_private_targets() -> Generator[None, None, None]:
    """Enable ALLOW_PRIVATE_TARGETS for the test session so safe_fetch can
    reach localhost fixture servers."""
    from app.config import get_settings

    prev = os.environ.get("ALLOW_PRIVATE_TARGETS")
    os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
    get_settings.cache_clear()

    yield

    if prev is None:
        del os.environ["ALLOW_PRIVATE_TARGETS"]
    else:
        os.environ["ALLOW_PRIVATE_TARGETS"] = prev
    get_settings.cache_clear()
