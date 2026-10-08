"""
SSRF-guarded HTTP wrapper.

All outbound network requests in this app MUST go through safe_fetch or
safe_head. No other code instantiates httpx.AsyncClient directly.

Protection layers, in order:
  1. Scheme allowlist (http / https only)
  2. Hostname name-based blocklist (localhost, *.localhost)
  3. Port allowlist (80, 443, 3000, 5173, 8000, 8080)
  4. DNS resolution + IP blocklist (loopback, RFC-1918, link-local, cloud metadata)
  5. Redirect loop: re-runs checks 2–4 on every hop, max 3 hops
  6. Response body cap: 5 MB; Content-Length header checked first, then streamed
"""

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from app.audit import log_url_fetched
from app.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BLOCKED_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("10.0.0.0/8"),      # RFC-1918 private
    ipaddress.ip_network("172.16.0.0/12"),   # RFC-1918 private
    ipaddress.ip_network("192.168.0.0/16"),  # RFC-1918 private
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),       # "this" network
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # unique-local IPv6
    ipaddress.ip_network("fe80::/10"),        # link-local IPv6
)

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 3000, 5173, 8000, 8080})
_MAX_BODY_BYTES: int = 5 * 1024 * 1024   # 5 MB
_MAX_REDIRECTS: int = 3


# ---------------------------------------------------------------------------
# Public exception and result types
# ---------------------------------------------------------------------------


class SSRFError(Exception):
    """Raised when a fetch request is blocked by the SSRF safety layer."""


@dataclass
class FetchResult:
    url: str                     # final URL after any redirects
    status_code: int
    headers: dict[str, str]
    content: bytes = field(default=b"")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_url(url: str) -> tuple[str, str, int]:
    """Validate scheme, hostname, and port.

    Returns (scheme, hostname, effective_port). Raises SSRFError on violation.
    Does not make any network calls.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"Malformed URL {url!r}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFError(
            f"Scheme {scheme!r} is not permitted. "
            f"Only {sorted(_ALLOWED_SCHEMES)} are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError(f"No hostname found in {url!r}")

    # Reject localhost variants by name before DNS (fast path)
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise SSRFError(f"Hostname {hostname!r} is blocked (localhost)")

    port: int = parsed.port or (443 if scheme == "https" else 80)
    if port not in _ALLOWED_PORTS:
        raise SSRFError(
            f"Port {port} is not in the allowed list: {sorted(_ALLOWED_PORTS)}"
        )

    return scheme, hostname, port


async def _check_host(hostname: str) -> None:
    """Resolve *hostname* and raise SSRFError if any resolved IP is blocked.

    Runs getaddrinfo in a thread-pool executor to avoid blocking the event loop.
    """
    loop = asyncio.get_running_loop()
    try:
        infos: list = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
        )
    except OSError as exc:
        raise SSRFError(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not infos:
        raise SSRFError(f"No addresses resolved for {hostname!r}")

    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        for net in _BLOCKED_NETS:
            if ip in net:
                raise SSRFError(
                    f"IP {ip} resolved from {hostname!r} is in blocked range {net}"
                )


async def _read_limited(response: httpx.Response) -> bytes:
    """Stream the response body up to _MAX_BODY_BYTES.

    Checks Content-Length first (fast reject), then enforces the limit while
    streaming. Raises SSRFError if the body exceeds the limit.
    """
    cl_header = response.headers.get("content-length", "").strip()
    if cl_header.isdigit() and int(cl_header) > _MAX_BODY_BYTES:
        raise SSRFError(
            f"Content-Length {cl_header} bytes exceeds the {_MAX_BODY_BYTES}-byte limit"
        )

    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes(chunk_size=65_536):
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            raise SSRFError(
                f"Response body exceeded the {_MAX_BODY_BYTES}-byte limit; request aborted"
            )
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def safe_fetch(url: str, *, method: str = "GET") -> FetchResult:
    """Fetch *url* with full SSRF protection.

    Raises:
        SSRFError: if the target is blocked at any point (scheme, IP, port,
                   redirect hop, or body size).
        httpx.TimeoutException: if the request times out.
        httpx.HTTPError: for other httpx-level errors.
    """
    settings = get_settings()

    if settings.allow_private_targets:
        # Local dev / test mode only.  Scheme is still enforced; everything
        # else (port, IP blocklist) is skipped.  The startup warning in
        # main.py ensures this is never silently enabled in production.
        logger.warning(
            "ALLOW_PRIVATE_TARGETS=true: SSRF protection bypassed for %s %s",
            method,
            url,
        )
        try:
            _parsed = urlparse(url)
            _scheme = (_parsed.scheme or "").lower()
        except Exception as exc:
            raise SSRFError(f"Malformed URL {url!r}") from exc
        if _scheme not in _ALLOWED_SCHEMES:
            raise SSRFError(
                f"Scheme {_scheme!r} is not permitted. "
                f"Only {sorted(_ALLOWED_SCHEMES)} are allowed."
            )
    else:
        _, hostname, _ = _validate_url(url)
        await _check_host(hostname)

    ua_headers = {"User-Agent": settings.user_agent}
    timeout = httpx.Timeout(settings.request_timeout_seconds)

    current_url = url
    redirects_followed = 0

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers=ua_headers,
    ) as client:
        while True:
            response = await client.request(method, current_url)

            if response.is_redirect:
                if redirects_followed >= _MAX_REDIRECTS:
                    raise SSRFError(
                        f"Exceeded the maximum of {_MAX_REDIRECTS} redirects "
                        f"originating from {url!r}"
                    )

                location = response.headers.get("location", "").strip()
                if not location:
                    raise SSRFError("Redirect response contained no Location header")

                # Resolve relative Location header against the current URL
                next_url = urljoin(current_url, location)

                # Re-run safety checks on every redirect hop
                if not settings.allow_private_targets:
                    _, next_host, _ = _validate_url(next_url)
                    await _check_host(next_host)

                current_url = next_url
                redirects_followed += 1
                continue

            # Non-redirect: read the body (empty for HEAD)
            content = b"" if method.upper() == "HEAD" else await _read_limited(response)
            result = FetchResult(
                url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                content=content,
            )
            log_url_fetched(result.url, method, result.status_code)
            return result


async def safe_head(url: str) -> FetchResult:
    """SSRF-guarded HEAD request. Convenience wrapper around safe_fetch."""
    return await safe_fetch(url, method="HEAD")
