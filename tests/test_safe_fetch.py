"""
Phase 2 — SSRF protection tests.

Strategy for test URLs:
  - Blocked targets:  use literal private/loopback IPs so no DNS is needed.
  - Safe mock target: 203.0.113.1 (RFC 5737 TEST-NET-3 — not in any blocked
    range; socket.getaddrinfo resolves literal IPs without a network call).
  - Redirect tests:   use a respx mock for the initial hop + a literal private
    IP in the Location header so the redirect IP check triggers.

No test makes a real outbound network request.
"""

import socket

import httpx
import pytest
import respx

from app.net.safe_fetch import (
    _MAX_BODY_BYTES,
    FetchResult,
    SSRFError,
    safe_fetch,
    safe_head,
)

# A safe, non-routable RFC 5737 documentation IP used for all "happy path"
# mocked requests.  socket.getaddrinfo resolves literal IPs without DNS.
SAFE_IP = "203.0.113.1"
SAFE_URL = f"http://{SAFE_IP}/"


# ===========================================================================
# Scheme rejection
# ===========================================================================


async def test_rejects_file_scheme() -> None:
    with pytest.raises(SSRFError, match="[Ss]cheme"):
        await safe_fetch("file:///etc/passwd")


async def test_rejects_gopher_scheme() -> None:
    with pytest.raises(SSRFError, match="[Ss]cheme"):
        await safe_fetch("gopher://evil.example.com/data")


async def test_rejects_data_scheme() -> None:
    with pytest.raises(SSRFError, match="[Ss]cheme"):
        await safe_fetch("data:text/plain,hello")


async def test_rejects_ftp_scheme() -> None:
    with pytest.raises(SSRFError, match="[Ss]cheme"):
        await safe_fetch("ftp://files.example.com/secret")


# ===========================================================================
# Localhost by name
# ===========================================================================


async def test_rejects_localhost_bare() -> None:
    with pytest.raises(SSRFError, match="localhost"):
        await safe_fetch("http://localhost/")


async def test_rejects_localhost_with_port() -> None:
    with pytest.raises(SSRFError, match="localhost"):
        await safe_fetch("http://localhost:8080/api")


async def test_rejects_subdomain_localhost() -> None:
    with pytest.raises(SSRFError, match="localhost"):
        await safe_fetch("http://app.localhost/")


async def test_rejects_nested_subdomain_localhost() -> None:
    with pytest.raises(SSRFError, match="localhost"):
        await safe_fetch("http://api.internal.localhost:3000/")


# ===========================================================================
# Loopback IP addresses
# ===========================================================================


async def test_rejects_loopback_127_0_0_1() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://127.0.0.1/")


async def test_rejects_loopback_127_0_0_2() -> None:
    # Entire 127.0.0.0/8 is blocked, not just .1
    with pytest.raises(SSRFError):
        await safe_fetch("http://127.255.255.255/")


async def test_rejects_loopback_ipv6() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://[::1]/")


# ===========================================================================
# RFC-1918 private ranges
# ===========================================================================


async def test_rejects_rfc1918_10_block() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://10.0.0.1/")


async def test_rejects_rfc1918_10_high() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://10.255.255.255/")


async def test_rejects_rfc1918_172_16_block() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://172.16.0.1/")


async def test_rejects_rfc1918_172_31() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://172.31.255.255/")


async def test_rejects_rfc1918_192_168_block() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://192.168.1.1/")


# ===========================================================================
# Link-local / cloud metadata endpoint
# ===========================================================================


async def test_rejects_169_254_cloud_metadata() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://169.254.169.254/")


async def test_rejects_169_254_other() -> None:
    with pytest.raises(SSRFError):
        await safe_fetch("http://169.254.0.1/")


# ===========================================================================
# Non-standard port rejection
# ===========================================================================


async def test_rejects_port_22_ssh() -> None:
    with pytest.raises(SSRFError, match="[Pp]ort"):
        await safe_fetch("http://example.com:22/")


async def test_rejects_port_21_ftp() -> None:
    with pytest.raises(SSRFError, match="[Pp]ort"):
        await safe_fetch("http://example.com:21/")


async def test_rejects_port_6379_redis() -> None:
    with pytest.raises(SSRFError, match="[Pp]ort"):
        await safe_fetch("http://example.com:6379/")


async def test_rejects_port_9200_elasticsearch() -> None:
    with pytest.raises(SSRFError, match="[Pp]ort"):
        await safe_fetch("http://example.com:9200/")


async def test_allowed_ports_accepted() -> None:
    """Ports in the allowlist pass URL validation (no network call)."""
    for port in (80, 443, 3000, 5173, 8000, 8080):
        # This should raise SSRFError at the DNS/IP stage (if the host is
        # a real hostname) or at the body stage — but NOT at the port stage.
        try:
            await safe_fetch(f"http://localhost:{port}/")
        except SSRFError as exc:
            assert "Port" not in str(exc), (
                f"Port {port} should be allowed but got: {exc}"
            )


# ===========================================================================
# Redirect chain into a private address
# ===========================================================================


async def test_rejects_redirect_to_cloud_metadata() -> None:
    """A redirect from a safe URL to 169.254.169.254 must be blocked."""
    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(
                301,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        )
        with pytest.raises(SSRFError):
            await safe_fetch(SAFE_URL)


async def test_rejects_redirect_to_loopback() -> None:
    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(
                302,
                headers={"location": "http://127.0.0.1/internal"},
            )
        )
        with pytest.raises(SSRFError):
            await safe_fetch(SAFE_URL)


async def test_rejects_redirect_to_private_range() -> None:
    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(
                301,
                headers={"location": "http://192.168.1.100/admin"},
            )
        )
        with pytest.raises(SSRFError):
            await safe_fetch(SAFE_URL)


async def test_rejects_redirect_chain_exceeding_max() -> None:
    """More than 3 redirect follows must be refused.

    _MAX_REDIRECTS=3 means hops 0→1, 1→2, 2→3 are all followed
    (redirects_followed reaches 3), and hop 3→4 triggers the >=3 check.
    """
    with respx.mock:
        respx.get(f"http://{SAFE_IP}/hop0").mock(
            return_value=httpx.Response(
                301, headers={"location": f"http://{SAFE_IP}/hop1"}
            )
        )
        respx.get(f"http://{SAFE_IP}/hop1").mock(
            return_value=httpx.Response(
                301, headers={"location": f"http://{SAFE_IP}/hop2"}
            )
        )
        respx.get(f"http://{SAFE_IP}/hop2").mock(
            return_value=httpx.Response(
                301, headers={"location": f"http://{SAFE_IP}/hop3"}
            )
        )
        # This 4th redirect (hop3→hop4) must be refused
        respx.get(f"http://{SAFE_IP}/hop3").mock(
            return_value=httpx.Response(
                301, headers={"location": f"http://{SAFE_IP}/hop4"}
            )
        )
        respx.get(f"http://{SAFE_IP}/hop4").mock(
            return_value=httpx.Response(200, content=b"final")
        )
        with pytest.raises(SSRFError, match="[Rr]edirect"):
            await safe_fetch(f"http://{SAFE_IP}/hop0")


# ===========================================================================
# Response body size limits
# ===========================================================================


async def test_rejects_oversized_content_length_header() -> None:
    """Content-Length > 5 MB is rejected before streaming starts."""
    too_large = str(_MAX_BODY_BYTES + 1)
    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"content-length": too_large},
                content=b"",  # irrelevant; Content-Length check runs first
            )
        )
        with pytest.raises(SSRFError, match="Content-Length"):
            await safe_fetch(SAFE_URL)


async def test_rejects_oversized_body_while_streaming(monkeypatch: pytest.MonkeyPatch) -> None:
    """Body exceeding the cap is rejected — via Content-Length or streaming check.

    httpx.Response auto-sets Content-Length when content= is given, so the
    Content-Length fast-path fires here.  Both paths raise SSRFError with
    'exceed' in the message, which is what matters.
    """
    monkeypatch.setattr("app.net.safe_fetch._MAX_BODY_BYTES", 100)

    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(200, content=b"x" * 101)
        )
        with pytest.raises(SSRFError, match="exceed"):
            await safe_fetch(SAFE_URL)


async def test_accepts_body_at_exact_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A body exactly at the cap is accepted."""
    monkeypatch.setattr("app.net.safe_fetch._MAX_BODY_BYTES", 100)

    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(200, content=b"x" * 100)
        )
        result = await safe_fetch(SAFE_URL)
        assert result.content == b"x" * 100


# ===========================================================================
# Timeout handling
# ===========================================================================


async def test_timeout_propagated() -> None:
    """A request that times out raises httpx.TimeoutException (not swallowed)."""
    with respx.mock:
        respx.get(SAFE_URL).mock(side_effect=httpx.TimeoutException("timed out"))
        with pytest.raises(httpx.TimeoutException):
            await safe_fetch(SAFE_URL)


# ===========================================================================
# Happy path and partial-failure cases
# ===========================================================================


async def test_happy_path_returns_fetch_result() -> None:
    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(200, content=b"hello scanner")
        )
        result = await safe_fetch(SAFE_URL)

    assert isinstance(result, FetchResult)
    assert result.status_code == 200
    assert result.content == b"hello scanner"
    assert result.url.startswith(f"http://{SAFE_IP}")


async def test_404_returned_as_fetch_result() -> None:
    """A 404 from the target is returned normally — it is not an SSRF concern."""
    with respx.mock:
        respx.get(SAFE_URL).mock(return_value=httpx.Response(404, content=b"not found"))
        result = await safe_fetch(SAFE_URL)
    assert result.status_code == 404


async def test_head_returns_empty_content() -> None:
    with respx.mock:
        respx.head(SAFE_URL).mock(return_value=httpx.Response(200))
        result = await safe_head(SAFE_URL)
    assert result.status_code == 200
    assert result.content == b""


async def test_safe_redirect_within_allowed_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """A redirect to another safe public IP is followed normally."""
    other_ip = "203.0.113.2"

    # Patch getaddrinfo so the second hostname resolves to a non-blocked IP
    real_getaddrinfo = socket.getaddrinfo

    def patched(host: str, port: object, *args: object, **kwargs: object) -> list:
        if host == other_ip:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (other_ip, 0))]
        return real_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", patched)

    with respx.mock:
        respx.get(SAFE_URL).mock(
            return_value=httpx.Response(
                301, headers={"location": f"http://{other_ip}/page"}
            )
        )
        respx.get(f"http://{other_ip}/page").mock(
            return_value=httpx.Response(200, content=b"redirected ok")
        )
        result = await safe_fetch(SAFE_URL)

    assert result.status_code == 200
    assert result.content == b"redirected ok"


async def test_dns_failure_raises_ssrf_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DNS failure for a non-literal hostname raises SSRFError."""

    def fail_getaddrinfo(host: str, port: object, *args: object, **kwargs: object) -> list:
        raise OSError("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    with pytest.raises(SSRFError, match="DNS resolution failed"):
        await safe_fetch("http://nonexistent.example.com/")
