"""
Phase 4 — Crawler integration tests.

These tests run the crawler against the real fixture servers
(vulnerable_app on port 8001, clean_app on port 8002).

ALLOW_PRIVATE_TARGETS must be set per-test via the allow_private_targets
fixture so that safe_fetch can reach 127.0.0.1 without being SSRF-blocked.
"""

import pytest

from app.net.crawler import ArtifactKind, CrawlResult, crawl

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _urls(result: CrawlResult) -> list[str]:
    return [a.url for a in result.artifacts]


def _of_kind(result: CrawlResult, kind: ArtifactKind) -> list[str]:
    return [a.url for a in result.artifacts if a.kind == kind]


def _content_of(result: CrawlResult, url_fragment: str) -> bytes:
    for a in result.artifacts:
        if url_fragment in a.url:
            return a.content
    return b""


# ---------------------------------------------------------------------------
# Vulnerable app — expected artefact inventory
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_returns_two_pages(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    assert result.pages_crawled == 2, "Expected index + about.html"


@pytest.mark.asyncio
async def test_crawl_origin_matches_server(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    assert result.origin == "http://127.0.0.1:8001"


@pytest.mark.asyncio
async def test_crawl_html_artifacts(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    html_urls = _of_kind(result, ArtifactKind.HTML)
    assert any("127.0.0.1:8001" in u for u in html_urls)
    assert any("about.html" in u for u in html_urls)


@pytest.mark.asyncio
async def test_crawl_finds_js_bundle(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    assert any("index.js" in u and "index.js.map" not in u for u in _urls(result))


@pytest.mark.asyncio
async def test_crawl_js_bundle_content(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """The JS bundle artifact must contain the known fake key bytes."""
    result = await crawl(vulnerable_server + "/")
    content = _content_of(result, "assets/index.js")
    assert b"sk-FAKE" in content
    assert b"sk-ant-api03-FAKE" in content


@pytest.mark.asyncio
async def test_crawl_finds_source_map(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    map_urls = _of_kind(result, ArtifactKind.SOURCE_MAP)
    assert any("index.js.map" in u for u in map_urls), f"No .map artifact; got: {_urls(result)}"


@pytest.mark.asyncio
async def test_crawl_parses_sources_content(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    sc_urls = _of_kind(result, ArtifactKind.SOURCE_MAP_CONTENT)
    assert len(sc_urls) == 2, f"Expected 2 sourcesContent entries, got {len(sc_urls)}"


@pytest.mark.asyncio
async def test_crawl_sources_content_has_keys(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """Both sourcesContent entries must carry fake provider keys."""
    result = await crawl(vulnerable_server + "/")
    combined = b"".join(
        a.content
        for a in result.artifacts
        if a.kind == ArtifactKind.SOURCE_MAP_CONTENT
    )
    assert b"sk-ant-api03-FAKE" in combined
    assert b"sk-FAKE" in combined


@pytest.mark.asyncio
async def test_crawl_finds_env_file(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    env_urls = _of_kind(result, ArtifactKind.ENV)
    assert any(".env" in u for u in env_urls), f"No ENV artifact; got: {_urls(result)}"


@pytest.mark.asyncio
async def test_crawl_env_contains_keys(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    content = _content_of(result, ".env")
    assert b"OPENAI_API_KEY" in content
    assert b"ANTHROPIC_API_KEY" in content


@pytest.mark.asyncio
async def test_crawl_finds_config_json(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    result = await crawl(vulnerable_server + "/")
    json_urls = _of_kind(result, ArtifactKind.JSON)
    assert any("config.json" in u for u in json_urls), f"No config.json artifact; got: {_urls(result)}"


@pytest.mark.asyncio
async def test_crawl_finds_inline_system_prompt(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """The window.__APP_CONFIG__ inline script must be in the artifact list."""
    result = await crawl(vulnerable_server + "/")
    inline_content = b"".join(
        a.content
        for a in result.artifacts
        if a.kind == ArtifactKind.SCRIPT_INLINE
    )
    assert b"systemPrompt" in inline_content
    assert b"You are a helpful customer service assistant" in inline_content


@pytest.mark.asyncio
async def test_crawl_stays_same_origin(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """No artifact URL should reference a different origin (third-party disabled)."""
    result = await crawl(vulnerable_server + "/", include_third_party=False)
    for art in result.artifacts:
        if art.url.startswith("http"):
            assert art.url.startswith(result.origin), (
                f"Off-origin artifact found: {art.url}"
            )


@pytest.mark.asyncio
async def test_crawl_response_headers_captured(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """CORS header from the fixture server must be captured in response_headers."""
    result = await crawl(vulnerable_server + "/")
    entry_headers = result.response_headers.get(result.entry_url, {})
    assert entry_headers.get("access-control-allow-origin") == "*"


@pytest.mark.asyncio
async def test_crawl_no_critical_errors(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    """The crawl should complete without fatal errors for all well-known 404s."""
    result = await crawl(vulnerable_server + "/")
    # 404s are fine (many well-known paths won't exist); only connection errors matter
    fatal = [(u, e) for u, e in result.errors if "Connection" in e or "SSRF" in e]
    assert not fatal, f"Unexpected fatal errors: {fatal}"


# ---------------------------------------------------------------------------
# Clean app — negative assertions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_crawl_no_env_artifact(
    clean_server: str, allow_private_targets: None
) -> None:
    result = await crawl(clean_server + "/")
    env_urls = _of_kind(result, ArtifactKind.ENV)
    assert not env_urls, f"Unexpected ENV artifacts in clean app: {env_urls}"


@pytest.mark.asyncio
async def test_clean_crawl_no_config_json(
    clean_server: str, allow_private_targets: None
) -> None:
    result = await crawl(clean_server + "/")
    json_urls = _of_kind(result, ArtifactKind.JSON)
    assert not json_urls, f"Unexpected JSON artifacts in clean app: {json_urls}"


@pytest.mark.asyncio
async def test_clean_crawl_no_source_map(
    clean_server: str, allow_private_targets: None
) -> None:
    result = await crawl(clean_server + "/")
    map_urls = _of_kind(result, ArtifactKind.SOURCE_MAP)
    assert not map_urls, f"Unexpected source map artifacts in clean app: {map_urls}"


@pytest.mark.asyncio
async def test_clean_crawl_js_has_no_keys(
    clean_server: str, allow_private_targets: None
) -> None:
    result = await crawl(clean_server + "/")
    js_content = _content_of(result, "assets/index.js")
    assert b"sk-" not in js_content
    assert b"AIza" not in js_content
    assert b"AKIA" not in js_content


@pytest.mark.asyncio
async def test_clean_crawl_finds_js_bundle(
    clean_server: str, allow_private_targets: None
) -> None:
    result = await crawl(clean_server + "/")
    js_urls = _of_kind(result, ArtifactKind.SCRIPT_EXTERNAL)
    assert any("index.js" in u for u in js_urls)


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_emits_progress(
    vulnerable_server: str, allow_private_targets: None
) -> None:
    events: list[tuple[str, int, int]] = []

    def _cb(stage: str, cur: int, total: int) -> None:
        events.append((stage, cur, total))

    await crawl(vulnerable_server + "/", on_progress=_cb)
    stages = {e[0] for e in events}
    assert stages, "Expected at least one progress event"
    assert "crawl" in stages or "entry" in stages
