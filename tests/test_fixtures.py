"""
Phase 3 — Fixture server smoke tests.

These tests verify that the deliberately vulnerable and clean fixture apps
are served correctly and contain the expected content the scanner should find.
Tests use httpx directly (not safe_fetch) because safe_fetch would reject
the localhost address without ALLOW_PRIVATE_TARGETS=true.
"""

import httpx

# ===========================================================================
# Vulnerable app — files must be accessible and contain expected content
# ===========================================================================


async def test_vulnerable_index_served(vulnerable_server: str) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/")
    assert resp.status_code == 200
    assert b"index.js" in resp.content
    assert b"about.html" in resp.content


async def test_vulnerable_about_page_served(vulnerable_server: str) -> None:
    """Crawler should discover /about.html via the link on the index page."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/about.html")
    assert resp.status_code == 200
    assert b"Acme" in resp.content


async def test_vulnerable_js_bundle_contains_openai_key(vulnerable_server: str) -> None:
    """Fake OpenAI key must be present in the JS bundle (Group 1 detection target)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/assets/index.js")
    assert resp.status_code == 200
    assert b"sk-FAKE" in resp.content


async def test_vulnerable_js_bundle_contains_anthropic_key(vulnerable_server: str) -> None:
    """Fake Anthropic key must be present in the JS bundle (Group 1 detection target)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/assets/index.js")
    assert resp.status_code == 200
    assert b"sk-ant-api03-FAKE" in resp.content


async def test_vulnerable_js_bundle_contains_direct_provider_call(
    vulnerable_server: str,
) -> None:
    """Direct call to api.openai.com must be visible in the JS bundle (Group 3 target)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/assets/index.js")
    assert resp.status_code == 200
    assert b"api.openai.com" in resp.content
    assert b"api.anthropic.com" in resp.content


async def test_vulnerable_js_bundle_has_source_map_comment(vulnerable_server: str) -> None:
    """Source map URL comment must be present so the crawler follows it."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/assets/index.js")
    assert resp.status_code == 200
    assert b"sourceMappingURL" in resp.content


async def test_vulnerable_source_map_served(vulnerable_server: str) -> None:
    """Source map must be accessible and contain sourcesContent."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/assets/index.js.map")
    assert resp.status_code == 200
    body = resp.json()
    assert "sourcesContent" in body
    # Both source files should contain fake keys
    combined = " ".join(body["sourcesContent"])
    assert "sk-ant-api03-FAKE" in combined
    assert "sk-FAKE" in combined


async def test_vulnerable_env_file_served(vulnerable_server: str) -> None:
    """/.env must return 200 — scanner treats this as Critical on its own."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/.env")
    assert resp.status_code == 200
    assert b"OPENAI_API_KEY" in resp.content
    assert b"ANTHROPIC_API_KEY" in resp.content
    assert b"AKIAFAKEACCESSKEYID0" in resp.content


async def test_vulnerable_config_json_served(vulnerable_server: str) -> None:
    """config.json must return 200 and contain fake API key fields."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/config.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "apiKey" in body
    assert body["apiKey"].startswith("sk-")


async def test_vulnerable_index_has_system_prompt(vulnerable_server: str) -> None:
    """System prompt must be visible in the page source (Group 3 detection target)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/")
    assert resp.status_code == 200
    text = resp.text
    assert "systemPrompt" in text
    assert "You are a helpful customer service assistant" in text


async def test_vulnerable_index_exposes_tool_schemas(vulnerable_server: str) -> None:
    """Tool definitions (function schemas) must be visible in the page source."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/")
    assert resp.status_code == 200
    text = resp.text
    assert "lookup_order" in text
    assert "get_customer_data" in text


async def test_vulnerable_cors_header_permissive(vulnerable_server: str) -> None:
    """The fixture server returns Access-Control-Allow-Origin: * (Group 3 target)."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/")
    assert resp.headers.get("access-control-allow-origin") == "*"


async def test_vulnerable_robots_txt_allows_all(vulnerable_server: str) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(vulnerable_server + "/robots.txt")
    assert resp.status_code == 200
    assert b"Allow" in resp.content


# ===========================================================================
# Clean app — deliberately absent content (baseline for negative tests)
# ===========================================================================


async def test_clean_index_served(clean_server: str) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/")
    assert resp.status_code == 200


async def test_clean_env_file_not_served(clean_server: str) -> None:
    """Clean app must NOT expose /.env."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/.env")
    assert resp.status_code == 404


async def test_clean_config_json_not_served(clean_server: str) -> None:
    """Clean app must NOT have an exposed config.json."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/config.json")
    assert resp.status_code == 404


async def test_clean_js_has_no_provider_keys(clean_server: str) -> None:
    """Clean JS bundle must contain no provider key patterns."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/assets/index.js")
    assert resp.status_code == 200
    text = resp.text
    assert "sk-" not in text
    assert "sk-ant-" not in text
    assert "AIza" not in text
    assert "gsk_" not in text
    assert "AKIA" not in text


async def test_clean_js_calls_local_proxy(clean_server: str) -> None:
    """Clean app must call a same-origin /api/chat proxy, not a provider URL."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/assets/index.js")
    text = resp.text
    assert "/api/chat" in text
    assert "api.openai.com" not in text
    assert "api.anthropic.com" not in text


async def test_clean_js_has_no_source_map(clean_server: str) -> None:
    """Clean JS bundle must not reference a source map in production."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/assets/index.js")
    assert b"sourceMappingURL" not in resp.content


async def test_clean_js_has_no_system_prompt(clean_server: str) -> None:
    async with httpx.AsyncClient() as client:
        resp = await client.get(clean_server + "/assets/index.js")
    text = resp.text
    assert "systemPrompt" not in text
    assert "You are a" not in text
