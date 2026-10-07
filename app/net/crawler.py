"""
Crawler and asset collector for LLM Security Check.

Stages (in order):
  1  Validate URL, extract origin
  2  Fetch robots.txt
  3  Fetch entry page
  4  BFS: discover and fetch same-origin HTML pages (depth ≤ 2, ≤ max_pages)
  5  Fetch same-origin external scripts and preload assets (≤ max_assets)
  6  Fetch source maps from JS files, parse sourcesContent arrays
  7  Probe well-known exposure paths (HEAD then GET on 200)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from app.config import get_settings
from app.net.safe_fetch import FetchResult, SSRFError, safe_fetch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known paths to probe (HEAD first, GET only on 200)
# ---------------------------------------------------------------------------

_WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/config.js",
    "/env.js",
    "/settings.json",
    "/.git/config",
    "/appsettings.json",
    "/static/js/main.js",
    "/assets/index.js",
    "/firebase-config.js",
    "/.well-known/security.txt",
    "/api/config",
    "/api/env",
)

_HTML_EXTENSIONS: frozenset[str] = frozenset({".html", ".htm", ".xhtml", ""})
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({".js", ".mjs", ".cjs"})
_SOURCE_MAP_RE: re.Pattern[bytes] = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s]+)")


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


class ArtifactKind(StrEnum):
    HTML = "html"
    SCRIPT_EXTERNAL = "script_external"  # fetched via <script src>
    SCRIPT_INLINE = "script_inline"      # <script> text content or metadata blob
    JSON = "json"
    ENV = "env"
    SOURCE_MAP = "source_map"             # the raw .map file
    SOURCE_MAP_CONTENT = "source_map_content"  # one sourcesContent entry
    WELL_KNOWN = "well_known"             # found via well-known probe (non-HTML)
    OTHER = "other"


@dataclass
class Artifact:
    url: str           # canonical URL, or synthetic key for inline content
    source_url: str    # page/asset this was discovered in
    kind: ArtifactKind
    content: bytes
    headers: dict[str, str] = field(default_factory=dict)
    is_third_party: bool = False


@dataclass
class CrawlResult:
    origin: str
    entry_url: str
    artifacts: list[Artifact]
    response_headers: dict[str, dict[str, str]]  # url → response headers (CORS/CSP)
    pages_crawled: int
    assets_scanned: int
    errors: list[tuple[str, str]]               # (url, reason)


ProgressCallback = Callable[[str, int, int], None]


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _origin(url: str) -> str:
    p = urlparse(url)
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port}"


def _norm(url: str, base: str | None = None) -> str:
    """Resolve *url* against *base* and strip the fragment."""
    if base:
        url = urljoin(base, url)
    p = urlparse(url)
    return urlunparse(p._replace(fragment=""))


def _same_origin(url: str, origin: str) -> bool:
    pu, po = urlparse(url), urlparse(origin)
    return pu.scheme == po.scheme and pu.hostname == po.hostname and pu.port == po.port


def _is_html_path(url: str) -> bool:
    path = urlparse(url).path.rstrip("/")
    return os.path.splitext(path)[1].lower() in _HTML_EXTENSIONS


def _kind_for(url: str) -> ArtifactKind:
    """Infer artifact kind from the URL path."""
    path = urlparse(url).path.lower()
    if "/.env" in path or path.endswith(".env"):
        return ArtifactKind.ENV
    if path.endswith(".map"):
        return ArtifactKind.SOURCE_MAP
    if path.endswith(".json"):
        return ArtifactKind.JSON
    ext = os.path.splitext(path)[1]
    if ext in _SCRIPT_EXTENSIONS:
        return ArtifactKind.SCRIPT_EXTERNAL
    if _is_html_path(url):
        return ArtifactKind.HTML
    return ArtifactKind.OTHER


# ---------------------------------------------------------------------------
# Robots.txt
# ---------------------------------------------------------------------------


async def _fetch_robots(origin: str, sem: asyncio.Semaphore) -> RobotFileParser:
    rp = RobotFileParser(f"{origin}/robots.txt")
    async with sem:
        try:
            r = await safe_fetch(f"{origin}/robots.txt")
            if r.status_code == 200:
                rp.parse(r.content.decode("utf-8", errors="replace").splitlines())
        except Exception:
            pass  # if robots.txt is unavailable, allow all
    return rp


def _robots_ok(rp: RobotFileParser, url: str, ua: str) -> bool:
    try:
        return rp.can_fetch(ua, url)
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Inline metadata collector
# ---------------------------------------------------------------------------


def _collect_meta(
    soup: BeautifulSoup, page_url: str, artifacts: list[Artifact]
) -> None:
    """Append one artifact for event handlers, data-* attrs, and <meta> tags."""
    lines: list[str] = []
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if isinstance(attr, str) and (attr.startswith("on") or attr.startswith("data-")):
                lines.append(f"{attr}={val!r}")
    for tag in soup.find_all("meta"):
        content = tag.get("content", "")
        if content:
            name = tag.get("name") or tag.get("property") or ""
            lines.append(f"meta:{name}={content!r}")
    if lines:
        artifacts.append(Artifact(
            url=f"inline_meta:{page_url}",
            source_url=page_url,
            kind=ArtifactKind.SCRIPT_INLINE,
            content="\n".join(lines).encode("utf-8", errors="replace"),
        ))


# ---------------------------------------------------------------------------
# Main crawler
# ---------------------------------------------------------------------------


async def crawl(
    target_url: str,
    *,
    include_third_party: bool = False,
    on_progress: ProgressCallback | None = None,
) -> CrawlResult:
    """Crawl *target_url* and return a CrawlResult with all discovered artifacts."""
    settings = get_settings()
    sem = asyncio.Semaphore(2)  # max 2 concurrent requests per target

    target_url = _norm(target_url)
    orig = _origin(target_url)
    ua = settings.user_agent

    artifacts: list[Artifact] = []
    resp_headers: dict[str, dict[str, str]] = {}
    errors: list[tuple[str, str]] = []
    fetched: set[str] = set()  # all URLs fetched or scheduled — prevents duplicates
    pages_crawled = 0
    assets_scanned = 0

    def _emit(stage: str, cur: int, total: int) -> None:
        if on_progress:
            on_progress(stage, cur, total)

    async def _get(url: str) -> FetchResult | None:
        async with sem:
            try:
                return await safe_fetch(url)
            except (SSRFError, Exception) as exc:
                errors.append((url, str(exc)))
                logger.debug("fetch failed %s: %s", url, exc)
                return None

    async def _head(url: str) -> FetchResult | None:
        async with sem:
            try:
                return await safe_fetch(url, method="HEAD")
            except Exception:
                return None

    # Stage 1 — robots.txt
    _emit("robots", 0, 1)
    robots = await _fetch_robots(orig, sem)

    # Stage 2 — entry page (direct semaphore acquire, not via _get so we can
    # return a detailed error rather than a silent None)
    _emit("entry", 0, 1)
    try:
        async with sem:
            entry = await safe_fetch(target_url)
    except (SSRFError, Exception) as exc:
        errors.append((target_url, str(exc)))
        return CrawlResult(
            origin=orig, entry_url=target_url, artifacts=[],
            response_headers={}, pages_crawled=0, assets_scanned=0, errors=errors,
        )

    # Re-derive origin from final URL (after any redirects)
    final_entry = _norm(entry.url)
    orig = _origin(final_entry)
    fetched.add(final_entry)
    resp_headers[final_entry] = entry.headers

    # Queues populated during BFS
    page_queue: deque[tuple[str, int, FetchResult]] = deque([(final_entry, 0, entry)])
    script_queue: dict[str, str] = {}   # url → source_page_url (last-writer wins)
    preload_queue: dict[str, str] = {}

    # Stage 3 — BFS page crawl (depth ≤ 2, ≤ max_pages)
    while page_queue and pages_crawled < settings.max_pages:
        url, depth, result = page_queue.popleft()
        pages_crawled += 1
        _emit("crawl", pages_crawled, settings.max_pages)

        ct = result.headers.get("content-type", "")
        if "html" not in ct and not result.content.lstrip()[:9].upper().startswith(b"<!DOCTYPE"):
            continue  # skip non-HTML responses that slipped through

        artifacts.append(Artifact(
            url=url, source_url=url, kind=ArtifactKind.HTML,
            content=result.content, headers=result.headers,
        ))

        try:
            soup = BeautifulSoup(result.content, "lxml")
        except Exception as exc:
            errors.append((url, f"HTML parse error: {exc}"))
            continue

        # Inline and external <script> tags
        for idx, tag in enumerate(soup.find_all("script")):
            src = tag.get("src")
            if src:
                abs_src = _norm(src, url)
                is_3p = not _same_origin(abs_src, orig)
                if not is_3p or include_third_party:
                    script_queue[abs_src] = url
            else:
                text = tag.get_text()
                if text.strip():
                    artifacts.append(Artifact(
                        url=f"inline:{url}:{idx}",
                        source_url=url,
                        kind=ArtifactKind.SCRIPT_INLINE,
                        content=text.encode("utf-8", errors="replace"),
                    ))

        # <link rel=preload> and <link rel=modulepreload>
        for tag in soup.find_all("link", rel=True):
            rel = " ".join(tag.get("rel", [])).lower()
            if "preload" in rel or "modulepreload" in rel:
                href = tag.get("href")
                if href:
                    abs_href = _norm(href, url)
                    if _same_origin(abs_href, orig):
                        preload_queue.setdefault(abs_href, url)

        # Inline event handlers, data-* attributes, <meta> tags
        _collect_meta(soup, url, artifacts)

        # Discover same-origin HTML links for BFS
        if depth < 2:
            candidates: list[str] = []
            for tag in soup.find_all("a", href=True):
                link = _norm(tag["href"], url)
                if (
                    _same_origin(link, orig)
                    and link not in fetched
                    and _is_html_path(link)
                    and _robots_ok(robots, link, ua)
                    and pages_crawled + len(candidates) < settings.max_pages
                ):
                    fetched.add(link)
                    candidates.append(link)
            if candidates:
                gathered = await asyncio.gather(*[_get(u) for u in candidates])
                for link, r in zip(candidates, gathered, strict=False):
                    if r and r.status_code == 200:
                        resp_headers[link] = r.headers
                        page_queue.append((link, depth + 1, r))

    # Stage 4 — fetch external scripts and preload assets
    all_assets = {**script_queue, **preload_queue}
    _emit("assets", 0, min(len(all_assets), settings.max_assets))
    for asset_url, src_page in all_assets.items():
        if assets_scanned >= settings.max_assets:
            break
        if asset_url in fetched:
            continue
        is_3p = not _same_origin(asset_url, orig)
        if not is_3p and not _robots_ok(robots, asset_url, ua):
            continue
        fetched.add(asset_url)
        r = await _get(asset_url)
        if r and r.status_code == 200:
            artifacts.append(Artifact(
                url=asset_url, source_url=src_page,
                kind=_kind_for(asset_url),
                content=r.content, headers=r.headers,
                is_third_party=is_3p,
            ))
            resp_headers[asset_url] = r.headers
            assets_scanned += 1
            _emit("assets", assets_scanned, settings.max_assets)

    # Stage 5 — source maps (only from external scripts)
    _emit("source_maps", 0, 1)
    seen_maps: set[str] = set()
    for art in list(artifacts):
        if art.kind != ArtifactKind.SCRIPT_EXTERNAL:
            continue
        map_url: str | None = None

        # Check //# sourceMappingURL= comment
        m = _SOURCE_MAP_RE.search(art.content)
        if m:
            ref = m.group(1).decode("utf-8", errors="replace").strip()
            if not ref.startswith("data:"):
                map_url = _norm(ref, art.url)

        # Check X-SourceMap / SourceMap response headers
        for hdr in ("x-sourcemap", "sourcemap"):
            if hdr_val := art.headers.get(hdr, "").strip():
                map_url = _norm(hdr_val, art.url)

        if not map_url or map_url in seen_maps or not _same_origin(map_url, orig):
            continue
        seen_maps.add(map_url)

        r = await _get(map_url)
        if not r or r.status_code != 200:
            continue

        artifacts.append(Artifact(
            url=map_url, source_url=art.url,
            kind=ArtifactKind.SOURCE_MAP,
            content=r.content, headers=r.headers,
        ))
        assets_scanned += 1

        # Parse sourcesContent entries
        try:
            sm = json.loads(r.content)
            sources: list[str] = sm.get("sources", [])
            for i, src_text in enumerate(sm.get("sourcesContent", [])):
                if not src_text:
                    continue
                src_name = sources[i] if i < len(sources) else f"src_{i}"
                artifacts.append(Artifact(
                    url=f"source_map_content:{map_url}:{i}:{src_name}",
                    source_url=map_url,
                    kind=ArtifactKind.SOURCE_MAP_CONTENT,
                    content=src_text.encode("utf-8", errors="replace"),
                ))
                assets_scanned += 1
        except (json.JSONDecodeError, TypeError) as exc:
            errors.append((map_url, f"source map parse: {exc}"))

    # Stage 6 — well-known path probing
    _emit("well_known", 0, len(_WELL_KNOWN_PATHS))
    for i, path in enumerate(_WELL_KNOWN_PATHS):
        probe_url = orig + path
        _emit("well_known", i, len(_WELL_KNOWN_PATHS))
        if probe_url in fetched:
            continue
        if not _robots_ok(robots, probe_url, ua):
            continue
        head = await _head(probe_url)
        if not head or head.status_code != 200:
            continue
        fetched.add(probe_url)
        r = await _get(probe_url)
        if r and r.status_code == 200:
            kind = _kind_for(probe_url)
            # HTML responses from well-known probes are unusual but keep original kind;
            # non-HTML well-known results that don't fit another category → WELL_KNOWN
            if kind == ArtifactKind.OTHER:
                kind = ArtifactKind.WELL_KNOWN
            artifacts.append(Artifact(
                url=probe_url, source_url=orig,
                kind=kind,
                content=r.content, headers=r.headers,
            ))
            resp_headers[probe_url] = r.headers
            assets_scanned += 1

    _emit("done", pages_crawled, pages_crawled)
    return CrawlResult(
        origin=orig,
        entry_url=final_entry,
        artifacts=artifacts,
        response_headers=resp_headers,
        pages_crawled=pages_crawled,
        assets_scanned=assets_scanned,
        errors=errors,
    )
