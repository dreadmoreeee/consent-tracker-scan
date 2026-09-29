"""Same-origin crawl loop. The page scanner is passed in, so this has no
browser dependency and can be tested with a fake scanner."""

from __future__ import annotations

import time
from collections import deque
from typing import Callable, Iterable
from urllib.parse import urldefrag, urlsplit, urlunsplit

from .domains import origin_of
from .robots import RobotsPolicy

MAX_PAGES = 20

SKIP_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".zip",
    ".gz", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".css", ".js", ".json",
    ".xml", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".woff",
    ".woff2", ".ttf", ".exe", ".dmg",
)


def normalize_url(url: str) -> str:
    url, _ = urldefrag(url.strip())
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, "")
    )


def same_origin_links(links: Iterable[str], origins: set[str]) -> list[str]:
    """Keep http(s) links on one of ``origins``, drop fragments and files."""
    seen: set[str] = set()
    out: list[str] = []
    for link in links:
        if not link:
            continue
        url = normalize_url(link)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            continue
        if origin_of(url) not in origins:
            continue
        if parts.path.lower().endswith(SKIP_EXTENSIONS):
            continue
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def crawl(
    start_url: str,
    scan_page: Callable[[str], dict],
    robots: RobotsPolicy,
    max_pages: int = 1,
    delay: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[dict], list[str]]:
    """Breadth-first crawl of up to ``max_pages`` same-origin pages.

    ``scan_page(url)`` must return an observation dict with at least
    ``final_url`` and ``links``. URLs disallowed by robots.txt are never
    requested; they are returned in the second list.
    """
    max_pages = max(1, min(int(max_pages), MAX_PAGES))
    wait = max(delay, robots.crawl_delay() or 0.0)
    start = normalize_url(start_url)
    origins = {origin_of(start)}
    queue: deque[str] = deque([start])
    queued = {start}
    observations: list[dict] = []
    skipped: list[str] = []
    while queue and len(observations) < max_pages:
        url = queue.popleft()
        if not robots.can_fetch(url):
            skipped.append(url)
            continue
        if observations and wait > 0:
            sleep(wait)
        if progress:
            progress(url)
        obs = scan_page(url)
        observations.append(obs)
        if len(observations) == 1 and obs.get("final_url"):
            # Follow a redirect such as example.com -> www.example.com.
            origins.add(origin_of(obs["final_url"]))
        for link in same_origin_links(obs.get("links", ()), origins):
            if link not in queued:
                queued.add(link)
                queue.append(link)
    return observations, skipped
