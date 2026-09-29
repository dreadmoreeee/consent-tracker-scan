"""High-level scan: robots.txt, crawl, browser, analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from .analyze import analyze
from .browser import BrowserSession
from .crawl import MAX_PAGES, crawl
from .robots import fetch_robots
from .trackers import TrackerDB, load_trackers


def scan_site(
    url: str,
    pages: int = 1,
    delay: float = 1.0,
    timeout: float = 30.0,
    wait_ms: int = 3000,
    trackers: TrackerDB | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Scan ``url`` (and up to ``pages`` same-origin pages) before consent.

    Raises ``ValueError`` for a bad URL and ``browser.BrowserUnavailable``
    when Chromium cannot start.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not an http(s) URL: {url!r}")
    pages = max(1, min(int(pages), MAX_PAGES))
    trackers = trackers or load_trackers()
    started = datetime.now(timezone.utc)
    robots = fetch_robots(url, timeout=min(timeout, 15.0))
    with BrowserSession(timeout=timeout, wait_ms=wait_ms) as session:
        observations, skipped = crawl(
            url, session.scan, robots, max_pages=pages, delay=delay, progress=progress
        )
        browser_version = session.version
    options = {
        "pages": pages,
        "delay": delay,
        "timeout": timeout,
        "wait_ms": wait_ms,
        "robots": robots.note,
        "browser": f"Chromium {browser_version} (headless, fresh profile per page)",
    }
    return analyze(
        url, observations, trackers, skipped_by_robots=skipped, options=options, now=started
    )
