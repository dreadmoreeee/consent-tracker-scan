"""robots.txt handling (RFC 9309 matching, see rfc9309.py) with a fetch timeout."""

from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .rfc9309 import RobotsTxt

USER_AGENT = "consent-tracker-scan"
USER_AGENT_HEADER = f"{USER_AGENT}/{__version__} (+https://marvin.demarkstudio.ca)"


class RobotsPolicy:
    """Answers "may this URL be fetched?" for one origin."""

    def __init__(self, parser: RobotsTxt | None, note: str = "") -> None:
        self._parser = parser
        self.note = note

    @classmethod
    def allow_all(cls, note: str = "") -> "RobotsPolicy":
        return cls(None, note)

    @classmethod
    def from_text(cls, text: str, note: str = "") -> "RobotsPolicy":
        return cls(RobotsTxt(text), note)

    @classmethod
    def disallow_all(cls, note: str = "") -> "RobotsPolicy":
        return cls.from_text("User-agent: *\nDisallow: /\n", note)

    def can_fetch(self, url: str) -> bool:
        if self._parser is None:
            return True
        return self._parser.can_fetch(USER_AGENT, url)

    def crawl_delay(self) -> float | None:
        if self._parser is None:
            return None
        delay = self._parser.crawl_delay(USER_AGENT)
        return float(delay) if delay is not None else None


def robots_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))


def fetch_robots(url: str, timeout: float = 10.0) -> RobotsPolicy:
    """Fetch and parse robots.txt for the origin of ``url``.

    Status handling follows ``RobotFileParser.read``: 401/403 mean
    "disallow everything", other 4xx mean "allow everything". Server errors
    and network failures are treated as "allow" and noted in the report.
    """
    target = robots_url(url)
    request = urllib.request.Request(target, headers={"User-Agent": USER_AGENT_HEADER})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(512 * 1024)
    except urllib.error.HTTPError as err:
        if err.code in (401, 403):
            return RobotsPolicy.disallow_all(f"robots.txt returned {err.code}: treated as disallow all")
        if 400 <= err.code < 500:
            return RobotsPolicy.allow_all(f"no robots.txt ({err.code})")
        return RobotsPolicy.allow_all(f"robots.txt returned {err.code}: treated as allow all")
    except (urllib.error.URLError, OSError, ValueError) as err:
        return RobotsPolicy.allow_all(f"robots.txt not reachable ({err}): treated as allow all")
    return RobotsPolicy.from_text(raw.decode("utf-8", errors="replace"), f"robots.txt read from {target}")
