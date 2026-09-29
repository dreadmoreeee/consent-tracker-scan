"""Load the bundled tracker list and match hosts, cookies and storage keys."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from importlib import resources
from pathlib import Path
from typing import Iterable

from .domains import host_matches, normalize_host

CATEGORIES = (
    "analytics",
    "advertising",
    "social_pixel",
    "session_replay",
    "tag_manager",
    "embed",
    "cdn_fonts",
    "consent",
)

# Categories that count as tracking before consent.
TRACKING_CATEGORIES = frozenset(
    {"analytics", "advertising", "social_pixel", "session_replay"}
)


@dataclass(frozen=True)
class Tracker:
    name: str
    category: str
    domains: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    storage: tuple[str, ...] = ()
    source: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Tracker":
        category = data.get("category", "")
        if category not in CATEGORIES:
            raise ValueError(f"unknown category {category!r} for {data.get('name')!r}")
        if not data.get("name"):
            raise ValueError("tracker entry without a name")
        return cls(
            name=data["name"],
            category=category,
            domains=tuple(normalize_host(d) for d in data.get("domains", ())),
            cookies=tuple(data.get("cookies", ())),
            storage=tuple(data.get("storage", ())),
            source=data.get("source", ""),
        )


@dataclass
class TrackerDB:
    trackers: list[Tracker] = field(default_factory=list)

    def match_host(self, host: str) -> Tracker | None:
        """Most specific (longest) matching domain wins."""
        best, best_len = None, -1
        for tracker in self.trackers:
            for domain in tracker.domains:
                if host_matches(host, domain) and len(domain) > best_len:
                    best, best_len = tracker, len(domain)
        return best

    def match_cookie(self, name: str, domain: str = "") -> Tracker | None:
        if domain:
            by_domain = self.match_host(domain)
            if by_domain is not None:
                return by_domain
        return self._match_pattern(name, "cookies")

    def match_storage(self, key: str, origin_host: str = "") -> Tracker | None:
        if origin_host:
            by_host = self.match_host(origin_host)
            if by_host is not None:
                return by_host
        return self._match_pattern(key, "storage")

    def _match_pattern(self, value: str, attr: str) -> Tracker | None:
        for tracker in self.trackers:
            for pattern in getattr(tracker, attr):
                if fnmatchcase(value, pattern):
                    return tracker
        return None


def _load_json(path: str | Path | None) -> dict:
    if path is None:
        text = (
            resources.files("consent_tracker_scan")
            .joinpath("data", "trackers.json")
            .read_text(encoding="utf-8")
        )
    else:
        text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def entries_from(data: dict | list) -> list[Tracker]:
    items = data.get("trackers", []) if isinstance(data, dict) else data
    return [Tracker.from_dict(item) for item in items]


def load_trackers(
    extra: Iterable[dict | Tracker] | None = None,
    extra_file: str | Path | None = None,
) -> TrackerDB:
    """Bundled list plus optional extra entries (extra entries win on ties)."""
    extras: list[Tracker] = []
    if extra_file is not None:
        extras.extend(entries_from(_load_json(extra_file)))
    for item in extra or ():
        extras.append(item if isinstance(item, Tracker) else Tracker.from_dict(item))
    return TrackerDB(extras + entries_from(_load_json(None)))
