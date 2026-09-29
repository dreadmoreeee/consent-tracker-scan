"""Turn raw page observations into a report with severities and notes.

No browser needed: the input is plain dicts (see ``browser.scan_page`` for
their shape), which keeps this module easy to test.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__
from .cmp import detect_cmp
from .domains import host_of, is_third_party, normalize_host, registrable_domain
from .trackers import TRACKING_CATEGORIES, Tracker, TrackerDB

SEVERITIES = ("high", "medium", "low", "info")
_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Severity of a third-party request, by tracker category.
REQUEST_SEVERITY = {
    "analytics": "high",
    "advertising": "high",
    "social_pixel": "high",
    "session_replay": "high",
    "tag_manager": "medium",
    "embed": "medium",
    "cdn_fonts": "low",
    "cookieless_analytics": "low",
    "consent": "info",
    "unknown": "medium",
}

DISCLAIMER = "This report is general information, not legal advice."


def _cookie_or_storage_severity(tracker: Tracker | None, third_party: bool) -> str:
    if tracker is None:
        return "medium" if third_party else "info"
    if tracker.category == "consent":
        return "info"
    if tracker.category in ("cdn_fonts", "cookieless_analytics"):
        return "low"
    return "high"


def _expiry(expires) -> str:
    if expires is None or expires < 0:
        return "session"
    try:
        return datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return str(expires)


def _expires_days(expires, now: float) -> float | None:
    if expires is None or expires < 0:
        return None
    return round((expires - now) / 86400, 1)


def _site_for(start_url: str, observations: list[dict]) -> str:
    for obs in observations:
        if not obs.get("error") and obs.get("final_url"):
            return registrable_domain(host_of(obs["final_url"]))
    return registrable_domain(host_of(start_url))


def analyze(
    start_url: str,
    observations: list[dict],
    trackers: TrackerDB,
    skipped_by_robots: list[str] | None = None,
    options: dict | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    now_ts = now.timestamp()
    site = _site_for(start_url, observations)

    cookies: dict[tuple, dict] = {}
    storage: dict[tuple, dict] = {}
    hosts: dict[str, dict] = {}
    requests: dict[str, dict] = {}
    pages: list[dict] = []
    banner = {"detected": False, "cmp": None, "evidence": [], "also_seen": []}

    for obs in observations:
        page_url = obs.get("final_url") or obs.get("url")
        page_banner = detect_cmp(
            obs.get("script_urls", ()), obs.get("dom_hits", ()), obs.get("generic_banner")
        )
        if page_banner["detected"] and not banner["detected"]:
            banner = dict(page_banner, page=page_url)
        first_party_requests = 0
        third_party_requests = 0

        for req in obs.get("requests", ()):
            url = req.get("url", "")
            if urlsplit(url).scheme not in ("http", "https", "ws", "wss"):
                continue
            host = host_of(url)
            if not host or not is_third_party(host, site):
                first_party_requests += 1
                continue
            third_party_requests += 1
            group = hosts.get(host)
            if group is None:
                tracker = trackers.match_host(host)
                category = tracker.category if tracker else "unknown"
                group = hosts[host] = {
                    "host": host,
                    "site": registrable_domain(host),
                    "tracker": tracker.name if tracker else None,
                    "category": category,
                    "severity": REQUEST_SEVERITY[category],
                    "source": tracker.source if tracker else None,
                    "requests": 0,
                    "resource_types": [],
                    "pages": [],
                }
            group["requests"] += 1
            rtype = req.get("resource_type") or "other"
            if rtype not in group["resource_types"]:
                group["resource_types"].append(rtype)
            if page_url not in group["pages"]:
                group["pages"].append(page_url)
            entry = requests.setdefault(
                url,
                {
                    "url": url,
                    "host": host,
                    "method": req.get("method", "GET"),
                    "resource_type": rtype,
                    "tracker": group["tracker"],
                    "category": group["category"],
                    "severity": group["severity"],
                    "count": 0,
                    "pages": [],
                },
            )
            entry["count"] += 1
            if page_url not in entry["pages"]:
                entry["pages"].append(page_url)

        for c in obs.get("cookies", ()):
            domain = normalize_host(c.get("domain", ""))
            key = (domain, c.get("name", ""), c.get("path", "/"))
            if key in cookies:
                if page_url not in cookies[key]["pages"]:
                    cookies[key]["pages"].append(page_url)
                continue
            third = is_third_party(domain, site)
            tracker = trackers.match_cookie(c.get("name", ""), domain if third else "")
            cookies[key] = {
                "name": c.get("name", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "party": "third" if third else "first",
                "expires": _expiry(c.get("expires")),
                "expires_in_days": _expires_days(c.get("expires"), now_ts),
                "secure": bool(c.get("secure")),
                "http_only": bool(c.get("httpOnly")),
                "same_site": c.get("sameSite") or "",
                "value_length": c.get("size", 0),
                "tracker": tracker.name if tracker else None,
                "category": tracker.category if tracker else "unknown",
                "severity": _cookie_or_storage_severity(tracker, third),
                "pages": [page_url],
            }

        for s in obs.get("storage", ()):
            origin = s.get("origin", "")
            key = (origin, s.get("type", "localStorage"), s.get("key", ""))
            if key in storage:
                if page_url not in storage[key]["pages"]:
                    storage[key]["pages"].append(page_url)
                continue
            ohost = host_of(origin)
            third = bool(ohost) and is_third_party(ohost, site)
            tracker = trackers.match_storage(s.get("key", ""), ohost if third else "")
            storage[key] = {
                "origin": origin,
                "type": s.get("type", "localStorage"),
                "key": s.get("key", ""),
                "party": "third" if third else "first",
                "value_length": s.get("size", 0),
                "tracker": tracker.name if tracker else None,
                "category": tracker.category if tracker else "unknown",
                "severity": _cookie_or_storage_severity(tracker, third),
                "pages": [page_url],
            }

        pages.append(
            {
                "url": obs.get("url"),
                "final_url": obs.get("final_url"),
                "status": obs.get("status"),
                "title": obs.get("title", ""),
                "error": obs.get("error"),
                "first_party_requests": first_party_requests,
                "third_party_requests": third_party_requests,
                "consent_banner": page_banner["cmp"] if page_banner["detected"] else None,
            }
        )

    cookie_list = sorted(cookies.values(), key=lambda c: (_ORDER[c["severity"]], c["party"], c["domain"], c["name"]))
    storage_list = sorted(storage.values(), key=lambda s: (_ORDER[s["severity"]], s["origin"], s["type"], s["key"]))
    host_list = sorted(hosts.values(), key=lambda h: (_ORDER[h["severity"]], h["host"]))
    findings = _findings(host_list, cookie_list, storage_list)
    summary = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITIES[:3]}
    summary.update(
        {
            "pages_scanned": sum(1 for p in pages if not p["error"]),
            "cookies": len(cookie_list),
            "first_party_cookies": sum(1 for c in cookie_list if c["party"] == "first"),
            "third_party_cookies": sum(1 for c in cookie_list if c["party"] == "third"),
            "storage_keys": len(storage_list),
            "third_party_hosts": len(host_list),
            "unknown_third_party_hosts": sum(1 for h in host_list if h["category"] == "unknown"),
            "trackers": sorted(
                {h["tracker"] for h in host_list if h["category"] in TRACKING_CATEGORIES}
                | {c["tracker"] for c in cookie_list if c["category"] in TRACKING_CATEGORIES}
                | {s["tracker"] for s in storage_list if s["category"] in TRACKING_CATEGORIES}
            ),
        }
    )
    report = {
        "tool": "consent-tracker-scan",
        "version": __version__,
        "scanned_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "start_url": start_url,
        "site": site,
        "options": options or {},
        "consent_given": False,
        "consent_banner": banner,
        "summary": summary,
        "findings": findings,
        "cookies": cookie_list,
        "storage": storage_list,
        "third_party_hosts": host_list,
        "third_party_requests": sorted(requests.values(), key=lambda r: (r["host"], r["url"])),
        "pages": pages,
        "skipped_by_robots": list(skipped_by_robots or ()),
        "disclaimer": DISCLAIMER,
    }
    report["notes"] = build_notes(report)
    return report


def _findings(host_list: list[dict], cookie_list: list[dict], storage_list: list[dict]) -> list[dict]:
    findings: list[dict] = []
    by_tracker: dict[str, list[dict]] = {}
    for h in host_list:
        if h["severity"] == "info":
            continue
        if h["tracker"]:
            by_tracker.setdefault(h["tracker"], []).append(h)
        else:
            findings.append(
                {
                    "severity": h["severity"],
                    "kind": "request",
                    "title": f"Unknown third party {h['host']} contacted before consent",
                    "detail": f"{h['requests']} request(s), types: {', '.join(h['resource_types'])}. Not in the tracker list; check what it is.",
                }
            )
    for name, groups in by_tracker.items():
        count = sum(g["requests"] for g in groups)
        category = groups[0]["category"]
        findings.append(
            {
                "severity": groups[0]["severity"],
                "kind": "request",
                "title": f"{name} ({category.replace('_', ' ')}) loaded before consent",
                "detail": f"{count} request(s) to {', '.join(g['host'] for g in groups)}.",
            }
        )
    for c in cookie_list:
        if c["severity"] == "info":
            continue
        who = f" by {c['tracker']} ({c['category'].replace('_', ' ')})" if c["tracker"] else ""
        findings.append(
            {
                "severity": c["severity"],
                "kind": "cookie",
                "title": f"{c['party'].capitalize()}-party cookie {c['name']} set{who} before consent",
                "detail": f"domain {c['domain']}, expires {c['expires']}.",
            }
        )
    for s in storage_list:
        if s["severity"] == "info":
            continue
        who = f" by {s['tracker']} ({s['category'].replace('_', ' ')})" if s["tracker"] else ""
        findings.append(
            {
                "severity": s["severity"],
                "kind": "storage",
                "title": f"{s['type']} key {s['key']} written{who} before consent",
                "detail": f"origin {s['origin']}.",
            }
        )
    kinds = {"request": 0, "cookie": 1, "storage": 2}
    findings.sort(key=lambda f: (_ORDER[f["severity"]], kinds[f["kind"]], f["title"]))
    return findings


def build_notes(report: dict) -> list[str]:
    """Plain-English notes tied to Quebec Law 25 and PIPEDA. Not legal advice."""
    notes = [DISCLAIMER + " It describes what a first-time visitor's browser did before any consent choice."]
    trackers = report["summary"]["trackers"]
    banner = report["consent_banner"]
    high = report["summary"]["high"]
    if trackers:
        notes.append(
            "Quebec Law 25: section 8.1 of Quebec's private-sector privacy act says a business that "
            "collects personal information with technology that can identify, locate or profile a person "
            "must first tell them, and tell them how to turn those functions on. The Commission d'acces a "
            "l'information reads this as those functions being off by default. "
            f"Here, {len(trackers)} tracker(s) ({', '.join(trackers)}) were active before any choice."
        )
        notes.append(
            "Quebec Law 25: section 9.1 (highest privacy settings by default) expressly does not apply to "
            "browser cookie settings, so the usual question under Law 25 is whether each tool above "
            "identifies, locates or profiles visitors."
        )
        notes.append(
            "PIPEDA: organisations need meaningful consent (Schedule 1, Principle 4.3). The Privacy "
            "Commissioner's guidance on online behavioural advertising accepts opt-out consent only when "
            "people are told clearly at or before the time of collection and can easily opt out. Tracking "
            "that starts on the first page view, before notice is shown, is hard to square with that."
        )
    if trackers and banner["detected"]:
        name = banner["cmp"] if banner["cmp"] != "generic" else "a generic cookie banner"
        notes.append(
            f"A consent banner was found ({name}), but the trackers above loaded before any choice. "
            "A banner only helps if tags wait for the visitor's choice (for example consent mode or a "
            "blocked-by-default tag setup)."
        )
    elif trackers:
        notes.append(
            "No consent banner was detected. Without notice at or before collection, neither the Law 25 "
            "transparency duty nor PIPEDA meaningful consent is likely to be met for the trackers above."
        )
    elif high:
        notes.append(
            "Tracker cookies or storage keys were found before consent even though no tracker request "
            "was seen; they may come from an earlier script or a first-party copy of a tracker."
        )
    else:
        notes.append(
            "No analytics, advertising, social pixel or session replay activity was seen before consent "
            "on the scanned pages."
        )
    if report["summary"]["unknown_third_party_hosts"]:
        notes.append(
            "Unknown third parties are not in the bundled list. They may be harmless (a CDN, an API) or "
            "trackers the list does not know; each one still receives the visitor's IP address."
        )
    notes.append(
        "The scan only sees what loaded on the scanned pages within the wait time, from this network "
        "location and browser. Trackers that fire later, on scroll or on other pages are not covered."
    )
    return notes


def exit_code(report: dict) -> int:
    """0 = no high findings, 1 = high findings, 2 = nothing could be scanned."""
    if report["summary"]["pages_scanned"] == 0:
        return 2
    return 1 if report["summary"]["high"] else 0
