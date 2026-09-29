import json
from datetime import datetime, timezone

from consent_tracker_scan.analyze import analyze, exit_code
from consent_tracker_scan.report import one_line_summary, to_json, to_markdown
from consent_tracker_scan.trackers import load_trackers

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
YEAR = NOW.timestamp() + 365 * 86400


def observation(**overrides):
    obs = {
        "url": "https://shop.example.ca/",
        "final_url": "https://www.shop.example.ca/",
        "status": 200,
        "title": "Shop",
        "error": None,
        "requests": [
            {"url": "https://www.shop.example.ca/", "resource_type": "document", "method": "GET"},
            {"url": "https://cdn.shop.example.ca/app.js", "resource_type": "script", "method": "GET"},
            {"url": "https://www.googletagmanager.com/gtag/js?id=G-1", "resource_type": "script", "method": "GET"},
            {"url": "https://region1.google-analytics.com/g/collect?v=2", "resource_type": "fetch", "method": "POST"},
            {"url": "https://connect.facebook.net/en_US/fbevents.js", "resource_type": "script", "method": "GET"},
            {"url": "https://fonts.googleapis.com/css2?family=Inter", "resource_type": "stylesheet", "method": "GET"},
            {"url": "https://widgets.mystery-vendor.io/w.js", "resource_type": "script", "method": "GET"},
            {"url": "data:image/png;base64,xyz", "resource_type": "image", "method": "GET"},
        ],
        "cookies": [
            {"name": "_ga", "domain": ".shop.example.ca", "path": "/", "expires": YEAR, "httpOnly": False, "secure": False, "sameSite": "Lax", "size": 26},
            {"name": "sessionid", "domain": "www.shop.example.ca", "path": "/", "expires": -1, "httpOnly": True, "secure": True, "sameSite": "Lax", "size": 32},
            {"name": "fr", "domain": ".facebook.com", "path": "/", "expires": YEAR, "httpOnly": True, "secure": True, "sameSite": "None", "size": 40},
            {"name": "uid", "domain": ".mystery-vendor.io", "path": "/", "expires": YEAR, "httpOnly": False, "secure": True, "sameSite": "None", "size": 8},
        ],
        "storage": [
            {"origin": "https://www.shop.example.ca", "type": "localStorage", "key": "ajs_anonymous_id", "size": 38},
            {"origin": "https://www.shop.example.ca", "type": "localStorage", "key": "cart", "size": 2},
            {"origin": "https://www.shop.example.ca", "type": "sessionStorage", "key": "tab", "size": 1},
        ],
        "script_urls": ["https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"],
        "dom_hits": ["#onetrust-banner-sdk"],
        "generic_banner": {"found": False},
        "links": [],
    }
    obs.update(overrides)
    return obs


def make_report(*observations, skipped=()):
    return analyze(
        "https://shop.example.ca/",
        list(observations) or [observation()],
        load_trackers(),
        skipped_by_robots=list(skipped),
        options={"pages": 1},
        now=NOW,
    )


def test_site_follows_redirect_and_first_party_subdomains():
    report = make_report()
    assert report["site"] == "example.ca"
    hosts = {h["host"] for h in report["third_party_hosts"]}
    assert "cdn.shop.example.ca" not in hosts
    assert report["pages"][0]["first_party_requests"] == 2


def test_request_severities():
    hosts = {h["host"]: h for h in make_report()["third_party_hosts"]}
    assert hosts["region1.google-analytics.com"]["severity"] == "high"
    assert hosts["connect.facebook.net"]["category"] == "social_pixel"
    assert hosts["www.googletagmanager.com"]["severity"] == "medium"
    assert hosts["fonts.googleapis.com"]["severity"] == "low"
    unknown = hosts["widgets.mystery-vendor.io"]
    assert (unknown["tracker"], unknown["category"], unknown["severity"]) == (None, "unknown", "medium")


def test_cookie_classification():
    cookies = {c["name"]: c for c in make_report()["cookies"]}
    assert cookies["_ga"]["party"] == "first" and cookies["_ga"]["severity"] == "high"
    assert cookies["_ga"]["tracker"] == "Google Analytics"
    assert cookies["_ga"]["expires"] == "2027-09-28T12:00:00Z"
    assert cookies["_ga"]["expires_in_days"] == 365.0
    assert cookies["sessionid"]["severity"] == "info" and cookies["sessionid"]["expires"] == "session"
    assert cookies["sessionid"]["http_only"] and cookies["sessionid"]["secure"]
    assert cookies["fr"]["party"] == "third" and cookies["fr"]["tracker"] == "Meta Pixel"
    assert cookies["uid"]["severity"] == "medium" and cookies["uid"]["tracker"] is None


def test_storage_classification():
    storage = {s["key"]: s for s in make_report()["storage"]}
    assert storage["ajs_anonymous_id"]["severity"] == "high"
    assert storage["cart"]["severity"] == "info"
    assert storage["tab"]["type"] == "sessionStorage"


def test_summary_findings_and_exit_code():
    report = make_report()
    s = report["summary"]
    assert s["trackers"] == ["Google Analytics", "Meta Pixel", "Segment"]
    assert (s["high"], s["medium"], s["low"]) == (5, 3, 1)
    assert report["findings"][0]["severity"] == "high"
    assert report["consent_banner"]["cmp"] == "OneTrust"
    assert exit_code(report) == 1


def test_clean_site_exits_zero():
    obs = observation(
        requests=[{"url": "https://www.shop.example.ca/", "resource_type": "document", "method": "GET"}],
        cookies=[], storage=[], script_urls=[], dom_hits=[],
    )
    report = make_report(obs)
    assert report["findings"] == [] and exit_code(report) == 0
    assert any("No analytics" in n for n in report["notes"])


def test_nothing_scanned_exits_two():
    report = make_report(observation(error="net::ERR_CONNECTION_REFUSED", requests=[], cookies=[], storage=[]))
    assert report["summary"]["pages_scanned"] == 0
    assert exit_code(report) == 2


def test_notes_reference_law25_pipeda_and_disclaimer():
    notes = " ".join(make_report()["notes"])
    assert "not legal advice" in notes
    assert "Law 25" in notes and "8.1" in notes
    assert "PIPEDA" in notes
    assert "OneTrust" in notes


def test_notes_when_no_banner():
    report = make_report(observation(script_urls=[], dom_hits=[]))
    assert any("No consent banner was detected" in n for n in report["notes"])


def test_duplicates_merge_across_pages():
    a = observation()
    b = observation(url="https://shop.example.ca/about", final_url="https://www.shop.example.ca/about")
    report = make_report(a, b)
    ga = next(c for c in report["cookies"] if c["name"] == "_ga")
    assert ga["pages"] == ["https://www.shop.example.ca/", "https://www.shop.example.ca/about"]
    fb = next(h for h in report["third_party_hosts"] if h["host"] == "connect.facebook.net")
    assert fb["requests"] == 2


def test_json_and_markdown_output():
    report = make_report(skipped=["https://www.shop.example.ca/private"])
    data = json.loads(to_json(report))
    assert data["consent_given"] is False
    assert data["tool"] == "consent-tracker-scan"
    md = to_markdown(report)
    for heading in ("## Summary", "## Findings", "## Cookies (4)", "## Web storage (3)", "## Third-party hosts", "## Notes (not legal advice)"):
        assert heading in md
    assert "| high | first | .shop.example.ca | _ga |" in md
    assert "- https://www.shop.example.ca/private" in md
    assert "OneTrust" in one_line_summary(report)


def test_markdown_escapes_pipes():
    obs = observation(cookies=[{"name": "a|b", "domain": "www.shop.example.ca", "path": "/", "expires": -1}])
    assert "a\\|b" in to_markdown(make_report(obs))
