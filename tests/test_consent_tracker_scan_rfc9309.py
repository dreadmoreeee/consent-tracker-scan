"""RFC 9309 robots.txt matching (the stdlib parser gets these wrong)."""
import pytest

from consent_tracker_scan.rfc9309 import RobotsTxt

UA = "mytool/1.0 (+https://example.org)"

DEMARK_STYLE = """User-agent: *
Allow: /
Disallow: /api/
Disallow: /app/
Disallow: /admin/

Sitemap: https://example.org/sitemap.xml
"""


@pytest.mark.parametrize("path,ok", [
    ("/", True), ("/en/pricing", True), ("/app/login", False), ("/app/", False),
    ("/api/v1/x", False), ("/admin", True), ("/admin/users", False), ("/robots.txt", True),
])
def test_most_specific_rule_wins_even_after_allow_all(path, ok):
    r = RobotsTxt(DEMARK_STYLE)
    assert r.can_fetch(UA, "https://example.org" + path) is ok
    assert r.sitemaps == ["https://example.org/sitemap.xml"]


def test_tie_goes_to_allow_and_wildcards_work():
    r = RobotsTxt("User-agent: *\nDisallow: /page\nAllow: /page\nDisallow: /*.pdf$\nDisallow: /tmp*/cache\n")
    assert r.can_fetch(UA, "https://x.org/page")
    assert not r.can_fetch(UA, "https://x.org/files/a.pdf")
    assert r.can_fetch(UA, "https://x.org/files/a.pdf?v=2")
    assert not r.can_fetch(UA, "https://x.org/tmp-1/cache/z")


def test_specific_user_agent_group_replaces_star_group():
    txt = "User-agent: *\nDisallow: /\n\nUser-agent: mytool\nDisallow: /private\nCrawl-delay: 3\n"
    r = RobotsTxt(txt)
    assert r.can_fetch(UA, "https://x.org/public")
    assert not r.can_fetch(UA, "https://x.org/private/a")
    assert not r.can_fetch("otherbot/2.0", "https://x.org/public")
    assert r.crawl_delay(UA) == 3.0


def test_empty_file_and_empty_disallow_allow_everything():
    assert RobotsTxt("").can_fetch(UA, "https://x.org/anything")
    assert RobotsTxt("User-agent: *\nDisallow:\n").can_fetch(UA, "https://x.org/anything")


def test_percent_encoding_is_compared_consistently():
    r = RobotsTxt("User-agent: *\nDisallow: /caf%C3%A9\n")
    assert not r.can_fetch(UA, "https://x.org/caf%c3%a9/menu")


def test_cookieless_analytics_is_known_and_low_severity():
    from consent_tracker_scan.analyze import REQUEST_SEVERITY
    from consent_tracker_scan.trackers import load_trackers

    db = load_trackers()
    hit = db.match_host("static.cloudflareinsights.com")
    assert hit is not None and hit.name == "Cloudflare Web Analytics"
    assert hit.category == "cookieless_analytics"
    assert REQUEST_SEVERITY["cookieless_analytics"] == "low"
