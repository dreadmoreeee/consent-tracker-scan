import socket

from consent_tracker_scan.crawl import MAX_PAGES, crawl, same_origin_links
from consent_tracker_scan.robots import RobotsPolicy, fetch_robots, robots_url


def test_policy_from_text():
    policy = RobotsPolicy.from_text("User-agent: *\nDisallow: /private\nCrawl-delay: 3\n")
    assert policy.can_fetch("http://example.com/")
    assert not policy.can_fetch("http://example.com/private/page.html")
    assert policy.crawl_delay() == 3.0


def test_policy_specific_user_agent():
    text = "User-agent: consent-tracker-scan\nDisallow: /\n\nUser-agent: *\nDisallow:\n"
    assert not RobotsPolicy.from_text(text).can_fetch("http://example.com/a")


def test_robots_url():
    assert robots_url("https://example.com:8443/a/b?c=1#d") == "https://example.com:8443/robots.txt"


def test_fetch_robots_from_local_server(site):
    site.add("/robots.txt", "User-agent: *\nDisallow: /secret\n", "text/plain")
    policy = fetch_robots(site.url("/"))
    assert policy.can_fetch(site.url("/ok"))
    assert not policy.can_fetch(site.url("/secret/x"))


def test_fetch_robots_404_allows_and_403_disallows(site):
    assert fetch_robots(site.url("/")).can_fetch(site.url("/anything"))
    site.add("/robots.txt", "no", "text/plain", status=403)
    assert not fetch_robots(site.url("/")).can_fetch(site.url("/anything"))


def test_fetch_robots_unreachable_allows_with_note():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    policy = fetch_robots(f"http://127.0.0.1:{port}/", timeout=2)
    assert policy.can_fetch(f"http://127.0.0.1:{port}/x")
    assert "not reachable" in policy.note


def test_same_origin_links_filters():
    links = [
        "http://a.test/page#top",
        "http://a.test/page",
        "http://b.test/other",
        "https://a.test/secure",
        "mailto:x@a.test",
        "http://a.test/file.pdf",
        "http://a.test",
    ]
    assert same_origin_links(links, {"http://a.test"}) == ["http://a.test/page", "http://a.test/"]


class FakeSite:
    """A fake page scanner: every page links to the pages in ``graph``."""

    def __init__(self, graph):
        self.graph = graph
        self.visited = []

    def __call__(self, url):
        self.visited.append(url)
        return {"url": url, "final_url": url, "links": self.graph.get(url, [])}


def test_crawl_respects_page_limit_and_order():
    graph = {"http://a.test/": [f"http://a.test/p{i}" for i in range(10)]}
    fake, sleeps = FakeSite(graph), []
    obs, skipped = crawl("http://a.test/", fake, RobotsPolicy.allow_all(), max_pages=3, delay=0.5, sleep=sleeps.append)
    assert fake.visited == ["http://a.test/", "http://a.test/p0", "http://a.test/p1"]
    assert len(obs) == 3 and skipped == []
    assert sleeps == [0.5, 0.5]


def test_crawl_caps_at_max_pages():
    graph = {"http://a.test/": [f"http://a.test/p{i}" for i in range(50)]}
    fake = FakeSite(graph)
    obs, _ = crawl("http://a.test/", fake, RobotsPolicy.allow_all(), max_pages=99, delay=0, sleep=lambda s: None)
    assert len(obs) == MAX_PAGES == 20


def test_crawl_skips_robots_disallowed_and_uses_crawl_delay():
    graph = {"http://a.test/": ["http://a.test/private/x", "http://a.test/ok", "http://other.test/"]}
    robots = RobotsPolicy.from_text("User-agent: *\nDisallow: /private\nCrawl-delay: 2\n")
    fake, sleeps = FakeSite(graph), []
    obs, skipped = crawl("http://a.test/", fake, robots, max_pages=5, delay=0.1, sleep=sleeps.append)
    assert fake.visited == ["http://a.test/", "http://a.test/ok"]
    assert skipped == ["http://a.test/private/x"]
    assert sleeps == [2.0]


def test_crawl_start_page_disallowed():
    fake = FakeSite({})
    obs, skipped = crawl("http://a.test/", fake, RobotsPolicy.disallow_all(), max_pages=5)
    assert obs == [] and skipped == ["http://a.test/"] and fake.visited == []
