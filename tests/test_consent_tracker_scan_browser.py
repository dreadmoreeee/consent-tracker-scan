"""End-to-end tests with real headless Chromium against local servers.

Skipped (with the reason) when Chromium cannot start.
"""

import json

import pytest

from consent_tracker_scan.analyze import exit_code
from consent_tracker_scan.cli import main
from consent_tracker_scan.scanner import scan_site
from consent_tracker_scan.trackers import load_trackers

FAST = {"delay": 0, "wait_ms": 400, "timeout": 15}

FAKE_TRACKER = {
    "name": "Fake Ads",
    "category": "advertising",
    "domains": ["localhost"],
    "cookies": ["_fk_*"],
    "storage": ["_fk_*"],
    "source": "tests (local fake tracker)",
}

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>{head}</head>
<body><h1>{title}</h1>{body}</body></html>"""


def page(title="Test", head="", body=""):
    return PAGE.format(title=title, head=head, body=body)


def serve_fake_tracker(tracker_host):
    tracker_host.add(
        "/t.js",
        "document.cookie = '_fk_id=abc123; path=/; max-age=86400';"
        "localStorage.setItem('_fk_seen', '1');"
        f"new Image().src = '{tracker_host.url('/pixel.gif')}?e=pageview';",
        "application/javascript",
    )
    tracker_host.add(
        "/pixel.gif", b"GIF89a", "image/gif",
        headers=[("Set-Cookie", "fk_uid=u1; Max-Age=86400; Path=/; SameSite=None; Secure")],
    )


def test_first_party_cookies_and_storage(chromium, site):
    site.add(
        "/",
        page(body="<script>document.cookie='pref=dark; path=/; max-age=3600';"
                  "localStorage.setItem('cart', '[]');"
                  "sessionStorage.setItem('tab', '1');</script>"),
        headers=[("Set-Cookie", "sid=s3cret; Path=/; HttpOnly; SameSite=Lax")],
    )
    report = scan_site(site.url("/"), **FAST)
    cookies = {c["name"]: c for c in report["cookies"]}
    assert set(cookies) == {"sid", "pref"}
    assert cookies["sid"]["http_only"] and cookies["sid"]["expires"] == "session"
    assert cookies["sid"]["party"] == "first" and cookies["sid"]["severity"] == "info"
    assert cookies["pref"]["expires"] != "session" and not cookies["pref"]["http_only"]
    storage = {(s["type"], s["key"]) for s in report["storage"]}
    assert storage == {("localStorage", "cart"), ("sessionStorage", "tab")}
    assert report["third_party_hosts"] == []
    assert report["pages"][0]["status"] == 200
    assert all("value" not in c for c in report["cookies"])  # values are never stored
    assert exit_code(report) == 0


def test_tracker_on_second_origin_is_classified(chromium, site, tracker_host):
    serve_fake_tracker(tracker_host)
    site.add("/", page(head=f'<script src="{tracker_host.url("/t.js")}"></script>'))
    report = scan_site(site.url("/"), trackers=load_trackers(extra=[FAKE_TRACKER]), **FAST)

    hosts = {h["host"]: h for h in report["third_party_hosts"]}
    assert hosts["localhost"]["tracker"] == "Fake Ads"
    assert hosts["localhost"]["severity"] == "high"
    assert hosts["localhost"]["requests"] == 2
    assert set(hosts["localhost"]["resource_types"]) == {"script", "image"}

    cookies = {c["name"]: c for c in report["cookies"]}
    assert cookies["_fk_id"]["party"] == "first"
    assert cookies["_fk_id"]["tracker"] == "Fake Ads" and cookies["_fk_id"]["severity"] == "high"
    assert cookies["fk_uid"]["party"] == "third" and cookies["fk_uid"]["severity"] == "high"
    assert cookies["fk_uid"]["secure"] and cookies["fk_uid"]["same_site"] == "None"

    storage = {s["key"]: s for s in report["storage"]}
    assert storage["_fk_seen"]["severity"] == "high"
    assert report["summary"]["trackers"] == ["Fake Ads"]
    assert exit_code(report) == 1


def test_unknown_third_party(chromium, site, tracker_host):
    tracker_host.add("/widget.js", "window.widget = 1;", "application/javascript")
    site.add("/", page(head=f'<script src="{tracker_host.url("/widget.js")}"></script>'))
    report = scan_site(site.url("/"), **FAST)
    host = report["third_party_hosts"][0]
    assert (host["host"], host["tracker"], host["category"], host["severity"]) == (
        "localhost", None, "unknown", "medium",
    )
    assert report["summary"]["unknown_third_party_hosts"] == 1
    assert any("Unknown third party localhost" in f["title"] for f in report["findings"])
    assert exit_code(report) == 0


BANNER_ONETRUST = """
<div id="onetrust-consent-sdk"><div id="onetrust-banner-sdk" role="dialog">
  <p>We use cookies to improve your experience.</p>
  <button id="onetrust-accept-btn-handler"
    onclick="document.cookie='OptanonAlertBoxClosed=1; path=/'; fetch('/accepted');">Accept All Cookies</button>
  <button id="onetrust-reject-all-handler">Reject All</button>
</div></div>
<script>
  // A real CMP would never do this, but it proves the scanner does not click.
  document.addEventListener('click', () => fetch('/clicked'), true);
</script>
"""


def test_onetrust_like_banner_detected_and_not_clicked(chromium, site):
    site.add("/otSDKStub.js", "window.OneTrustStub = true;", "application/javascript")
    site.add("/", page(head='<script src="/otSDKStub.js"></script>', body=BANNER_ONETRUST))
    report = scan_site(site.url("/"), **FAST)
    banner = report["consent_banner"]
    assert banner["detected"] and banner["cmp"] == "OneTrust"
    assert "selector #onetrust-banner-sdk" in banner["evidence"]
    assert any(e.startswith("script ") and "otsdkstub.js" in e for e in banner["evidence"])
    assert "/accepted" not in site.paths() and "/clicked" not in site.paths()
    assert "OptanonAlertBoxClosed" not in {c["name"] for c in report["cookies"]}


def test_cookiebot_like_and_generic_banners(chromium, site):
    site.add(
        "/",
        page(body='<div id="CybotCookiebotDialog"><p>This website uses cookies.</p>'
                  "<button onclick=\"fetch('/accepted')\">Allow all</button></div>"
                  '<a href="/generic">next</a>'),
    )
    site.add(
        "/generic",
        page(body='<div class="cookie-notice-container"><p>We use cookies on this site.</p>'
                  "<button onclick=\"fetch('/accepted')\">Got it</button></div>"),
    )
    report = scan_site(site.url("/"), pages=2, **FAST)
    assert [p["consent_banner"] for p in report["pages"]] == ["Cookiebot", "generic"]
    assert report["consent_banner"]["cmp"] == "Cookiebot"
    assert "/accepted" not in site.paths()


def test_no_banner(chromium, site):
    site.add("/", page(body="<p>Plain page.</p>"))
    assert scan_site(site.url("/"), **FAST)["consent_banner"]["detected"] is False


def link_farm(site, robots):
    site.add("/robots.txt", robots, "text/plain")
    links = "".join(f'<a href="{p}">{p}</a>' for p in ("/a", "/b", "/c", "/private/x", "/a#frag"))
    site.add("/", page(body=links))
    for p in ("/a", "/b", "/c", "/private/x"):
        site.add(p, page(title=p))


def test_pages_limit(chromium, site):
    link_farm(site, "User-agent: *\nDisallow:\n")
    report = scan_site(site.url("/"), pages=2, **FAST)
    assert [p["url"] for p in report["pages"]] == [site.url("/"), site.url("/a")]
    html_paths = [p for p in site.paths() if p not in ("/robots.txt", "/favicon.ico")]
    assert html_paths == ["/", "/a"]


def test_robots_disallow_is_respected(chromium, site):
    link_farm(site, "User-agent: *\nDisallow: /private/\n")
    report = scan_site(site.url("/"), pages=10, **FAST)
    assert report["summary"]["pages_scanned"] == 4
    assert report["skipped_by_robots"] == [site.url("/private/x")]
    assert "/private/x" not in site.paths()
    assert site.paths()[0] == "/robots.txt"


def test_robots_blocking_start_page_exits_two(chromium, site, capsys):
    site.add("/robots.txt", "User-agent: *\nDisallow: /\n", "text/plain")
    site.add("/", page())
    assert main([site.url("/"), "--quiet", "--delay", "0", "--wait-ms", "0"]) == 2
    assert site.paths() == ["/robots.txt"]
    assert "blocked by robots.txt" in capsys.readouterr().err


def test_cli_writes_json_and_markdown(chromium, site, tracker_host, tmp_path, capsys):
    serve_fake_tracker(tracker_host)
    site.add("/", page(head=f'<script src="{tracker_host.url("/t.js")}"></script>'))
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"trackers": [FAKE_TRACKER]}), encoding="utf-8")
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    code = main([
        site.url("/"), "--pages", "1", "--delay", "0", "--wait-ms", "400", "--timeout", "15",
        "--json", str(out_json), "--md", str(out_md), "--extra-trackers", str(extra), "--quiet",
    ])
    assert code == 1
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["trackers"] == ["Fake Ads"]
    assert data["options"]["pages"] == 1
    md = out_md.read_text(encoding="utf-8")
    assert "**HIGH** Fake Ads (advertising) loaded before consent" in md
    assert "not legal advice" in md
    assert "1 page(s):" in capsys.readouterr().out


def test_unreachable_site(chromium):
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    report = scan_site(f"http://127.0.0.1:{port}/", **FAST)
    assert report["pages"][0]["error"]
    assert exit_code(report) == 2
