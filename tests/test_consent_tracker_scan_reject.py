"""--reject: click only the reject button, reload, check trackers stop."""

import json

from consent_tracker_scan.analyze import analyze_reject, exit_code
from consent_tracker_scan.cli import main
from consent_tracker_scan.report import one_line_summary, to_markdown
from consent_tracker_scan.scanner import scan_site
from consent_tracker_scan.trackers import load_trackers

FAST = {"delay": 0, "wait_ms": 400, "timeout": 15}

FAKE_TRACKER = {
    "name": "Fake Ads",
    "category": "advertising",
    "domains": ["localhost"],
    "cookies": ["_fk_*"],
    "storage": [],
    "source": "tests (local fake tracker)",
}
TRACKERS = load_trackers(extra=[FAKE_TRACKER])


def banner_page(tracker_url, honours_reject=True, buttons=None):
    buttons = buttons if buttons is not None else (
        '<button id="acc" onclick="decide(\'accepted\')">Accept all</button>'
        '<button id="rej" onclick="decide(\'rejected\')">Reject all</button>'
    )
    gate = "!document.cookie.includes('consent=rejected')" if honours_reject else "true"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Shop</title>
<script>
function decide(v) {{ document.cookie = 'consent=' + v + '; path=/; max-age=3600';
  document.getElementById('banner').remove(); }}
if ({gate}) {{ var s = document.createElement('script'); s.src = '{tracker_url}';
  document.head.appendChild(s); }}
</script></head><body><h1>Shop</h1>
<div id="banner" class="cookie-banner"><p>We use cookies.</p>{buttons}</div>
</body></html>"""


def serve_tracker(tracker_host):
    tracker_host.add("/t.js", "document.cookie='_fk_id=1; path=/; max-age=86400';",
                     "application/javascript")
    return tracker_host.url("/t.js")


def test_reject_honoured(chromium, site, tracker_host):
    site.add("/", banner_page(serve_tracker(tracker_host)))
    report = scan_site(site.url("/"), trackers=TRACKERS, reject=True, **FAST)
    rej = report["after_reject"]
    assert rej["verdict"] == "ok", rej
    assert rej["clicked"]["text"] == "Reject all"
    assert rej["tracking_requests"] == [] and rej["new_tracking_cookies"] == []
    md = to_markdown(report)
    assert "## After clicking Reject" in md and "OK: no tracking request" in md
    assert one_line_summary(report).endswith("after reject: ok")


def test_reject_ignored_is_a_failure(chromium, site, tracker_host):
    site.add("/", banner_page(serve_tracker(tracker_host), honours_reject=False))
    report = scan_site(site.url("/"), trackers=TRACKERS, reject=True, **FAST)
    rej = report["after_reject"]
    assert rej["verdict"] == "fail"
    assert [e["host"] for e in rej["tracking_requests"]] == ["localhost"]
    assert exit_code(report) == 1
    assert "FAIL: tracking continues" in to_markdown(report)


def test_accept_is_never_clicked(chromium, site, tracker_host):
    buttons = '<button onclick="decide(\'accepted\')">Accept all</button><button>Settings</button>'
    site.add("/", banner_page(serve_tracker(tracker_host), buttons=buttons))
    report = scan_site(site.url("/"), trackers=TRACKERS, reject=True, **FAST)
    assert report["after_reject"]["verdict"] == "no_button"
    assert report["after_reject"]["clicked"] is None
    assert "No reject button was found" in to_markdown(report)


def test_cmp_selector_is_preferred(chromium, site, tracker_host):
    buttons = ('<button id="onetrust-accept-btn-handler">OK</button>'
               '<button id="onetrust-reject-all-handler" onclick="decide(\'rejected\')">No thanks</button>')
    site.add("/", banner_page(serve_tracker(tracker_host), buttons=buttons))
    report = scan_site(site.url("/"), trackers=TRACKERS, reject=True, **FAST)
    rej = report["after_reject"]
    assert rej["verdict"] == "ok"
    assert rej["clicked"]["how"] == "selector #onetrust-reject-all-handler"


def test_without_flag_nothing_is_clicked(chromium, site, tracker_host):
    site.add("/", banner_page(serve_tracker(tracker_host)))
    report = scan_site(site.url("/"), trackers=TRACKERS, **FAST)
    assert "after_reject" not in report
    assert site.paths().count("/") == 1  # one page load, no second visit


def test_cli_reject_flag(chromium, site, tracker_host, tmp_path, capsys):
    site.add("/", banner_page(serve_tracker(tracker_host)))
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps([FAKE_TRACKER]), encoding="utf-8")
    out = tmp_path / "r.json"
    main([site.url("/"), "--reject", "--quiet", "--wait-ms", "400", "--delay", "0",
          "--extra-trackers", str(extra), "--json", str(out)])
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["after_reject"]["verdict"] == "ok"
    assert "after reject: ok" in capsys.readouterr().out


# --- pure analysis, no browser ------------------------------------------------

def test_analyze_reject_verdicts():
    site = "https://shop.example/"
    base = {"clicked": {"how": "text", "text": "Reject all"}, "error": None,
            "cookies_before": [{"name": "_fk_old", "domain": ".shop.example"}]}
    ok = analyze_reject({**base, "requests": [{"url": "https://shop.example/app.js"}],
                         "cookies_after": [{"name": "_fk_old", "domain": ".shop.example"},
                                           {"name": "consent", "domain": "shop.example"}]}, site, TRACKERS)
    assert ok["verdict"] == "ok"  # a tracker cookie set before the click is not blamed on reject
    bad = analyze_reject({**base, "requests": [{"url": "http://localhost:1/p.gif"}] * 2,
                          "cookies_after": [{"name": "_fk_new", "domain": ".shop.example"}]}, site, TRACKERS)
    assert bad["verdict"] == "fail"
    assert bad["tracking_requests"][0]["requests"] == 2
    assert bad["new_tracking_cookies"][0]["name"] == "_fk_new"
    assert analyze_reject({"clicked": None}, site, TRACKERS)["verdict"] == "no_button"
    assert analyze_reject({"error": "boom"}, site, TRACKERS)["verdict"] == "error"


def test_cookieless_analytics_after_reject_is_not_a_failure():
    r = analyze_reject({"clicked": {"how": "text", "text": "Decline"},
                        "requests": [{"url": "https://static.cloudflareinsights.com/beacon.min.js"}],
                        "cookies_before": [], "cookies_after": []}, "https://shop.example/", TRACKERS)
    assert r["verdict"] == "ok"
