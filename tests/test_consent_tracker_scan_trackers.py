import json

import pytest

from consent_tracker_scan.trackers import CATEGORIES, Tracker, load_trackers

REQUIRED = {
    "www.google-analytics.com": ("Google Analytics", "analytics"),
    "region1.analytics.google.com": ("Google Analytics", "analytics"),
    "www.googletagmanager.com": ("Google Tag Manager", "tag_manager"),
    "googleads.g.doubleclick.net": ("Google Ads / DoubleClick", "advertising"),
    "connect.facebook.net": ("Meta Pixel", "social_pixel"),
    "analytics.tiktok.com": ("TikTok Pixel", "social_pixel"),
    "snap.licdn.com": ("LinkedIn Insight Tag", "social_pixel"),
    "static.hotjar.com": ("Hotjar", "session_replay"),
    "www.clarity.ms": ("Microsoft Clarity", "session_replay"),
    "www.youtube.com": ("YouTube embed", "embed"),
    "www.youtube-nocookie.com": ("YouTube embed", "embed"),
    "player.vimeo.com": ("Vimeo embed", "embed"),
    "static.ads-twitter.com": ("Twitter / X Pixel", "social_pixel"),
    "ct.pinterest.com": ("Pinterest Tag", "social_pixel"),
    "sc-static.net": ("Snap Pixel", "social_pixel"),
    "bat.bing.com": ("Microsoft Advertising UET (Bing)", "advertising"),
    "cdn.segment.com": ("Segment", "analytics"),
    "api-js.mixpanel.com": ("Mixpanel", "analytics"),
    "fonts.googleapis.com": ("Google Fonts", "cdn_fonts"),
    "fonts.gstatic.com": ("Google Fonts", "cdn_fonts"),
}


@pytest.mark.parametrize("host", sorted(REQUIRED))
def test_required_vendors_are_classified(host):
    tracker = load_trackers().match_host(host)
    assert tracker is not None, host
    assert (tracker.name, tracker.category) == REQUIRED[host]


def test_every_entry_is_documented():
    db = load_trackers()
    assert len(db.trackers) >= 20
    for t in db.trackers:
        assert t.category in CATEGORIES
        assert t.source, f"{t.name} has no source"
        assert t.domains or t.cookies, f"{t.name} matches nothing"
    used = {t.category for t in db.trackers}
    assert used == set(CATEGORIES)


def test_unknown_host_is_not_matched():
    assert load_trackers().match_host("cdn.my-own-shop.ca") is None


def test_cookie_and_storage_patterns():
    db = load_trackers()
    assert db.match_cookie("_ga_ABC123").name == "Google Analytics"
    assert db.match_cookie("_fbp").name == "Meta Pixel"
    assert db.match_cookie("_hjSessionUser_123").name == "Hotjar"
    assert db.match_cookie("mp_abc_mixpanel").name == "Mixpanel"
    assert db.match_cookie("IDE", "doubleclick.net").category == "advertising"
    assert db.match_cookie("sessionid") is None
    assert db.match_storage("ajs_anonymous_id").name == "Segment"
    assert db.match_storage("cart") is None


def test_extra_entries_take_priority(tmp_path):
    extra = {"name": "My Override", "category": "analytics", "domains": ["fonts.googleapis.com"]}
    db = load_trackers(extra=[extra])
    assert db.match_host("fonts.googleapis.com").name == "My Override"
    path = tmp_path / "extra.json"
    path.write_text(json.dumps({"trackers": [extra]}), encoding="utf-8")
    assert load_trackers(extra_file=path).match_host("fonts.googleapis.com").name == "My Override"


def test_bad_category_is_rejected():
    with pytest.raises(ValueError):
        Tracker.from_dict({"name": "x", "category": "spyware"})
