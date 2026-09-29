import pytest

from consent_tracker_scan.cmp import SIGNATURES, detect_cmp


@pytest.mark.parametrize("sig", SIGNATURES, ids=lambda s: s.name)
def test_each_cmp_detected_by_selector(sig):
    result = detect_cmp([], [sig.selectors[0]])
    assert result["detected"] and result["cmp"] == sig.name


@pytest.mark.parametrize(
    "url, name",
    [
        ("https://cdn.cookielaw.org/scripttemplates/otSDKStub.js", "OneTrust"),
        ("https://consent.cookiebot.com/uc.js?cbid=abc", "Cookiebot"),
        ("https://cdn-cookieyes.com/client_data/x/script.js", "CookieYes"),
        ("https://shop.ca/wp-content/plugins/complianz-gdpr/cookiebanner/js/complianz.min.js", "Complianz"),
        ("https://cmp.osano.com/abc/osano.js", "Osano"),
        ("https://cmp.quantcast.com/choice/abc/example.com/choice.js", "Quantcast Choice"),
    ],
)
def test_cmp_detected_by_script_url(url, name):
    assert detect_cmp([url], [])["cmp"] == name


def test_generic_banner_is_fallback():
    generic = {"found": True, "element": "div#cookie-notice", "text": "We use cookies. Accept"}
    result = detect_cmp(["https://example.com/app.js"], [], generic)
    assert result == {
        "detected": True,
        "cmp": "generic",
        "evidence": ["element div#cookie-notice: We use cookies. Accept"],
        "also_seen": [],
    }


def test_named_cmp_beats_generic_and_others_listed():
    result = detect_cmp([], ["#CybotCookiebotDialog", "#onetrust-banner-sdk"], {"found": True})
    assert result["cmp"] == "OneTrust"
    assert result["also_seen"] == ["Cookiebot"]


def test_nothing_detected():
    assert detect_cmp(["https://example.com/app.js"], [], {"found": False})["detected"] is False
