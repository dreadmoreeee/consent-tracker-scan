import pytest

from consent_tracker_scan.domains import (
    host_matches,
    is_third_party,
    origin_of,
    registrable_domain,
)


@pytest.mark.parametrize(
    "host, expected",
    [
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("www.ville.qc.ca", "ville.qc.ca"),
        ("marvin.github.io", "marvin.github.io"),
        ("WWW.Example.COM.", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_third_party_decisions():
    assert not is_third_party("cdn.example.com", "example.com")
    assert is_third_party("www.google-analytics.com", "example.com")
    assert is_third_party("localhost", "127.0.0.1")
    assert is_third_party("127.0.0.2", "127.0.0.1")
    assert is_third_party("bob.github.io", "alice.github.io")


def test_host_matches_is_suffix_on_label_boundary():
    assert host_matches("region1.google-analytics.com", "google-analytics.com")
    assert host_matches("google-analytics.com", "google-analytics.com")
    assert not host_matches("notgoogle-analytics.com", "google-analytics.com")


def test_origin_drops_default_port():
    assert origin_of("HTTPS://Example.com:443/x") == "https://example.com"
    assert origin_of("http://127.0.0.1:8080/a") == "http://127.0.0.1:8080"
