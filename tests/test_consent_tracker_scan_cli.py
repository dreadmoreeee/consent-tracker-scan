import pytest

from consent_tracker_scan import cli
from consent_tracker_scan.browser import BrowserUnavailable


@pytest.mark.parametrize("pages", ["0", "21", "x"])
def test_pages_out_of_range_is_usage_error(pages, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["http://127.0.0.1/", "--pages", pages])
    assert exc.value.code == 2


def test_non_http_url_is_rejected(capsys):
    assert cli.main(["ftp://example.com/"]) == 2
    assert "not an http(s) URL" in capsys.readouterr().err


def test_browser_unavailable_exit_code(monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise BrowserUnavailable("Chromium could not start (test)")

    monkeypatch.setattr(cli, "scan_site", boom)
    assert cli.main(["http://127.0.0.1/"]) == 2
    assert "Chromium could not start" in capsys.readouterr().err


def test_bad_extra_trackers_file(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"trackers": [{"name": "x", "category": "nope"}]}', encoding="utf-8")
    assert cli.main(["http://127.0.0.1/", "--extra-trackers", str(bad)]) == 2
    assert "cannot load extra trackers" in capsys.readouterr().err


def test_module_entry_point_help():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    out = subprocess.run(
        [sys.executable, "-m", "consent_tracker_scan", "--help"],
        cwd=root, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0
    assert "--pages" in out.stdout and "Exit codes" in out.stdout
