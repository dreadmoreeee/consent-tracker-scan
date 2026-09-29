"""Local HTTP fixture servers (random free ports, no internet)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest


class FixtureServer:
    """Serves fixed routes and records every request as (host, path)."""

    def __init__(self, bind: str = "127.0.0.1", name: str = "127.0.0.1") -> None:
        self.routes: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}
        self.log: list[tuple[str, str]] = []
        self.name = name
        server_self = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                server_self.log.append((self.headers.get("Host", ""), self.path))
                status, headers, body = server_self.routes.get(
                    path, (404, [("Content-Type", "text/plain")], b"not found")
                )
                self.send_response(status)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer((bind, 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def origin(self) -> str:
        return f"http://{self.name}:{self.port}"

    def url(self, path: str = "/") -> str:
        return self.origin + path

    def add(self, path, body, content_type="text/html; charset=utf-8", status=200, headers=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.routes[path] = (status, [("Content-Type", content_type), *headers], body)

    def paths(self) -> list[str]:
        return [urlsplit(p).path for _, p in self.log]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def site():
    """First-party site on http://127.0.0.1:<random port>."""
    server = FixtureServer(name="127.0.0.1")
    yield server
    server.close()


@pytest.fixture
def tracker_host():
    """Second origin reached as http://localhost:<other port>.

    Chromium treats localhost and 127.0.0.1 as different sites, so this is a
    real third party from the browser's point of view.
    """
    server = FixtureServer(name="localhost")
    yield server
    server.close()


@pytest.fixture(scope="session")
def chromium():
    """Skip browser tests with a clear reason if Chromium cannot start."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright is not installed (pip install playwright)")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            version = browser.version
            browser.close()
    except Exception as err:  # pragma: no cover - depends on the machine
        pytest.skip(
            "Chromium could not start (" + str(err).strip().splitlines()[0]
            + "); run: python -m playwright install chromium"
        )
    return version
