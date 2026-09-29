"""Serve the demo site and its fake third parties on your own machine.

    python examples/serve_demo.py

Three local origins, so the browser sees three different sites:

    http://127.0.0.1:8401   the demo shop (first party)
    http://localhost:8402   "Demo Analytics", a fake tracker
    http://127.0.0.2:8403   a chat widget that is not in any tracker list

Then, in another terminal:

    python -m consent_tracker_scan http://127.0.0.1:8401/ --pages 3 \
        --extra-trackers examples/demo-trackers.json

Nothing here talks to the internet. Stop with Ctrl+C.
"""

from __future__ import annotations

import argparse
import mimetypes
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00"
    b"\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def make_handler(root: Path, replacements: dict[str, str], first_party: bool):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # keep the terminal readable
            print(f"{self.headers.get('Host', '?')} {self.command} {self.path}")

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/collect":
                # The fake tracker's beacon: sets a third-party cookie.
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header(
                    "Set-Cookie",
                    f"da_uid={secrets.token_hex(8)}; Max-Age=31536000; Path=/; SameSite=None; Secure",
                )
                self.send_header("Content-Length", str(len(GIF)))
                self.end_headers()
                self.wfile.write(GIF)
                return
            if path.endswith("/"):
                path += "index.html"
            file = (root / path.lstrip("/")).resolve()
            if root not in file.parents or not file.is_file():
                self.send_error(404)
                return
            body = file.read_bytes()
            if file.suffix in (".html", ".js"):
                text = body.decode("utf-8")
                for key, value in replacements.items():
                    text = text.replace(key, value)
                body = text.encode("utf-8")
            self.send_response(200)
            ctype = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or file.suffix == ".js":
                ctype += "; charset=utf-8"
            self.send_header("Content-Type", ctype)
            if first_party and file.suffix == ".html":
                self.send_header(
                    "Set-Cookie", f"shop_session={secrets.token_hex(8)}; Path=/; HttpOnly; SameSite=Lax"
                )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def start_demo(site_port: int = 8401, tracker_port: int = 8402, widget_port: int = 8403):
    """Start the three servers in background threads; return (servers, site_url)."""
    tracker = f"http://localhost:{tracker_port}"
    widget = f"http://127.0.0.2:{widget_port}"
    replacements = {"{{TRACKER}}": tracker, "{{WIDGET}}": widget}
    specs = [
        ("127.0.0.1", site_port, HERE / "demo_site", True),
        ("127.0.0.1", tracker_port, HERE / "demo_thirdparty", False),  # reached as "localhost"
        ("127.0.0.2", widget_port, HERE / "demo_thirdparty", False),
    ]
    servers = []
    for host, port, root, first_party in specs:
        server = ThreadingHTTPServer((host, port), make_handler(root.resolve(), replacements, first_party))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    return servers, f"http://127.0.0.1:{site_port}/"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--site-port", type=int, default=8401)
    parser.add_argument("--tracker-port", type=int, default=8402)
    parser.add_argument("--widget-port", type=int, default=8403)
    args = parser.parse_args()
    servers, url = start_demo(args.site_port, args.tracker_port, args.widget_port)
    print(f"Demo site: {url}  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
