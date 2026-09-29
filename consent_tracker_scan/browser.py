"""The only module that talks to Playwright.

Each page is loaded in a fresh browser context (empty cookies and storage),
so every page is seen the way a first-time visitor landing on it sees it.
Nothing on the page is clicked, typed into or scrolled.
"""

from __future__ import annotations

from .cmp import ALL_SELECTORS, GENERIC_BANNER_JS


class BrowserUnavailable(RuntimeError):
    """Playwright or Chromium is missing or cannot start."""


STORAGE_JS = r"""
() => {
  const dump = (store) => {
    const out = [];
    try {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        out.push([k, (store.getItem(k) || '').length]);
      }
    } catch (e) {}
    return out;
  };
  let local = [], session = [];
  try { local = dump(window.localStorage); } catch (e) {}
  try { session = dump(window.sessionStorage); } catch (e) {}
  return {origin: window.location.origin, local, session};
}
"""

SELECTORS_JS = """
(sels) => sels.filter(s => { try { return !!document.querySelector(s); } catch (e) { return false; } })
"""


class BrowserSession:
    """Context manager around one headless Chromium process."""

    def __init__(self, timeout: float = 30.0, wait_ms: int = 3000, locale: str = "en-CA") -> None:
        self.timeout_ms = int(timeout * 1000)
        self.wait_ms = int(wait_ms)
        self.locale = locale
        self.version = ""
        self._pw = None
        self._browser = None

    def __enter__(self) -> "BrowserSession":
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as err:
            raise BrowserUnavailable("Playwright is not installed: pip install playwright") from err
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=True)
        except Exception as err:  # Playwright raises its own Error type
            self._pw.stop()
            first = str(err).strip().splitlines()[0] if str(err).strip() else type(err).__name__
            raise BrowserUnavailable(
                f"Chromium could not start ({first}). Try: python -m playwright install chromium"
            ) from err
        self.version = self._browser.version
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
        finally:
            if self._pw is not None:
                self._pw.stop()

    def scan(self, url: str) -> dict:
        """Load ``url`` once and return an observation dict.

        Keys: url, final_url, status, title, error, warning, requests,
        cookies, storage, script_urls, dom_hits, generic_banner, links.
        Cookie and storage values are not kept, only their length.
        """
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        obs: dict = {
            "url": url, "final_url": None, "status": None, "title": "", "error": None,
            "warning": None, "requests": [], "cookies": [], "storage": [],
            "script_urls": [], "dom_hits": [], "generic_banner": {"found": False}, "links": [],
        }
        context = self._browser.new_context(locale=self.locale, service_workers="block")
        try:
            context.on(
                "request",
                lambda r: obs["requests"].append(
                    {"url": r.url, "resource_type": r.resource_type, "method": r.method}
                ),
            )
            page = context.new_page()
            page.on(
                "websocket",
                lambda ws: obs["requests"].append(
                    {"url": ws.url, "resource_type": "websocket", "method": "GET"}
                ),
            )
            try:
                response = page.goto(url, wait_until="load", timeout=self.timeout_ms)
                obs["status"] = response.status if response else None
            except PlaywrightTimeout:
                obs["warning"] = f"load event did not fire within {self.timeout_ms // 1000}s; partial results"
            except PlaywrightError as err:
                obs["error"] = str(err).strip().splitlines()[0]
                return obs
            page.wait_for_timeout(self.wait_ms)
            obs["final_url"] = page.url
            obs["title"] = self._safe(page.title, "")
            obs["cookies"] = [
                {
                    "name": c.get("name", ""), "domain": c.get("domain", ""), "path": c.get("path", "/"),
                    "expires": c.get("expires", -1), "httpOnly": c.get("httpOnly", False),
                    "secure": c.get("secure", False), "sameSite": c.get("sameSite", ""),
                    "size": len(c.get("value", "")),
                }
                for c in context.cookies()
            ]
            obs["storage"] = self._storage(page)
            dom_scripts = self._safe(
                lambda: page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)"), []
            )
            net_scripts = [r["url"] for r in obs["requests"] if r["resource_type"] == "script"]
            obs["script_urls"] = list(dict.fromkeys(net_scripts + dom_scripts))
            obs["dom_hits"] = self._safe(lambda: page.evaluate(SELECTORS_JS, list(ALL_SELECTORS)), [])
            obs["generic_banner"] = self._safe(lambda: page.evaluate(GENERIC_BANNER_JS), {"found": False})
            obs["links"] = self._safe(
                lambda: page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)"), []
            )
        finally:
            context.close()
        return obs

    @staticmethod
    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            return default

    def _storage(self, page) -> list[dict]:
        seen: set[str] = set()
        out: list[dict] = []
        for frame in page.frames:
            data = self._safe(lambda: frame.evaluate(STORAGE_JS), None)
            if not data or data.get("origin") in (None, "null") or data["origin"] in seen:
                continue
            seen.add(data["origin"])
            for kind, items in (("localStorage", data["local"]), ("sessionStorage", data["session"])):
                for key, size in items:
                    out.append({"origin": data["origin"], "type": kind, "key": key, "size": size})
        return out
