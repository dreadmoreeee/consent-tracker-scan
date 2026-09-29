"""Command line interface.

Exit codes: 0 no high-severity findings, 1 at least one high-severity
finding, 2 usage error or nothing could be scanned (bad URL, browser
missing, start page blocked by robots.txt or unreachable).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyze import exit_code
from .browser import BrowserUnavailable
from .crawl import MAX_PAGES
from .report import one_line_summary, to_json, to_markdown
from .scanner import scan_site
from .trackers import load_trackers


def _pages(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if not 1 <= n <= MAX_PAGES:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_PAGES}")
    return n


def _non_negative(value: str) -> float:
    try:
        n = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if n < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="consent-tracker-scan",
        description=(
            "Load a site in headless Chromium as a first-time visitor, never click the consent "
            "banner, and report cookies, web storage and third-party requests seen before consent."
        ),
        epilog="Exit codes: 0 no high findings, 1 high findings, 2 error or nothing scanned.",
    )
    p.add_argument("url", help="start URL (http or https)")
    p.add_argument("--pages", type=_pages, default=1, help=f"same-origin pages to scan, 1-{MAX_PAGES} (default 1)")
    p.add_argument("--delay", type=_non_negative, default=1.0, help="seconds between pages (default 1; robots.txt Crawl-delay wins if larger)")
    p.add_argument("--timeout", type=_non_negative, default=30.0, help="page load timeout in seconds (default 30)")
    p.add_argument("--wait-ms", type=int, default=3000, help="extra wait after the load event, in ms (default 3000)")
    p.add_argument("--json", metavar="FILE", help="write the JSON report here")
    p.add_argument("--md", metavar="FILE", help="write the Markdown report here")
    p.add_argument("--extra-trackers", metavar="FILE", help="JSON file with more tracker entries (same format as the bundled list)")
    p.add_argument("--quiet", action="store_true", help="no progress messages on stderr")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        trackers = load_trackers(extra_file=args.extra_trackers)
    except (OSError, ValueError) as err:
        print(f"error: cannot load extra trackers: {err}", file=sys.stderr)
        return 2
    progress = None if args.quiet else (lambda u: print(f"scanning {u}", file=sys.stderr))
    try:
        report = scan_site(
            args.url,
            pages=args.pages,
            delay=args.delay,
            timeout=args.timeout,
            wait_ms=max(0, args.wait_ms),
            trackers=trackers,
            progress=progress,
        )
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except BrowserUnavailable as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.json:
        Path(args.json).write_text(to_json(report), encoding="utf-8")
    if args.md:
        Path(args.md).write_text(to_markdown(report), encoding="utf-8")
    if args.json or args.md:
        print(one_line_summary(report))
    else:
        sys.stdout.write(to_markdown(report))
    code = exit_code(report)
    if code == 2:
        reason = "blocked by robots.txt" if report["skipped_by_robots"] else "could not be loaded"
        print(f"error: no page could be scanned (start page {reason})", file=sys.stderr)
    return code
