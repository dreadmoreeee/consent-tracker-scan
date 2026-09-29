"""JSON and Markdown rendering of a report dict."""

from __future__ import annotations

import json


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return lines


def _flags(c: dict) -> str:
    flags = []
    if c["secure"]:
        flags.append("Secure")
    if c["http_only"]:
        flags.append("HttpOnly")
    if c["same_site"]:
        flags.append(f"SameSite={c['same_site']}")
    return " ".join(flags)


def to_markdown(report: dict) -> str:
    s = report["summary"]
    banner = report["consent_banner"]
    opts = report.get("options", {})
    out = [
        f"# Consent tracker scan: {report['start_url']}",
        "",
        f"Scanned {report['scanned_at']} as a first-time visitor. No consent was given and no banner "
        f"was clicked. Site: `{report['site']}`. Pages scanned: {s['pages_scanned']}"
        + (f" (limit {opts['pages']})" if "pages" in opts else "")
        + ".",
        "",
        "## Summary",
        "",
        f"- Findings: **{s['high']} high**, {s['medium']} medium, {s['low']} low",
        f"- Consent banner: "
        + (f"detected ({banner['cmp']})" if banner["detected"] else "not detected"),
        f"- Cookies: {s['cookies']} ({s['first_party_cookies']} first-party, {s['third_party_cookies']} third-party)",
        f"- Web storage keys: {s['storage_keys']}",
        f"- Third-party hosts: {s['third_party_hosts']} ({s['unknown_third_party_hosts']} unknown)",
        f"- Trackers before consent: {', '.join(s['trackers']) if s['trackers'] else 'none'}",
        "",
        "## Findings",
        "",
    ]
    if report["findings"]:
        for f in report["findings"]:
            out.append(f"- **{f['severity'].upper()}** {f['title']}. {f['detail']}")
    else:
        out.append("No findings.")
    out += ["", f"## Cookies ({s['cookies']})", ""]
    if report["cookies"]:
        out += _table(
            ["Severity", "Party", "Domain", "Name", "Expires", "Flags", "Tracker"],
            [
                [c["severity"], c["party"], c["domain"], c["name"], c["expires"], _flags(c), c["tracker"] or ""]
                for c in report["cookies"]
            ],
        )
    else:
        out.append("None.")
    out += ["", f"## Web storage ({s['storage_keys']})", ""]
    if report["storage"]:
        out += _table(
            ["Severity", "Party", "Origin", "Type", "Key", "Tracker"],
            [
                [x["severity"], x["party"], x["origin"], x["type"], x["key"], x["tracker"] or ""]
                for x in report["storage"]
            ],
        )
    else:
        out.append("None.")
    out += ["", f"## Third-party hosts ({s['third_party_hosts']})", ""]
    if report["third_party_hosts"]:
        out += _table(
            ["Severity", "Host", "Tracker", "Category", "Requests", "Types"],
            [
                [h["severity"], h["host"], h["tracker"] or "unknown", h["category"], h["requests"], ", ".join(h["resource_types"])]
                for h in report["third_party_hosts"]
            ],
        )
    else:
        out.append("None.")
    out += ["", "## Pages", ""]
    out += _table(
        ["URL", "Status", "3rd-party requests", "Banner", "Error"],
        [
            [p["final_url"] or p["url"], p["status"], p["third_party_requests"], p["consent_banner"] or "", p["error"] or ""]
            for p in report["pages"]
        ],
    )
    if report["skipped_by_robots"]:
        out += ["", "Skipped because robots.txt disallows them:", ""]
        out += [f"- {u}" for u in report["skipped_by_robots"]]
    if banner["detected"]:
        out += ["", "## Consent banner evidence", ""]
        out += [f"- {e}" for e in banner["evidence"]]
    out += ["", "## Notes (not legal advice)", ""]
    out += [f"- {n}" for n in report["notes"]]
    out.append("")
    return "\n".join(out)


def one_line_summary(report: dict) -> str:
    s = report["summary"]
    banner = report["consent_banner"]
    return (
        f"{s['pages_scanned']} page(s): {s['high']} high, {s['medium']} medium, {s['low']} low; "
        f"{s['cookies']} cookie(s), {s['storage_keys']} storage key(s), "
        f"{s['third_party_hosts']} third-party host(s); banner: "
        + (banner["cmp"] if banner["detected"] else "none")
    )
