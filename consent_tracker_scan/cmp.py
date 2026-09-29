"""Consent banner (CMP) detection from script URLs and DOM selector hits.

The browser side only reports which of ``ALL_SELECTORS`` exist on the page
and what a generic heuristic found; the decision is made here so it can be
tested without a browser.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CMPSignature:
    name: str
    script_patterns: tuple[str, ...]
    selectors: tuple[str, ...]


SIGNATURES: tuple[CMPSignature, ...] = (
    CMPSignature(
        "OneTrust",
        ("cdn.cookielaw.org", "optanon.blob.core.windows.net", "otsdkstub.js", "otbannersdk.js", "onetrust.com"),
        ("#onetrust-banner-sdk", "#onetrust-consent-sdk", ".optanon-alert-box-wrapper"),
    ),
    CMPSignature(
        "Cookiebot",
        ("consent.cookiebot.com", "consentcdn.cookiebot.com", "/uc.js?cbid", "cookiebot"),
        ("#CybotCookiebotDialog", "#CookiebotWidget"),
    ),
    CMPSignature(
        "CookieYes",
        ("cdn-cookieyes.com", "cookieyes.com", "cookie-law-info"),
        (".cky-consent-container", ".cky-consent-bar", "#cookie-law-info-bar"),
    ),
    CMPSignature(
        "Complianz",
        ("complianz-gdpr", "complianz", "cmplz"),
        ("#cmplz-cookiebanner-container", ".cmplz-cookiebanner"),
    ),
    CMPSignature(
        "Osano",
        ("cmp.osano.com", "osano.js"),
        (".osano-cm-window", ".osano-cm-dialog"),
    ),
    CMPSignature(
        "Quantcast Choice",
        ("cmp.quantcast.com", "quantcast.mgr.consensu.org"),
        (".qc-cmp2-container", "#qc-cmp2-ui", "#qc-cmp2-container"),
    ),
    CMPSignature(
        "Usercentrics",
        ("app.usercentrics.eu", "web.cmp.usercentrics.eu"),
        ("#usercentrics-root", "#usercentrics-cmp-ui"),
    ),
    CMPSignature(
        "Didomi",
        ("sdk.privacy-center.org",),
        ("#didomi-host", "#didomi-notice"),
    ),
    CMPSignature(
        "TrustArc",
        ("consent.trustarc.com", "consent-pref.trustarc.com"),
        ("#truste-consent-track", "#teconsent"),
    ),
)

ALL_SELECTORS: tuple[str, ...] = tuple(
    sel for sig in SIGNATURES for sel in sig.selectors
)

# Runs in the page. Looks for a visible element that talks about cookies or
# consent and offers a button. It only reads the DOM; it never clicks.
GENERIC_BANNER_JS = r"""
() => {
  const nameRe = /cookie|consent|gdpr|privacy-banner|cc-window|cc-banner|cookie-notice|temoin/i;
  const textRe = /cookie|consent|t.moin|privacy|confidentialit/i;
  const buttonRe = /accept|agree|allow|got it|ok\b|okay|reject|decline|refuse|refuser|accepter|j'accepte|manage|preferences|settings|param/i;
  const candidates = document.querySelectorAll('div,section,aside,dialog,form,footer,[role="dialog"],[role="alertdialog"],[aria-modal="true"]');
  for (const el of candidates) {
    const label = (el.id || '') + ' ' + (typeof el.className === 'string' ? el.className : '') + ' ' + (el.getAttribute('aria-label') || '');
    if (!nameRe.test(label) && !/dialog/.test(el.getAttribute('role') || '')) continue;
    const text = (el.innerText || '').trim();
    if (!text || text.length > 4000 || !textRe.test(text)) continue;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') continue;
    const buttons = Array.from(el.querySelectorAll('button,a,input[type=button],input[type=submit],[role=button]'));
    if (!buttons.some(b => buttonRe.test((b.innerText || b.value || b.getAttribute('aria-label') || '')))) continue;
    const tag = el.tagName.toLowerCase() + (el.id ? '#' + el.id : '');
    return {found: true, element: tag, text: text.replace(/\s+/g, ' ').slice(0, 160)};
  }
  return {found: false};
}
"""


def detect_cmp(
    script_urls: list[str] | tuple[str, ...],
    dom_hits: list[str] | tuple[str, ...],
    generic: dict | None = None,
) -> dict:
    """Decide which consent banner is present.

    Returns ``{"detected", "cmp", "evidence"}``. A named CMP wins over the
    generic heuristic; the first signature with evidence is reported, other
    matches are listed in ``also_seen``.
    """
    lowered = [u.lower() for u in script_urls]
    hits = set(dom_hits)
    matches: list[tuple[str, list[str]]] = []
    for sig in SIGNATURES:
        evidence = [f"selector {s}" for s in sig.selectors if s in hits]
        for pattern in sig.script_patterns:
            for url in lowered:
                if pattern in url:
                    evidence.append(f"script {url}")
                    break
        if evidence:
            matches.append((sig.name, evidence))
    if matches:
        name, evidence = matches[0]
        return {
            "detected": True,
            "cmp": name,
            "evidence": evidence,
            "also_seen": [m[0] for m in matches[1:]],
        }
    if generic and generic.get("found"):
        return {
            "detected": True,
            "cmp": "generic",
            "evidence": [f"element {generic.get('element', '?')}: {generic.get('text', '')}"],
            "also_seen": [],
        }
    return {"detected": False, "cmp": None, "evidence": [], "also_seen": []}


# --- reject mode ---------------------------------------------------------------
# CMP-specific "reject all" buttons, then a text match. Only an element whose own
# text clearly means "refuse" is ever clicked; nothing else on the page is touched.
REJECT_SELECTORS: tuple[str, ...] = (
    "#onetrust-reject-all-handler",
    "#CybotCookiebotDialogBodyButtonDecline",
    ".cky-btn-reject",
    ".cmplz-deny",
    ".osano-cm-denyAll",
    "#didomi-notice-disagree-button",
    "[data-testid='uc-deny-all-button']",
    ".qc-cmp2-summary-buttons button[mode='secondary']",
    "#truste-consent-required",
)

FIND_REJECT_JS = r"""
(selectors) => {
  const visible = (el) => {
    const s = window.getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
  };
  const mark = (el, how) => {
    el.setAttribute('data-cts-reject', '1');
    return {found: true, how: how, text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 60)};
  };
  for (const sel of selectors) {
    let el = null;
    try { el = document.querySelector(sel); } catch (e) {}
    if (el && visible(el)) return mark(el, 'selector ' + sel);
  }
  const re = /^\s*(reject all|reject|decline all|decline|refuse all|refuse|deny all|deny|only necessary|only essential|necessary only|essential only|tout refuser|refuser|continuer sans accepter|rechazar todo|rechazar|no acepto)\s*[.!]?\s*$/i;
  const els = document.querySelectorAll('button,a,input[type=button],input[type=submit],[role=button]');
  for (const el of els) {
    const t = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
    if (t && re.test(t) && visible(el)) return mark(el, 'text');
  }
  return {found: false};
}
"""
