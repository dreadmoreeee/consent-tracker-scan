"""Host helpers: registrable domain and first/third-party decisions.

This uses a small built-in list of multi-label public suffixes instead of the
full Public Suffix List, to stay dependency-free. It covers the common cases
(``example.co.uk``, ``example.qc.ca``, ``user.github.io``); unusual suffixes
fall back to "last two labels".
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

# Public suffixes with more than one label. Registrable domain = one label
# plus the longest matching suffix.
MULTI_LABEL_SUFFIXES = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk net.uk ltd.uk plc.uk
    com.au net.au org.au edu.au gov.au
    co.nz org.nz net.nz govt.nz
    co.jp ne.jp or.jp ac.jp
    com.br net.br org.br gov.br
    com.mx org.mx gob.mx
    co.za org.za gov.za
    com.cn net.cn org.cn gov.cn
    com.tw com.hk com.sg com.my com.ph com.tr com.ar com.co com.pe
    co.in net.in org.in gov.in co.kr or.kr co.il
    ab.ca bc.ca mb.ca nb.ca nf.ca nl.ca ns.ca nt.ca nu.ca on.ca pe.ca qc.ca
    sk.ca yk.ca gc.ca
    github.io gitlab.io netlify.app vercel.app pages.dev herokuapp.com
    blogspot.com wordpress.com azurewebsites.net cloudfront.net
    web.app firebaseapp.com appspot.com
    """.split()
)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def normalize_host(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def registrable_domain(host: str) -> str:
    """Return the registrable domain ("site") for a host name.

    IP addresses and single-label names such as ``localhost`` are returned
    unchanged, so ``127.0.0.1`` and ``localhost`` count as different sites,
    the same way browsers treat them.
    """
    host = normalize_host(host)
    if not host or _is_ip(host) or "." not in host:
        return host
    labels = host.split(".")
    for size in (3, 2):
        if len(labels) > size and ".".join(labels[-size:]) in MULTI_LABEL_SUFFIXES:
            return ".".join(labels[-size - 1:])
    return ".".join(labels[-2:])


def host_of(url: str) -> str:
    return normalize_host(urlsplit(url).hostname or "")


def is_third_party(host: str, site: str) -> bool:
    """True when ``host`` belongs to a different registrable domain than ``site``."""
    return registrable_domain(host) != registrable_domain(site)


def host_matches(host: str, domain: str) -> bool:
    """True when ``host`` equals ``domain`` or is a subdomain of it."""
    host, domain = normalize_host(host), normalize_host(domain)
    return host == domain or host.endswith("." + domain)


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = normalize_host(parts.hostname or "")
    port = parts.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port in (None, default) else f"{host}:{port}"
    return f"{scheme}://{netloc}"
