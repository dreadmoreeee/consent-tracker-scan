"""See what a website does before the visitor gives consent."""

__version__ = "0.1.0"


def scan_site(*args, **kwargs):
    """Shortcut for :func:`consent_tracker_scan.scanner.scan_site`."""
    from .scanner import scan_site as _scan_site

    return _scan_site(*args, **kwargs)
