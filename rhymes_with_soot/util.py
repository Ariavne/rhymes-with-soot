from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import request


def utcnow() -> datetime:
    """Return the current time as a naive UTC datetime.
    Avoids the 3.12 ``datetime.utcnow()`` deprecation; keeps SQLite comparisons working."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def safe_referrer(default=None):
    """Return the Referer only if safe to redirect to.
    Allows a relative path (single ``/``, not ``//``) or an absolute http(s) URL
    whose host matches the current request host. Prevents open-redirect via the Referer header."""
    ref = request.referrer
    if ref:
        parts = urlsplit(ref)
        if not parts.netloc:
            if ref.startswith("/") and not ref.startswith("//"):
                return ref
        elif parts.scheme in ("http", "https") and parts.netloc == request.host:
            return ref
    return default


def format_size(n: int) -> str:
    n = int(n or 0)
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"
