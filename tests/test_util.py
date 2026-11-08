"""util.py helper tests, focused on the open-redirect guard."""
from datetime import datetime, timezone

from rhymes_with_soot.util import utcnow, safe_referrer, format_size


def test_utcnow_is_naive_utc(app):
    with app.test_request_context("/"):
        now = utcnow()
        assert now.tzinfo is None
        # Should be within a second of the real UTC now.
        delta = abs((datetime.now(timezone.utc).replace(tzinfo=None) - now).total_seconds())
        assert delta < 2


def test_format_size():
    assert format_size(512) == "512 B"
    assert format_size(2048) == "2.0 KB"
    assert format_size(5 * 1024 * 1024) == "5.0 MB"
    assert format_size(0) == "0 B"


def _ref(client, referer, host="example.com"):
    with client.application.test_request_context(
        "/", headers={"Referer": referer, "Host": host}
    ):
        return safe_referrer(default="/default")


def test_relative_referrer_allowed(client):
    assert _ref(client, "/dashboard") == "/dashboard"


def test_protocol_relative_referrer_rejected(client):
    # //evil.com is a protocol-relative URL pointing off-host.
    assert _ref(client, "//evil.com") == "/default"


def test_same_host_absolute_allowed(client):
    assert _ref(client, "https://example.com/dashboard", host="example.com") == (
        "https://example.com/dashboard"
    )


def test_cross_host_referrer_rejected(client):
    assert _ref(client, "https://evil.com/phish") == "/default"


def test_no_referrer_returns_default(client):
    assert _ref(client, None) == "/default"
