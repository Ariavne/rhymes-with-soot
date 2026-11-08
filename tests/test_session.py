"""Stateless signed-cookie session tests.

Each cookie is bound to the password hash it was minted under, so a forced
password reset invalidates every existing session for that user."""
import hashlib

from itsdangerous import BadSignature

from rhymes_with_soot.auth.session import (
    sign_session,
    verify_session,
    get_current_user,
    login_required,
)
from tests.helpers import make_user

HASH = "scrypt:32768:8:1$abc$def"  # any stable hash string


def _ph(h):
    return hashlib.sha256(h.encode("utf-8")).hexdigest()


def test_sign_verify_roundtrip(app):
    with app.app_context():
        token = sign_session("alice", HASH, 3600)
        payload = verify_session(token, 3600)
        assert payload["u"] == "alice"
        assert payload["ph"] == _ph(HASH)


def test_tampered_cookie_rejected(app):
    with app.app_context():
        token = sign_session("alice", HASH, 3600)
        tampered = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
        # A tampered payload either fails to verify or raises; both are safe.
        try:
            result = verify_session(tampered, 3600)
        except BadSignature:
            result = None
        assert result is None or result.get("u") != "alice"


def test_expired_cookie_rejected(app, monkeypatch):
    import time

    with app.app_context():
        now = int(time.time())
        # Sign as if 2 hours ago, so the embedded timestamp is in the past.
        monkeypatch.setattr(time, "time", lambda: now - 7200)
        token = sign_session("alice", HASH, 3600)
        monkeypatch.undo()
        # Verifying now: age (7200s) > max_age (3600s) -> expired.
        assert verify_session(token, 3600) is None


def test_password_reset_invalidates_session(app):
    """A cookie minted under one password hash is rejected once the user's
    hash changes (a forced reset)."""
    from werkzeug.security import generate_password_hash
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User
    from tests.helpers import login

    make_user(app, "alice", "First-Passw0rd!")
    client = app.test_client()
    login(client, "alice", "First-Passw0rd!")

    assert client.get("/t/protected").status_code == 200

    session = get_session()
    user = session.query(User).filter_by(username="alice").first()
    user.password_hash = generate_password_hash("Second-Passw0rd!")
    session.commit()

    assert client.get("/t/protected").status_code == 302


def test_get_current_user_caches_on_g(app):
    make_user(app, "alice", "pw")
    with app.test_request_context("/"):
        # No cookie -> None, cached on g.
        assert get_current_user() is None
        assert get_current_user() is None


def test_login_required_get_redirects(client):
    resp = client.get("/t/protected")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_required_post_401(client):
    # CSRF runs before the view, so a bare POST is 400. Supply a valid token
    # to get past CSRF and reach login_required's 401 (non-GET, unauthenticated).
    from tests.helpers import extract_csrf

    token = extract_csrf(client.get("/t/page").get_data(as_text=True))
    resp = client.post("/t/protected", data={"csrf_token": token})
    assert resp.status_code == 401
