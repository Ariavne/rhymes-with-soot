"""Stateless signed cookie session. Valid on any worker; no server-side store.
Each cookie is bound to the password hash it was minted under, so a forced
password reset invalidates every existing session for that user."""
import hashlib
import hmac
import time
from functools import wraps

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import request, current_app, g, redirect, url_for, abort

def _get_serializer():
    # "session" namespaces the shared rws_serializers cache: other serializer
    # kinds in this app reuse the (SECRET_KEY, ENV_PREFIX) prefix.
    key = (current_app.config["SECRET_KEY"], current_app.config["ENV_PREFIX"],
           "session")
    ext = current_app.extensions.setdefault("rws_serializers", {})
    if key not in ext:
        ext[key] = URLSafeTimedSerializer(key[0], salt=key[1])
    return ext[key]


def _hash_password(password_hash: str) -> str:
    """SHA-256 fingerprint of the user's password hash, carried in the
    session payload. The salted hash itself never leaves the database; the
    digest is enough to bind a cookie to the password generation it was
    minted under."""
    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()


def sign_session(username: str, password_hash: str) -> str:
    payload = {
        "u": username,
        "ph": _hash_password(password_hash),
    }
    return _get_serializer().dumps(payload)


def verify_session(cookie_value: str, max_age: int):
    """Return the session payload {u, ph}, or None when the cookie is
    missing a valid signature or is expired."""
    try:
        return _get_serializer().loads(cookie_value, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


def get_current_user():
    """Load the current user from the session cookie. Returns User or None.
    Cached on ``g`` for the request. A cookie whose password fingerprint
    does not match the user's current hash is rejected (forced reset)."""
    if hasattr(g, "current_user"):
        return g.current_user

    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    cookie = request.cookies.get(current_app.config["SESSION_COOKIE"])
    if not cookie:
        g.current_user = None
        return None

    payload = verify_session(cookie, current_app.config["SESSION_MAX_AGE"])
    if not payload:
        g.current_user = None
        return None

    session = get_session()
    user = session.query(User).filter_by(username=payload.get("u")).first()
    if user is None or not hmac.compare_digest(
            str(payload.get("ph") or ""),
            _hash_password(user.password_hash)):
        g.current_user = None
        return None
    g.current_user = user
    return user


def login_required(f):
    """Decorator: require an authenticated user.

    Redirects to the login page for GET requests (with a ``next`` param so the
    user returns to the page they asked for), returns 401 for others.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if user is None:
            if request.method == "GET":
                qs = request.query_string.decode()
                next_url = request.path + ("?" + qs if qs else "")
                return redirect(url_for("auth.login", next=next_url))
            abort(401)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator: require an authenticated user with role 'admin'.

    Like login_required for anonymous users (login redirect / 401), then 403
    for authenticated non-admins.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if user is None:
            if request.method == "GET":
                qs = request.query_string.decode()
                next_url = request.path + ("?" + qs if qs else "")
                return redirect(url_for("auth.login", next=next_url))
            abort(401)
        if user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated
