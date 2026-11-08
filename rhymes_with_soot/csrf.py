"""CSRF via signed HttpOnly cookie + synchronizer token.
The token is bound to the current identity: a token issued for one user (or for
anonymous) is rejected under a different identity."""
import logging
import secrets
import time

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import request, current_app, g, abort

logger = logging.getLogger("rhymes_with_soot")

CSRF_MAX_AGE = 7 * 24 * 3600


def _get_serializer():
    # "csrf" namespaces the shared rws_serializers cache: other serializer
    # kinds in this app reuse the (SECRET_KEY, ENV_PREFIX) prefix.
    key = (current_app.config["SECRET_KEY"], current_app.config["ENV_PREFIX"],
           "csrf")
    ext = current_app.extensions.setdefault("rws_serializers", {})
    if key not in ext:
        # Salt is namespaced by ENV_PREFIX so sites sharing a key (e.g. in dev)
        # don't cross-validate.
        ext[key] = URLSafeTimedSerializer(key[0], salt=f"{key[1]}-csrf")
    return ext[key]


def _current_identity() -> str:
    """Return the logged-in username, or "" when anonymous.
    Must be called within a request context."""
    from rhymes_with_soot.auth.session import get_current_user
    user = get_current_user()
    return user.username if user else ""


def get_csrf_token() -> str:
    """Return the current CSRF token, generating one if the cookie is absent, expired,
    or bound to a different identity. Cached on ``g``; rendered into templates via a
    context processor."""
    if hasattr(g, "csrf_token"):
        return g.csrf_token
    identity = _current_identity()
    cookie = request.cookies.get(current_app.config["CSRF_COOKIE"])
    if cookie:
        try:
            payload = _get_serializer().loads(cookie, max_age=CSRF_MAX_AGE)
            if payload.get("u") == identity:
                g.csrf_token = payload["t"]
                g.csrf_token_new = False
                return g.csrf_token
        except (BadSignature, SignatureExpired):
            pass
    g.csrf_token = secrets.token_hex(16)
    g.csrf_token_new = True
    return g.csrf_token


def sign_token(token: str, identity: str = "") -> str:
    payload = {"t": token, "u": identity, "exp": int(time.time()) + CSRF_MAX_AGE}
    return _get_serializer().dumps(payload)


def verify_csrf():
    """Ensure a state-changing request carries a valid token matching the
    cookie, and that the cookie is bound to the current session user."""
    token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if request.is_json:
        token = token or (request.json or {}).get("csrf_token")
    if not token:
        logger.warning("CSRF rejected (no token) %s %s ip=%s", request.method, request.path, request.remote_addr)
        abort(400)

    cookie = request.cookies.get(current_app.config["CSRF_COOKIE"])
    if not cookie:
        logger.warning("CSRF rejected (no cookie) %s %s ip=%s", request.method, request.path, request.remote_addr)
        abort(400)
    try:
        payload = _get_serializer().loads(cookie, max_age=CSRF_MAX_AGE)
    except (BadSignature, SignatureExpired):
        logger.warning("CSRF rejected (bad cookie signature) %s %s ip=%s", request.method, request.path, request.remote_addr)
        abort(400)

    if not secrets.compare_digest(token, payload["t"]):
        logger.warning("CSRF rejected (token mismatch) %s %s ip=%s", request.method, request.path, request.remote_addr)
        abort(400)

    if payload.get("u") != _current_identity():
        logger.warning("CSRF rejected (identity mismatch) %s %s ip=%s", request.method, request.path, request.remote_addr)
        abort(400)

    g.csrf_token = payload["t"]
