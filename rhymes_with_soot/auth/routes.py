"""Authentication routes. The framework owns only /login and /logout; a site provides /.
After login, the user is redirected to LOGIN_REDIRECT."""
import logging

from flask import (
    Blueprint, request, render_template, redirect, url_for,
    make_response, current_app,
)
from werkzeug.security import check_password_hash, generate_password_hash

from rhymes_with_soot.auth.session import sign_session, get_current_user

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger("rhymes_with_soot")

# A precomputed hash checked when the username is unknown, so a failed
# login costs the same time whether or not the account exists.
_DUMMY_HASH = generate_password_hash("timing-equalizer-not-a-real-password")


def _login_redirect():
    return current_app.config.get("LOGIN_REDIRECT", "/")


def _safe_next(default):
    """Return the ``next`` param if it is a same-origin path, else default.

    Rejects absolute URLs and protocol-relative URLs (``//evil.example``) to
    prevent open redirects.

    Read from the form body first: the login form carries ``next`` as a hidden
    field, so on POST it is not in the query string.
    """
    nxt = request.form.get("next", "") or request.args.get("next", "")
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return default


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if get_current_user():
            return redirect(_safe_next(_login_redirect()))
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template("login.html", error="Username and password are required."), 400

    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    user = session.query(User).filter_by(username=username).first()

    hash_to_check = user.password_hash if user is not None else _DUMMY_HASH
    if user is None or not check_password_hash(hash_to_check, password):
        logger.warning("Login failed user=%r ip=%s", username, request.remote_addr)
        return render_template("login.html", error="Invalid username or password."), 401

    logger.info("Login user=%s ip=%s", username, request.remote_addr)
    resp = make_response(redirect(_safe_next(_login_redirect())))
    cookie_value = sign_session(username, user.password_hash)
    resp.set_cookie(
        current_app.config["SESSION_COOKIE"],
        cookie_value,
        max_age=current_app.config["SESSION_MAX_AGE"],
        secure=request.is_secure,
        httponly=True,
        samesite="Lax",
        path="/",
    )
    return resp


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user = get_current_user()
    logger.info("Logout user=%s ip=%s", user.username if user else "?", request.remote_addr)
    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie(current_app.config["SESSION_COOKIE"], path="/")
    return resp
