"""Framework admin: account management for site operators.

Admins manage accounts only — create a user, force a password reset, and
delete a user. The page shows usernames, roles, and creation dates and
nothing else: an admin can never view or recover another user's data, on
this site or any other.
"""
import logging
import re
import secrets

from flask import Blueprint, request, render_template, abort
from werkzeug.security import generate_password_hash

from rhymes_with_soot.admin.passwords import (
    is_reserved_username,
    validate_password,
)
from rhymes_with_soot.auth.session import admin_required, get_current_user

admin_bp = Blueprint("admin", __name__)
logger = logging.getLogger("rhymes_with_soot")

ROLES = ("user", "admin")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _user_list():
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    return session.query(User).order_by(User.username).all()


def _page(error=None, notice=None):
    return render_template("admin.html", users=_user_list(),
                           error=error, notice=notice)


def _password_error(problems):
    return "Password must " + " and ".join(problems) + "."


def _password_pair():
    """Return (password, error): the form must carry two matching entries."""
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")
    if not secrets.compare_digest(password, confirm):
        return None, "The two password entries do not match."
    return password, None


@admin_bp.route("/admin", methods=["GET"])
@admin_required
def index():
    return _page()


@admin_bp.route("/admin/users", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "user")
    if role not in ROLES:
        role = "user"

    if not _USERNAME_RE.match(username):
        return _page(error="Username must be 1-64 characters: "
                            "letters, numbers, '.', '_' or '-'.")
    if is_reserved_username(username):
        return _page(error=f"Username {username!r} is reserved; "
                            "choose a different name.")

    password, pw_error = _password_pair()
    if pw_error:
        return _page(error=pw_error)

    problems = validate_password(password)
    if problems:
        return _page(error=_password_error(problems))

    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    if session.query(User).filter_by(username=username).first() is not None:
        return _page(error="That username is already taken.")

    session.add(User(username=username,
                     password_hash=generate_password_hash(password),
                     role=role))
    session.commit()
    logger.info("Admin %s created %s %s",
                get_current_user().username, role, username)
    return _page(notice="Created %s as %s." % (username, role))


@admin_bp.route("/admin/users/<username>/reset", methods=["POST"])
@admin_required
def reset_password(username):
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        abort(404)

    password, pw_error = _password_pair()
    if pw_error:
        return _page(error=pw_error)

    problems = validate_password(password)
    if problems:
        return _page(error=_password_error(problems))

    user.password_hash = generate_password_hash(password)
    session.commit()
    logger.info("Admin %s forced a password reset for %s",
                get_current_user().username, username)
    return _page(notice="Password reset for %s." % username)


@admin_bp.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def delete_user(username):
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    current = get_current_user()
    if username == current.username:
        return _page(error="You cannot delete your own account.")

    session = get_session()
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        abort(404)

    session.delete(user)
    session.commit()
    logger.info("Admin %s deleted user %s", current.username, username)
    return _page(notice="Deleted %s." % username)
