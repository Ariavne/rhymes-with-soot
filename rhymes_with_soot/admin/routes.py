"""Framework admin: account management for site operators.

Admins manage accounts and access — create a user, change a user's role,
force a password reset, delete a user, and grant or revoke the site's
declared accesses. The page shows usernames, roles, creation dates, and
access grants and nothing else: an admin can never view or recover another
user's data, on this site or any other.
"""
import logging
import re
import secrets

from flask import Blueprint, jsonify, request, render_template, abort
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


def _access_grants():
    from rhymes_with_soot.access import UserAccess
    from rhymes_with_soot.db import get_session

    session = get_session()
    rows = session.query(UserAccess.username, UserAccess.key,
                         UserAccess.value).all()
    grants = {}
    for username, key, value in rows:
        grants.setdefault(username, {}).setdefault(key, set()).add(value)
    return grants


def _access_groups():
    """The declared accesses grouped by the first dot-segment of their key,
    for the admin editor's section layout. Keys without a dot sit in an
    ungrouped section."""
    from rhymes_with_soot.access import list_access_defs

    groups = []
    by_ns = {}
    for d in list_access_defs():
        ns = d.key.split(".", 1)[0]
        if ns not in by_ns:
            by_ns[ns] = []
            groups.append((ns, by_ns[ns]))
        by_ns[ns].append(d)
    return groups


def _page(error=None, notice=None):
    from rhymes_with_soot.access import list_access_defs
    from rhymes_with_soot.admin import user_purge

    users = _user_list()
    # The user panel is driven by ?user= (links) or the user= form field the
    # panel's own actions carry; an unknown or missing value leaves the right
    # pane empty.
    selected = request.args.get("user") or request.form.get("user", "")
    selected_role = None
    if selected:
        for u in users:
            if u.username == selected:
                selected_role = u.role
                break
        else:
            selected = None

    return render_template("admin.html", users=users,
                           access_defs=list_access_defs(),
                           access_groups=_access_groups(),
                           access_grants=_access_grants(),
                           selected_user=selected,
                           su_role=selected_role,
                           has_purge=bool(user_purge),
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


def _as_number(val):
    """A non-negative JSON number as a string, or None when not one.

    JSON booleans are ints in Python; they are not numbers here."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    if val < 0:
        return None
    return str(val)


def _validate_desired(body):
    """Validate a set_access body. Returns a {key: set of values} map, or
    None when the body is unusable.

    Declared keys are checked against their declaration: a toggle must be a
    boolean, a select/multi a list of strings drawn from its choices, a
    number a non-negative JSON number.
    Undeclared keys accept a boolean or a list of well-formed strings, so a
    grant outlives its declaration."""
    from rhymes_with_soot.access import access_defs_by_key, is_valid_key

    if not isinstance(body, dict) or not isinstance(body.get("access"), dict):
        return None
    defs = access_defs_by_key()
    desired = {}
    for key, val in body["access"].items():
        if not is_valid_key(key):
            return None
        d = defs.get(key)
        if d is None:
            if val is True:
                values = {""}
            elif val is False:
                values = set()
            elif isinstance(val, list) and all(
                    isinstance(v, str) and is_valid_key(v) for v in val):
                values = set(val)
            else:
                return None
        elif d.kind == "toggle":
            if val is True:
                values = {""}
            elif val is False:
                values = set()
            else:
                return None
        elif d.kind == "number":
            if val is None:
                # Cleared: back to the declared default.
                values = set()
            else:
                num = _as_number(val)
                if num is None:
                    return None
                values = {num}
        else:
            legal = {v for v, _ in d.choices}
            if not isinstance(val, list):
                return None
            values = set()
            for v in val:
                if not isinstance(v, str) or v not in legal:
                    return None
                values.add(v)
        desired[key] = values
    return desired


def _apply_access(session, username, current, desired):
    """Replace the user's access set with ``desired`` (a {key: set of
    values} map) and log the diff. A key absent from ``desired`` is fully
    revoked."""
    from rhymes_with_soot.access import UserAccess

    current = current.get(username, {})
    granted = set()
    revoked = set()
    for key in set(current) | set(desired):
        old = current.get(key, set())
        new = desired.get(key, set())
        for v in new - old:
            session.add(UserAccess(username=username, key=key, value=v))
            granted.add(f"{key}={v}" if v else key)
        for v in old - new:
            session.query(UserAccess).filter_by(
                username=username, key=key, value=v
            ).delete()
            revoked.add(f"{key}={v}" if v else key)
    if granted or revoked:
        logger.info(
            "Admin %s changed access for %s: %s %s",
            get_current_user().username, username,
            " ".join("+%s" % k for k in sorted(granted)),
            " ".join("-%s" % k for k in sorted(revoked)),
        )


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


@admin_bp.route("/admin/users/<username>/role", methods=["POST"])
@admin_required
def set_role(username):
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    current = get_current_user()

    session = get_session()
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        abort(404)

    role = request.form.get("role", "")
    if role not in ROLES:
        return _page(error="Role must be 'user' or 'admin'.")

    # Changing one's own role is never allowed: a demotion could strand the
    # site with no admin, and self-elevation is how an admin multiplies
    # their own reach.
    if username == current.username:
        return _page(error="You cannot change your own role.")

    user.role = role
    session.commit()
    logger.info("Admin %s set %s's role to %s",
                current.username, username, role)
    return _page(notice="Set %s's role to %s." % (username, role))


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

    # Destructive: the form must carry the username typed back.
    if request.form.get("confirm", "") != username:
        return _page(error="Type the username to confirm the deletion.")

    # A site may hook a purge to remove the user's data before the row goes.
    from rhymes_with_soot.admin import user_purge
    for purge in user_purge:
        try:
            purge(username)
        except Exception:
            logger.exception("User purge failed for %s; aborting deletion",
                             username)
            return _page(error="Deleting %s failed: removing the user's "
                               "data raised an error." % username)

    session.delete(user)
    session.commit()
    logger.info("Admin %s deleted user %s", current.username, username)
    return _page(notice="Deleted %s." % username)


@admin_bp.route("/admin/users/<username>/purge", methods=["POST"])
@admin_required
def purge_user(username):
    """Remove the user's data (the site's purge hooks) without deleting the
    account. The form must carry the username typed back."""
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User
    from rhymes_with_soot.admin import user_purge

    session = get_session()
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        abort(404)

    if request.form.get("confirm", "") != username:
        return _page(error="Type the username to confirm.")

    if not user_purge:
        return _page(error="This site registers no user data to purge.")

    for purge in user_purge:
        try:
            purge(username)
        except Exception:
            logger.exception("User purge failed for %s", username)
            return _page(error="Removing %s's data raised an error."
                         % username)
    logger.info("Admin %s purged the data of %s",
                get_current_user().username, username)
    return _page(notice="Removed %s's data." % username)


@admin_bp.route("/admin/users/<username>/access", methods=["POST"])
@admin_required
def set_access(username):
    """Replace the user's access set with the complete set in the request
    body; the diff is the grant/revoke applied."""
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    current = get_current_user()
    if username == current.username:
        # The same rule as the role endpoint: no one edits their own
        # permission levels, whatever the new set would be.
        logger.warning(
            "Admin %s attempted to change their own access; refused",
            username,
        )
        abort(400)

    session = get_session()
    user = session.query(User).filter_by(username=username).first()
    if user is None:
        abort(404)

    body = request.get_json(silent=True)
    desired = _validate_desired(body)
    if desired is None:
        abort(400)

    _apply_access(session, username, _access_grants(), desired)
    session.commit()

    from rhymes_with_soot.access import access_defs_by_key

    defs = access_defs_by_key()
    response = {}
    for key, values in sorted(desired.items()):
        if not values:
            continue
        if values == {""}:
            response[key] = True
        elif defs.get(key) is not None and defs[key].kind == "number":
            v = next(iter(values))
            num = float(v)
            response[key] = int(num) if num.is_integer() else num
        else:
            response[key] = sorted(values)
    return jsonify({"access": response})
