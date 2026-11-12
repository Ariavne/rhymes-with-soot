"""Per-user access: named capabilities an operator grants to or revokes from
individual users, distinct from role (which gates the /admin area). Holding an
access confers no admin privileges; an admin holds every declared access
fully, whatever the grants table says.

An access is one of four kinds:

- "toggle" — a boolean capability. Either held or not.
- "select" — exactly one value from a declared set of choices.
- "multi" — any number of values from a declared set of choices.
- "number" — a single non-negative number (a cap, a limit); a user
  holding no value gets the access's declared default.

Sites declare their accesses at import time with register_access (the same
pattern as register_setting). Declaration controls what the admin's access
editor offers and how it validates values; enforcement accepts any well-formed
key and value, declared or not, so a grant outlives its declaration.

Enforcement is server-side (the requires() route decorator and the user_has /
user_values helpers); hiding UI with the template helpers provides no
enforcement by itself.
"""
import logging
import re
from dataclasses import dataclass
from functools import wraps

from flask import (
    abort, g, has_request_context, redirect, request, url_for,
)
from sqlalchemy import Column, DateTime, String

from rhymes_with_soot.auth.session import get_current_user
from rhymes_with_soot.db import get_session, register_migration, has_table
from rhymes_with_soot.models import Base, now

logger = logging.getLogger("rhymes_with_soot")

# Same shape as setting keys; dots are allowed so sites may namespace keys
# (area.feature). The keys carry no grouping semantics.
_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# The sentinel value stored for toggle grants.
TOGGLE_VALUE = ""

KINDS = ("toggle", "select", "multi", "number")


class UserAccess(Base):
    """One access value granted to one user.

    A toggle is a single row with value = TOGGLE_VALUE; a select is a single
    row with the chosen value; a multi is one row per chosen value.
    """

    __tablename__ = "user_access"

    username = Column(String(64), primary_key=True)
    key = Column(String(128), primary_key=True)
    value = Column(String(128), nullable=False, default=TOGGLE_VALUE,
                   primary_key=True)
    granted_at = Column(DateTime, default=now)


def _ensure_user_access_value_column(engine):
    """create_all never alters existing tables, so rebuild the table with
    the new (username, key, value) primary key. Existing grants are toggles
    and copy across with the empty value."""
    from sqlalchemy import inspect, text

    if not has_table(engine, "user_access"):
        return
    cols = {c["name"] for c in inspect(engine).get_columns("user_access")}
    if "value" in cols:
        return
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE user_access_new ("
            "username VARCHAR(64) NOT NULL, "
            "key VARCHAR(128) NOT NULL, "
            "value VARCHAR(128) NOT NULL, "
            "granted_at DATETIME, "
            "PRIMARY KEY (username, key, value)"
            ")"
        ))
        conn.execute(text(
            "INSERT INTO user_access_new "
            "(username, key, value, granted_at) "
            "SELECT username, key, '', granted_at FROM user_access"
        ))
        conn.execute(text("DROP TABLE user_access"))
        conn.execute(text("ALTER TABLE user_access_new RENAME TO user_access"))
    logger.info("Rebuilt user_access with its value column")


register_migration(_ensure_user_access_value_column)


@dataclass(frozen=True)
class AccessDef:
    """One access a site declares for the admin's access editor.

    ``kind`` is "toggle", "select", "multi", or "number". For "select" and
    "multi", ``choices`` is a non-empty tuple of (value, label) pairs. For
    "number", ``default`` is the non-negative number a user holding no
    value gets.
    """

    key: str
    label: str
    kind: str = "toggle"
    choices: tuple = ()
    default: object = None
    help: str = ""


_ACCESS_DEFS = []


def register_access(key, label, *, kind="toggle", choices=(), default=None,
                    help=""):
    """Declare an access this site uses.

    Call at import time (the site's models module is the natural place),
    like register_setting / register_migration. Declared accesses are the
    only keys the admin's access editor can grant; enforcement accepts any
    well-formed key and value, declared or not.

    ``kind`` is "toggle" (default), "select", "multi", or "number". For
    "select" and "multi", ``choices`` is a non-empty sequence of (value,
    label) pairs. For "number", ``default`` is a non-negative number.
    """
    if kind not in KINDS:
        raise ValueError(f"access kind must be one of {KINDS}, got {kind!r}")
    choices = tuple(choices)
    if kind in ("select", "multi") and not choices:
        raise ValueError(f"a {kind} access for {key!r} needs choices")
    if kind == "number" and (
            default is None or isinstance(default, bool) or default < 0):
        raise ValueError(
            f"a number access for {key!r} needs a non-negative default"
        )
    _ACCESS_DEFS.append(AccessDef(key, label, kind=kind,
                                  choices=choices, default=default,
                                  help=help))


def list_access_defs():
    return list(_ACCESS_DEFS)


def access_defs_by_key():
    return {d.key: d for d in _ACCESS_DEFS}


def declared_keys():
    return {d.key for d in _ACCESS_DEFS}


def is_valid_key(key):
    return isinstance(key, str) and bool(_KEY_RE.match(key))


def load_accesses(username):
    session = get_session()
    rows = session.query(UserAccess.key, UserAccess.value) \
        .filter_by(username=username).all()
    grants = {}
    for key, value in rows:
        grants.setdefault(key, set()).add(value)
    return grants


def _full_grants():
    """The grants an admin holds: every declared access at its full value set.
    A role alone confers every capability the site declares, so the grants
    table is not consulted for an admin."""
    grants = {}
    for d in _ACCESS_DEFS:
        if d.kind == "toggle":
            grants[d.key] = {TOGGLE_VALUE}
        elif d.kind in ("select", "multi"):
            grants[d.key] = {v for v, _ in d.choices}
        elif d.kind == "number":
            grants[d.key] = {str(d.default)}
    return grants


def _accesses_for(user):
    """The user's {key: set of values}; an admin holds every declared access
    fully. Within a request it is loaded once and cached, because grants
    cannot change mid-request."""
    if user.role == "admin":
        return _full_grants()
    username = user.username
    if has_request_context():
        cache = g.setdefault("rws_user_access", {})
        if username not in cache:
            cache[username] = load_accesses(username)
        return cache[username]
    return load_accesses(username)


def user_has(user, key):
    """True when the user holds the access (any value for it). False for an
    anonymous user."""
    if user is None:
        return False
    return bool(_accesses_for(user).get(key))


def user_values(user, key):
    """The set of values the user holds for a valued access. Empty for an
    anonymous user and for a toggle (which carries no values — use user_has)."""
    if user is None:
        return set()
    return {v for v in _accesses_for(user).get(key, set())
            if v != TOGGLE_VALUE}


def user_value(user, key):
    """The value of a number access as a number (int when whole), or None
    when the user holds no value, is anonymous, or holds a non-numeric
    value (the table can hold one for a number-declared key)."""
    if user is None:
        return None
    values = user_values(user, key)
    if not values:
        return None
    try:
        num = float(next(iter(values)))
    except (TypeError, ValueError):
        return None
    return int(num) if num.is_integer() else num


def access_default(key):
    """The default a site declared for an access, or None when the access
    is undeclared or declared without one."""
    d = access_defs_by_key().get(key)
    if d is None:
        return None
    return d.default


def requires(*keys):
    """Decorator: require the authenticated user to hold ALL of ``keys``.

    Anonymous: login redirect (GET) / 401.
    Authenticated without an access: 403.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if user is None:
                if request.method == "GET":
                    qs = request.query_string.decode()
                    next_url = request.path + ("?" + qs if qs else "")
                    return redirect(url_for("auth.login", next=next_url))
                abort(401)
            grants = _accesses_for(user)
            if not all(grants.get(k) for k in keys):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator
