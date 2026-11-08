"""Per-user persistent settings: a JSON key/value store in the site's database,
a /settings page rendered from the settings a site declares, and a JSON API.

The framework owns the table, the page, the API, and the server-side helpers;
sites decide which settings exist by calling register_setting at import time
(the site's models module is the natural place), the way they register
migrations. A user's settings are invisible to every other user, including
admins.

Values are always encrypted at rest (AES-256-GCM) with the site's
ENCRYPTION_KEY — the same key that encrypts file storage. A row written
by an older framework version before the key became mandatory reads back
as plaintext.
"""
import base64
import json
import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from flask import Blueprint, jsonify, render_template, request
from sqlalchemy import Column, DateTime, String
from sqlalchemy.types import JSON, TypeDecorator

from rhymes_with_soot import storage
from rhymes_with_soot.auth.session import get_current_user, login_required
from rhymes_with_soot.db import get_session
from rhymes_with_soot.models import Base, now

logger = logging.getLogger("rhymes_with_soot")

settings_bp = Blueprint("settings", __name__)

_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _valid_image_url(value):
    """An image_url value is empty or a same-origin relative path (a stored
    file's serve URL). External URLs, protocol-relative URLs, and scheme URLs
    (javascript:, data:) are all refused — the value feeds an <img> src."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    return value.startswith("/") and not value.startswith("//")


def _valid_url(value):
    """A url value is empty or a link: a same-origin relative path or an
    absolute http(s) URL. Any other scheme (javascript:, data:, ...) is
    refused — the value feeds an <a href>."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    return urlsplit(value).scheme in ("", "http", "https")


def _validate_value(d, value):
    """Validate a normalized value against a declared setting's kind.
    Returns (value, error): error is None when the value is acceptable.
    Both the /settings page and the JSON API validate through this, so a
    declared setting accepts the same values no matter which path set it.
    Keys with no declaration are validated by the caller (any JSON allowed)."""
    if d.kind == "toggle":
        if not isinstance(value, bool):
            return None, f"{d.label} must be true or false."
        return value, None
    if d.kind in ("select", "segment"):
        if value not in {val for val, _ in d.choices}:
            return None, f"{d.label} has an invalid value."
        return value, None
    if d.kind == "image_url":
        if not _valid_image_url(value):
            return None, f"{d.label} must be a URL on this site."
        return value or None, None
    if d.kind == "url":
        if not _valid_url(value):
            return None, f"{d.label} must be a valid URL."
        return value or None, None
    if d.kind == "number":
        if value is None:
            return d.default, None
        if isinstance(value, bool) or not isinstance(value, int):
            return None, f"{d.label} must be a whole number."
        return value, None
    # "text" (and any other kind): a string.
    if not isinstance(value, str):
        return None, f"{d.label} must be text."
    return value, None


# Setting declarations, in registration order.
_SETTING_DEFS = []


@dataclass(frozen=True)
class SettingDef:
    """One setting a site offers on the /settings page.

    ``kind`` is one of:

    - "text" — a free-text input.
    - "number" — a whole number.
    - "select" — a dropdown over ``choices``.
    - "segment" — a row of single-tap buttons over ``choices`` (the same
      value model as "select"; rendered as segments by the settings dialog
      and as a radio row on the /settings page).
    - "toggle" — a boolean checkbox.
    - "image_url" — a URL string (a stored file's serve URL); the empty
      value means "no image". The value feeds an <img> src, so only
      same-origin paths are accepted. The picker is provided client-side:
      a site registers a row renderer for this kind (see
      static/js/settings_dialog.js) that lets the user upload a file or
      choose from their library and stores the resulting URL.
    - "url" — a link: a same-origin relative path or an absolute http(s)
      URL; the empty value means "no link". The value is intended for an
      <a href>, so other schemes (javascript:, data:) are refused.

    For "select" and "segment", ``choices`` is a tuple of (value, label)
    pairs. ``default`` is shown (and submitted) when the user has not set
    the setting.
    """

    key: str
    label: str
    kind: str = "text"
    default: object = None
    choices: tuple = ()
    help: str = ""


def register_setting(key, label, *, kind="text", default=None, choices=(),
                     help=""):
    """Declare a setting for the /settings page.

    Call at import time (the site's models module is the natural place), like
    register_migration. The setting is rendered on /settings and in the
    settings dialog, and persisted in the per-user user_settings store.

    ``kind`` is one of "text", "number", "select", "segment", "toggle",
    "image_url", or "url" (see SettingDef for the semantics of each).
    """
    _SETTING_DEFS.append(SettingDef(
        key, label, kind=kind, default=default,
        choices=tuple(choices), help=help,
    ))


def list_setting_defs():
    """The settings a site has declared, in registration order."""
    return list(_SETTING_DEFS)


# Store


def _looks_like_json(value):
    """True when a stored string is plain JSON (a legacy row written before
    a key was configured), not undecryptable ciphertext."""
    return (value[:1] in ("{", "[", '"', "-") or value[:1].isdigit()
            or value in ("true", "false", "null"))


class EncryptedJSON(TypeDecorator):
    """A JSON column encrypted at rest with the site's ENCRYPTION_KEY —
    the same key that encrypts file storage.

    The value is stored as base64(nonce || ciphertext+tag), the same
    format as storage.encrypt_secret. A row written by an older framework
    version before the key became mandatory is returned as plaintext, so
    pre-existing databases keep working.
    """

    impl = JSON
    cache_ok = True

    @staticmethod
    def _aesgcm():
        # Imported on first use so the module loads without the package.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        key = storage.resolve_key()
        plaintext = json.dumps(value, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        ct = self._aesgcm()(key).encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, str):
            return value
        key = storage.resolve_key()
        try:
            raw = base64.b64decode(value, validate=True)
            if len(raw) > 12:
                plaintext = self._aesgcm()(key).decrypt(raw[:12], raw[12:], None)
                return json.loads(plaintext.decode("utf-8"))
            return value
        except Exception:
            # Not decryptable ciphertext. A row written by an older
            # framework version is still plain JSON and reads back as-is;
            # anything else is corrupt or tampered and surfaces as None
            # with a warning.
            if _looks_like_json(value):
                return value
            logger.warning("user_settings value is corrupt or tampered; "
                           "returning None")
            return None


class UserSetting(Base):
    """One setting for one user. ``value`` is any JSON document,
    encrypted at rest."""

    __tablename__ = "user_settings"

    username = Column(String(64), primary_key=True)
    key = Column(String(128), primary_key=True)
    value = Column(EncryptedJSON, nullable=True)
    updated_at = Column(DateTime, default=now, onupdate=now)


# Server-side helpers (usable from any site code, in or out of a request)


def load_settings(username):
    """Return the user's settings as a dict, or {} when they have none."""
    session = get_session()
    rows = session.query(UserSetting).filter_by(username=username).all()
    return {row.key: row.value for row in rows}


def get_setting(username, key, default=None):
    """Return one setting's value, or ``default`` when the key is unset."""
    session = get_session()
    row = session.query(UserSetting).filter_by(username=username, key=key).first()
    return default if row is None else row.value


def set_setting(username, key, value):
    """Create or update one setting. The value must be JSON-serializable."""
    session = get_session()
    row = session.query(UserSetting).filter_by(username=username, key=key).first()
    if row is None:
        session.add(UserSetting(username=username, key=key, value=value))
    else:
        row.value = value
    session.commit()


def delete_setting(username, key):
    """Delete one setting; return True when a row was removed."""
    session = get_session()
    row = session.query(UserSetting).filter_by(username=username, key=key).first()
    if row is None:
        return False
    session.delete(row)
    session.commit()
    return True


# /settings page


def _normalize_form_value(d, form):
    """Read one declared setting from a submitted form into a Python value.
    The value is then checked against the declared kind by _validate_value."""
    if d.kind == "toggle":
        # A checkbox is only present in the form when it is checked.
        return form.get(d.key) is not None
    if d.kind == "number":
        raw = (form.get(d.key) or "").strip()
        if raw == "":
            return None  # blank means "reset to the declared default"
        try:
            return int(raw)
        except ValueError:
            return raw  # non-numeric: validation reports it
    if d.kind in ("image_url", "url"):
        return (form.get(d.key) or "").strip()
    return form.get(d.key, "")


def _read_def(d, form):
    """Read one declared setting from a submitted form. Returns (value, error)."""
    return _validate_value(d, _normalize_form_value(d, form))


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def page():
    username = get_current_user().username
    defs = list_setting_defs()
    values = load_settings(username)
    if request.method == "GET":
        return render_template("settings.html", defs=defs, values=values,
                               notice=None, error=None)

    error = None
    new_values = {}
    for d in defs:
        v, err = _read_def(d, request.form)
        if err:
            error = err
            break
        new_values[d.key] = v
    if error:
        return render_template("settings.html", defs=defs, values=values,
                               notice=None, error=error)
    for d in defs:
        set_setting(username, d.key, new_values[d.key])
    logger.info("Settings saved user=%s keys=%s", username,
                ",".join(d.key for d in defs))
    return render_template("settings.html", defs=defs, values=new_values,
                           notice="Settings saved.", error=None)


# JSON API (for sites that build custom controls)


@settings_bp.route("/api/settings", methods=["GET"])
@login_required
def api_list():
    return jsonify(load_settings(get_current_user().username))


@settings_bp.route("/api/settings/defs", methods=["GET"])
@login_required
def api_defs():
    """The site's setting declarations plus the user's current values, as JSON.

    Feeds client-side settings UIs (e.g. a settings dialog) that render the
    controls themselves and auto-save each change via PUT /api/settings/<key>.
    """
    username = get_current_user().username
    return jsonify({
        "defs": [{
            "key": d.key,
            "label": d.label,
            "kind": d.kind,
            "default": d.default,
            "choices": [list(c) for c in d.choices],
            "help": d.help,
        } for d in list_setting_defs()],
        "values": load_settings(username),
    })


@settings_bp.route("/api/settings/<key>", methods=["PUT"])
@login_required
def api_put(key):
    if not _KEY_RE.match(key):
        return jsonify({"error": "Invalid key."}), 400
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "value" not in body:
        return jsonify({"error": "Body must be a JSON object with a 'value' field."}), 400
    value = body["value"]
    d = next((x for x in list_setting_defs() if x.key == key), None)
    if d is not None:
        value, err = _validate_value(d, value)
        if err:
            return jsonify({"error": err}), 400
    set_setting(get_current_user().username, key, value)
    return jsonify(load_settings(get_current_user().username))


@settings_bp.route("/api/settings/<key>", methods=["DELETE"])
@login_required
def api_delete(key):
    if not _KEY_RE.match(key):
        return jsonify({"error": "Invalid key."}), 400
    delete_setting(get_current_user().username, key)
    return jsonify(load_settings(get_current_user().username))
