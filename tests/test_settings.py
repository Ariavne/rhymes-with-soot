"""Persistent user settings: API, /settings page, and helper tests."""
import sqlite3

import pytest

from tests.helpers import extract_csrf, login, make_user

PW = "Sup3r-Secret!pw"  # 15 chars: upper, lower, digit, symbol
KEYED_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _login(app, username):
    make_user(app, username, PW)
    client = app.test_client()
    login(client, username, PW)
    return client


def _token(client):
    """GET a page to issue the CSRF cookie + token bound to the logged-in user."""
    token = extract_csrf(client.get("/t/page").get_data(as_text=True))
    assert token
    return token


def _put(client, token, key, value):
    return client.put(
        f"/api/settings/{key}",
        json={"value": value},
        headers={"X-CSRF-Token": token},
    )


def _get(client, token):
    return client.get("/api/settings", headers={"X-CSRF-Token": token})


def _delete(client, token, key):
    return client.delete(f"/api/settings/{key}", headers={"X-CSRF-Token": token})


# Access control


def test_settings_requires_login(client):
    resp = client.get("/api/settings")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_settings_put_requires_csrf(app):
    client = _login(app, "alice")
    token = _token(client)
    resp = client.put("/api/settings/theme", json={"value": "dark"})
    assert resp.status_code == 400
    assert _get(client, token).get_json() == {}


# CRUD


def test_get_empty_when_unset(app):
    client = _login(app, "alice")
    token = _token(client)
    assert _get(client, token).get_json() == {}


def test_put_creates_and_returns_all(app):
    client = _login(app, "alice")
    token = _token(client)
    resp = _put(client, token, "theme", "dark")
    assert resp.status_code == 200
    assert resp.get_json() == {"theme": "dark"}


def test_put_upserts_existing_key(app):
    client = _login(app, "alice")
    token = _token(client)
    _put(client, token, "theme", "dark")
    resp = _put(client, token, "theme", "light")
    assert resp.get_json() == {"theme": "light"}


def test_put_stores_nested_json(app):
    client = _login(app, "alice")
    token = _token(client)
    _put(client, token, "prefs", {"font": 14, "wrap": True})
    assert _get(client, token).get_json() == {"prefs": {"font": 14, "wrap": True}}


def test_put_rejects_invalid_key(app):
    client = _login(app, "alice")
    token = _token(client)
    # "" and "bad/key" have no routable path (Flask 404s before the view runs).
    assert _put(client, token, "", "x").status_code == 404
    assert _put(client, token, "bad/key", "x").status_code == 404
    for bad in ("has space", "a" * 129, "bad:key"):
        resp = _put(client, token, bad, "x")
        assert resp.status_code == 400, bad
    assert _get(client, token).get_json() == {}


def test_put_rejects_malformed_body(app):
    client = _login(app, "alice")
    token = _token(client)
    # No "value" field.
    resp = client.put("/api/settings/theme", json={"nope": 1},
                      headers={"X-CSRF-Token": token})
    assert resp.status_code == 400
    # Not a JSON object.
    resp = client.put("/api/settings/theme", json=["dark"],
                      headers={"X-CSRF-Token": token})
    assert resp.status_code == 400
    assert _get(client, token).get_json() == {}


def test_delete_removes_key(app):
    client = _login(app, "alice")
    token = _token(client)
    _put(client, token, "theme", "dark")
    resp = _delete(client, token, "theme")
    assert resp.get_json() == {}


def test_delete_is_idempotent(app):
    client = _login(app, "alice")
    token = _token(client)
    assert _delete(client, token, "missing").status_code == 200
    assert _get(client, token).get_json() == {}


# Per-user isolation


def test_settings_are_per_user(app):
    ca = _login(app, "alice")
    cb = _login(app, "bob")
    tok_a, tok_b = _token(ca), _token(cb)

    _put(ca, tok_a, "theme", "dark")

    # bob sees nothing of alice's
    assert _get(cb, tok_b).get_json() == {}

    # bob sets his own; alice's stays put
    _put(cb, tok_b, "theme", "light")
    assert _get(ca, tok_a).get_json() == {"theme": "dark"}
    assert _get(cb, tok_b).get_json() == {"theme": "light"}


# Server-side helpers


def test_helpers_set_get_load_delete(app):
    """The helpers work outside a request, within an app context."""
    from rhymes_with_soot.settings import (
        load_settings, get_setting, set_setting, delete_setting,
    )

    with app.app_context():
        assert load_settings("alice") == {}
        assert get_setting("alice", "theme") is None
        assert get_setting("alice", "theme", default="system") == "system"

        set_setting("alice", "theme", "dark")
        set_setting("alice", "wrap", True)
        assert get_setting("alice", "theme") == "dark"
        assert load_settings("alice") == {"theme": "dark", "wrap": True}

        set_setting("alice", "theme", "light")  # upsert
        assert get_setting("alice", "theme") == "light"

        assert delete_setting("alice", "theme") is True
        assert delete_setting("alice", "nope") is False
        assert load_settings("alice") == {"wrap": True}


# At-rest encryption


def _keyed_app(tmp_path):
    """A fresh app whose config carries an ENCRYPTION_KEY."""
    from rhymes_with_soot import create_app
    from rhymes_with_soot.config import BaseConfig
    from tests.conftest import SECRET_KEY, test_bp

    users = tmp_path / "users.json"
    users.write_text("{}\n")
    config = type(
        "KeyedConfig",
        (BaseConfig,),
        {
            "ENV_PREFIX": "TEST",
            "SECRET_KEY": SECRET_KEY,
            "DB_PATH": str(tmp_path / "keyed.db"),
            "USERS_FILE": str(users),
            "APP_NAME": "Test Site",
            "LOGIN_REDIRECT": "/t/home",
            "SESSION_COOKIE": "test_session",
            "CSRF_COOKIE": "test_csrf",
            "ENCRYPTION_KEY": KEYED_KEY,
        },
    )
    return create_app(config, blueprints=[test_bp])


def _raw_value(db_path, username, key):
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM user_settings WHERE username = ? AND key = ?",
            (username, key),
        ).fetchone()
    return row[0] if row else None


def test_create_app_refuses_without_key(tmp_path, monkeypatch):
    """A site without ENCRYPTION_KEY/ENCRYPTION_KEYFILE cannot start:
    there is no plaintext fallback."""
    import rhymes_with_soot.storage as storage_mod

    # The storage module caches its key process-wide; start clean so the
    # keyless app below is the one that resolves (and refuses) it.
    monkeypatch.setattr(storage_mod, "_key", None)

    from rhymes_with_soot import create_app
    from rhymes_with_soot.config import BaseConfig
    from tests.conftest import SECRET_KEY, test_bp

    users = tmp_path / "users.json"
    users.write_text("{}\n")
    config = type(
        "KeylessConfig",
        (BaseConfig,),
        {
            "ENV_PREFIX": "TEST",
            "SECRET_KEY": SECRET_KEY,
            "DB_PATH": str(tmp_path / "keyless.db"),
            "USERS_FILE": str(users),
            "APP_NAME": "Test Site",
            "LOGIN_REDIRECT": "/t/home",
            "SESSION_COOKIE": "test_session",
            "CSRF_COOKIE": "test_csrf",
        },
    )
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        create_app(config, blueprints=[test_bp])


def test_key_stores_ciphertext_and_round_trips(tmp_path, monkeypatch):
    import rhymes_with_soot.storage as storage_mod

    # The storage module caches its key process-wide; start clean so the
    # keyed app below is the one that resolves it.
    monkeypatch.setattr(storage_mod, "_key", None)
    app = _keyed_app(tmp_path)

    client = _login(app, "alice")
    token = _token(client)
    resp = _put(client, token, "prefs", {"theme": "dark", "n": 3})
    assert resp.get_json() == {"prefs": {"theme": "dark", "n": 3}}

    raw = _raw_value(str(tmp_path / "keyed.db"), "alice", "prefs")
    assert raw is not None
    assert "theme" not in raw  # no plaintext leak in the file

    # A fresh read decrypts back to the original document.
    assert _get(client, token).get_json() == {"prefs": {"theme": "dark", "n": 3}}


def test_legacy_plaintext_row_reads_with_key(tmp_path, monkeypatch):
    import rhymes_with_soot.storage as storage_mod

    monkeypatch.setattr(storage_mod, "_key", None)
    app = _keyed_app(tmp_path)

    client = _login(app, "alice")
    token = _token(client)

    # Simulate rows written before a key was configured: plain JSON,
    # both a scalar string and an object.
    with sqlite3.connect(str(tmp_path / "keyed.db")) as conn:
        conn.execute(
            "INSERT INTO user_settings (username, key, value) VALUES (?, ?, ?)",
            ("alice", "theme", '"dark"'),
        )
        conn.execute(
            "INSERT INTO user_settings (username, key, value) VALUES (?, ?, ?)",
            ("alice", "prefs", '{"a": 1}'),
        )
        conn.commit()

    assert _get(client, token).get_json() == {"theme": "dark", "prefs": {"a": 1}}


# /settings page


@pytest.fixture
def settings_registry():
    """Isolate the process-global setting declarations for a test."""
    from rhymes_with_soot import settings as settings_mod

    saved = list(settings_mod._SETTING_DEFS)
    settings_mod._SETTING_DEFS.clear()
    yield settings_mod._SETTING_DEFS
    settings_mod._SETTING_DEFS.clear()
    settings_mod._SETTING_DEFS.extend(saved)


def _register_test_settings():
    from rhymes_with_soot.settings import register_setting

    register_setting("theme", "Theme", kind="select",
                     choices=[("dark", "Dark"), ("light", "Light")], default="dark")
    register_setting("appearance", "Appearance", kind="segment",
                     choices=[("system", "System"), ("dark", "Dark"),
                              ("light", "Light")],
                     default="system")
    register_setting("avatar", "Avatar", kind="image_url")
    register_setting("profile_link", "Profile link", kind="url")
    register_setting("font_size", "Font size", kind="number", default=14)
    register_setting("notifications", "Enable notifications",
                     kind="toggle", default=False)


def test_settings_page_requires_login(client):
    resp = client.get("/settings")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_settings_page_renders_declared_settings(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    body = client.get("/settings").get_data(as_text=True)
    assert "Theme" in body
    assert "Font size" in body
    assert "Enable notifications" in body
    # Unset settings render at their declared defaults.
    assert 'value="dark"' in body or 'selected' in body
    assert 'value="14"' in body


def test_settings_page_saves_on_post(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token,
        "theme": "light",
        "appearance": "light",
        "avatar": "/uploads/abc123",
        "profile_link": "https://example.com",
        "font_size": "18",
        "notifications": "on",
    })
    assert resp.status_code == 200
    assert "Settings saved." in resp.get_data(as_text=True)
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice") == {
        "theme": "light", "appearance": "light",
        "avatar": "/uploads/abc123", "profile_link": "https://example.com",
        "font_size": 18,
        "notifications": True,
    }


def test_settings_page_toggle_off_saves_false(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    # First enable, then submit without the checkbox present (unchecked).
    client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "font_size": "14", "notifications": "on",
    })
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "font_size": "14",
    })
    assert resp.status_code == 200
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice")["notifications"] is False


def test_settings_page_rejects_bad_select(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token,
        "theme": "neon",  # not a declared choice
        "appearance": "system",
        "font_size": "14",
    })
    assert resp.status_code == 200
    assert "invalid" in resp.get_data(as_text=True).lower()
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice") == {}


def test_settings_page_rejects_bad_number(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "font_size": "big",
    })
    assert resp.status_code == 200
    assert "whole number" in resp.get_data(as_text=True)
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice") == {}


def test_settings_page_renders_segment_and_avatar(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    body = client.get("/settings").get_data(as_text=True)
    # A segment renders one radio per choice, checked on the current value.
    assert body.count('name="appearance"') == 3
    assert 'value="system"' in body and "checked" in body
    # The avatar renders a plain URL input; the picker is client-side.
    assert 'id="set-avatar"' in body


def test_settings_page_segment_saves_and_validates(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "light",
    })
    assert resp.status_code == 200
    assert "Settings saved." in resp.get_data(as_text=True)
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice")["appearance"] == "light"

    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "neon",
    })
    assert resp.status_code == 200
    assert "invalid" in resp.get_data(as_text=True).lower()
    assert load_settings("alice")["appearance"] == "light"


def test_settings_page_avatar_blank_is_none(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")
    token = _token(client)
    url = "/uploads/abc123"
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "avatar": url,
    })
    assert "Settings saved." in resp.get_data(as_text=True)
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice")["avatar"] == url

    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "avatar": "   ",
    })
    assert "Settings saved." in resp.get_data(as_text=True)
    assert load_settings("alice")["avatar"] is None


def test_avatar_rejects_non_same_origin_values(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")

    # Page POST: every non-same-origin shape is refused.
    for bad in (
        "https://example.com/a.png",
        "//evil.example/a.png",
        "javascript:alert(1)",
        "data:image/png;base64,AAAA",
        "example.com/a.png",
        42,
    ):
        token = _token(client)
        resp = client.post("/settings", data={
            "csrf_token": token, "theme": "dark", "appearance": "system",
            "avatar": bad,
        })
        assert resp.status_code == 200
        assert "this site" in resp.get_data(as_text=True)

    # JSON API: same rule.
    token = _token(client)
    for bad in ("https://example.com/a.png", "//evil.example", "javascript:x"):
        resp = _put(client, token, "avatar", bad)
        assert resp.status_code == 400, bad

    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice") == {}


def test_url_setting_validates_links(app, settings_registry):
    _register_test_settings()
    client = _login(app, "alice")

    # Same-origin paths and absolute http(s) URLs are accepted via the API.
    for good in ("/about", "https://example.com", "http://example.com/x"):
        token = _token(client)
        resp = _put(client, token, "profile_link", good)
        assert resp.status_code == 200, good
    from rhymes_with_soot.settings import load_settings
    assert load_settings("alice")["profile_link"] == "http://example.com/x"

    # Any other scheme is refused, on both the page and the API.
    for bad in ("javascript:alert(1)", "data:text/html,hi", "vbscript:x"):
        token = _token(client)
        resp = client.post("/settings", data={
            "csrf_token": token, "theme": "dark", "appearance": "system",
            "profile_link": bad,
        })
        assert resp.status_code == 200
        assert "valid URL" in resp.get_data(as_text=True)

        token = _token(client)
        resp = _put(client, token, "profile_link", bad)
        assert resp.status_code == 400, bad

    # Blank clears the link.
    token = _token(client)
    resp = client.post("/settings", data={
        "csrf_token": token, "theme": "dark", "appearance": "system",
        "profile_link": "   ",
    })
    assert "Settings saved." in resp.get_data(as_text=True)
    assert load_settings("alice")["profile_link"] is None
