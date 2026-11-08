import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

from tests.helpers import extract_csrf, login, make_user

GOOD_PW = "Sup3r-Secret!pw"  # 15 chars: upper, lower, digit, symbol


def _admin_client(app, username="root"):
    make_user(app, username, GOOD_PW, role="admin")
    client = app.test_client()
    login(client, username, GOOD_PW)
    return client


def _post(client, path, data):
    """POST form data with a fresh CSRF token (fetched from /admin).

    Password endpoints require the two-entry match, so a matching confirm
    is added unless the caller is testing that check itself."""
    token = extract_csrf(client.get("/admin").get_data(as_text=True))
    assert token
    if "password" in data and "confirm" not in data:
        data = {**data, "confirm": data["password"]}
    return client.post(path, data={**data, "csrf_token": token})


def _users(app):
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    return {u.username: u for u in session.query(User).all()}


# Access control


def test_admin_page_requires_login(client, app):
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_admin_page_forbidden_for_regular_user(client, app):
    make_user(app, "carol", GOOD_PW)
    login(client, "carol", GOOD_PW)
    resp = client.get("/admin")
    assert resp.status_code == 403


def test_admin_page_renders_for_admin(app):
    client = _admin_client(app)
    resp = client.get("/admin")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "root" in body
    assert "Set password & create" in body
    assert "pw-dialog" in body


def test_admin_post_requires_csrf(app):
    client = _admin_client(app)
    resp = client.post(
        "/admin/users",
        data={"username": "dave", "password": GOOD_PW, "role": "user"},
    )
    assert resp.status_code == 400
    assert "dave" not in _users(app)


# Create


def test_create_user(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users",
                 {"username": "dave", "password": GOOD_PW, "role": "user"})
    assert resp.status_code == 200
    users = _users(app)
    assert "dave" in users
    assert users["dave"].role == "user"
    # The created account can log in with the password the admin set.
    c2 = app.test_client()
    assert login(c2, "dave", GOOD_PW).status_code == 302


def test_create_admin(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users",
                 {"username": "erin", "password": GOOD_PW, "role": "admin"})
    assert resp.status_code == 200
    assert _users(app)["erin"].role == "admin"


def test_create_user_rejects_weak_password(app):
    client = _admin_client(app)
    # Each fails exactly one policy rule (all are 14 chars long).
    for weak in ("short", "alllowercase1!", "NoDigitsHere!!",
                 "NoSymbolHere11", "noupper12345!x"):
        resp = _post(client, "/admin/users",
                     {"username": "weak", "password": weak, "role": "user"})
        assert resp.status_code == 200
        assert "Password must" in resp.get_data(as_text=True)
    assert "weak" not in _users(app)


def test_create_user_rejects_password_mismatch(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users",
                 {"username": "dave", "password": GOOD_PW, "role": "user",
                  "confirm": "Other-Passw0rd!x"})
    assert resp.status_code == 200
    assert "do not match" in resp.get_data(as_text=True)
    assert "dave" not in _users(app)


def test_create_user_rejects_missing_confirm(app):
    client = _admin_client(app)
    token = extract_csrf(client.get("/admin").get_data(as_text=True))
    resp = client.post("/admin/users",
                       data={"username": "dave", "password": GOOD_PW,
                             "role": "user", "csrf_token": token})
    assert resp.status_code == 200
    assert "do not match" in resp.get_data(as_text=True)
    assert "dave" not in _users(app)


def test_create_user_rejects_bad_username(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users",
                 {"username": "bad name!", "password": GOOD_PW, "role": "user"})
    assert resp.status_code == 200
    assert "bad name!" not in _users(app)


def test_create_user_rejects_reserved_username(app):
    client = _admin_client(app)
    for name in ("admin", "Administrator"):
        resp = _post(client, "/admin/users",
                     {"username": name, "password": GOOD_PW, "role": "user"})
        assert resp.status_code == 200
        assert "reserved" in resp.get_data(as_text=True)
        assert name not in _users(app)


def test_create_user_rejects_duplicate(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users",
                 {"username": "root", "password": GOOD_PW, "role": "user"})
    assert resp.status_code == 200
    assert "already taken" in resp.get_data(as_text=True)
    assert _users(app)["root"].role == "admin"  # unchanged


# Reset


def test_reset_password(app):
    client = _admin_client(app)
    make_user(app, "frank", "Old-Passw0rd!x")
    resp = _post(client, "/admin/users/frank/reset",
                 {"password": "N3w-Passw0rd!x"})
    assert resp.status_code == 200
    frank = _users(app)["frank"]
    assert check_password_hash(frank.password_hash, "N3w-Passw0rd!x")
    assert not check_password_hash(frank.password_hash, "Old-Passw0rd!x")
    # The new password actually logs in.
    c2 = app.test_client()
    assert login(c2, "frank", "N3w-Passw0rd!x").status_code == 302


def test_reset_password_rejects_weak(app):
    client = _admin_client(app)
    make_user(app, "frank", "Old-Passw0rd!x")
    resp = _post(client, "/admin/users/frank/reset", {"password": "nope"})
    assert resp.status_code == 200
    assert "Password must" in resp.get_data(as_text=True)
    assert check_password_hash(_users(app)["frank"].password_hash, "Old-Passw0rd!x")


def test_reset_password_rejects_mismatch(app):
    client = _admin_client(app)
    make_user(app, "frank", "Old-Passw0rd!x")
    resp = _post(client, "/admin/users/frank/reset",
                 {"password": "N3w-Passw0rd!x", "confirm": "N3w-Passw0rd!y"})
    assert resp.status_code == 200
    assert "do not match" in resp.get_data(as_text=True)
    assert check_password_hash(_users(app)["frank"].password_hash, "Old-Passw0rd!x")


def test_reset_password_404s_for_unknown_user(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users/ghost/reset", {"password": GOOD_PW})
    assert resp.status_code == 404


# Delete


def test_delete_user(app):
    client = _admin_client(app)
    make_user(app, "gina", "Old-Passw0rd!x")
    resp = _post(client, "/admin/users/gina/delete", {})
    assert resp.status_code == 200
    assert "gina" not in _users(app)
    c2 = app.test_client()
    assert login(c2, "gina", "Old-Passw0rd!x").status_code == 401


def test_delete_own_account_rejected(app):
    client = _admin_client(app, username="root")
    resp = _post(client, "/admin/users/root/delete", {})
    assert resp.status_code == 200
    assert "root" in _users(app)


def test_delete_404s_for_unknown_user(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users/ghost/delete", {})
    assert resp.status_code == 404


# Migration


def test_role_column_added_to_old_databases(tmp_path):
    """A database created before users.role existed gets the column on boot."""
    from rhymes_with_soot import create_app
    from rhymes_with_soot.config import BaseConfig

    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, "
        "username VARCHAR(64) UNIQUE NOT NULL, "
        "password_hash VARCHAR(256) NOT NULL, created_at DATETIME)"
    )
    conn.execute(
        "INSERT INTO users (id, username, password_hash) "
        "VALUES ('1', 'legacy', ?)",
        (generate_password_hash("Legacy-Pw-1234"),),
    )
    conn.commit()
    conn.close()

    config = type(
        "OldDbConfig",
        (BaseConfig,),
        {
            "ENV_PREFIX": "TEST",
            "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
            "DB_PATH": str(db_path),
            "USERS_FILE": str(tmp_path / "users.json"),
            "APP_NAME": "Test Site",
            "SESSION_COOKIE": "test_session",
            "CSRF_COOKIE": "test_csrf",
            "ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
    )
    app = create_app(config)

    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    session = get_session()
    user = session.query(User).filter_by(username="legacy").first()
    assert user is not None
    assert user.role == "user"  # existing users default to 'user'
    # The legacy user can still log in.
    client = app.test_client()
    assert login(client, "legacy", "Legacy-Pw-1234").status_code == 302
