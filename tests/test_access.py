"""User access: kinds, check helpers, the requires() decorator, and the
admin endpoint's replace semantics."""
import logging

import pytest

from rhymes_with_soot.access import (
    UserAccess,
    access_default,
    list_access_defs,
    register_access,
    user_has,
    user_value,
    user_values,
)
from rhymes_with_soot.db import get_session
from rhymes_with_soot.models import User
from tests.helpers import extract_csrf, login, make_user

PW = "Sup3r-Secret!pw"

# Declared for the admin editor tests; the test blueprint's gated route
# uses the undeclared key "secret" on purpose.
register_access("secret", label="Secret", help="Grants the gated route.")
register_access("other", label="Other")
register_access("model", label="Model", kind="select",
                choices=(("m1", "Model 1"), ("m2", "Model 2")))
register_access("area.tools", label="Tools", kind="multi",
                choices=(("a", "A"), ("b", "B")))
register_access("files.quota", label="Storage quota", kind="number",
                default=100)


def _grant(app, username, key, value=""):
    session = get_session()
    session.add(UserAccess(username=username, key=key, value=value))
    session.commit()


def _revoke(app, username, key, value=""):
    session = get_session()
    session.query(UserAccess).filter_by(
        username=username, key=key, value=value
    ).delete()
    session.commit()


def _grants(app, username):
    session = get_session()
    rows = session.query(UserAccess.key, UserAccess.value) \
        .filter_by(username=username).all()
    return {(k, v) for k, v in rows}


def _user(app, username):
    session = get_session()
    return session.query(User).filter_by(username=username).first()


def _login(app, username):
    make_user(app, username, PW)
    client = app.test_client()
    login(client, username, PW)
    return client


def _admin_client(app):
    make_user(app, "root", PW, role="admin")
    client = app.test_client()
    login(client, "root", PW)
    return client


def _post_json(client, path, body):
    """JSON POST with a fresh CSRF token (fetched from /admin)."""
    token = extract_csrf(client.get("/admin").get_data(as_text=True))
    assert token
    return client.post(path, json=body, headers={"X-CSRF-Token": token})


# Declarations


def test_register_and_list_access_defs():
    defs = list_access_defs()
    keys = [d.key for d in defs]
    assert keys.index("secret") < keys.index("other")
    secret = defs[keys.index("secret")]
    assert secret.label == "Secret"
    assert secret.help == "Grants the gated route."
    assert secret.kind == "toggle"
    assert secret.choices == ()


def test_register_valued_access_kinds():
    defs = {d.key: d for d in list_access_defs()}
    assert defs["model"].kind == "select"
    assert defs["model"].choices == (("m1", "Model 1"), ("m2", "Model 2"))
    assert defs["area.tools"].kind == "multi"
    assert defs["area.tools"].choices == (("a", "A"), ("b", "B"))


def test_register_rejects_bad_kind():
    with pytest.raises(ValueError):
        register_access("bad.kind", label="Bad", kind="nope")


def test_register_valued_requires_choices():
    with pytest.raises(ValueError):
        register_access("bad.select", label="Bad", kind="select")
    with pytest.raises(ValueError):
        register_access("bad.multi", label="Bad", kind="multi")


def test_register_number_requires_default():
    with pytest.raises(ValueError):
        register_access("bad.number", label="Bad", kind="number")
    with pytest.raises(ValueError):
        register_access("bad.number", label="Bad", kind="number", default=-1)
    with pytest.raises(ValueError):
        register_access("bad.number", label="Bad", kind="number", default=True)


def test_register_number_stores_default():
    defs = {d.key: d for d in list_access_defs()}
    assert defs["files.quota"].kind == "number"
    assert defs["files.quota"].default == 100


# Check helpers


def test_helpers_are_false_for_anonymous_user(app):
    assert user_has(None, "secret") is False
    assert user_values(None, "model") == set()
    assert user_value(None, "files.quota") is None


def test_access_default_reads_declaration(app):
    assert access_default("files.quota") == 100
    assert access_default("secret") is None
    assert access_default("not-declared") is None


def test_user_value_none_when_ungranted(app):
    make_user(app, "alice", PW)
    alice = _user(app, "alice")
    assert user_value(alice, "files.quota") is None


def test_user_value_returns_granted_value(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "files.quota", "250")
    alice = _user(app, "alice")
    assert user_value(alice, "files.quota") == 250


def test_user_value_float_grant(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "files.quota", "1.5")
    alice = _user(app, "alice")
    assert user_value(alice, "files.quota") == 1.5


def test_user_value_non_numeric_grant_is_none(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "files.quota", "not-a-number")
    alice = _user(app, "alice")
    assert user_value(alice, "files.quota") is None


def test_user_has_reflects_grants(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "secret")
    alice = _user(app, "alice")
    assert user_has(alice, "secret") is True
    assert user_has(alice, "other") is False
    _revoke(app, "alice", "secret")
    assert user_has(alice, "secret") is False


def test_user_has_is_true_for_any_valued_grant(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "model", "m1")
    alice = _user(app, "alice")
    assert user_has(alice, "model") is True
    _revoke(app, "alice", "model", "m1")
    assert user_has(alice, "model") is False


def test_user_values_returns_held_values(app):
    make_user(app, "alice", PW)
    _grant(app, "alice", "model", "m1")
    _grant(app, "alice", "area.tools", "a")
    _grant(app, "alice", "area.tools", "b")
    _grant(app, "alice", "secret")
    alice = _user(app, "alice")
    assert user_values(alice, "model") == {"m1"}
    assert user_values(alice, "area.tools") == {"a", "b"}
    # A toggle carries no values.
    assert user_values(alice, "secret") == set()
    # An unheld access is empty.
    assert user_values(alice, "other") == set()


# requires() decorator


def test_requires_anonymous_get_redirects_to_login(app):
    client = app.test_client()
    resp = client.get("/t/gated")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_requires_anonymous_post_is_401(app):
    client = app.test_client()
    token = extract_csrf(client.get("/login").get_data(as_text=True))
    resp = client.post("/t/gated",
                       data={"csrf_token": token})
    assert resp.status_code == 401


def test_requires_authenticated_without_access_is_403(app):
    client = _login(app, "alice")
    assert client.get("/t/gated").status_code == 403
    token = extract_csrf(client.get("/t/page").get_data(as_text=True))
    resp = client.post("/t/gated", data={"csrf_token": token})
    assert resp.status_code == 403


def test_requires_with_access_passes(app):
    client = _login(app, "alice")
    _grant(app, "alice", "secret")
    assert client.get("/t/gated").status_code == 200
    token = extract_csrf(client.get("/t/page").get_data(as_text=True))
    resp = client.post("/t/gated", data={"csrf_token": token})
    assert resp.get_data(as_text=True) == "gated"


def test_requires_all_keys_must_be_held(app):
    client = _login(app, "alice")
    _grant(app, "alice", "secret")
    assert client.get("/t/gated-two").status_code == 403
    _grant(app, "alice", "other")
    assert client.get("/t/gated-two").status_code == 200


def test_grant_takes_effect_on_next_request(app):
    client = _login(app, "alice")
    assert client.get("/t/gated").status_code == 403
    _grant(app, "alice", "secret")
    assert client.get("/t/gated").status_code == 200
    _revoke(app, "alice", "secret")
    assert client.get("/t/gated").status_code == 403


# Template helper


def test_template_helper_hides_section_without_access(app):
    client = _login(app, "alice")
    body = client.get("/t/gated-page").get_data(as_text=True)
    assert "granted" not in body
    _grant(app, "alice", "secret")
    body = client.get("/t/gated-page").get_data(as_text=True)
    assert "granted" in body


def test_template_helper_anonymous(app):
    client = app.test_client()
    body = client.get("/t/gated-page").get_data(as_text=True)
    assert "granted" not in body


# Admin endpoint


def test_admin_set_access_grant_and_revoke(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    _grant(app, "alice", "secret")

    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"secret": True, "other": True}})
    assert resp.status_code == 200
    assert resp.get_json() == {"access": {"secret": True, "other": True}}
    assert _grants(app, "alice") == {("secret", ""), ("other", "")}

    resp = _post_json(client, "/admin/users/alice/access", {"access": {}})
    assert resp.status_code == 200
    assert resp.get_json() == {"access": {}}
    assert _grants(app, "alice") == set()


def test_admin_set_access_replaces_whole_set(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    _grant(app, "alice", "secret")
    _grant(app, "alice", "other")

    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"other": True}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == {("other", "")}


def test_admin_set_access_valued_select(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)

    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"model": ["m1"]}})
    assert resp.status_code == 200
    assert resp.get_json() == {"access": {"model": ["m1"]}}
    assert _grants(app, "alice") == {("model", "m1")}

    # A new selection replaces the old one.
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"model": ["m2"]}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == {("model", "m2")}

    # Empty list revokes the select.
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"model": []}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == set()


def test_admin_set_access_valued_multi(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)

    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"area.tools": ["a", "b"]}})
    assert resp.status_code == 200
    assert resp.get_json() == {"access": {"area.tools": ["a", "b"]}}
    assert _grants(app, "alice") == {("area.tools", "a"),
                                     ("area.tools", "b")}

    # Removing one value keeps the other.
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"area.tools": ["a"]}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == {("area.tools", "a")}


def test_admin_set_access_number(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)

    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"files.quota": 250}})
    assert resp.status_code == 200
    assert resp.get_json() == {"access": {"files.quota": 250}}
    assert _grants(app, "alice") == {("files.quota", "250")}

    # A new value replaces the old one.
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"files.quota": 1}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == {("files.quota", "1")}

    # Clearing (null) revokes the value; the declared default applies.
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"files.quota": None}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == set()
    alice = _user(app, "alice")
    assert user_value(alice, "files.quota") is None
    assert access_default("files.quota") == 100


def test_admin_set_access_rejects_bad_number(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    for body in ({"access": {"files.quota": -5}},
                {"access": {"files.quota": "250"}},
                {"access": {"files.quota": [250]}},
                {"access": {"files.quota": True}}):
        resp = _post_json(client, "/admin/users/alice/access", body)
        assert resp.status_code == 400
    assert _grants(app, "alice") == set()


def test_admin_set_access_rejects_value_outside_choices(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    for body in ({"access": {"model": ["nope"]}},
                 {"access": {"area.tools": ["nope"]}}):
        resp = _post_json(client, "/admin/users/alice/access", body)
        assert resp.status_code == 400
    assert _grants(app, "alice") == set()


def test_admin_set_access_rejects_mismatched_kind(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    for body in ({"access": {"model": True}},
                 {"access": {"secret": ["x"]}}):
        resp = _post_json(client, "/admin/users/alice/access", body)
        assert resp.status_code == 400
    assert _grants(app, "alice") == set()


def test_admin_set_access_undeclared_key_accepts_any_value(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    resp = _post_json(client, "/admin/users/alice/access",
                      {"access": {"legacy.model": ["old-m"]}})
    assert resp.status_code == 200
    assert _grants(app, "alice") == {("legacy.model", "old-m")}


def test_admin_set_access_is_logged(app, caplog):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    _grant(app, "alice", "secret")
    with caplog.at_level(logging.INFO, logger="rhymes_with_soot"):
        _post_json(client, "/admin/users/alice/access",
                   {"access": {"other": True}})
    line = " ".join(r.getMessage() for r in caplog.records)
    assert "Admin root changed access for alice" in line
    assert "+other" in line and "-secret" in line


def test_admin_set_access_valued_log_lines(app, caplog):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    with caplog.at_level(logging.INFO, logger="rhymes_with_soot"):
        _post_json(client, "/admin/users/alice/access",
                   {"access": {"model": ["m1"]}})
    line = " ".join(r.getMessage() for r in caplog.records)
    assert "+model=m1" in line


def test_admin_set_access_forwards_grant_to_route(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    _post_json(client, "/admin/users/alice/access",
               {"access": {"secret": True}})
    c2 = app.test_client()
    login(c2, "alice", PW)
    assert c2.get("/t/gated").status_code == 200


def test_admin_set_access_forbidden_for_regular_user(app):
    client = _login(app, "alice")
    resp = client.post("/admin/users/alice/access",
                       json={"access": {"secret": True}})
    assert resp.status_code in (400, 403)
    assert _grants(app, "alice") == set()


def test_admin_set_access_requires_csrf(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    resp = client.post("/admin/users/alice/access",
                       json={"access": {"secret": True}})
    assert resp.status_code == 400
    assert _grants(app, "alice") == set()


def test_admin_set_access_404s_for_unknown_user(app):
    client = _admin_client(app)
    resp = _post_json(client, "/admin/users/ghost/access", {"access": {}})
    assert resp.status_code == 404


def test_admin_set_access_rejects_bad_body(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    for body in ({"nope": 1}, {"access": "secret"}, {"access": ["a"]},
                 {"access": {"a" * 129: True}},
                 {"access": {"bad key!": True}}):
        resp = _post_json(client, "/admin/users/alice/access", body)
        assert resp.status_code == 400
    assert _grants(app, "alice") == set()


# Admin page


def test_admin_page_renders_two_pane_with_access_groups(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    _grant(app, "alice", "secret")
    _grant(app, "alice", "model", "m1")

    # No user selected: the left pane lists users, the right pane is empty.
    body = client.get("/admin").get_data(as_text=True)
    assert "alice" in body
    assert "Select a user to manage their account and accesses." in body
    assert "access-sections" not in body

    # Selecting a user renders the panel with grouped, kind-shaped controls.
    body = client.get("/admin?user=alice").get_data(as_text=True)
    assert 'data-key="secret"' in body
    assert 'data-key="model" data-kind="select"' in body
    assert 'data-key="area.tools" data-kind="multi"' in body
    # The granted toggle is pre-checked; the granted select value is selected.
    assert 'data-key="secret"' in body
    assert "m1" in body
    assert "data-access-url" in body
    assert "area" in body  # the namespace group heading


def test_admin_page_unknown_user_select_is_ignored(app):
    client = _admin_client(app)
    body = client.get("/admin?user=ghost").get_data(as_text=True)
    assert "Select a user to manage their account and accesses." in body


def test_admin_set_role(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    resp = _post(client, "/admin/users/alice/role", {"role": "admin"})
    assert resp.status_code == 200
    assert _user(app, "alice").role == "admin"


def test_admin_set_role_rejects_bad_value(app):
    client = _admin_client(app)
    make_user(app, "alice", PW)
    resp = _post(client, "/admin/users/alice/role", {"role": "superuser"})
    assert resp.status_code == 200
    assert _user(app, "alice").role == "user"


def test_admin_cannot_change_own_role(app):
    client = _admin_client(app)
    # Demotion and self-elevation are both refused; the role never changes.
    for role in ("user", "admin"):
        resp = _post(client, "/admin/users/root/role", {"role": role})
        assert resp.status_code == 200
        assert "cannot change your own role" in resp.get_data(as_text=True)
        assert _user(app, "root").role == "admin"


def test_admin_cannot_change_own_access(app):
    client = _admin_client(app)
    _grant(app, "root", "other")
    # Editing one's own grants is refused outright, whatever the new set.
    resp = _post_json(client, "/admin/users/root/access",
                      {"access": {}})
    assert resp.status_code == 400
    assert _grants(app, "root") == {("other", "")}


def test_admin_set_role_404s_for_unknown_user(app):
    client = _admin_client(app)
    resp = _post(client, "/admin/users/ghost/role", {"role": "user"})
    assert resp.status_code == 404


def _post(client, path, data):
    """POST form data with a fresh CSRF token (fetched from /admin)."""
    token = extract_csrf(client.get("/admin").get_data(as_text=True))
    assert token
    return client.post(path, data={**data, "csrf_token": token})
