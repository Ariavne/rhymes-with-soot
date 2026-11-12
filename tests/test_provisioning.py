"""User provisioning tests.

Provisioning is all-or-nothing and fails loudly: every entry in users.json
is validated before anything is written, so a malformed entry, a reserved
username, a policy-non-compliant password, or a missing/invalid role raises
ProvisioningError and creates no users. After provisioning the database must
hold at least one admin; an empty or missing users.json that leaves none
raises ProvisioningError so the app cannot start with no one able to manage
it.

Each entry is an object:
{"username": {"password": "...", "role": "user" | "admin", "access": ...}}.
The access field is a mapping of keys to booleans (toggles), lists of values
(valued accesses), or numbers. It is granted only to users this run creates.
"""
import json

import pytest
from werkzeug.security import check_password_hash

from rhymes_with_soot.access import UserAccess, register_access
from rhymes_with_soot.db import get_session
from rhymes_with_soot.models import User
from rhymes_with_soot.provisioning import ProvisioningError, provision_users
from tests.helpers import make_user

# Compliant: >=12 chars, upper, lower, digit, symbol.
ALICE = "Alice-Pw-12345"
BOB = "Bob-Pw-567890"

# Declared so the dict-form value checks below run against real choices.
register_access("prov.select", label="Prov Select", kind="select",
                choices=(("m1", "One"), ("m2", "Two")))
register_access("prov.multi", label="Prov Multi", kind="multi",
                choices=(("x", "X"), ("y", "Y")))


def _entry(password, access=None, role="admin"):
    # access defaults to an empty mapping; pass a dict for grants.
    if access is None:
        access = {}
    return {"password": password, "role": role, "access": access}


def _users(app):
    session = get_session()
    return {u.username: u for u in session.query(User).all()}


def _grants(app, username):
    session = get_session()
    rows = session.query(UserAccess.key, UserAccess.value) \
        .filter_by(username=username).all()
    return {(k, v) for k, v in rows}


def test_provisions_new_users(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE), "bob": _entry(BOB)}, f)
    provision_users(app)
    users = _users(app)
    assert set(users) == {"alice", "bob"}
    # Passwords are stored hashed, not plaintext.
    assert users["alice"].password_hash != ALICE
    assert check_password_hash(users["alice"].password_hash, ALICE)


def test_provisioned_users_are_admins(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE)}, f)
    provision_users(app)
    assert _users(app)["alice"].role == "admin"


def test_grants_access_to_new_users(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump(
            {"alice": _entry(ALICE, access={"a.b": True, "c": True})}, f
        )
    provision_users(app)
    assert _grants(app, "alice") == {("a.b", ""), ("c", "")}


def test_grants_access_from_mapping_form(app):
    access = {
        "a.b": True,
        "c": False,
        "d.multi": ["x", "y"],
        "e.select": ["m1"],
    }
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE, access=access)}, f)
    provision_users(app)
    # False is a no-grant; list values become one row each.
    assert _grants(app, "alice") == {
        ("a.b", ""), ("d.multi", "x"), ("d.multi", "y"), ("e.select", "m1"),
    }


def test_idempotent_on_rerun(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE)}, f)
    provision_users(app)
    provision_users(app)
    users = _users(app)
    assert set(users) == {"alice"}


def test_existing_users_not_overwritten(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry("Alice-Pw-1111")}, f)
    provision_users(app)

    with open(app.config["USERS_FILE"], "w") as f:
        json.dump(
            {"alice": _entry("Alice-Pw-2222", access={"a": True})}, f
        )
    provision_users(app)

    alice = _users(app)["alice"]
    # The original hash wins; the second password must not authenticate.
    assert check_password_hash(alice.password_hash, "Alice-Pw-1111")
    assert not check_password_hash(alice.password_hash, "Alice-Pw-2222")
    # The skipped entry's access list is not applied either.
    assert _grants(app, "alice") == set()


def test_provisioning_refuses_weak_passwords(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry("short"),
                   "bob": _entry("onlylowercase")}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_provisioning_refuses_reserved_usernames(app):
    for name in ("admin", "Administrator", "ADMIN"):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump({name: _entry(ALICE)}, f)
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_refuses_non_object_entries(app):
    for entry in (ALICE, None, [], ["password"]):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump({"alice": entry}, f)
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_refuses_missing_password(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": {"access": ["a"]}}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_provisioning_refuses_non_mapping_access(app):
    # access must be a mapping; a string, number, or list is refused.
    for access in ("a", 1, "a b", ["a"], [1], ["a.b", "c"]):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump({"alice": {"password": ALICE, "access": access}}, f)
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_refuses_bad_mapping_access(app):
    # A non-list/non-bool value, a value outside a declared key's choices,
    # more than one value for a select, and an undeclared key with a value
    # that is not a well-formed key.
    for access in (
        {"a": "nope"},
        {"prov.select": ["nope"]},
        {"prov.select": ["m1", "m2"]},
        {"prov.multi": "x"},
        {"a.b": ["bad value"]},
        {"a.b": {"x": 1}},
    ):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump({"alice": {"password": ALICE, "access": access}}, f)
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_accepts_mapping_with_valid_values(app):
    access = {"prov.select": ["m1"], "prov.multi": ["x", "y"], "c": True}
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE, access=access)}, f)
    provision_users(app)
    assert _grants(app, "alice") == {
        ("prov.select", "m1"), ("prov.multi", "x"), ("prov.multi", "y"),
        ("c", ""),
    }


def test_provisioning_fails_all_or_nothing(app):
    # One good entry, one bad: nothing is written.
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": _entry(ALICE), "bob": _entry("short")}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_missing_file_creates_empty_then_refuses_no_admin(app):
    import os

    os.remove(app.config["USERS_FILE"])
    with pytest.raises(ProvisioningError):
        provision_users(app)
    # The file is still created empty so the operator knows where to add an
    # admin account, but startup is refused: there is no admin yet.
    with open(app.config["USERS_FILE"]) as f:
        assert json.load(f) == {}
    assert _users(app) == {}


def test_provisioned_user_role_is_respected(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump(
            {"alice": _entry(ALICE, role="user"),
             "bob": _entry(BOB, role="admin")},
            f,
        )
    provision_users(app)
    users = _users(app)
    assert users["alice"].role == "user"
    assert users["bob"].role == "admin"


def test_provisioning_refuses_missing_role(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": {"password": ALICE, "access": []}}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_provisioning_refuses_bad_role(app):
    for role in ("superuser", "Admin", "", 1):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump(
                {"alice": {"password": ALICE, "role": role, "access": []}}, f
            )
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_refuses_when_no_admin(app):
    # A users.json that provisions only regular users leaves the database
    # with no admin; startup must be refused and nothing written.
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump(
            {"alice": _entry(ALICE, role="user"),
             "bob": _entry(BOB, role="user")},
            f,
        )
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_provisioning_empty_file_refuses_no_admin(app):
    with open(app.config["USERS_FILE"], "w") as f:
        f.write("{}\n")
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_existing_admin_satisfies_requirement(app):
    # An admin created outside users.json means an empty file is fine: the
    # no-admin check looks at the database, not the file.
    make_user(app, "root", "Root-Passw0rd!x", role="admin")
    with open(app.config["USERS_FILE"], "w") as f:
        f.write("{}\n")
    provision_users(app)  # must not raise
    assert _users(app)["root"].role == "admin"


def test_malformed_json_raises(app):
    with open(app.config["USERS_FILE"], "w") as f:
        f.write("{not valid json")
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}
