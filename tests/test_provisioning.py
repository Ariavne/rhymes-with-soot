"""User provisioning tests.

Provisioning is all-or-nothing and fails loudly: every entry in users.json
is validated before anything is written, so a reserved username or a
policy-non-compliant password raises ProvisioningError and creates no users.
"""
import json

import pytest
from werkzeug.security import check_password_hash

from rhymes_with_soot.db import get_session
from rhymes_with_soot.models import User
from rhymes_with_soot.provisioning import ProvisioningError, provision_users

# Compliant: >=12 chars, upper, lower, digit, symbol.
ALICE = "Alice-Pw-12345"
BOB = "Bob-Pw-567890"


def _users(app):
    session = get_session()
    return {u.username: u for u in session.query(User).all()}


def test_provisions_new_users(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": ALICE, "bob": BOB}, f)
    provision_users(app)
    users = _users(app)
    assert set(users) == {"alice", "bob"}
    # Passwords are stored hashed, not plaintext.
    assert users["alice"].password_hash != ALICE
    assert check_password_hash(users["alice"].password_hash, ALICE)


def test_provisioned_users_are_admins(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": ALICE}, f)
    provision_users(app)
    assert _users(app)["alice"].role == "admin"


def test_idempotent_on_rerun(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": ALICE}, f)
    provision_users(app)
    provision_users(app)
    users = _users(app)
    assert set(users) == {"alice"}


def test_existing_users_not_overwritten(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": "Alice-Pw-1111"}, f)
    provision_users(app)

    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": "Alice-Pw-2222"}, f)
    provision_users(app)

    alice = _users(app)["alice"]
    # The original hash wins; the second password must not authenticate.
    assert check_password_hash(alice.password_hash, "Alice-Pw-1111")
    assert not check_password_hash(alice.password_hash, "Alice-Pw-2222")


def test_provisioning_refuses_weak_passwords(app):
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": "short", "bob": "onlylowercase"}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_provisioning_refuses_reserved_usernames(app):
    for name in ("admin", "Administrator", "ADMIN"):
        with open(app.config["USERS_FILE"], "w") as f:
            json.dump({name: ALICE}, f)
        with pytest.raises(ProvisioningError):
            provision_users(app)
        assert _users(app) == {}


def test_provisioning_fails_all_or_nothing(app):
    # One good entry, one bad: nothing is written.
    with open(app.config["USERS_FILE"], "w") as f:
        json.dump({"alice": ALICE, "bob": "short"}, f)
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}


def test_missing_file_creates_empty(app):
    import os

    os.remove(app.config["USERS_FILE"])
    provision_users(app)  # must not raise
    with open(app.config["USERS_FILE"]) as f:
        assert json.load(f) == {}


def test_malformed_json_raises(app):
    with open(app.config["USERS_FILE"], "w") as f:
        f.write("{not valid json")
    with pytest.raises(ProvisioningError):
        provision_users(app)
    assert _users(app) == {}
