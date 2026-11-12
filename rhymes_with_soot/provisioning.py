"""User provisioning from a users.json file on startup.
Existing users are not overwritten. The file is not committed to version
control.

Each entry is an object: {"username": {"password": "...", "role":
"user" | "admin", "access": ...}}.
The access value is granted to users that this run creates; entries for
existing users are skipped, including their access.

The access field is a mapping: {"k1": true, "model": ["m1"],
"multi": ["a", "b"], "files.quota": 1073741824} — a boolean is a toggle
grant, a list of values is a valued grant (select/multi), a number is a
number grant.

Provisioning is all-or-nothing and fails loudly: every entry is validated
before anything is written. A reserved username, a policy-non-compliant
password, a missing or invalid role, or a malformed entry raises
ProvisioningError — no users are created and the app must not start. After
provisioning, the database must hold at least one admin; an empty or missing
users.json that leaves none raises ProvisioningError as well."""
import json
import logging

from werkzeug.security import generate_password_hash

from rhymes_with_soot.admin.passwords import (
    is_reserved_username,
    validate_password,
)

logger = logging.getLogger("rhymes_with_soot")


class ProvisioningError(Exception):
    """users.json could not be provisioned; the app must not start."""


def _validate(users_data):
    """All the problems with a users.json payload, as human-readable
    phrases. Empty when every entry is provisionable."""
    from rhymes_with_soot.access import access_defs_by_key, is_valid_key

    problems = []
    defs = access_defs_by_key()
    for username, entry in users_data.items():
        if is_reserved_username(username):
            problems.append(
                f"username {username!r} is reserved; choose a different name"
            )
            continue
        if not isinstance(entry, dict):
            problems.append(
                f"entry for {username!r} must be an object with 'password' "
                "and 'role' keys"
            )
            continue
        if "password" not in entry:
            problems.append(
                f"entry for {username!r} is missing a 'password'"
            )
        else:
            pw_problems = validate_password(entry["password"])
            if pw_problems:
                problems.append(
                    f"password for {username!r} must "
                    + " and ".join(pw_problems)
                )
        if "role" not in entry:
            problems.append(
                f"entry for {username!r} is missing a 'role'"
            )
        elif entry["role"] not in ("user", "admin"):
            problems.append(
                f"role for {username!r} must be 'user' or 'admin'"
            )
        problems.extend(_access_problems(entry.get("access", {}), username, defs))
    return problems


def _access_problems(access, username, defs):
    """The problems with one entry's access field."""
    from rhymes_with_soot.access import is_valid_key

    problems = []
    if not isinstance(access, dict):
        problems.append(
            f"'access' for {username!r} must be a mapping of keys to "
            "booleans / lists of values / numbers"
        )
        return problems
    pairs = []
    for key, value in access.items():
        if value is True:
            pairs.append((key, ""))
        elif value is False:
            continue
        elif isinstance(value, list):
            d = defs.get(key)
            if d is not None and d.kind == "number":
                problems.append(
                    f"access {key!r} for {username!r} is a number and "
                    "takes a single number, not a list"
                )
            else:
                for v in value:
                    pairs.append((key, v))
        elif (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
        ):
            pairs.append((key, str(value)))
        else:
            problems.append(
                f"access value for {key!r} for {username!r} must be "
                "a boolean, a number, or a list of values"
            )

    for key, value in pairs:
        if not is_valid_key(key):
            problems.append(
                f"access key {key!r} for {username!r} is invalid"
            )
            continue
        d = defs.get(key)
        if d is None:
            # Undeclared keys are allowed; their values are checked for
            # shape only, with no kind to validate against.
            if value and not is_valid_key(value):
                problems.append(
                    f"access value {value!r} for {key!r} for "
                    f"{username!r} is invalid"
                )
            continue
        if d.kind == "toggle" and value:
            problems.append(
                f"access {key!r} for {username!r} is a toggle and takes "
                "no value"
            )
        elif d.kind == "number" and value == "":
            problems.append(
                f"access {key!r} for {username!r} is a number; grant a "
                "value in the mapping form"
            )
        elif d.kind in ("select", "multi") and value:
            if value not in {v for v, _ in d.choices}:
                problems.append(
                    f"access value {value!r} for {key!r} for {username!r} "
                    "is not one of its declared choices"
                )
        elif d.kind in ("select", "multi"):
            problems.append(
                f"access {key!r} for {username!r} is valued and needs "
                "one of its declared choices"
            )
    if isinstance(access, dict):
        for key, value in access.items():
            d = defs.get(key)
            if d is not None and d.kind == "select" \
                    and isinstance(value, list) and len(value) > 1:
                problems.append(
                    f"access {key!r} for {username!r} is a select and "
                    "takes at most one value"
                )
    return problems


def _access_pairs(access):
    """The (key, value) grants an access field expresses. Booleans are
    toggles, lists one pair per value, and numbers one pair with the
    number's string form."""
    pairs = []
    for key, value in access.items():
        if value is True:
            pairs.append((key, ""))
        elif isinstance(value, list):
            for v in value:
                pairs.append((key, v))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            pairs.append((key, str(value)))
    return pairs


def provision_users(app):
    """Load users from the site's users.json into the database.

    Any problem with the file (unparseable JSON, a malformed entry, a
    reserved username, a policy-non-compliant password, a missing or invalid
    role) raises ProvisioningError without creating a single user. After
    provisioning, the database must hold at least one admin — an empty or
    missing users.json that leaves none raises ProvisioningError as well, so
    the app cannot start with no one able to manage it.
    """
    from rhymes_with_soot.access import UserAccess, declared_keys
    from rhymes_with_soot.db import get_session
    from rhymes_with_soot.models import User

    users_file = app.config["USERS_FILE"]
    try:
        with open(users_file, "r", encoding="utf-8") as f:
            users_data = json.load(f)
    except FileNotFoundError:
        # Create an empty file so the operator knows where to add accounts.
        try:
            with open(users_file, "w", encoding="utf-8") as f:
                f.write("{}\n")
            logger.warning(
                "Users file not found; created an empty one at %s. "
                "Add accounts as JSON of {\"username\": {\"password\": \"...\", "
                "\"role\": \"admin\", \"access\": {}}}, e.g. "
                "{\"alice\": {\"password\": \"a-long-password\", "
                "\"role\": \"admin\"}}, then restart the service. Only users "
                "listed here are provisioned.",
                users_file,
            )
        except OSError as e:
            logger.error("Failed to create users file %s: %s", users_file, e)
        users_data = {}
    except json.JSONDecodeError as e:
        raise ProvisioningError(
            f"Users file {users_file} is not valid JSON: {e}"
        ) from e

    if not isinstance(users_data, dict):
        raise ProvisioningError(
            f"Users file {users_file} must be a JSON object mapping "
            "usernames to {\"password\", \"role\", \"access\"}."
        )

    problems = _validate(users_data)
    if problems:
        for problem in problems:
            logger.error("Refusing to provision: %s", problem)
        raise ProvisioningError(
            f"Users file {users_file} has {len(problems)} problem(s); "
            "no users were created. Fix the file and restart."
        )

    from sqlalchemy.exc import IntegrityError

    session = get_session()
    declared = declared_keys()
    try:
        # The database must hold at least one admin; check before writing so
        # a users.json that provisions only regular users refuses without
        # creating a single user.
        existing_admins = session.query(User).filter_by(role="admin").count()
        new_admin = any(
            entry["role"] == "admin" for entry in users_data.values()
        )
        if existing_admins == 0 and not new_admin:
            raise ProvisioningError(
                "No admin user exists. Provision at least one account with "
                "\"role\": \"admin\" in users.json and restart; the app will "
                "not start without one."
            )
        for username, entry in users_data.items():
            with session.no_autoflush:
                existing = session.query(User).filter_by(username=username).first()
            if existing is not None:
                continue
            # users.json is the operator's list of seeded accounts.
            session.add(User(
                username=username,
                password_hash=generate_password_hash(entry["password"]),
                role=entry["role"],
            ))
            for key, value in _access_pairs(entry.get("access", {})):
                if key not in declared:
                    # Enforcement accepts undeclared keys; warn so a typo
                    # or an undeclared key does not pass silently.
                    logger.warning(
                        "Access %r provisioned for %s is not declared by "
                        "the site", key, username,
                    )
                session.add(UserAccess(username=username, key=key, value=value))
            logger.info("Provisioned %s: %s", entry["role"], username)
        session.commit()
    except IntegrityError:
        # Another worker provisioned the same user concurrently.
        session.rollback()
        logger.debug("Provisioning race: user already exists (another worker).")
    finally:
        session.close()
