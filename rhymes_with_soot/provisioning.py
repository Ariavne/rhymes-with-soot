"""User provisioning from a users.json file on startup.
Existing users are not overwritten. The file is not committed to version
control.

Provisioning is all-or-nothing and fails loudly: every entry is validated
before anything is written. A reserved username or a policy-non-compliant
password raises ProvisioningError — no users are created and the app must
not start."""
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
    problems = []
    for username, password in users_data.items():
        if is_reserved_username(username):
            problems.append(
                f"username {username!r} is reserved; choose a different name"
            )
        pw_problems = validate_password(password)
        if pw_problems:
            problems.append(
                f"password for {username!r} must " + " and ".join(pw_problems)
            )
    return problems


def provision_users(app):
    """Load users from the site's users.json into the database.

    Idempotent for valid files: existing users are never overwritten.
    Any problem with the file (unparseable JSON, a reserved username, a
    policy-non-compliant password) raises ProvisioningError without
    creating a single user.
    """
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
                "Add accounts as JSON of {\"username\": \"password\"}, e.g. "
                "{\"alice\": \"a-long-password\"}, then restart the service. "
                "Only users listed here are provisioned.",
                users_file,
            )
        except OSError as e:
            logger.error("Failed to create users file %s: %s", users_file, e)
        return
    except json.JSONDecodeError as e:
        raise ProvisioningError(
            f"Users file {users_file} is not valid JSON: {e}"
        ) from e

    if not isinstance(users_data, dict):
        raise ProvisioningError(
            f"Users file {users_file} must be a JSON object mapping "
            "usernames to passwords."
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
    try:
        for username, password in users_data.items():
            with session.no_autoflush:
                existing = session.query(User).filter_by(username=username).first()
            if existing is not None:
                continue
            # users.json is the operator's list of seeded admins.
            session.add(User(
                username=username,
                password_hash=generate_password_hash(password),
                role="admin",
            ))
            logger.info("Provisioned admin: %s", username)
        session.commit()
    except IntegrityError:
        # Another worker provisioned the same user concurrently.
        session.rollback()
        logger.debug("Provisioning race: user already exists (another worker).")
    finally:
        session.close()
