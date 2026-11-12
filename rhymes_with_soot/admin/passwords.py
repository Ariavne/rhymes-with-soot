"""The framework's account policy: password requirements and reserved
usernames, applied everywhere an account is created (admin create,
forced reset, users.json provisioning)."""

MIN_LENGTH = 12

# Usernames that can never be created, checked case-insensitively.
# Reserving "admin" means a users.json that ships the template example
# verbatim can never provision a known-credential account. The dot-only
# names are reserved because they break URL routing — a browser
# normalizes them away from the path.
RESERVED_USERNAMES = frozenset({"admin", "administrator", ".", ".."})


def is_reserved_username(username):
    """True when the username is reserved (case-insensitive)."""
    return username.lower() in RESERVED_USERNAMES


def validate_password(password):
    """Return the list of unmet requirements (empty when acceptable).

    Each item is a phrase completing "Password must ...", e.g.
    "be at least 12 characters long".
    """
    if not isinstance(password, str):
        return ["be a string"]
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append("be at least %d characters long" % MIN_LENGTH)
    if not any(c.isupper() for c in password):
        problems.append("contain an uppercase letter")
    if not any(c.islower() for c in password):
        problems.append("contain a lowercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("contain a number")
    if not any(not c.isalnum() for c in password):
        problems.append("contain a symbol")
    return problems
