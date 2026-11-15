"""Framework admin: account management for site operators."""
from functools import wraps

from rhymes_with_soot.admin.panels import (  # noqa: F401
    AdminPanel,
    list_admin_panels,
    register_admin_panel,
)

# Hooks a site registers for removing a user's data. Each hook is
# ``purge(username)`` and is called when an admin deletes the user (before
# the row goes) or purges their data. A hook that raises aborts the
# deletion, so a user is never left without their data.
user_purge = []


def register_user_purge(purge):
    """Register a ``purge(username)`` hook for user deletion / purge."""
    user_purge.append(purge)
    return purge
