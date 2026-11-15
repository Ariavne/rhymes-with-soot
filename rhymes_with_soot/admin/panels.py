"""Admin panels: extra operator pages a site hangs off the /admin page.

A site registers a panel at import time (the same pattern as
register_user_purge) with a label and the Flask endpoint that renders the
page. The admin page renders one link per registered panel, so a site's
operator pages live under the framework's admin page without the framework
knowing anything about them.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class AdminPanel:
    """One link the admin page renders: a label plus the endpoint it opens."""

    label: str
    endpoint: str


_PANELS = []


def register_admin_panel(label, endpoint):
    """Declare an operator page linked from the /admin page.

    Call at import time. ``endpoint`` is a Flask endpoint name (the admin
    page resolves it with url_for when it renders)."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("an admin panel needs a non-empty label")
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("an admin panel needs an endpoint name")
    _PANELS.append(AdminPanel(label.strip(), endpoint.strip()))
    return endpoint


def list_admin_panels():
    """The registered panels, in registration order."""
    return list(_PANELS)
