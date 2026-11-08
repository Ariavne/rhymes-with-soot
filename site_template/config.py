"""Site config: set ENV_PREFIX, cookie names, and APP_NAME.
ENV_PREFIX, SESSION_COOKIE, and CSRF_COOKIE are required — the app refuses to
start without them. The ENCRYPTION_KEY is required by the framework: there is
no plaintext fallback for stored files or settings."""
import os

from rhymes_with_soot.config import BaseConfig


class SiteTemplateConfig(BaseConfig):
    ENV_PREFIX = "SITE_TEMPLATE"
    APP_NAME = "Site Template"
    LOGIN_REDIRECT = "/"
    SESSION_COOKIE = "site_template_session"
    CSRF_COOKIE = "site_template_csrf"

    # At-rest encryption key. Required: the app refuses to start without it.
    ENCRYPTION_KEY = os.environ.get("SITE_TEMPLATE_ENCRYPTION_KEY")
    ENCRYPTION_KEYFILE = os.environ.get("SITE_TEMPLATE_ENCRYPTION_KEYFILE")
