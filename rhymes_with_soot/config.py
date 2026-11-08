"""BaseConfig: resolves SECRET_KEY / DB_PATH / USERS_FILE from <ENV_PREFIX>_* env vars.
ENV_PREFIX, SESSION_COOKIE, CSRF_COOKIE, and APP_NAME are required — a site must set
its own before the app can start."""
import os


class BaseConfig:
    # Session lifetime, in seconds.
    SESSION_MAX_AGE = 7 * 24 * 3600

    # Content-Security-Policy header sent on every response. Set to a CSP
    # string to enable; leave None (default) to disable.
    CSP = None

    # Set True when the app runs behind a single reverse proxy (e.g. nginx on
    # the same host) that sets X-Forwarded-For. The app must only be reachable
    # from that proxy (bind to 127.0.0.1); otherwise clients can spoof their
    # own IP in the logs.
    TRUST_PROXY = False

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        own = cls.__dict__
        # ENV_PREFIX names the environment variables the site reads. It can't be
        # read from the environment (it IS the prefix), so it must be set on the class.
        if not hasattr(cls, "ENV_PREFIX"):
            raise RuntimeError(
                f"{cls.__name__} must set ENV_PREFIX (e.g. ENV_PREFIX = \"MYSITE\"). "
                "It names the <ENV_PREFIX>_* environment variables the site reads."
            )
        if "SECRET_KEY" not in own:
            cls.SECRET_KEY = cls._load_secret_key()
        if "DB_PATH" not in own:
            cls.DB_PATH = cls._require_env("DB_PATH")
        if "USERS_FILE" not in own:
            cls.USERS_FILE = cls._require_env("USERS_FILE")
        # Cookie names are the site's identity in the browser. They must be set so
        # one framework can back many sites without colliding.
        if "SESSION_COOKIE" not in own:
            raise RuntimeError(
                f"{cls.__name__} must set SESSION_COOKIE "
                "(e.g. SESSION_COOKIE = \"mysite_session\")."
            )
        if "CSRF_COOKIE" not in own:
            raise RuntimeError(
                f"{cls.__name__} must set CSRF_COOKIE "
                "(e.g. CSRF_COOKIE = \"mysite_csrf\")."
            )
        # APP_NAME is what the framework renders in titles and the login heading;
        # without it a site would silently show the framework's name.
        if "APP_NAME" not in own:
            raise RuntimeError(
                f"{cls.__name__} must set APP_NAME (e.g. APP_NAME = \"My Site\")."
            )

    @classmethod
    def _env(cls, name, default=None):
        """Read an environment variable using this site's prefix."""
        return os.environ.get(f"{cls.ENV_PREFIX}_{name}", default)

    @classmethod
    def _require_env(cls, name):
        """Read a required environment variable, or refuse to start."""
        value = os.environ.get(f"{cls.ENV_PREFIX}_{name}")
        if not value:
            raise RuntimeError(
                f"Missing {cls.ENV_PREFIX}_{name} environment variable. "
                "Set it before starting the site."
            )
        return value

    @classmethod
    def _load_secret_key(cls):
        """Resolve the session/CSRF signing key."""
        key = cls._env("SECRET_KEY")
        if not key:
            keyfile = cls._env("SECRET_KEYFILE")
            if keyfile:
                try:
                    with open(keyfile, "r", encoding="utf-8") as f:
                        key = f.read().strip()
                except OSError:
                    key = ""
        if not key:
            raise RuntimeError(
                f"No {cls.ENV_PREFIX}_SECRET_KEY: set the env var or a "
                f"{cls.ENV_PREFIX}_SECRET_KEYFILE."
            )
        return key
