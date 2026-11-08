"""Application factory.
create_app(config_class, blueprints) builds the Flask app: registers the framework
auth blueprint first, then the site's blueprints in order. The site's templates/ and
static/ (located next to its config file) shadow the framework's by filename."""
import hashlib
import inspect
import logging
import os

from flask import Flask, request, g, url_for, abort, send_from_directory
from jinja2 import ChoiceLoader, FileSystemLoader

logger = logging.getLogger("rhymes_with_soot")

from rhymes_with_soot.csrf import (
    get_csrf_token, verify_csrf, sign_token, _current_identity,
    CSRF_MAX_AGE,
)

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
FRAMEWORK_TEMPLATES = os.path.join(_PACKAGE_DIR, "templates")
FRAMEWORK_STATIC = os.path.join(_PACKAGE_DIR, "static")


def create_app(config_class, blueprints=None):
    """Create and configure a site's Flask application.

    ``config_class`` is the site's Config (a ``BaseConfig`` subclass).
    ``blueprints`` is the ordered list of the site's blueprints; the framework
    registers its own auth blueprint before them.
    """
    app = Flask(__name__, static_folder=None, static_url_path="/static")
    app.config.from_object(config_class)

    # Everything the site stores (uploads, per-user settings) is encrypted
    # at rest with the site's ENCRYPTION_KEY; there is no plaintext
    # fallback. Resolve it now so a missing, unreadable, or malformed key
    # crashes the startup instead of the first write.
    from rhymes_with_soot import storage
    with app.app_context():
        storage.resolve_key()

    # Behind a trusted single proxy, take the real client IP from
    # X-Forwarded-For so log lines attribute requests to clients, not the proxy.
    if app.config.get("TRUST_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    # Logging must be registered before the first log call so startup lines
    # are captured.
    from rhymes_with_soot.logging import register_logging
    register_logging(app)

    logger.info("App starting (pid=%d)", os.getpid())

    site_dir = os.path.dirname(os.path.abspath(inspect.getfile(config_class)))
    site_templates = os.path.join(site_dir, "templates")
    site_static = os.path.join(site_dir, "static")

    template_folders = []
    if os.path.isdir(site_templates):
        template_folders.append(site_templates)
    template_folders.append(FRAMEWORK_TEMPLATES)
    app.jinja_loader = ChoiceLoader([FileSystemLoader(f) for f in template_folders])

    static_folders = []
    if os.path.isdir(site_static):
        static_folders.append(site_static)
    static_folders.append(FRAMEWORK_STATIC)

    from rhymes_with_soot.auth.routes import auth_bp
    from rhymes_with_soot.admin.routes import admin_bp
    from rhymes_with_soot.settings import settings_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(settings_bp)
    for bp in (blueprints or []):
        app.register_blueprint(bp)

    # create_all after blueprints are registered so site models are on Base.
    from rhymes_with_soot.db import init_db
    init_db(app)

    from rhymes_with_soot.util import format_size
    app.jinja_env.filters["format_size"] = format_size

    @app.after_request
    def _hsts(response):
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.after_request
    def _csp(response):
        csp = app.config.get("CSP")
        if csp:
            response.headers["Content-Security-Policy"] = csp
        return response

    @app.before_request
    def _csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            verify_csrf()

    @app.after_request
    def _csrf_cookie(response):
        token = getattr(g, "csrf_token", None)
        if token and getattr(g, "csrf_token_new", False):
            response.set_cookie(
                app.config["CSRF_COOKIE"],
                sign_token(token, _current_identity()),
                max_age=CSRF_MAX_AGE,
                httponly=True,
                samesite="Lax",
                secure=request.is_secure,
                path="/",
            )
        return response

    static_versions = {}

    def static_url(filename):
        path = _find_static(static_folders, filename)
        if path is None:
            return url_for("static", filename=filename)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return url_for("static", filename=filename)
        key = (path, mtime)
        version = static_versions.get(key)
        if version is None:
            with open(path, "rb") as f:
                version = hashlib.sha256(f.read()).hexdigest()[:12]
            static_versions[key] = version
        return url_for("static", filename=filename) + "?v=" + version

    @app.route("/static/<path:filename>")
    def static(filename):
        path = _find_static(static_folders, filename)
        if path is None:
            abort(404)
        return send_from_directory(os.path.dirname(path), os.path.basename(path))

    @app.context_processor
    def _inject():
        from rhymes_with_soot.auth.session import get_current_user
        return {
            "csrf_token": get_csrf_token(),
            "static_url": static_url,
            "current_user": get_current_user(),
            "app_name": app.config["APP_NAME"],
        }

    from rhymes_with_soot.errors import register_error_handlers
    register_error_handlers(app)

    return app


def _find_static(folders, filename):
    """Return the absolute path of ``filename`` in the first folder that has it."""
    for folder in folders:
        path = os.path.join(folder, filename)
        if not os.path.isfile(path):
            continue
        base = os.path.realpath(folder)
        real = os.path.realpath(path)
        if not real.startswith(base + os.sep):
            continue
        return path
    return None
