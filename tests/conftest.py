"""Shared fixtures for the rhymes_with_soot test suite.
TestConfig sets values on cls.__dict__ so __init_subclass__ never reads os.environ."""
import os
import shutil
import sys

# The suite must not litter the tree with bytecode caches. Set before any
# project import so no .pyc files are written during the run.
sys.dont_write_bytecode = True

import pytest
from flask import Blueprint, render_template, request

from rhymes_with_soot import create_app
from rhymes_with_soot.auth.session import get_current_user, login_required
from rhymes_with_soot.config import BaseConfig

# Project root (the parent of tests/).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pytest_configure(config):
    # Don't create a .pytest_cache directory; the suite cleans up after itself.
    config.pluginmanager.set_blocked("cacheprovider")


def _purge_caches():
    """Delete every __pycache__ dir and the .pytest_cache under the project
    root, whether the artifacts are from this run or a prior one."""
    pytest_cache = os.path.join(_ROOT, ".pytest_cache")
    if os.path.isdir(pytest_cache):
        shutil.rmtree(pytest_cache, ignore_errors=True)
    for dirpath, dirnames, _filenames in os.walk(_ROOT):
        for name in list(dirnames):
            if name == "__pycache__":
                shutil.rmtree(os.path.join(dirpath, name), ignore_errors=True)
                dirnames.remove(name)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    # Runs after cacheprovider has written .pytest_cache, so the tree is left
    # clean. trylast ensures we go after any other sessionfinish hooks.
    _purge_caches()

SECRET_KEY = "test-secret-key-0123456789abcdef0123456789abcdef"
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Test blueprint
# Exercises the framework's security hooks: /protected uses login_required,
# /echo is a state-changing route that must pass CSRF, /page renders a logged-in
# page carrying a fresh CSRF token, and /raise triggers the error handlers.
test_bp = Blueprint("test", __name__, url_prefix="/t")


@test_bp.route("/home")
def home():
    return "home"


@test_bp.route("/protected", methods=["GET", "POST"])
@login_required
def protected():
    return f"hello {get_current_user().username}"


@test_bp.route("/echo", methods=["POST"])
def echo():
    return "ok"


@test_bp.route("/page")
def page():
    return render_template("page.html")


@test_bp.route("/raise")
def raise_code():
    from werkzeug.exceptions import abort

    abort(request.args.get("code", 404, type=int))


# Fixtures
@pytest.fixture
def app(tmp_path):
    db_path = tmp_path / "test.db"
    users_file = tmp_path / "users.json"
    users_file.write_text("{}\n")

    config = type(
        "TestConfig",
        (BaseConfig,),
        {
            "ENV_PREFIX": "TEST",
            "SECRET_KEY": SECRET_KEY,
            "DB_PATH": str(db_path),
            "USERS_FILE": str(users_file),
            "APP_NAME": "Test Site",
            "LOGIN_REDIRECT": "/t/home",
            "SESSION_COOKIE": "test_session",
            "CSRF_COOKIE": "test_csrf",
            "ENCRYPTION_KEY": ENCRYPTION_KEY,
        },
    )
    return create_app(config, blueprints=[test_bp])


@pytest.fixture
def client(app):
    return app.test_client()
