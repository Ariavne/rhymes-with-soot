"""BaseConfig env-var resolution and failure-mode tests."""
import os
import pytest

from rhymes_with_soot.config import BaseConfig


def test_missing_secret_key_raises():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        type(
            "NoSecret",
            (BaseConfig,),
            {"ENV_PREFIX": "NOSUCHPREFIX", "DB_PATH": "/tmp/x.db",
             "USERS_FILE": "/tmp/u.json",
             "SESSION_COOKIE": "x_session", "CSRF_COOKIE": "x_csrf"},
        )


def test_missing_env_prefix_raises():
    """ENV_PREFIX must be set on the class — it can't be read from the environment."""
    with pytest.raises(RuntimeError, match="ENV_PREFIX"):
        type(
            "NoPrefix",
            (BaseConfig,),
            {"SECRET_KEY": "k", "DB_PATH": "/tmp/x.db",
             "USERS_FILE": "/tmp/u.json",
             "SESSION_COOKIE": "x_session", "CSRF_COOKIE": "x_csrf"},
        )


def test_missing_cookies_raise(monkeypatch):
    """SESSION_COOKIE and CSRF_COOKIE are required; the app refuses to start without them."""
    monkeypatch.setenv("MC_SECRET_KEY", "k")
    monkeypatch.setenv("MC_DB_PATH", "/tmp/x.db")
    monkeypatch.setenv("MC_USERS_FILE", "/tmp/u.json")
    with pytest.raises(RuntimeError, match="SESSION_COOKIE"):
        type(
            "NoSessionCookie",
            (BaseConfig,),
            {"ENV_PREFIX": "MC", "CSRF_COOKIE": "mc_csrf", "APP_NAME": "M"},
        )
    with pytest.raises(RuntimeError, match="CSRF_COOKIE"):
        type(
            "NoCsrfCookie",
            (BaseConfig,),
            {"ENV_PREFIX": "MC", "SESSION_COOKIE": "mc_session", "APP_NAME": "M"},
        )


def test_missing_app_name_raises(monkeypatch):
    """APP_NAME is required; without it a site would silently show the framework's name."""
    monkeypatch.setenv("MA_SECRET_KEY", "k")
    monkeypatch.setenv("MA_DB_PATH", "/tmp/x.db")
    monkeypatch.setenv("MA_USERS_FILE", "/tmp/u.json")
    with pytest.raises(RuntimeError, match="APP_NAME"):
        type(
            "NoAppName",
            (BaseConfig,),
            {"ENV_PREFIX": "MA", "SESSION_COOKIE": "ma_session",
             "CSRF_COOKIE": "ma_csrf"},
        )


def test_missing_required_env_raises(monkeypatch):
    monkeypatch.delenv("X_SECRET_KEY", raising=False)
    monkeypatch.delenv("X_DB_PATH", raising=False)
    with pytest.raises(RuntimeError, match="DB_PATH"):
        type(
            "NoDb",
            (BaseConfig,),
            {"ENV_PREFIX": "X", "SECRET_KEY": "k", "USERS_FILE": "/tmp/u.json",
             "SESSION_COOKIE": "x_session", "CSRF_COOKIE": "x_csrf"},
        )


def test_env_var_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("RES_SECRET_KEY", "from-env")
    monkeypatch.setenv("RES_DB_PATH", str(tmp_path / "x.db"))
    monkeypatch.setenv("RES_USERS_FILE", str(tmp_path / "u.json"))
    cfg = type("EnvCfg", (BaseConfig,),
               {"ENV_PREFIX": "RES",
                "SESSION_COOKIE": "res_session", "CSRF_COOKIE": "res_csrf",
                "APP_NAME": "Res"})
    assert cfg.SECRET_KEY == "from-env"
    assert cfg.DB_PATH == str(tmp_path / "x.db")


def test_secret_keyfile(tmp_path, monkeypatch):
    keyfile = tmp_path / "key.txt"
    keyfile.write_text("file-secret\n")
    monkeypatch.delenv("FK_SECRET_KEY", raising=False)
    monkeypatch.setenv("FK_SECRET_KEYFILE", str(keyfile))
    monkeypatch.setenv("FK_DB_PATH", "/tmp/x.db")
    monkeypatch.setenv("FK_USERS_FILE", "/tmp/u.json")
    cfg = type("FileCfg", (BaseConfig,),
               {"ENV_PREFIX": "FK",
                "SESSION_COOKIE": "fk_session", "CSRF_COOKIE": "fk_csrf",
                "APP_NAME": "Fk"})
    assert cfg.SECRET_KEY == "file-secret"


def test_explicit_class_values_bypass_env(monkeypatch):
    """Setting values on the class skips env lookups entirely (the CI path)."""
    monkeypatch.delenv("CI_SECRET_KEY", raising=False)
    cfg = type(
        "CiCfg",
        (BaseConfig,),
        {"ENV_PREFIX": "CI", "SECRET_KEY": "k", "DB_PATH": "/tmp/x.db",
         "USERS_FILE": "/tmp/u.json",
         "SESSION_COOKIE": "ci_session", "CSRF_COOKIE": "ci_csrf",
         "APP_NAME": "Ci"},
    )
    assert cfg.SECRET_KEY == "k"
