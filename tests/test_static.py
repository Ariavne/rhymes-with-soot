"""Static route tests: legitimate files resolve, path traversal is confined.

Regression test for the /static/<path> traversal: _find_static must refuse any
request whose resolved path escapes the static folder, whether via ``../`` or
a symlink planted inside it.
"""
import os

from rhymes_with_soot import _find_static, FRAMEWORK_STATIC


def test_legit_file_resolves():
    assert (
        _find_static([FRAMEWORK_STATIC], "css/framework.css")
        == os.path.join(FRAMEWORK_STATIC, "css/framework.css")
    )


def test_missing_file_is_none():
    assert _find_static([FRAMEWORK_STATIC], "css/nope.css") is None


def test_dotdot_traversal_is_confined():
    # Two levels up from rhymes_with_soot/static/ reaches tests/conftest.py.
    assert _find_static([FRAMEWORK_STATIC], "../../tests/conftest.py") is None
    # Deep traversal outside the repo entirely.
    assert _find_static([FRAMEWORK_STATIC], "../../../etc/passwd") is None


def test_symlink_escape_is_confined(tmp_path):
    # A symlink inside a static folder pointing outside must be refused.
    target = tmp_path / "secret.txt"
    target.write_text("secret\n")
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    os.symlink(target, static_dir / "escape.txt")
    assert _find_static([str(static_dir)], "escape.txt") is None
    # A real file in the same folder still resolves.
    legit = static_dir / "ok.txt"
    legit.write_text("ok\n")
    assert _find_static([str(static_dir)], "ok.txt") == str(legit)
