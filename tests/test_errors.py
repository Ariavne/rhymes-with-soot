"""Error handler tests: every code returns JSON for AJAX clients and the
themed page otherwise. This is the parametrized test that pins the
docstring/implementation contract in errors.py."""
import pytest

from rhymes_with_soot.errors import register_error_handlers

# (code, expected JSON message)
CASES = [
    (400, "Bad request"),
    (401, "Unauthorized"),
    (403, "Forbidden"),
    (404, "Not found"),
    (405, "Method not allowed"),
    (410, "Gone"),
    (413, "File too large"),
    (416, "Range not satisfiable"),
    (418, "I'm a teapot"),
    (500, "Internal server error"),
]


@pytest.mark.parametrize("code,message", CASES)
def test_json_response(client, code, message):
    resp = client.get(
        f"/t/raise?code={code}", headers={"Accept": "application/json"}
    )
    assert resp.status_code == code
    assert resp.is_json
    assert resp.get_json()["error"] == message


@pytest.mark.parametrize("code,message", CASES)
def test_html_response(client, code, message):
    resp = client.get(f"/t/raise?code={code}", headers={"Accept": "text/html"})
    assert resp.status_code == code
    assert not resp.is_json
    body = resp.get_data(as_text=True)
    assert "error-page" in body
    assert str(code) in body


def test_all_handlers_registered(app):
    # Guard against a code being logged (LOGGED_STATUS_CODES) but unhandled.
    for code, _ in CASES:
        handler = app.error_handler_spec[None].get(code)
        assert handler is not None, f"no handler registered for {code}"
