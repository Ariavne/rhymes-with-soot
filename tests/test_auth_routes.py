from tests.helpers import extract_csrf, login, make_user


def test_login_get_renders(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"csrf_token" in resp.get_data()


def test_login_get_redirects_when_authenticated(client):
    make_user(client.application, "alice", "pw")
    login(client, "alice", "pw")
    resp = client.get("/login")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/t/home")


def test_login_bad_credentials(client):
    session_cookie = client.application.config["SESSION_COOKIE"]
    make_user(client.application, "alice", "correct")
    resp = login(client, "alice", "wrong")
    assert resp.status_code == 401
    assert client.get_cookie(session_cookie) is None


def test_login_success_sets_secure_cookie(client):
    session_cookie = client.application.config["SESSION_COOKIE"]
    make_user(client.application, "alice", "correct")
    resp = login(client, "alice", "correct")
    assert resp.status_code == 302
    cookie = client.get_cookie(session_cookie)
    assert cookie is not None
    assert cookie.http_only is True
    assert str(cookie.same_site).lower() == "lax"


def test_logout_clears_session(client):
    session_cookie = client.application.config["SESSION_COOKIE"]
    make_user(client.application, "alice", "correct")
    login(client, "alice", "correct")
    assert client.get_cookie(session_cookie) is not None
    # Logout is POST and requires a CSRF token.
    from tests.helpers import extract_csrf

    page = client.get("/t/page")
    token = extract_csrf(page.get_data(as_text=True))
    resp = client.post("/logout", data={"csrf_token": token})
    assert resp.status_code == 302
    assert client.get_cookie(session_cookie) is None


def test_login_redirects_to_next_from_form(client):
    """The login form carries ``next`` as a hidden field, so on POST the
    redirect must read it from the form body, not the (empty) query string."""
    make_user(client.application, "alice", "pw")
    page = client.get("/login?next=/t/protected")
    token = extract_csrf(page.get_data(as_text=True))
    assert 'name="next" value="/t/protected"' in page.get_data(as_text=True)

    resp = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "pw",
            "csrf_token": token,
            "next": "/t/protected",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/t/protected")


def test_login_next_rejects_protocol_relative_in_form(client):
    """A form-carried ``next`` is still screened against open redirects."""
    make_user(client.application, "alice", "pw")
    page = client.get("/login")
    token = extract_csrf(page.get_data(as_text=True))
    resp = client.post(
        "/login",
        data={
            "username": "alice",
            "password": "pw",
            "csrf_token": token,
            "next": "//evil.example",
        },
    )
    assert resp.status_code == 302
    # Falls back to LOGIN_REDIRECT, not the attacker's host.
    assert resp.headers["Location"].endswith("/t/home")
