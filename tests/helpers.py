import re

from rhymes_with_soot.db import get_session
from rhymes_with_soot.models import User
from werkzeug.security import generate_password_hash


def make_user(app, username, password, role="user"):
    """Insert a user directly, bypassing the users.json provisioning path."""
    session = get_session()
    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
    )
    session.add(user)
    session.commit()
    return user


def extract_csrf(html):
    """Pull the CSRF token out of a rendered page's hidden field."""
    m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html)
    return m.group(1) if m else None


def login(client, username, password):
    """Drive the real /login form: GET for the token, then POST the creds."""
    resp = client.get("/login")
    token = extract_csrf(resp.get_data(as_text=True))
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
    )
