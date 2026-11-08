# rhymes_with_soot

A Flask application framework for building small, self-contained sites. One framework
installation can host any number of sites; each site is a Python package with its own
database file, cookie names, environment-variable prefix, and templates — and the
framework supplies everything a site needs in between: authentication, account
administration, per-user settings, encrypted file storage, CSRF protection, error
pages, and logging.

## Features

- **Multi-site hosting.** Every site reads its own `<ENV_PREFIX>_*` environment
  variables, uses its own cookie names, and stores its data in its own SQLite file.
  Sites never collide.
- **Stateless sessions.** Sessions are signed cookies (itsdangerous), valid on any
  worker with no server-side store. Each session is bound to the password hash it was
  minted under, so a forced password reset invalidates every existing session for
  that user.
- **CSRF protection** via a signed, HttpOnly cookie plus a synchronizer token bound
  to the current identity (a token issued for one user is rejected under another).
- **Encrypted file storage.** Everything a site stores — uploaded files and per-user
  settings — is encrypted at rest with AES-256-GCM. There is no plaintext fallback:
  a site without an encryption key refuses to start.
- **Per-user settings.** Sites declare settings at import time; the framework
  provides the database table, a `/settings` page, a JSON API, and an auto-saving
  client-side settings dialog.
- **Account administration.** A built-in admin page lets operators create users,
  force password resets, and delete users — nothing more. An admin can never view or
  recover another user's data.
- **Startup provisioning.** A `users.json` file seeds operator accounts
  all-or-nothing, with full validation before anything is written.
- **Template/static shadowing.** A site's `templates/` and `static/` shadow the
  framework's by filename, so a site rebrands every page by overriding one file.

## Requirements

- Python 3.10+
- Dependencies (see [`requirements.txt`](requirements.txt)):
  `flask`, `sqlalchemy` (2.x), `itsdangerous`, `werkzeug`, `cryptography`,
  `python-magic` (requires the system `libmagic` library), `requests`,
  `websocket-client`

## Project layout

```
rhymes_with_soot/           # the framework
    __init__.py             # create_app() application factory
    config.py               # BaseConfig — every site's Config subclasses this
    csrf.py                 # signed-cookie CSRF protection
    db.py                   # SQLite engine, scoped session, migration registry
    errors.py               # HTTP error handlers (HTML + JSON)
    logging.py              # request logging
    models.py               # shared declarative Base, User model
    provisioning.py         # users.json startup provisioning
    settings.py             # per-user settings: table, page, JSON API
    storage.py              # AES-256-GCM file storage and serving
    util.py                 # small shared helpers
    admin/                  # account management (routes + password policy)
    auth/                   # session signing/verification, /login and /logout
    static/                 # framework CSS/JS (framework.css, admin.js,
                            #   settings_dialog.js)
    templates/              # framework pages: framework_base.html, base.html,
                            #   login.html, admin.html, settings pages, errors/
site_template/              # copy source for a new site
```

A site is a package that imports the framework, defines a `BaseConfig` subclass and
one or more blueprints, and exposes a ready-to-serve WSGI `app`.

## Creating a site

`site_template/` is the copy source. Duplicate it to `sites/<name>/` and rename every
`site_template` reference — package name, config class, blueprint name, `ENV_PREFIX`,
and `url_for` targets. The template shows the minimal shape of a site:

```python
# sites/mysite/__init__.py
from rhymes_with_soot import create_app
from mysite.config import MySiteConfig
from mysite.routes import mysite_bp

def create():
    app = create_app(MySiteConfig, blueprints=[mysite_bp])
    from rhymes_with_soot.provisioning import provision_users
    provision_users(app)
    return app

app = create()
```

### Configuration

Every site's Config subclasses
[`BaseConfig`](rhymes_with_soot/config.py) and must set, on the class:

| Attribute | Meaning |
| --- | --- |
| `ENV_PREFIX` | Names the environment variables the site reads (`<PREFIX>_*`). Required. |
| `SESSION_COOKIE` | Session cookie name. Required. |
| `CSRF_COOKIE` | CSRF cookie name. Required. |
| `APP_NAME` | Rendered in page titles and the login heading. Required. |

The rest are resolved from environment variables at import time, or from class
attributes if set directly:

| Setting | Environment variable | Notes |
| --- | --- | --- |
| `SECRET_KEY` | `<PREFIX>_SECRET_KEY` | Signs sessions and CSRF tokens. Falls back to `<PREFIX>_SECRET_KEYFILE` (path to a file containing the key). Required. |
| `DB_PATH` | `<PREFIX>_DB_PATH` | SQLite database file. Required. |
| `USERS_FILE` | `<PREFIX>_USERS_FILE` | Provisioning file, see below. Required. |
| `ENCRYPTION_KEY` | — | 32 bytes (64 hex chars). Falls back to `ENCRYPTION_KEYFILE`. Required: there is no plaintext fallback for stored files or settings. |
| `STORAGE_DIR` | — | Directory in which stored files live. Required by the storage helpers; all storage paths are confined to it. |
| `SESSION_MAX_AGE` | — | Session lifetime in seconds. Default 7 days. |
| `LOGIN_REDIRECT` | — | Where to send users after login. Default `/`. |
| `CSP` | — | `Content-Security-Policy` header sent on every response. Default `None` (disabled). |
| `TRUST_PROXY` | — | `True` when behind a single reverse proxy that sets `X-Forwarded-For`. The app must be reachable only from that proxy. Default `False`. |

The app refuses to start if any required setting is missing, and it resolves the
encryption key during `create_app` so a missing or malformed key crashes startup
instead of the first write.

### Application factory

[`create_app(config_class, blueprints)`](rhymes_with_soot/__init__.py) builds the
Flask app:

1. Loads the site's config.
2. Resolves `ENCRYPTION_KEY` (fails fast if absent).
3. Wraps the WSGI app in `ProxyFix` when `TRUST_PROXY` is set.
4. Registers logging.
5. Points the Jinja loader and static serving at the site's `templates/` and
   `static/` (located next to the config file) first, then the framework's. A site
   file shadows a framework file by filename.
6. Registers the framework blueprints — auth, admin, settings — then the site's
   blueprints in the order given.
7. Creates database tables and runs migrations (site models must already be
   imported, which is why this happens after blueprint registration).
8. Installs the Jinja `format_size` filter, HSTS/CSP headers, CSRF protection,
   versioned static serving, and the template context processor.

Every template automatically receives:

- `csrf_token` — the current CSRF token;
- `static_url(filename)` — a static asset URL with a content-hash version
  query string for cache busting;
- `current_user` — the logged-in `User` or `None`;
- `app_name` — the site's `APP_NAME`.

Static files are served from the site's `static/` first, then the framework's, with
path-traversal protection.

## Authentication

Sessions are stateless signed cookies (see
[`auth/session.py`](rhymes_with_soot/auth/session.py)):

- The payload is `{username, sha256(password_hash)}`; the salted hash itself never
  leaves the database. The digest binds each cookie to the password generation it
  was minted under, so a forced reset invalidates all of that user's sessions.
- The cookie is `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS, path `/`, with
  `SESSION_MAX_AGE` as its lifetime.
- `get_current_user()` verifies the cookie, re-checks the password fingerprint
  against the database, and caches the result on `g` for the request.

The framework owns two routes (see [`auth/routes.py`](rhymes_with_soot/auth/routes.py)):

- `GET/POST /login` — renders the login page; on success sets the session cookie and
  redirects to `LOGIN_REDIRECT` or a same-origin `next` parameter (absolute and
  protocol-relative URLs are rejected to prevent open redirects). A precomputed
  dummy hash is checked when the username is unknown so a failed login costs the
  same time whether or not the account exists.
- `POST /logout` — deletes the session cookie and redirects to the login page.
  Logout is POST-only, so it goes through a form (or fetch) carrying the CSRF token.

Site routes use the decorators from
[`auth/session.py`](rhymes_with_soot/auth/session.py):

```python
from rhymes_with_soot.auth.session import login_required, admin_required, get_current_user

@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=get_current_user().username)
```

- `@login_required` — redirects anonymous GET requests to `/login?next=...`; returns
  401 for other methods.
- `@admin_required` — like `@login_required`, then 403 for authenticated non-admins.

Users have a `role` of `user` or `admin` (see the
[`User` model](rhymes_with_soot/models.py)).

## CSRF protection

State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) are verified before they
reach any route (see [`csrf.py`](rhymes_with_soot/csrf.py)). The token may be
supplied as the `X-CSRF-Token` header, a `csrf_token` form field, or a `csrf_token`
key in a JSON body. It must match the signed cookie, and the cookie must have been
issued for the current identity — a token minted while anonymous (or for another
user) is rejected.

In server-rendered forms, include the hidden field:

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```

JavaScript can read `window.CSRF_TOKEN` (injected by the framework base template)
and send it as the `X-CSRF-Token` header.

## Database and migrations

The framework uses SQLite via SQLAlchemy 2.x (see
[`db.py`](rhymes_with_soot/db.py)). Each site has its own database file at
`DB_PATH`; WAL mode, `synchronous=NORMAL`, and a 30-second busy timeout are set on
every connection. All models — the framework's and the site's — share one
declarative `Base` from [`models.py`](rhymes_with_soot/models.py), so `create_all`
creates every table at startup. The scoped session is removed at the end of each
request; use `get_session()` from `rhymes_with_soot.db` in views and helpers.

Site models are ordinary SQLAlchemy models on the shared `Base`:

```python
from sqlalchemy import Column, String, DateTime
from rhymes_with_soot.models import Base, uuid4, now

class Note(Base):
    __tablename__ = "notes"
    id = Column(String(36), primary_key=True, default=uuid4)
    body = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=now)
```

Because `create_all` never alters existing tables, schema changes are made with
migration steps:

```python
from rhymes_with_soot.db import register_migration, has_table

def _add_column(engine):
    if not has_table(engine, "notes"):
        return
    # inspect columns, ALTER TABLE if the column is missing

register_migration(_add_column)
```

Register at import time (the site's models module is the natural place). Steps run
in registration order after `create_all`, at every startup. They must be idempotent
— check before changing — and a step that raises is logged and skipped so one bad
migration cannot take the site down. The framework itself ships one migration that
adds `users.role` to databases that predate the column.

## User provisioning

At startup, [`provision_users(app)`](rhymes_with_soot/provisioning.py) loads the
site's `users.json` (`USERS_FILE`) into the database. The file maps usernames to
passwords and is the operator's list of seeded **admins**:

```json
{
  "jdoe": "a-long-compliant-password"
}
```

Provisioning is all-or-nothing and fails loudly. Every entry is validated before
anything is written: a reserved username or a policy-non-compliant password raises
`ProvisioningError` and the app must not start. Existing users are never
overwritten, so the step is idempotent. If the file does not exist, an empty one is
created and a warning logged; if it contains invalid JSON or is not a JSON object,
startup fails. The file is not committed to version control.

### Password policy and reserved usernames

The account policy lives in
[`admin/passwords.py`](rhymes_with_soot/admin/passwords.py) and applies everywhere
an account is created — admin create, forced reset, and `users.json` provisioning:

- Passwords must be at least 12 characters and contain an uppercase letter, a
  lowercase letter, a number, and a symbol.
- Reserved usernames (checked case-insensitively): `admin`, `administrator`, `.`,
  `..`.

## Administration

The framework admin (see [`admin/routes.py`](rhymes_with_soot/admin/routes.py)) is
account management only. The `/admin` page shows usernames, roles, and creation
dates and nothing else — an admin can never view or recover another user's data.

| Route | Action |
| --- | --- |
| `GET /admin` | User list. |
| `POST /admin/users` | Create a user (`username`, `role`, `password`, `confirm`). |
| `POST /admin/users/<username>/reset` | Force a password reset. |
| `POST /admin/users/<username>/delete` | Delete a user (not the admin's own account). |

Usernames must match `^[A-Za-z0-9._-]{1,64}$` and not be reserved. Passwords are
entered only in a dialog (see [`static/js/admin.js`](rhymes_with_soot/static/js/admin.js))
that mirrors the policy client-side for feedback and submits as a plain form POST;
the server re-checks the policy and the two-entry match on every request.

## Per-user settings

Sites decide which settings exist by calling `register_setting` at import time —
the site's models module is the natural place, the way migrations are registered
(see [`settings.py`](rhymes_with_soot/settings.py)):

```python
from rhymes_with_soot.settings import register_setting

register_setting("theme", "Theme", kind="select",
                 choices=[("light", "Light"), ("dark", "Dark")],
                 default="light", help="Appearance of the site.")
```

Setting kinds:

| Kind | Value | Notes |
| --- | --- | --- |
| `text` | string | Free-text input. |
| `number` | int | Whole number; a blank entry resets to the declared default. |
| `select` | one of `choices` | Dropdown. |
| `segment` | one of `choices` | Same value model as `select`; rendered as a row of single-tap buttons. |
| `toggle` | bool | Checkbox. |
| `image_url` | string | A stored file's serve URL; empty means "no image". Only same-origin paths are accepted (the value feeds an `<img>` src). |
| `url` | string | A same-origin relative path or absolute http(s) URL; empty means "no link". Other schemes are refused (the value feeds an `<a>` href). |

For `select`/`segment`, `choices` is a tuple of `(value, label)` pairs. `default`
is shown and submitted when the user has not set the value.

The framework owns the storage, the page, and the API:

- **Storage** — one `user_settings` row per user per key. Values are always
  encrypted at rest (AES-256-GCM) with the site's `ENCRYPTION_KEY`. A row written
  as plaintext by an older framework version reads back unchanged. A user's
  settings are invisible to every other user, including admins.
- **Page** — `GET/POST /settings` renders the declared settings with their current
  values; each control also auto-saves via the API as it changes. A site
  customizes the page by providing its own `templates/settings.html` that extends
  `framework_settings.html` (which offers a `settings_extra` block for extra
  sections).
- **JSON API** — for custom client-side controls:
  - `GET /api/settings` — the user's settings as a JSON object.
  - `GET /api/settings/defs` — the site's declarations plus the user's current
    values.
  - `PUT /api/settings/<key>` — body `{"value": ...}`; validated against the
    declared kind.
  - `DELETE /api/settings/<key>` — removes the setting.

  Keys must match `^[A-Za-z0-9._-]{1,128}$`.
- **Server-side helpers** — usable from any site code, in or out of a request:
  `load_settings(username)`, `get_setting(username, key, default=None)`,
  `set_setting(username, key, value)`, `delete_setting(username, key)`.

### The settings dialog

[`static/js/settings_dialog.js`](rhymes_with_soot/static/js/settings_dialog.js)
provides an auto-saving dialog for sites that build their own UI:

```js
import { openSettingsDialog } from "/static/js/settings_dialog.js";
openSettingsDialog({ title: "Settings", onSaved: (key, value) => {} });
```

Built-in row renderers cover `text`, `number`, `select`, `segment`, and `toggle`;
`url` and `image_url` fall back to a plain text input. A site can supply its own
control for any kind with `registerRowRenderer(kind, render)` — `render(def, value,
ctx)` returns the control element and `ctx.save(key, value)` persists it. After
each successful save, a `settings:saved` `CustomEvent` fires on `document` with
`{detail: {key, value}}`. The dialog is dismissed by Escape or a backdrop click.

## File storage

[`storage.py`](rhymes_with_soot/storage.py) encrypts files at rest with
AES-256-GCM in 16 MiB chunks. Files without the `SOOT` magic header are rejected —
there is no plaintext fallback. The on-disk format:

```
MAGIC "SOOT" (4) | version (1) | chunk size (8) | num chunks (8) | plaintext size (8)
chunk: nonce (12) | ciphertext length (8) | ciphertext
...
trailing index: 8-byte disk offset per chunk (enables O(1) seeks)
```

The encryption key comes from `ENCRYPTION_KEY` (64 hex chars) or
`ENCRYPTION_KEYFILE` and is resolved once per process — key rotation requires a
restart.

Key helpers:

- `resolve_key()` — the site's 32-byte key; raises if unconfigured.
- `generate_storage_path(user_id)` — a storage path relative to `STORAGE_DIR`,
  scoped to the user.
- `save_upload(uploaded_file, user_id, storage_path, on_progress=None)` — encrypt
  an uploaded file to disk; returns the plaintext size.
- `delete_from_disk(storage_path)` / `get_file_path(storage_path)` — remove or
  locate a stored file. Paths are confined to `STORAGE_DIR` (traversal raises).
- `is_encrypted(path)` — true when a file carries the `SOOT` header.
- `encrypt_secret(plaintext)` / `decrypt_secret(ciphertext)` — for short secrets;
  `base64(nonce || ciphertext+tag)`.
- `EncryptedFileReader(path)` — a seekable, decrypting file-like reader with O(1)
  seeks via the trailing offset index.
- `serve_encrypted(path, mimetype, download_name, as_attachment=False)` — serve a
  stored file with RFC 7233 single-range support (206/416), streaming in 1 MiB
  blocks so large files never load into memory.
- `serve_stored_file(path, filename, content_type, as_attachment=False)` — serve
  with an inline-vs-attachment policy: only a small set of preview types (PNG,
  JPEG, GIF, WebP, MP4, WebM, OGG video, common audio) render inline; everything
  else downloads.
- `detect_content_type(head, filename, declared=None)` — media types from libmagic;
  everything else falls back to the declared type, then the filename extension.

`Content-Disposition` filenames are sanitized and RFC 5987-quoted for non-ASCII
names.

## Templates and static assets

The framework ships a base template and the pages it owns (login, admin, settings,
error pages). The shadowing pattern works in two layers:

- `framework_base.html` — the real base: page title block, the framework
  stylesheet, `window.CSRF_TOKEN`, and `styles` / `content` / `scripts` blocks.
- `base.html` — a default that simply extends `framework_base.html`.

A site customizes branding by providing its **own** `templates/base.html` that
extends `framework_base.html` (extending `base.html` would resolve to itself and
recurse). Because the framework's own pages extend `base.html`, overriding it
rebrands every page at once. The same pattern applies to the settings page via
`framework_settings.html`.

Error pages (`errors/400.html` … `errors/500.html`) can be overridden the same way
by dropping a same-named template in the site's `templates/`.

Static assets work the same: the site's `static/` shadows the framework's by
filename, and `static_url(...)` in templates appends a content-hash version for
cache busting. The framework's stylesheet is `static/css/framework.css`; site CSS
is conventionally loaded in the `styles` block after it, so it can extend or
override framework styles.

## Error handling

[`errors.py`](rhymes_with_soot/errors.py) registers handlers for 400, 401, 403,
404, 405, 410, 413, 416, 418, and 500. Each renders the framework's error page, or
a one-line JSON body when the client explicitly prefers JSON (`Accept` or JSON
content type). 429 is deliberately not handled in the app — rate limiting is
enforced upstream.

## Logging

The framework configures the `rhymes_with_soot` logger (stream handler, INFO level)
and logs every 4xx/5xx response as one line with the client IP —
`400, 401, 403, 404, 410, 413, 429` plus any 5xx. Sites should reuse the same
logger:

```python
import logging
logger = logging.getLogger("rhymes_with_soot")
```

## Security notes

- **Encryption at rest is mandatory.** Files and settings are AES-256-GCM with the
  site's `ENCRYPTION_KEY`; a site without a key cannot start.
- **Sessions are bound to password generations.** A forced reset kills all of a
  user's sessions, on every worker, with no server-side invalidation store.
- **CSRF tokens are identity-bound** and salted per site, so two sites sharing a
  signing key (e.g. in development) cannot cross-validate.
- **Open redirects are closed off** in three places: the login `next` parameter,
  `safe_referrer()` in `util.py`, and the `image_url`/`url` setting validators.
- **Headers.** HSTS (`max-age=31536000; includeSubDomains`) on HTTPS responses;
  `Content-Security-Policy` when `CSP` is configured.
- **Login timing is equalized** for unknown usernames.
- **Storage paths cannot escape `STORAGE_DIR`**, and static serving resolves
  symlinks before serving.
- **Admins are account managers only.** The framework exposes no route by which an
  admin can read another user's data or settings.

## Utilities

[`util.py`](rhymes_with_soot/util.py):

- `utcnow()` — naive-UTC current time (keeps SQLite comparisons working).
- `safe_referrer(default=None)` — the `Referer` header only when it is a same-host
  path or URL safe to redirect to.
- `format_size(n)` — human-readable byte sizes; also available in templates as the
  `format_size` Jinja filter.

## License

All rights reserved. See [`LICENSE`](LICENSE).
