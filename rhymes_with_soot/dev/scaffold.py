"""Scaffold a new site from site_template/ and generate its dev environment.

Two cases:

- ``sites/<name>/`` does not exist: ``init_site`` copies ``site_template/``,
  renames every template identifier (package, config class, ENV_PREFIX,
  cookies, blueprint), and writes the dev env + dev account.
- ``sites/<name>/`` exists but has no ``dev/.env.dev``: the code is left
  alone; only the dev env (generated from the site's real ``ENV_PREFIX``) and
  dev account are created.

In both cases:

- ``sites/<name>/dev/.env.dev`` holds the site's ``<PREFIX>_*`` dev values.
- ``sites/<name>/dev/users.json`` holds a single dev account.
- All dev state (DB, uploads, log, pid) lives in ``sites/<name>/dev/``, so
  the site is a self-contained plugin.

Relative state paths in the env file resolve against the repo root, which is
also where the runner starts the server.
"""
import ast
import json
import os
import re
import secrets
import shutil

from rhymes_with_soot.dev import REPO_ROOT

TEMPLATE_DIR = os.path.join(REPO_ROOT, "site_template")

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class ScaffoldError(Exception):
    pass


def _title(name):
    """my_site -> MySite"""
    return "".join(part.capitalize() for part in name.split("_"))


def _pretty(name):
    """my_site -> My Site"""
    return " ".join(part.capitalize() for part in name.split("_"))


def _env_prefix(site_dir):
    """Read ENV_PREFIX from an existing site's config.py (no import side effects)."""
    path = os.path.join(site_dir, "config.py")
    with open(path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "ENV_PREFIX":
                    return ast.literal_eval(stmt.value)
    raise ScaffoldError(f"no ENV_PREFIX found in {path}")


def _scaffold(name, site_dir, prefix):
    """Copy the template and rename every identifier to the new site's."""
    # Order matters: longest/most specific spellings first.
    replacements = (
        ("SITE_TEMPLATE", prefix),
        ("SiteTemplate", _title(name)),
        ("Site Template", _pretty(name)),
        ("site_template", name),
    )
    shutil.copytree(TEMPLATE_DIR, site_dir)
    # Rename at the byte level so binary assets (logo.png, favicon.ico) copy
    # through cleanly; the replacement strings are ASCII, so a match can never
    # straddle a UTF-8 multibyte boundary.
    for dirpath, _dirnames, filenames in os.walk(site_dir):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            with open(path, "rb") as f:
                data = f.read()
            for old, new in replacements:
                data = data.replace(old.encode("ascii"), new.encode("ascii"))
            with open(path, "wb") as f:
                f.write(data)

    readme = (
        f"# {name}\n"
        "\n"
        "A rhymes_with_soot site, scaffolded from `site_template/`.\n"
        "\n"
        "## Development\n"
        "\n"
        "```bash\n"
        f"python -m rhymes_with_soot.dev run {name}        # start on http://127.0.0.1:5000 (all interfaces)\n"
        f"python -m rhymes_with_soot.dev restart {name}    # stop + start\n"
        f"python -m rhymes_with_soot.dev stop {name}\n"
        "```\n"
        "\n"
        f"Dev secrets and all dev state live in `sites/{name}/dev/`. Log in\n"
        "with the dev account printed when this site was initialized.\n"
    )
    with open(os.path.join(site_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)


def init_site(name, root=REPO_ROOT):
    """Prepare ``sites/<name>/`` for the dev harness.

    Returns a dict of dev details (env file, username, password, ...).
    """
    if not _NAME_RE.match(name):
        raise ScaffoldError(
            f"invalid site name {name!r}: use lowercase letters, digits, and "
            "underscores, starting with a letter (e.g. my_site)"
        )
    if name == "site_template":
        raise ScaffoldError("'site_template' is reserved")

    site_dir = os.path.join(root, "sites", name)
    env_file = os.path.join(site_dir, "dev", ".env.dev")
    if os.path.exists(env_file):
        raise ScaffoldError(f"{env_file} already exists; nothing to initialize")

    dev_dir = os.path.join(site_dir, "dev")
    os.makedirs(dev_dir, exist_ok=True)

    if os.path.exists(site_dir):
        # Existing site: keep its code, just give it a dev environment.
        prefix = _env_prefix(site_dir)
        scaffolded = False
    else:
        prefix = name.upper()
        _scaffold(name, site_dir, prefix)
        scaffolded = True

    # Dev account (gitignored; the only place the plaintext password exists).
    # Regenerate until it meets the framework password policy, so the dev
    # account can always log in.
    from rhymes_with_soot.admin.passwords import validate_password
    password = secrets.token_urlsafe(12)
    while validate_password(password):
        password = secrets.token_urlsafe(12)
    with open(os.path.join(dev_dir, "users.json"), "w", encoding="utf-8") as f:
        json.dump({"dev": password}, f, indent=2)
        f.write("\n")

    # The site's dev environment, in the format runner.load_dotenv parses.
    env_lines = [
        f"# {name} dev environment — generated by "
        f"`python -m rhymes_with_soot.dev init {name}`.",
        f"# All dev state lives in sites/{name}/dev/ so real data is untouched.",
        "",
        f"{prefix}_SECRET_KEY={secrets.token_hex(32)}",
        f"{prefix}_ENCRYPTION_KEY={secrets.token_hex(32)}",
        f"{prefix}_DB_PATH=sites/{name}/dev/app.db",
        f"{prefix}_STORAGE_DIR=sites/{name}/dev/uploads",
        f"{prefix}_USERS_FILE=sites/{name}/dev/users.json",
        "",
    ]
    with open(env_file, "w", encoding="utf-8") as f:
        f.write("\n".join(env_lines))

    return {
        "name": name,
        "prefix": prefix,
        "site_dir": site_dir,
        "env_file": env_file,
        "dev_dir": dev_dir,
        "username": "dev",
        "password": password,
        "scaffolded": scaffolded,
    }
