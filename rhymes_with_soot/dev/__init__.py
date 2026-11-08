"""Dev harness: `python -m rhymes_with_soot.dev`.

Works for any site in this repo:

- ``init <site>`` scaffolds ``sites/<site>/`` from ``site_template/`` and
  generates the site's dev environment (``sites/<site>/dev/.env.dev``) plus a
  dev account in ``sites/<site>/dev/users.json``.
- ``run`` / ``restart`` / ``stop`` / ``status <site>`` manage a per-site dev
  server behind a pidfile (``sites/<site>/dev/server.pid``) — deterministic
  stop/restart, no port scanning or PID hunting.

Each site is a self-contained plugin: all dev state (env, DB, uploads, users,
pidfile, log) lives under ``sites/<site>/dev/`` so a dev server never touches
the site's real (production) data.
"""
import os

# Repo root: this file is <root>/rhymes_with_soot/dev/__init__.py.
REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
