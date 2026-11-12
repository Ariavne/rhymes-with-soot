"""Per-site dev server management: env loading + pidfile boot.

Works for any site:

- The site's ``sites/<name>/dev/.env.dev`` supplies its ``<PREFIX>_*`` values.
- The server runs as a single detached process (``flask run --no-reload``)
  whose PID is recorded in ``sites/<name>/dev/server.pid``. Stop and restart
  read that file — deterministic, no port scanning or PID hunting.
- The site's dev port is assigned once at ``init`` and stored in
  ``sites/<name>/dev/server.port``; ``run``/``restart`` default to it, so
  each site keeps its own port.
- Server output goes to ``sites/<name>/dev/server.log``.

All dev state (env, DB, uploads, users, log, pid, port) lives in the site's
own ``sites/<name>/dev/`` directory, so each site is a self-contained
plugin. Relative env paths resolve against the repo root, which is the
server's cwd.
"""
import os
import signal
import socket
import subprocess
import time

from rhymes_with_soot.dev import REPO_ROOT

DEFAULT_PORT = 5000
DEFAULT_HOST = "0.0.0.0"
STARTUP_TIMEOUT = 15  # seconds to wait for the server to accept connections

_WILDCARD_HOSTS = ("0.0.0.0", "::")


def lan_ip():
    """Best-effort IP this machine presents on its network, or None.

    A connected UDP socket (no packets are sent) reveals the address the
    system would use to reach the internet.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def status_url(port=DEFAULT_PORT, host=DEFAULT_HOST):
    if host in _WILDCARD_HOSTS:
        display_host = lan_ip() or "127.0.0.1"
    else:
        display_host = host
    return f"http://{display_host}:{port}"


class RunnerError(Exception):
    pass


def _dev_dir(name, root=REPO_ROOT):
    return os.path.join(root, "sites", name, "dev")


def env_file(name, root=REPO_ROOT):
    return os.path.join(root, "sites", name, "dev", ".env.dev")


def pidfile(name, root=REPO_ROOT):
    return os.path.join(_dev_dir(name, root), "server.pid")


def portfile(name, root=REPO_ROOT):
    return os.path.join(_dev_dir(name, root), "server.port")


def remembered_port(name, root=REPO_ROOT):
    """The site's dev port, or None."""
    try:
        with open(portfile(name, root), "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def logfile(name, root=REPO_ROOT):
    return os.path.join(_dev_dir(name, root), "server.log")


def load_dotenv(path):
    """Parse a KEY=VALUE file into os.environ.

    Skips blanks and ``#`` comments. Existing environment variables win, so a
    shell export can override the file.
    """
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


def _venv_flask(root=REPO_ROOT):
    venv = os.path.join(root, ".venv", "bin", "flask")
    if not os.path.exists(venv):
        raise RunnerError(
            f"{venv} not found: create the project venv first "
            "(`python -m venv .venv && . .venv/bin/activate && "
            "pip install -r requirements.txt`)"
        )
    return venv


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid(name, root=REPO_ROOT):
    """Return the running server's PID, or None."""
    path = pidfile(name, root)
    try:
        with open(path, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return pid if _alive(pid) else None


def _is_dev_server(pid, name):
    """True when the live process with this pid is the site's dev server.

    A stale pidfile can hold a pid the OS has since assigned to an
    unrelated process; signaling without this check would kill it. A
    process that cannot be identified is treated as not ours — a wrong
    kill is worse than a stale pidfile."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().decode("utf-8", "replace")
    except OSError:
        return False
    return "flask" in cmdline and f"sites.{name}" in cmdline


def stop(name, root=REPO_ROOT, timeout=5):
    """Stop the site's dev server (if running). Returns the stopped PID or None."""
    pid = read_pid(name, root)
    if pid is None:
        return None
    if not _is_dev_server(pid, name):
        # Stale pidfile: remove it without signaling the reused pid.
        _rm_pidfile(name, root)
        return None
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + timeout
        while time.time() < deadline and _alive(pid):
            time.sleep(0.2)
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    _rm_pidfile(name, root)
    return pid


def _rm_pidfile(name, root=REPO_ROOT):
    try:
        os.remove(pidfile(name, root))
    except OSError:
        pass


def _wait_ready(proc, name, host, port, root, log_path,
                timeout=STARTUP_TIMEOUT):
    """Wait until the server accepts a connection, or raise RunnerError.

    The process is watched while waiting: a failed bind (the port held by
    another server) kills flask instantly, and the probe alone would see the
    other server and report a false success."""
    probe_host = "127.0.0.1" if host in _WILDCARD_HOSTS else host
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            _rm_pidfile(name, root)
            raise RunnerError(
                f"{name} exited during startup; check {log_path}"
            )
        try:
            with socket.create_connection((probe_host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.3)
    _rm_pidfile(name, root)
    raise RunnerError(
        f"server did not accept connections on {probe_host}:{port} within "
        f"{timeout}s; check {log_path}"
    )


def start(name, port=DEFAULT_PORT, host=DEFAULT_HOST, root=REPO_ROOT):
    """Start the site's dev server detached. Returns (PID, resolved port).

    ``port=None`` uses the site's port (``server.port``, assigned at init),
    falling back to the default; a site with no portfile gets one on its
    first start. Refuses to start a second instance while one is running.
    """
    port = port if port is not None else (
        remembered_port(name, root) or DEFAULT_PORT
    )
    existing = read_pid(name, root)
    if existing is not None:
        raise RunnerError(
            f"{name} is already running (pid {existing}); "
            f"use `python -m rhymes_with_soot.dev restart {name}`"
        )

    env_path = env_file(name, root)
    if not os.path.exists(env_path):
        raise RunnerError(
            f"no dev environment at {env_path}; "
            f"run `python -m rhymes_with_soot.dev init {name}` first"
        )
    load_dotenv(env_path)

    dev = _dev_dir(name, root)
    os.makedirs(dev, exist_ok=True)
    log = open(logfile(name, root), "ab")
    # Both import styles must resolve: `sites.<name>` (repo root on the path)
    # and top-level `<name>` (sites/ on the path).
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([root, os.path.join(root, "sites")])
    proc = subprocess.Popen(
        [
            _venv_flask(root),
            "--app", f"sites.{name}",
            "run",
            "--host", host,
            "--port", str(port),
            "--no-reload",
        ],
        cwd=root,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log.close()
    with open(pidfile(name, root), "w", encoding="utf-8") as f:
        f.write(str(proc.pid))

    _wait_ready(proc, name, host, port, root, logfile(name, root))
    if not os.path.exists(portfile(name, root)):
        with open(portfile(name, root), "w", encoding="utf-8") as f:
            f.write(str(port))
    return proc.pid, port


def restart(name, port=DEFAULT_PORT, host=DEFAULT_HOST, root=REPO_ROOT):
    """Stop (if running) and start the site's dev server. Returns
    (PID, resolved port)."""
    stop(name, root)
    return start(name, port, host, root)
