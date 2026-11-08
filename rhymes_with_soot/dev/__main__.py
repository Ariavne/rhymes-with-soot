"""CLI entry point: ``python -m rhymes_with_soot.dev <command> <site>``.

Commands:

    init <site>                 Scaffold sites/<site>/ + generate dev env + dev user
    run <site> [--port N]       Start the dev server (default port 5000)
    start <site> [--port N]     Alias for run
    restart <site> [--port N]   Stop (if running) and start the dev server
    stop <site>                 Stop the dev server
    status <site>               Show whether the dev server is running

run/start/restart also accept ``--host IP`` (default 0.0.0.0, all
interfaces, so other devices on the network can reach the server); use
``--host 127.0.0.1`` to keep the server local-only.
"""
import argparse
import sys

from rhymes_with_soot.dev.runner import (
    DEFAULT_HOST, DEFAULT_PORT, RunnerError, lan_ip, read_pid, restart,
    start, status_url, stop,
)
from rhymes_with_soot.dev.scaffold import ScaffoldError, init_site


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m rhymes_with_soot.dev",
        description=(
            "Development harness for rhymes_with_soot sites.\n\n"
            "Browser verification: drive the dev server with the Python "
            "`playwright` package from the project .venv, launching the "
            "SYSTEM Firefox (p.firefox.launch(headless=True)) — not the MCP "
            "playwright tools, which hard-launch Chrome (not installed here). "
            "Run scripts with `.venv/bin/python`."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="scaffold a new site + dev environment")
    p_init.add_argument("site", help="site package name (e.g. my_site)")

    for cmd in ("run", "start", "restart"):
        p = sub.add_parser(cmd, help=f"{cmd} the site's dev server")
        p.add_argument("site")
        p.add_argument("--port", type=int, default=DEFAULT_PORT)
        p.add_argument("--host", default=DEFAULT_HOST,
                       help="listen address (default 0.0.0.0, all "
                            "interfaces); use 127.0.0.1 to keep it local")

    for cmd in ("stop", "status"):
        p = sub.add_parser(cmd, help=f"{cmd} the site's dev server")
        p.add_argument("site")

    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            _cmd_init(args.site)
        elif args.command in ("run", "start"):
            _cmd_run(args.site, args.port, args.host)
        elif args.command == "restart":
            _cmd_restart(args.site, args.port, args.host)
        elif args.command == "stop":
            _cmd_stop(args.site)
        elif args.command == "status":
            _cmd_status(args.site)
    except (RunnerError, ScaffoldError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _cmd_init(name):
    details = init_site(name)
    if details["scaffolded"]:
        print(f"Initialized sites/{name}/ from site_template/")
    else:
        print(f"Dev environment for existing site {name}/")
    print(f"  dev env:   {details['env_file']}")
    print(f"  dev state: {details['dev_dir']}/")
    print(f"  dev user:  {details['username']} / {details['password']}")
    print()
    print(f"Start it with:  python -m rhymes_with_soot.dev run {name}")


def _lan_notice(port, host):
    if host in ("0.0.0.0", "::"):
        ip = lan_ip()
        if ip:
            print(f"  listening on all interfaces; other devices can reach "
                  f"it at http://{ip}:{port}")


def _cmd_run(name, port, host):
    pid = start(name, port, host)
    print(f"{name} running (pid {pid}) at {status_url(port, host)}")
    _lan_notice(port, host)


def _cmd_restart(name, port, host):
    pid = restart(name, port, host)
    print(f"{name} restarted (pid {pid}) at {status_url(port, host)}")
    _lan_notice(port, host)


def _cmd_stop(name):
    pid = stop(name)
    if pid is None:
        print(f"{name} is not running")
    else:
        print(f"{name} stopped (pid {pid})")


def _cmd_status(name):
    pid = read_pid(name)
    if pid is None:
        print(f"{name}: stopped")
    else:
        print(f"{name}: running (pid {pid})")


if __name__ == "__main__":
    sys.exit(main())
