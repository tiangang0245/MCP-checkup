"""Command line entry point. v0.1 implements ``list`` (discovery + normalised view).

Console strings stay ASCII: Windows terminals on a non-UTF-8 codepage mangle
Chinese output, so the Chinese-facing material lives in README / docs / reports.
"""

from __future__ import annotations

import argparse
import json
import sys

from .clients import CLIENTS
from .config_loader import ConfigFile, McpServer, discover, redact


def _print_server(s: McpServer) -> None:
    target = s.url or " ".join([s.command] + [redact(a) for a in s.args]) or "-"
    flags = []
    if s.disabled:
        flags.append("disabled")
    if s.secret_env_keys:
        flags.append("secret-env:" + ",".join(s.secret_env_keys))
    tail = f"  [{', '.join(flags)}]" if flags else ""
    print(f"    {s.name:<28} {s.transport:<7} {target}{tail}")


def _print_file(cf: ConfigFile) -> None:
    print(f"\n  {cf.client or '?'}  {cf.path}")
    if cf.error:
        print(f"    !! {cf.error}")
        return
    if not cf.servers:
        print("    (no servers)")
        return
    print(f"    {len(cf.servers)} servers")
    for s in cf.servers:
        _print_server(s)


def cmd_list(args: argparse.Namespace) -> int:
    try:
        files = discover(project=args.project, client=args.client, extra=tuple(args.config or ()))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([f.to_dict() for f in files], ensure_ascii=False, indent=2))
        return 0

    total = sum(len(f.servers) for f in files)
    print("mcp-checkup v0.1 - config discovery (read-only, never executes server code)")
    print(f"{len(files)} config files / {total} servers")
    if not files:
        print("no known client config found.")
        print("use --config <path> for a specific file, or --project <dir> for project-level configs.")
        print("supported: " + ", ".join(c.name for c in CLIENTS))
        return 1
    for cf in files:
        _print_file(cf)
    print("\nenv / header values are never printed - key names only.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-checkup", description="offline MCP config checkup for individual agent users")
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="list MCP configs found on this machine and in a project (v0.1)")
    lst.add_argument("--client", help="restrict to one client, e.g. 'Claude Desktop', Qoder, Cursor")
    lst.add_argument("--project", help="project root: scans .mcp.json, .cursor/mcp.json and friends")
    lst.add_argument("--config", action="append", help="extra config file (repeatable)")
    lst.add_argument("--json", action="store_true", help="JSON output (never contains secret values)")
    lst.set_defaults(func=cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
