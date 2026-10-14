"""Command line entry point: ``list`` (discovery) and ``scan`` (rule checkup)."""

from __future__ import annotations

import argparse
import json
import sys

from .clients import CLIENTS
from .config_loader import ConfigFile, McpServer, discover, redact
from .rules import SEVERITY_ORDER, evaluate, load_rules, score

SEV_TAG = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   ", "info": "INFO  "}


def enable_utf8_console() -> None:
    """Rule titles are Chinese; a legacy cp936 console would mangle them."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


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


def _empty(files: list[ConfigFile]) -> bool:
    if files:
        return False
    print("no known client config found.")
    print("use --config <path> for a specific file, or --project <dir> for project-level configs.")
    print("supported: " + ", ".join(c.name for c in CLIENTS))
    return True


def cmd_list(args: argparse.Namespace) -> int:
    files = discover(project=args.project, client=args.client, extra=tuple(args.config or ()))
    if args.json:
        print(json.dumps([f.to_dict() for f in files], ensure_ascii=False, indent=2))
        return 0
    total = sum(len(f.servers) for f in files)
    print("mcp-checkup - config discovery (read-only, never executes server code)")
    print(f"{len(files)} config files / {total} servers")
    if _empty(files):
        return 1
    for cf in files:
        _print_file(cf)
    print("\nenv / header values are never printed - key names only.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    files = discover(project=args.project, client=args.client, extra=tuple(args.config or ()))
    rules = load_rules()
    reports = []
    for cf in files:
        for s in cf.servers:
            reports.append((cf, s, evaluate(s, rules)))

    findings = [f for _, _, fs in reports for f in fs]
    if args.json:
        print(json.dumps({
            "rules_loaded": len(rules),
            "score": score(findings),
            "files": [f.to_dict() for f in files],
            "findings": [f.to_dict() for f in findings],
        }, ensure_ascii=False, indent=2))
    else:
        if _empty(files):
            return 1
        print(f"mcp-checkup v0.2 - 规则体检（{len(rules)} 条规则 · 离线 · 只读）")
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = " / ".join(f"{v} {k}" for k, v in counts.items() if v)
        print(f"发现 {summary or '0 findings'}")
        print(f"风险分 {score(findings)}（high=10 medium=4 low=1）\n")
        current = None
        for cf, s, fs in reports:
            key = (cf.path, s.name)
            if key != current:
                print(f"  {s.name}  ({cf.path})")
                current = key
            if not fs:
                print("    ok")
            for f in fs:
                print(f"    {SEV_TAG.get(f.severity, f.severity)}  {f.rule_id:<26} {f.field:<14} {f.title}")
                if f.excerpt:
                    print(f"            {f.excerpt}")
                if args.verbose and f.detail:
                    print(f"            → {f.detail}")
            print()

    if args.fail_on:
        blocking = [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= SEVERITY_ORDER[args.fail_on]]
        if blocking:
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-checkup", description="offline MCP config checkup for individual agent users")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_text in (("list", "list MCP configs found on this machine and in a project"),
                            ("scan", "run the rule engine against those configs")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--client", help="restrict to one client, e.g. 'Claude Desktop', Qoder, Cursor")
        sp.add_argument("--project", help="project root: scans .mcp.json, .cursor/mcp.json and friends")
        sp.add_argument("--config", action="append", help="extra config file (repeatable)")
        sp.add_argument("--json", action="store_true", help="JSON output (never contains secret values)")
        sp.set_defaults(func=cmd_list if name == "list" else cmd_scan)

    scan = sub.choices["scan"]
    scan.add_argument("-v", "--verbose", action="store_true", help="print the detail line for each finding")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding of this severity or worse appears")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    enable_utf8_console()
    return args.func(args)
