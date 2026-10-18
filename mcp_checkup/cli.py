"""Command line entry point: ``list`` (discovery) and ``scan`` (rule checkup)."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .clients import CLIENTS
from .config_loader import ConfigFile, McpServer, discover, redact
from .diff_tools import compare, summarise
from .diff_tools import to_markdown as diff_markdown
from .rules import SEVERITY_ORDER, evaluate, load_rules, score
from .snapshot import capture, latest_for, load, save
from .report import build as build_report, to_json, to_markdown, write as write_report

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
    reports = [(cf, s, evaluate(s, rules)) for cf in files for s in cf.servers]
    findings = [f for _, _, fs in reports for f in fs]
    payload = build_report(files, reports, len(rules))

    if args.out:
        text = to_json(payload) if args.out.lower().endswith(".json") else to_markdown(payload)
        written = write_report(args.out, text)
        print(f"报告已写入 {written}")

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if _empty(files):
            return 1
        print(f"mcp-checkup v{__version__} - 规则体检（{len(rules)} 条规则 · 离线 · 只读）")
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = " / ".join(f"{v} {k}" for k, v in counts.items() if v)
        print(f"发现 {summary or '0 findings'} · 结论：{payload['summary']['verdict']}")
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


def cmd_snapshot(args: argparse.Namespace) -> int:
    if not args.allow_exec:
        print("snapshot has to start the server to read its tool definitions.")
        print("that is the one thing this repo otherwise refuses to do, so it is opt-in:")
        print("  add --allow-exec  (only for a server you already run in your client)")
        return 2
    wanted = {s.name: s for cf in discover(project=args.project, client=args.client,
                                           extra=tuple(args.config or ())) for s in cf.servers}
    if args.server not in wanted:
        print(f"error: server '{args.server}' not found. known: " + ", ".join(sorted(wanted)))
        return 2
    server = wanted[args.server]
    if server.transport != "stdio":
        print(f"error: {server.transport} servers are not supported yet (needs auth handling).")
        return 2
    previous = latest_for(args.dir, server.name)
    try:
        snap = capture(server, timeout=args.timeout)
    except Exception as e:                                    # noqa: BLE001 - report any handshake failure
        print(f"error: 抓取失败 - {e}")
        return 1
    path = save(snap, args.dir)
    print(f"snapshot  {path}")
    print(f"  tools {snap['tool_count']}  fingerprint {snap['fingerprint']}")
    if not previous:
        print("  这是该 server 的第一份快照，已作为基线。")
        return 0
    changes = compare(load(previous), snap, load_rules())
    print(f"  与上一份（{os.path.basename(previous)}）相比：")
    _print_changes(changes)
    return 0


def _print_changes(changes) -> None:
    if not changes:
        print("    工具定义无变化。")
        return
    tag = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   ", "info": "INFO  "}
    for c in changes:
        extra = f"  {','.join(c.rules)}" if c.rules else ""
        print(f"    {tag.get(c.severity, c.severity)}  {c.tool:<24} {c.kind:<22} {c.detail}{extra}")


def cmd_diff(args: argparse.Namespace) -> int:
    old, new = load(args.old), load(args.new)
    changes = compare(old, new, load_rules())
    counts = summarise(changes)
    if args.json:
        print(json.dumps({"old": old.get("captured_at"), "new": new.get("captured_at"),
                          "counts": counts, "changes": [c.to_dict() for c in changes]},
                         ensure_ascii=False, indent=2))
    else:
        print(f"diff - {old.get('server')}  {old.get('captured_at')} -> {new.get('captured_at')}")
        print(f"变化 {len(changes)} 项（high {counts['high']} / medium {counts['medium']} / low {counts['low']}）\n")
        _print_changes(changes)
    if args.out:
        written = write_report(args.out, diff_markdown(old, new, changes))
        print(f"\n报告已写入 {written}")
    if args.fail_on:
        if any(SEVERITY_ORDER.get(c.severity, 9) <= SEVERITY_ORDER[args.fail_on] for c in changes):
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
    scan.add_argument("--out", help="write a report file (.md or .json) alongside the terminal output")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if a finding of this severity or worse appears")

    snap = sub.add_parser("snapshot", help="record a stdio server's tool definitions (starts the process - opt-in)")
    snap.add_argument("--server", required=True, help="server name as written in the config")
    snap.add_argument("--client", help="restrict discovery to one client")
    snap.add_argument("--project", help="project root to look in")
    snap.add_argument("--config", action="append", help="extra config file (repeatable)")
    snap.add_argument("--dir", default="snapshots", help="where snapshots are stored (default: ./snapshots)")
    snap.add_argument("--timeout", type=float, default=20.0, help="handshake timeout in seconds")
    snap.add_argument("--allow-exec", action="store_true", help="acknowledge that the server process will be started")
    snap.set_defaults(func=cmd_snapshot)

    dif = sub.add_parser("diff", help="compare two snapshots and split cosmetic from material changes")
    dif.add_argument("old", help="baseline snapshot .json")
    dif.add_argument("new", help="newer snapshot .json")
    dif.add_argument("--json", action="store_true", help="JSON output")
    dif.add_argument("--out", help="write a Markdown report")
    dif.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 on a change of this severity or worse")
    dif.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    enable_utf8_console()
    return args.func(args)
