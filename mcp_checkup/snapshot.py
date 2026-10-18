"""Capture a server's declared tools, so a later change can be noticed.

This is the one command in the tool that starts a process: reading tool
definitions requires an ``initialize`` + ``tools/list`` handshake. It is
therefore gated behind an explicit flag in the CLI and limited to stdio
servers. Credentials are re-read from the config solely to launch the process -
they are never written into a snapshot.
"""

from __future__ import annotations

import io
import json
import os
import queue
import re
import subprocess
import threading
from datetime import datetime

from . import __version__
from .config_loader import McpServer, load_file
from .jcs import fingerprint

PROTOCOL_VERSION = "2025-06-18"
UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def raw_block(config_path: str, server_name: str) -> dict | None:
    """The untouched server object (with env / cwd), used only to launch."""
    try:
        with io.open(config_path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    for key in ("mcpServers", "servers", "context_servers", "mcp"):
        block = doc.get(key) if isinstance(doc, dict) else None
        if isinstance(block, dict) and isinstance(block.get(server_name), dict):
            return block[server_name]
    return None


def _reader(proc, sink: queue.Queue) -> None:
    try:
        for line in proc.stdout:
            sink.put(line)
    except Exception as e:                      # noqa: BLE001 - the pipe died with the process
        sink.put(e)
    finally:
        sink.put(None)


def _await_id(sink: queue.Queue, want: int, deadline: float) -> dict:
    while True:
        left = deadline - datetime.now().timestamp()
        if left <= 0:
            raise TimeoutError("server did not answer in time")
        try:
            item = sink.get(timeout=left)
        except queue.Empty:
            raise TimeoutError("server did not answer in time") from None
        if item is None:
            raise RuntimeError("server closed the pipe before answering")
        if isinstance(item, Exception):
            raise item
        try:
            msg = json.loads(item)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want:
            if "error" in msg:
                raise RuntimeError(f"server error: {msg['error']}")
            return msg.get("result") or {}


def _send(proc, payload: dict) -> None:
    proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    proc.stdin.flush()


def list_tools(command: str, args: list[str], env: dict[str, str] | None = None,
               cwd: str | None = None, timeout: float = 20.0) -> list[dict]:
    proc = subprocess.Popen([command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
                            cwd=cwd or None, env={**os.environ, **(env or {})})
    sink: queue.Queue = queue.Queue()
    threading.Thread(target=_reader, args=(proc, sink), daemon=True).start()
    deadline = datetime.now().timestamp() + timeout
    try:
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                "clientInfo": {"name": "mcp-checkup", "version": __version__}}})
        _await_id(sink, 1, deadline)
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        result = _await_id(sink, 2, deadline)
    finally:
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    tools = result.get("tools")
    return [t for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []


def capture(server: McpServer, timeout: float = 20.0) -> dict:
    block = raw_block(server.source, server.name) or {}
    env = {str(k): str(v) for k, v in (block.get("env") or {}).items() if isinstance(v, (str, int, float))}
    tools = list_tools(server.command, server.args, env=env, cwd=block.get("cwd"), timeout=timeout)
    return {
        "server": server.name,
        "source": server.source,
        "captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "captured_by": f"mcp-checkup {__version__}",
        "transport": server.transport,
        "command": server.command,
        "args": list(server.args),
        "fingerprint": fingerprint(tools),
        "tool_count": len(tools),
        "tools": sorted(tools, key=lambda t: str(t.get("name") or "")),
    }


def filename_for(snap: dict) -> str:
    """Timestamp + fingerprint: two captures in the same second must not overwrite
    each other, or a diff silently compares a snapshot with itself."""
    stamp = re.sub(r"\D", "", snap["captured_at"])[:14]
    when = f"{stamp[:8]}-{stamp[8:14] or '000000'}"
    digest = str(snap.get("fingerprint", "")).replace("sha256:", "")[:10] or "nohash"
    return f"{UNSAFE.sub('-', snap['server'])}-{when}-{digest}.json"


def save(snap: dict, directory: str) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.abspath(os.path.join(directory, filename_for(snap)))
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(snap, fh, ensure_ascii=False, indent=2)
    return path


def load(path: str) -> dict:
    with io.open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "tools" not in doc:
        raise ValueError(f"not a snapshot file: {path}")
    return doc


def latest_for(directory: str, server_name: str) -> str | None:
    """Newest saved snapshot of one server, for `diff --against-latest`."""
    if not os.path.isdir(directory):
        return None
    prefix = UNSAFE.sub("-", server_name) + "-"
    hits = [os.path.join(directory, n) for n in sorted(os.listdir(directory)) if n.startswith(prefix)]
    return max(hits, key=os.path.getmtime) if hits else None
