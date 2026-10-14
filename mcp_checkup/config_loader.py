"""Read MCP client configs into one normalised shape.

Secret values are never carried into the report: env / header values stay in
``_private_*`` and are excluded from ``to_dict()``. Rules that need to reason
about a value ask for a derived flag instead of the value itself.
"""

from __future__ import annotations

import io
import json
import os
import re
from dataclasses import dataclass, field

from .clients import CLIENTS, PROJECT_FILES, SERVER_KEYS

REMOTE_TYPES = {"http", "https", "sse", "streamable-http", "streamable_http"}

_SECRETISH = re.compile(r"(token|secret|password|passwd|apikey|api_key|api-key|credential|access_key|auth)", re.I)
_ASSIGN = re.compile(r"(--?\w*(?:token|key|secret|password|passwd)\w*)([= ])(\S+)", re.I)


def looks_secret(name: str) -> bool:
    return bool(_SECRETISH.search(name))


def redact(text: str) -> str:
    """Mask values of obviously-secret command-line arguments."""
    return _ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)


@dataclass
class McpServer:
    name: str
    source: str
    transport: str                      # stdio | http | sse | unknown
    command: str = ""
    args: list[str] = field(default_factory=list)
    url: str = ""
    env_keys: list[str] = field(default_factory=list)
    header_keys: list[str] = field(default_factory=list)
    raw_keys: list[str] = field(default_factory=list)
    disabled: bool = False
    _private_env: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def remote(self) -> bool:
        return self.transport in ("http", "sse")

    @property
    def secret_env_keys(self) -> list[str]:
        return [k for k in self.env_keys if looks_secret(k)]

    def has_env_value(self, key: str) -> bool:
        return bool(self._private_env.get(key, "").strip())

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source": self.source,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "url": self.url,
            "env_keys": list(self.env_keys),
            "header_keys": list(self.header_keys),
            "raw_keys": list(self.raw_keys),
            "disabled": self.disabled,
        }


@dataclass
class ConfigFile:
    path: str
    client: str
    servers: list[McpServer] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        out = {"path": self.path, "client": self.client, "servers": [s.to_dict() for s in self.servers]}
        if self.error:
            out["error"] = self.error
        return out


def _transport_of(cfg: dict, url: str) -> str:
    declared = str(cfg.get("type") or cfg.get("transport") or "").lower()
    if declared in REMOTE_TYPES:
        return "sse" if declared == "sse" else "http"
    if url:
        return "sse" if url.lower().startswith("sse") else "http"
    if cfg.get("command"):
        return "stdio"
    return "unknown"


def _server_from(name: str, cfg, path: str) -> McpServer | None:
    if not isinstance(cfg, dict):
        return None
    url = str(cfg.get("url") or cfg.get("uri") or "")
    env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    return McpServer(
        name=name,
        source=path,
        transport=_transport_of(cfg, url),
        command=str(cfg.get("command") or ""),
        args=[str(a) for a in (cfg.get("args") or [])],
        url=url,
        env_keys=[str(k) for k in env],
        header_keys=[str(k) for k in headers],
        raw_keys=sorted(cfg.keys()),
        disabled=bool(cfg.get("disabled")) or cfg.get("enabled") is False,
        _private_env={str(k): str(v) for k, v in env.items()},
    )


def load_file(path: str, client: str = "") -> ConfigFile:
    cf = ConfigFile(path=path, client=client)
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except json.JSONDecodeError as e:
        cf.error = f"invalid JSON: {e}"
        return cf
    except OSError as e:
        cf.error = f"unreadable: {e}"
        return cf
    if not isinstance(doc, dict):
        cf.error = "top level is not an object"
        return cf
    for key in SERVER_KEYS:
        block = doc.get(key)
        if isinstance(block, dict):
            for name, cfg in block.items():
                server = _server_from(str(name), cfg, path)
                if server:
                    cf.servers.append(server)
            break
    return cf


def discover(project: str | None = None, client: str | None = None, extra: tuple[str, ...] = ()) -> list[ConfigFile]:
    """Every config that exists on this machine (plus --project and --config additions)."""
    found: list[ConfigFile] = []
    seen: set[str] = set()

    def add(path: str, who: str) -> None:
        full = os.path.abspath(os.path.expanduser(path))
        if full in seen:
            return
        seen.add(full)
        found.append(load_file(full, who))

    for p in extra:
        add(p, "user-supplied")

    if client and not any(c.name.lower() == client.lower() for c in CLIENTS):
        raise ValueError(f"unknown client: {client}")
    clients = CLIENTS if not client else tuple(c for c in CLIENTS if c.name.lower() == client.lower())

    for c in clients:
        for path in c.existing():
            add(path, c.name)

    if project:
        root = os.path.abspath(os.path.expanduser(project))
        for rel in PROJECT_FILES:
            p = os.path.join(root, rel)
            if os.path.isfile(p):
                add(p, f"project:{os.path.basename(root)}")
    return found
