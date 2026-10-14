"""Known client config locations.

Paths are a fixed allowlist, never a filesystem walk: scanning the whole profile
is slow and would surface files the user never intended to audit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _home() -> str:
    return os.path.expanduser("~")


def _appdata() -> str:
    return os.environ.get("APPDATA") or os.path.join(_home(), "AppData", "Roaming")


def _xdg_config() -> str:
    return os.environ.get("XDG_CONFIG_HOME") or os.path.join(_home(), ".config")


@dataclass(frozen=True)
class Client:
    name: str
    paths: tuple[str, ...]

    def existing(self) -> list[str]:
        return [p for p in self.paths if os.path.isfile(p)]


CLIENTS: tuple[Client, ...] = (
    Client("Claude Desktop", (
        os.path.join(_appdata(), "Claude", "claude_desktop_config.json"),
        os.path.join(_home(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    )),
    Client("Cursor", (os.path.join(_home(), ".cursor", "mcp.json"),)),
    Client("Windsurf", (os.path.join(_home(), ".codeium", "windsurf", "mcp_config.json"),)),
    Client("VS Code", (
        os.path.join(_appdata(), "Code", "User", "mcp.json"),
        os.path.join(_xdg_config(), "Code", "User", "mcp.json"),
    )),
    Client("Cline", (
        os.path.join(_home(), ".cline", "mcp_settings.json"),
        os.path.join(_appdata(), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
    )),
    Client("Qoder", (
        os.path.join(_home(), ".qoder-cn", "mcp.json"),
        os.path.join(_home(), ".qoder", "mcp.json"),
    )),
    Client("Zed", (
        os.path.join(_xdg_config(), "zed", "settings.json"),
        os.path.join(_home(), ".zed", "settings.json"),
    )),
    Client("Gemini CLI", (os.path.join(_home(), ".gemini", "settings.json"),)),
    Client("opencode", (os.path.join(_xdg_config(), "opencode", "opencode.json"),)),
    Client("Continue", (os.path.join(_home(), ".continue", "config.json"),)),
)

# where each client keeps its server map; first match wins
SERVER_KEYS: tuple[str, ...] = ("mcpServers", "servers", "context_servers", "mcp")

# project-level files, resolved relative to a project root
PROJECT_FILES: tuple[str, ...] = (
    ".mcp.json",
    os.path.join(".cursor", "mcp.json"),
    os.path.join(".vscode", "mcp.json"),
    os.path.join(".qoder", "mcp.json"),
    os.path.join(".qoder-cn", "mcp.json"),
)


def by_name(name: str) -> Client | None:
    for c in CLIENTS:
        if c.name.lower() == name.lower():
            return c
    return None
