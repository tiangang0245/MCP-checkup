"""Optional local dashboard for the checkup.

Self-contained on purpose: nothing else in the package imports this module, and
the CLI only registers `serve` when it is present. Delete web.py, tests/test_web.py
and the web/ directory and the rest of the tool keeps working unchanged.

It binds to loopback only and serves no remote assets: the data it renders is a
list of your authorised MCP servers and what they are configured to run.
"""

from __future__ import annotations

import io
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .config_loader import discover
from .rules import evaluate, load_rules

WEB_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
MAX_BODY = 64 * 1024


def scan_payload(project: str | None = None, client: str | None = None,
                 configs: list[str] | None = None) -> dict:
    """Everything the UI shows. Secret values are absent by construction: to_dict()
    keeps key names only."""
    rules = load_rules()
    files = discover(project=project, client=client, extra=tuple(configs or ()))
    servers, findings = [], []
    for cf in files:
        for s in cf.servers:
            fs = evaluate(s, rules)
            servers.append({**s.to_dict(), "client": cf.client, "error": cf.error,
                            "findings": [f.rule_id for f in fs]})
            findings.extend(f.to_dict() for f in fs)
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"version": __version__, "rules_loaded": len(rules), "servers": servers,
            "findings": findings, "counts": counts,
            "files": [{"path": cf.path, "client": cf.client, "error": cf.error,
                       "servers": len(cf.servers)} for cf in files]}


def rule_inventory() -> list[dict]:
    return [{"id": r.id, "severity": r.severity, "title": r.title, "detail": r.detail,
             "scope": r.scope} for r in load_rules()]


class Handler(BaseHTTPRequestHandler):
    server_version = "mcp-checkup/" + __version__
    LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")

    def log_message(self, *_args) -> None:          # keep the console readable
        pass

    def _host_ok(self) -> bool:
        """Reject any Host header that is not loopback. Without this, DNS rebinding
        would let a remote page rebind its own domain to 127.0.0.1 and read the
        response, which lists the servers you have authorised."""
        raw = (self.headers.get("Host") or "").strip().lower()
        if raw.startswith("["):                       # [::1]:8765
            raw = raw[1:].split("]", 1)[0]
        elif raw.count(":") == 1:                     # 127.0.0.1:8765
            raw = raw.rsplit(":", 1)[0]
        return raw in self.LOOPBACK_HOSTS

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # everything the page needs is same-origin; anything else is a bug or an edit
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                         "font-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _static(self, route: str) -> None:
        name, ctype = STATIC[route]                   # fixed map: no path is ever joined
        path = os.path.join(WEB_ROOT, name)
        if not os.path.isfile(path):
            self._json({"error": "web assets missing"}, 404)
            return
        with io.open(path, "rb") as fh:
            self._send(200, fh.read(), ctype)

    def do_GET(self) -> None:                         # noqa: N802 - stdlib naming
        if not self._host_ok():
            self._json({"error": "host header must be loopback"}, 403)
            return
        route = self.path.split("?", 1)[0]
        if route in STATIC:
            self._static(route)
        elif route == "/api/scan":
            self._json(scan_payload())
        elif route == "/api/rules":
            self._json({"rules": rule_inventory()})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:                        # noqa: N802 - stdlib naming
        if not self._host_ok():
            self._json({"error": "host header must be loopback"}, 403)
            return
        if self.path.split("?", 1)[0] != "/api/scan":
            self._json({"error": "not found"}, 404)
            return
        try:
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, OSError):
            self._json({"error": "bad request body"}, 400)
            return
        configs = [c for c in (body.get("configs") or []) if isinstance(c, str) and c.endswith(".json")]
        client = body.get("client")
        project = body.get("project")
        try:
            self._json(scan_payload(project=project if isinstance(project, str) else None,
                                    client=client if isinstance(client, str) else None,
                                    configs=configs))
        except ValueError as e:
            self._json({"error": str(e)}, 400)


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("the dashboard only binds loopback: it renders which servers you have "
                         "authorised, so it must not be reachable from the network")
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = make_server(host, port)
    actual = httpd.server_address[1]
    print(f"mcp-checkup dashboard  http://{host}:{actual}  (Ctrl+C to stop)")
    print("只监听本机；不加载任何外部资源；不写入任何文件。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def is_free(host: str = "127.0.0.1", port: int = 8765) -> bool:
    """True when nothing is listening yet. Uses connect (not bind) so an IPv6
    loopback host is not forced through an AF_INET socket."""
    try:
        socket.create_connection((host, port), timeout=0.3).close()
    except OSError:
        return True
    return False
