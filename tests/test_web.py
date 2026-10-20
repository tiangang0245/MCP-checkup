"""Tests for the optional web module.

Two things are under test: the panel must not leak (it is the only part of this
tool that answers an HTTP request), and it must really be deletable - the rest
of the CLI has to work with web.py absent.
"""

import http.client
import io
import json
import os
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcp_checkup import cli, web

HERE = os.path.dirname(os.path.abspath(__file__))
EX = os.path.join(HERE, "..", "examples")
SUSPICIOUS = os.path.join(EX, "fixture_suspicious.mcp.json")
SECRET = "sk-EXAMPLE-NOT-A-REAL-KEY-000000000000"
PKG = os.path.dirname(os.path.abspath(web.__file__))
CORE_MODULES = ("clients.py", "config_loader.py", "rules.py", "jcs.py",
                "snapshot.py", "diff_tools.py", "report.py", "known_names.py")


class LiveServer:
    """Real loopback listener on an ephemeral port - the guards only count if
    the stack is actually serving."""

    def __enter__(self):
        self.httpd = web.make_server("127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def request(self, method, path, body=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            headers = {"Host": host if host is not None else "127.0.0.1:%d" % self.port}
            if body is not None:
                headers["Content-Type"] = "application/json"
                # the repo lives under a Chinese directory name, so the body is not latin-1
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8")
        finally:
            conn.close()


class BindingTest(unittest.TestCase):
    def test_non_loopback_host_is_refused(self):
        for bad in ("0.0.0.0", "10.0.0.5", "192.168.1.20", "example.com"):
            with self.assertRaises(ValueError, msg=bad):
                web.make_server(bad, 0)

    def test_loopback_hosts_bind(self):
        for good in ("127.0.0.1", "localhost"):
            web.make_server(good, 0).server_close()

    def test_ipv6_loopback_binds_when_available(self):
        try:
            httpd = web.make_server("::1", 0)
        except OSError:
            self.skipTest("no IPv6 loopback on this box")
        httpd.server_close()


class ApiTest(unittest.TestCase):
    def test_scan_shape_and_secret_values_stay_out(self):
        with LiveServer() as srv:
            status, raw = srv.request("POST", "/api/scan", {"configs": [SUSPICIOUS], "client": "Qoder"})
            self.assertEqual(200, status)
            doc = json.loads(raw)
            for key in ("version", "rules_loaded", "servers", "findings", "counts", "files"):
                self.assertIn(key, doc)
            with open(SUSPICIOUS, encoding="utf-8") as fh:
                self.assertIn(SECRET, fh.read())          # the value is on disk...
            self.assertNotIn(SECRET, raw)                  # ...and never in the response
            self.assertIn("OPENAI_API_KEY", raw)           # key names do cross
            self.assertTrue(any(f["rule"] == "zh.override" for f in doc["findings"]))
            self.assertGreaterEqual(doc["counts"]["high"], 4)

    def test_rules_inventory_matches_the_engine(self):
        with LiveServer() as srv:
            status, raw = srv.request("GET", "/api/rules")
            self.assertEqual(200, status)
            rules = json.loads(raw)["rules"]
            self.assertEqual(len(web.rule_inventory()), len(rules))
            self.assertTrue(all({"id", "severity", "title", "detail", "scope"} <= set(r) for r in rules))

    def test_unknown_route_is_not_a_file_reader(self):
        with LiveServer() as srv:
            for path in ("/web/app.js", "/../mcp_checkup/web.py", "/api/../rules/structural.json",
                         "/api/nope", "/favicon.ico"):
                status, raw = srv.request("GET", path)
                self.assertEqual(404, status, path)
                self.assertEqual({"error": "not found"}, json.loads(raw))

    def test_static_assets_are_served(self):
        with LiveServer() as srv:
            status, raw = srv.request("GET", "/")
            self.assertEqual(200, status)
            self.assertIn("mcp-checkup", raw)
            self.assertEqual(200, srv.request("GET", "/app.js")[0])
            self.assertEqual(200, srv.request("GET", "/style.css")[0])

    def test_post_body_must_be_json(self):
        with LiveServer() as srv:
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("POST", "/api/scan", body="not json",
                         headers={"Content-Type": "application/json",
                                  "Host": "127.0.0.1:%d" % srv.port})
            self.assertEqual(400, conn.getresponse().status)
            conn.close()

    def test_host_header_has_to_be_loopback(self):
        """DNS rebinding: a remote page repoints its own domain at 127.0.0.1."""
        with LiveServer() as srv:
            for bad in ("evil.example.com", "127.0.0.1.evil.com", "localhost.evil.com", ""):
                status, raw = srv.request("GET", "/api/scan", host=bad)
                self.assertEqual(403, status, bad)
                self.assertNotIn("servers", json.loads(raw))
            self.assertEqual(200, srv.request("GET", "/api/scan", host="localhost:8765")[0])

    def test_response_headers_lock_the_page_down(self):
        with LiveServer() as srv:
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("GET", "/", headers={"Host": "127.0.0.1"})
            resp = conn.getresponse()
            resp.read()
            csp = resp.getheader("Content-Security-Policy") or ""
            self.assertIn("default-src 'self'", csp)
            self.assertNotIn("unsafe-inline", csp)
            self.assertEqual("nosniff", resp.getheader("X-Content-Type-Options"))
            conn.close()

    def test_frontend_has_no_markup_sink(self):
        """Tool descriptions are attacker-controllable data; the only safe way to
        show them is textContent. innerHTML would turn a poisoned description into XSS."""
        for name in ("app.js", "index.html"):
            with open(os.path.join(web.WEB_ROOT, name), encoding="utf-8") as fh:
                src = fh.read()
            self.assertNotIn("innerHTML", src, name)
            self.assertNotIn("document.write", src, name)

    def test_configs_are_limited_to_json_paths(self):
        with LiveServer() as srv:
            status, raw = srv.request("POST", "/api/scan",
                                      {"configs": [os.path.join(EX, "clean.mcp.json"),
                                                   os.path.join(EX, "clean.txt"),
                                                   "C:/Windows/win.ini", 42, None]})
            self.assertEqual(200, status)
            chosen = [f for f in json.loads(raw)["files"] if f["client"] == "user-supplied"]
            self.assertEqual(1, len(chosen))          # only the .json survived
            self.assertTrue(chosen[0]["path"].endswith("clean.mcp.json"))


class DeletableModuleTest(unittest.TestCase):
    """'Not keen on the web page? delete it' has to be true, not a slogan."""

    def test_serve_exists_only_while_web_is_importable(self):
        self.assertIsNotNone(cli._web)
        self.assertIs(cli.cmd_serve, cli.build_parser().parse_args(["serve"]).func)
        saved, cli._web = cli._web, None
        try:
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                cli.build_parser().parse_args(["serve"])
        finally:
            cli._web = saved

    def test_no_core_module_imports_web(self):
        for name in CORE_MODULES:
            with open(os.path.join(PKG, name), encoding="utf-8") as fh:
                src = fh.read()
            self.assertNotIn("from .web", src, name)
            self.assertNotIn("import web", src, name)


    def test_other_commands_still_run_without_the_panel(self):
        saved, cli._web = cli._web, None
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                code = cli.main(["scan", "--config", os.path.join(EX, "clean.mcp.json"), "--client", "Qoder"])
        finally:
            cli._web = saved
        self.assertEqual(0, code)
        self.assertIn("0 findings", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
