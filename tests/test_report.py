import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from mcp_checkup.cli import main
from mcp_checkup.config_loader import load_file
from mcp_checkup.report import build, to_json, to_markdown, write
from mcp_checkup.rules import evaluate, load_rules

HERE = os.path.dirname(os.path.abspath(__file__))
EX = os.path.join(HERE, "..", "examples")
RULES = load_rules()


def payload_for(*names):
    files = [load_file(os.path.join(EX, n), "example") for n in names]
    reports = [(cf, s, evaluate(s, RULES)) for cf in files for s in cf.servers]
    return build(files, reports, len(RULES))


class MarkdownTest(unittest.TestCase):
    def test_suspicious_report_shape(self):
        md = to_markdown(payload_for("fixture_suspicious.mcp.json"))
        for needle in ("# MCP 配置体检报告", "## 明细", "zh.override", "st.secret_in_config",
                       "## 附录 A", "## 附录 B · 本报告查不出什么", "静态检测"):
            self.assertIn(needle, md)

    def test_clean_report_says_all_clear(self):
        md = to_markdown(payload_for("clean.mcp.json"))
        self.assertIn("未发现问题", md)
        self.assertIn("所有被扫描的 server 均未命中规则", md)

    def test_secret_value_never_reaches_the_report(self):
        secret = "sk-EXAMPLE-NOT-A-REAL-KEY-000000000000"
        p = payload_for("fixture_suspicious.mcp.json")
        blob = to_markdown(p) + to_json(p)
        self.assertNotIn(secret, blob)
        self.assertIn("OPENAI_API_KEY", blob)   # the key name is the finding, not its value


class JsonTest(unittest.TestCase):
    def test_payload_is_serialisable_and_carries_meta(self):
        p = payload_for("clean.mcp.json", "fixture_suspicious.mcp.json")
        doc = json.loads(to_json(p))
        self.assertEqual("mcp-checkup", doc["meta"]["tool"])
        self.assertGreaterEqual(doc["meta"]["rules_loaded"], 25)
        self.assertEqual(4, doc["summary"]["servers"])
        self.assertGreater(doc["summary"]["score"], 0)


class CliTest(unittest.TestCase):
    def test_out_writes_markdown_and_keeps_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "sub", "report.md")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["scan", "--config", os.path.join(EX, "fixture_suspicious.mcp.json"),
                             "--client", "Qoder", "--out", target, "--fail-on", "high"])
            self.assertEqual(1, code)
            self.assertTrue(os.path.isfile(target))
            with io.open(target, encoding="utf-8") as fh:
                self.assertIn("## 明细", fh.read())
            self.assertIn("报告已写入", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
