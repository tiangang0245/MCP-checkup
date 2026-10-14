import json
import os
import unittest

from mcp_checkup.config_loader import discover, load_file, redact
from mcp_checkup.config_loader import looks_secret

HERE = os.path.dirname(os.path.abspath(__file__))
EX = os.path.join(HERE, "..", "examples")


def ex(name: str) -> str:
    return os.path.join(EX, name)


class LoadTest(unittest.TestCase):
    def test_clean_file(self):
        cf = load_file(ex("clean.mcp.json"), "test")
        self.assertEqual("", cf.error)
        by = {s.name: s for s in cf.servers}
        self.assertEqual({"filesystem", "weather"}, set(by))
        self.assertEqual("stdio", by["filesystem"].transport)
        self.assertEqual("http", by["weather"].transport)
        self.assertTrue(by["weather"].remote)
        self.assertEqual(["LOG_LEVEL"], by["filesystem"].env_keys)
        self.assertEqual(["Authorization"], by["weather"].header_keys)
        self.assertEqual([], by["filesystem"].secret_env_keys)

    def test_suspicious_file_shape(self):
        cf = load_file(ex("fixture_suspicious.mcp.json"), "test")
        by = {s.name: s for s in cf.servers}
        self.assertEqual(["OPENAI_API_KEY"], by["filesystem-utils"].secret_env_keys)
        self.assertFalse(looks_secret("LOG_LEVEL"))
        self.assertTrue(by["filesystem-utils"].has_env_value("OPENAI_API_KEY"))

    def test_values_never_serialised(self):
        cf = load_file(ex("fixture_suspicious.mcp.json"), "test")
        blob = json.dumps([cf.to_dict()], ensure_ascii=False)
        self.assertNotIn("sk-EXAMPLE", blob)
        self.assertIn("OPENAI_API_KEY", blob)

    def test_broken_json_is_a_finding_not_a_crash(self):
        cf = load_file(ex("does_not_exist.json"), "test")
        self.assertTrue(cf.error)
        self.assertEqual([], cf.servers)

    def test_redact_masks_secret_args(self):
        self.assertEqual("--api-key=*** x", redact("--api-key=supersecret x"))
        self.assertEqual("--path=/tmp", redact("--path=/tmp"))

    def test_discover_accepts_explicit_config(self):
        files = discover(extra=(ex("clean.mcp.json"),))
        mine = [f for f in files if f.client == "user-supplied"]
        self.assertEqual(1, len(mine))
        self.assertEqual(2, len(mine[0].servers))

    def test_discover_unknown_client(self):
        with self.assertRaises(ValueError):
            discover(client="Nonexistent IDE")


if __name__ == "__main__":
    unittest.main()
