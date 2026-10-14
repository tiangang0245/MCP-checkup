"""Rule engine: JSON text rules + semantic checks that need several fields.

Text rules live in ``rules/*.json`` so adding coverage is a data change. Excerpts
come only from author-written config text, never from env / header values.
"""

from __future__ import annotations

import io
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field

from .config_loader import McpServer
from .known_names import OFFICIAL_PACKAGES, OFFICIAL_SCOPE

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_WEIGHT = {"high": 10, "medium": 4, "low": 1, "info": 0}
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


@dataclass
class Finding:
    rule_id: str
    severity: str
    server: str
    source: str
    field: str
    title: str
    detail: str = ""
    excerpt: str = ""
    refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule_id, "severity": self.severity, "server": self.server,
                "source": self.source, "field": self.field, "title": self.title,
                "detail": self.detail, "excerpt": self.excerpt, "refs": list(self.refs)}


@dataclass
class TextRule:
    id: str
    severity: str
    title: str
    detail: str
    scope: str
    regex: re.Pattern
    refs: list[str]


def _excerpt(text: str, start: int, end: int, width: int = 96) -> str:
    lo, hi = max(0, start - width // 2), min(len(text), end + width // 2)
    shown = "".join(ch if unicodedata.category(ch)[0] != "C" else f"\\u{ord(ch):04x}"
                    for ch in text[lo:hi])
    return ("…" if lo else "") + shown + ("…" if hi < len(text) else "")


def load_rules(rules_dir: str = RULES_DIR) -> list[TextRule]:
    rules = []
    if not os.path.isdir(rules_dir):
        return rules
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith(".json"):
            continue
        with io.open(os.path.join(rules_dir, name), encoding="utf-8-sig") as fh:
            doc = json.load(fh)
        for r in doc.get("rules", []):
            rules.append(TextRule(r["id"], r.get("severity", "low"), r.get("title", r["id"]),
                                  r.get("detail", ""), r.get("scope", "any"),
                                  re.compile(r["pattern"], re.I | re.U), r.get("refs", [])))
    return rules


def _distance(a: str, b: str, cap: int = 2) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _typosquat(server: McpServer) -> list[Finding]:
    out = []
    for cand in [server.name] + [a for a in server.args if "/" in a or "@" in a]:
        low = cand.strip().lower()
        if len(low) < 6 or low in OFFICIAL_PACKAGES:
            continue
        near = next((k for k in OFFICIAL_PACKAGES if _distance(low, k.lower()) <= 2), None)
        if near:
            out.append(Finding("st.typosquat", "high", server.name, server.source, "name/args",
                               "包名与官方包高度相似（疑似仿冒）",
                               f"“{cand}” 与官方 “{near}” 编辑距离 ≤2，仿冒名是投毒常用手法。",
                               cand, ["docs/威胁模型.md#①"]))
        elif low.startswith(OFFICIAL_SCOPE):
            out.append(Finding("st.unknown_official_scope", "medium", server.name, server.source,
                               "name/args", "非官方的 @modelcontextprotocol 包",
                               f"“{cand}” 使用官方 scope，但不在已知官方包清单内。",
                               cand, ["docs/威胁模型.md#①"]))
    return out


def _semantic(server: McpServer) -> list[Finding]:
    out = []
    for key in server.secret_env_keys:
        if server.has_env_value(key):
            out.append(Finding("st.secret_in_config", "high", server.name, server.source,
                               f"env.{key}", "配置里内联了凭据",
                               "键名看起来是密钥且已填值。值未被读取、未被打印；改用环境变量引用并轮换该凭据。",
                               "", ["docs/威胁模型.md#④"]))
    local = any(h in server.url for h in LOCAL_HOSTS)
    if server.remote and not server.header_keys and not local:
        out.append(Finding("st.remote_no_auth", "medium", server.name, server.source, "headers",
                           "远程 server 未声明鉴权头", f"{server.url} 无 headers；端点若可达公网即等于无鉴权。",
                           "", ["docs/威胁模型.md#⑥"]))
    if server.remote and server.url.lower().startswith("http://") and not local:
        out.append(Finding("st.plaintext_http", "high", server.name, server.source, "url",
                           "远程 server 走明文 http", "令牌与工具调用内容可被中间人读取。",
                           server.url, ["docs/威胁模型.md#④"]))
    out.extend(_typosquat(server))
    return out


def evaluate(server: McpServer, rules: list[TextRule]) -> list[Finding]:
    findings = _semantic(server)
    scannable = server.scannable()
    for rule in rules:
        if rule.scope == "name":
            pairs = [("name", server.name)]
        elif rule.scope == "any":
            pairs = scannable
        else:
            pairs = [(f, t) for f, t in scannable if f.startswith(rule.scope)]
        for fld, text in pairs:
            m = rule.regex.search(text)
            if m:
                findings.append(Finding(rule.id, rule.severity, server.name, server.source, fld,
                                        rule.title, rule.detail, _excerpt(text, m.start(), m.end()),
                                        rule.refs))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
    return findings


def score(findings: list[Finding]) -> int:
    return sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
