"""Compare two tool snapshots and split "typo fix" from "capability change".

Pure offline: it reads two saved snapshot files and never touches a server.
New descriptions are re-run through the v0.2 rule set, so a rug-pull that adds
injection wording shows up as the same rule ids the config scanner would give.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .jcs import canonical
from .rules import TextRule

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_PUNCT = re.compile(r"[\W_]+", re.UNICODE)


@dataclass
class Change:
    tool: str
    kind: str
    severity: str
    detail: str
    rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"tool": self.tool, "kind": self.kind, "severity": self.severity,
                "detail": self.detail, "rules": list(self.rules)}


def _flat(text: str) -> str:
    return _PUNCT.sub("", (text or "").lower())


def _matched(text: str, rules: list[TextRule]) -> list[str]:
    return [r.id for r in rules if r.scope != "name" and r.regex.search(text or "")]


def _tools_by_name(snap: dict) -> dict[str, dict]:
    return {str(t.get("name")): t for t in snap.get("tools", []) if isinstance(t, dict)}


def _schema_of(tool: dict) -> dict:
    s = tool.get("inputSchema") or tool.get("input_schema")
    return s if isinstance(s, dict) else {}


def _diff_schema(name: str, old: dict, new: dict) -> list[Change]:
    out: list[Change] = []
    req_old = set(old.get("required") or [])
    req_new = set(new.get("required") or [])
    added_req = req_new - req_old
    if added_req:
        out.append(Change(name, "required_added", "high",
                          "新增必填参数 " + "、".join(sorted(added_req)) + "：调用方必须提供的东西变多了，能做什么也变多了"))
    props_old = old.get("properties") if isinstance(old.get("properties"), dict) else {}
    props_new = new.get("properties") if isinstance(new.get("properties"), dict) else {}
    for key in sorted(set(props_new) - set(props_old)):
        out.append(Change(name, "property_added", "medium", f"新增参数 `{key}`"))
    for key in sorted(set(props_old) - set(props_new)):
        out.append(Change(name, "property_removed", "medium", f"移除参数 `{key}`"))
    for key in sorted(set(props_old) & set(props_new)):
        a, b = props_old[key], props_new[key]
        if canonical(a) == canonical(b):
            continue
        if isinstance(a, dict) and isinstance(b, dict):
            stripped_a = {k: v for k, v in a.items() if k != "description"}
            stripped_b = {k: v for k, v in b.items() if k != "description"}
            if canonical(stripped_a) == canonical(stripped_b):
                out.append(Change(name, "param_doc_only", "low", f"参数 `{key}` 只改了说明文字"))
                continue
            if a.get("type") != b.get("type"):
                out.append(Change(name, "param_type_changed", "high",
                                  f"参数 `{key}` 类型 {a.get('type')} → {b.get('type')}"))
                continue
            enum_a, enum_b = a.get("enum"), b.get("enum")
            if isinstance(enum_a, list) and isinstance(enum_b, list) and set(enum_b) - set(enum_a):
                out.append(Change(name, "enum_widened", "medium",
                                  f"参数 `{key}` 可选值新增：" + "、".join(map(str, sorted(set(enum_b) - set(enum_a))))))
                continue
        out.append(Change(name, "param_changed", "medium", f"参数 `{key}` 定义变化"))
    return out


def compare(old: dict, new: dict, rules: list[TextRule] | None = None) -> list[Change]:
    rules = rules or []
    a, b = _tools_by_name(old), _tools_by_name(new)
    out: list[Change] = []

    for name in sorted(set(b) - set(a)):
        out.append(Change(name, "tool_added", "high", "新增工具：这是能力扩张，最需要人看一眼"))
    for name in sorted(set(a) - set(b)):
        out.append(Change(name, "tool_removed", "medium", "工具消失：可能是清理，也可能是改名绕过审查"))

    for name in sorted(set(a) & set(b)):
        ta, tb = a[name], b[name]
        da, db = str(ta.get("description") or ""), str(tb.get("description") or "")
        if da != db:
            hit_new, hit_old = set(_matched(db, rules)), set(_matched(da, rules))
            fresh = sorted(hit_new - hit_old)
            if fresh:
                out.append(Change(name, "description_poisoned", "high",
                                  "描述改动命中投毒规则（改动前不命中）", fresh))
            elif _flat(da) == _flat(db):
                out.append(Change(name, "description_cosmetic", "low", "描述只做了外观修改（空格 / 标点 / 大小写）"))
            else:
                out.append(Change(name, "description_changed", "medium",
                                  "描述实质改写：模型看到的就是这段话，行为可能随之改变"))
        out.extend(_diff_schema(name, _schema_of(ta), _schema_of(tb)))

    out.sort(key=lambda c: (SEVERITY_ORDER.get(c.severity, 9), c.tool, c.kind))
    return out


def summarise(changes: list[Change]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for c in changes:
        counts[c.severity] = counts.get(c.severity, 0) + 1
    return counts


def to_markdown(old: dict, new: dict, changes: list[Change]) -> str:
    a, b = summarise(changes), None
    out = ["# 工具定义变更审查", ""]
    out += [f"- 基线：`{old.get('server')}` @ {old.get('captured_at')}（{old.get('tool_count')} 个工具）",
            f"- 对比：`{new.get('server')}` @ {new.get('captured_at')}（{new.get('tool_count')} 个工具）",
            f"- 指纹：`{old.get('fingerprint')}` → `{new.get('fingerprint')}`",
            f"- 结论：**{'无变化' if not changes else '有变化，需人工确认'}**"
            f"（高危 {a['high']} · 中危 {a['medium']} · 低危 {a['low']}）", ""]
    if not changes:
        out += ["两次快照的工具定义完全一致。", ""]
    else:
        out += ["| 级别 | 工具 | 变化 | 说明 |", "|---|---|---|---|"]
        for c in changes:
            label = {"high": "高危", "medium": "中危", "low": "低危", "info": "提示"}[c.severity]
            detail = c.detail + ("：" + "、".join(f"`{r}`" for r in c.rules) if c.rules else "")
            out.append(f"| {label} | `{c.tool}` | `{c.kind}` | {detail} |")
        out += ["", "## 怎么读这份变更", "",
                "- **外观改动**（typo、空格、措辞润色）不需要警觉，量大也不危险。",
                "- **实质改动**（新增工具、新增必填参数、描述语义改写）才是 rug-pull 的落点：过审时给你看的描述，"
                "和运行时真正喂给模型的那份，可以不是同一份。",
                "- 高危项建议：先冻结该 server，读一遍新描述与新参数，再决定是否重新建立基线快照。", ""]
    return "\n".join(out)
