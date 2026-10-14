"""Report layer: one scan -> a shareable Markdown / JSON document.

Nothing here may emit an env or header value; the only free text that reaches a
report is author-written config text already filtered by the rule engine.
"""

from __future__ import annotations

import io
import json
import os
from collections import Counter
from datetime import datetime

from . import __version__
from .config_loader import redact
from .rules import SEVERITY_ORDER, Finding, score

SEVERITY_CN = {"high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
ADVICE = {
    "high": "建议立即处置：移除该 server，或改写配置后再扫描确认。",
    "medium": "建议本轮修掉：多为权限过宽或缺少鉴权声明。",
    "low": "留意即可：单独出现通常是正常约束，与同族语句同时出现时才是攻击话术。",
    "info": "信息项，不需要动作。",
}


def build(files, reports, rules_loaded: int) -> dict:
    counts = Counter(f.severity for _, _, fs in reports for f in fs)
    servers = []
    for cf, s, fs in reports:
        servers.append({
            "client": cf.client, "source": cf.path, "name": s.name, "transport": s.transport,
            "target": s.url or " ".join([s.command] + [redact(a) for a in s.args]),
            "disabled": s.disabled, "env_keys": s.env_keys, "header_keys": s.header_keys,
            "findings": [f.rule_id for f in fs],
        })
    findings = [f for _, _, fs in reports for f in fs]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
    return {
        "meta": {
            "tool": "mcp-checkup", "version": __version__,
            "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
            "rules_loaded": rules_loaded, "mode": "offline / read-only / never executes server code",
            "files": [cf.path for cf in files],
        },
        "summary": {
            "servers": len(servers), "findings": len(findings),
            "by_severity": {k: counts.get(k, 0) for k in SEVERITY_ORDER},
            "score": score(findings),
            "verdict": ("未发现问题" if not findings
                        else "存在高危项，建议先清" if counts.get("high")
                        else "有中低危项，建议修" if counts.get("medium") else "仅提示项"),
        },
        "servers": servers,
        "findings": [f.to_dict() for f in findings],
    }


def to_json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _short(path: str) -> str:
    """Relative where possible: a committed sample report should not carry a home path."""
    try:
        rel = os.path.relpath(path)
    except ValueError:          # different drive on Windows
        return path
    return path if rel.startswith("..") else rel


def to_markdown(payload: dict) -> str:
    m, s = payload["meta"], payload["summary"]
    out = ["# MCP 配置体检报告", ""]
    out += [f"- 工具：mcp-checkup v{m['version']}",
            f"- 生成时间：{m['generated']}",
            f"- 规则数：{m['rules_loaded']}",
            f"- 模式：{m['mode']}",
            f"- 扫描配置：{len(m['files'])} 个文件 / {s['servers']} 个 server",
            f"- 结论：**{s['verdict']}**（风险分 {s['score']}；"
            + "、".join(f"{SEVERITY_CN[k]} {v}" for k, v in s["by_severity"].items() if v) + "）",
            ""]

    by_server = {}
    for f in payload["findings"]:
        by_server.setdefault((f["source"], f["server"]), []).append(f)

    out += ["## 明细", ""]
    if not payload["findings"]:
        out += ["所有被扫描的 server 均未命中规则。", ""]
    else:
        clean = sum(1 for sv in payload["servers"] if not sv["findings"])
        if clean:
            out += [f"另有 {clean} 个 server 未命中任何规则（清单见附录 A）。", ""]
    for (source, name), fs in by_server.items():
        out += [f"### {name}", f"- 来源：`{_short(source)}`", ""]
        out += ["| 级别 | 规则 | 字段 | 说明 |", "|---|---|---|---|"]
        for f in fs:
            out.append(f"| {SEVERITY_CN.get(f['severity'], f['severity'])} | `{f['rule']}` | "
                       f"`{f['field']}` | {f['title']} |")
        out.append("")
        for sev in ("high", "medium", "low", "info"):
            group = [f for f in fs if f["severity"] == sev]
            if not group:
                continue
            out += [f"**{SEVERITY_CN[sev]}**", ""]
            for f in group:
                out += [f"- `{f['rule']}` · `{f['field']}`：{f['detail'] or f['title']}"]
                if f["excerpt"]:
                    out += [f"  ```text\n  {f['excerpt']}\n  ```"]
            out += ["", ADVICE[sev], ""]

    out += ["## 附录 A · 扫描到的 server", "",
            "| 客户端 | 名称 | 传输 | 目标 | env 键（值未采集） | 命中 |", "|---|---|---|---|---|---|"]
    for sv in payload["servers"]:
        env = ", ".join(sv["env_keys"]) or "-"
        target = sv["target"].replace("|", "\\|")
        out.append(f"| {sv['client'] or '-'} | {sv['name']} | {sv['transport']} | `{target}` | {env} | "
                   f"{'、'.join('`' + r + '`' for r in sv['findings']) or '—'} |")

    out += ["", "## 附录 B · 本报告查不出什么", "",
            "- **静态检测**：运行时才拼出来的命令、反射调用、沙箱逃逸不在能力内（v0.5 才碰）。",
            "- **不看工具真实定义**：只读你写的配置；server 上线后改工具定义（rug-pull）要靠 v0.4 的快照 diff。",
            "- **不联网**：仿冒名比对用的是内置官方包清单，注册表新出现的恶意包认不出。",
            "- 命中不等于已中招，未命中也不等于安全；报告是排查起点，不是结论。", ""]
    return "\n".join(out)


def write(path: str, text: str) -> str:
    full = os.path.abspath(os.path.expanduser(path))
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with io.open(full, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return full
