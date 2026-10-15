# mcp-checkup

**English** · [简体中文](README_zh.md)

> An offline, read-only, zero-dependency config checkup for people who **use** MCP servers — not for enterprises that host them.

## Why this exists

Almost every MCP security tool today is written from one of two angles: the enterprise gateway, or scanning somebody else's repository. The largest and least-protected surface is neither of those — it is the handful of `mcp.json` files sitting on an individual developer's laptop, full of API keys, pointing at servers that were installed once and never reviewed.

`mcp-checkup` reads those files, normalises them, and runs detection rules over the text their author wrote. It never starts a server, never imports one, and never opens a socket.

The attack-surface model behind the rule set is written up in [`docs/威胁模型.md`](docs/威胁模型.md) (Chinese).

## What it does today (v0.3)

```bash
python -m mcp_checkup list                       # every known client config on this machine
python -m mcp_checkup scan                       # run the rule engine over them
python -m mcp_checkup scan -v                    # + the explanation line for each finding
python -m mcp_checkup scan --project D:\my-repo  # include project-level .mcp.json / .cursor/mcp.json
python -m mcp_checkup scan --config path/x.json  # audit an arbitrary file
python -m mcp_checkup scan --out report.md       # shareable Markdown report (.json also works)
python -m mcp_checkup scan --json                # machine-readable (never contains secret values)
python -m mcp_checkup scan --fail-on high        # exit 1 on a high finding - ready for CI
```

Sample output against `examples/fixture_suspicious.mcp.json` (rule titles are bilingual by design — Chinese corpora rules report in Chinese, English ones in English):

```
mcp-checkup v0.3 - 规则体检（28 条规则 · 离线 · 只读）
发现 4 high / 1 medium · 结论：存在高危项，建议先清
风险分 44（high=10 medium=4 low=1）

  filesystem-utils  (examples\fixture_suspicious.mcp.json)
    HIGH    st.secret_in_config        env.OPENAI_API_KEY 配置里内联了凭据
    HIGH    zh.override                description    中文指令覆盖语句

  pdf-tools  (examples\fixture_suspicious.mcp.json)
    HIGH    en.hide_from_user          description    Ask to hide behaviour from the user
    HIGH    st.zero_width              description    不可见控制字符
    MEDIUM  st.long_base64             description    超长 base64 样字符串
```

A clean config (`examples/clean.mcp.json`) reports **0 findings** — the false-positive bar is enforced by a test, not by good intentions.

Example report: [docs/示例报告.md](docs/示例报告.md).

## Supported clients

Claude Desktop, Cursor, Windsurf, VS Code, Cline, Qoder, Zed, Gemini CLI, opencode, Continue — plus project-level files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`). The path list is a fixed allowlist in [`mcp_checkup/clients.py`](mcp_checkup/clients.py): no filesystem walks, so nothing gets read that you did not ask for.

## Design constraints

| Constraint | What it means in practice |
|---|---|
| **Offline** | No network calls, no registry lookups |
| **Read-only** | Parses config files; never launches or imports an MCP server |
| **Zero dependencies** | Python standard library only (3.10+); `git clone` and run |
| **No secret leakage** | `env` / header **values** never enter the data model, the report, or `--json` output — only key names are kept |

## Rules (28)

Rules are data, not code: drop an entry into `rules/*.json` and it takes effect without touching Python.

| File | Surface | Representative rules |
|---|---|---|
| [`rules/poisoning_zh.json`](rules/poisoning_zh.json) (9) | ② tool definitions | `zh.override` instruction-override in Chinese · `zh.hide_from_user` · `zh.exfiltrate` · `zh.bypass` · `zh.silent` · `zh.role_change` · `zh.invalidate_prev` · `zh.read_sensitive` · `zh.mandatory_call` |
| [`rules/poisoning_en.json`](rules/poisoning_en.json) (8) | ② same, English corpora | `en.override` · `en.hide_from_user` · `en.exfiltrate` · `en.bypass` · `en.silent` · `en.role_change` · `en.prepend_call` · `en.internal_note` |
| [`rules/structural.json`](rules/structural.json) (11) | ②③⑤⑥ | `st.zero_width` invisible/bidi chars · `st.long_base64` · `st.pipe_to_shell` · `st.dynamic_exec` · `st.powershell_encoded` · `st.base64_decode` · `st.wildcard_bind` · `st.root_path` / `st.home_dir` over-broad grants · `st.dotenv` · `st.exfil_endpoint` |
| built into the engine | ①④⑥ | `st.secret_in_config` (fires only when the key looks like a credential **and** has a value) · `st.plaintext_http` · `st.remote_no_auth` · `st.typosquat` (edit distance ≤2 from an official package) · `st.unknown_official_scope` |

Scanned scope is limited to text the config author controls — `command`, `args[i]`, `url`, description-style fields. `localhost` and `127.0.0.1` are exempt from the plaintext-HTTP and no-auth checks, so ordinary local development does not light up the report.

## What this tool cannot find

Read this before trusting a clean scan:

- **Static analysis only.** Commands assembled at runtime, reflection, and sandbox escapes are out of scope (v0.5 is where that starts).
- **It does not see live tool definitions.** It audits what *you* wrote in config; a server that changes its definitions after approval (rug-pull) needs the snapshot diff planned for v0.4.
- **No registry access.** Typosquat matching runs against a bundled official-package list, so a malicious package that appeared last week is not recognised.
- A finding is not proof of compromise, and zero findings is not proof of safety. The report is a triage starting point.

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1 | Config discovery, normalised view, secret redaction | done |
| v0.2 | Rule engine: hygiene + zh/en tool-description poisoning (28 rules) | done |
| v0.3 | Report layer: Markdown / JSON output with verdict and limits | done |
| v0.4 | Rug-pull review: JCS hash pinning + snapshot diff | planned |
| v0.5 | Dynamic detection: local range + eval / exec / reflection probing | planned |

Static first, dynamic later — deliberately. Pure static rules were proven unable to keep up with the runtime path of 2026's most severe MCP RCE, so dynamic checks are the real endgame; they just need a range, which is an order of magnitude more work.

## Layout

```
mcp_checkup/     clients.py (path allowlist) · config_loader.py (normalise + redact)
                 rules.py (engine + built-in semantic checks) · known_names.py
                 report.py (Markdown / JSON) · cli.py
rules/           poisoning_zh.json · poisoning_en.json · structural.json   <- add rules here
tests/           stdlib unittest: loading / redaction / detection / false-positive bar / report
examples/        clean.mcp.json · fixture_suspicious.mcp.json (inert payloads)
docs/            威胁模型.md (threat model) · 示例报告.md (sample report)
SECURITY.md      red lines and coordinated disclosure
```

## Tests

```bash
PYTHONPATH=. python -m unittest discover -s tests -v      # 26 cases, no pytest needed
```

`FalsePositiveBarTest` pins the "clean config, zero findings" bar: if a new rule dirties `examples/clean.mcp.json`, the suite goes red.

## Red lines

Defensive detection only: no network, no executing server code, ranges stay local, disclosure is coordinated. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) · Copyright © 2026 tiangang0245
