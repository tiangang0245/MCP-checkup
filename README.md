# mcp-checkup

**English** · [简体中文](README_zh.md)

> An offline, read-only, zero-dependency config checkup for people who **use** MCP servers — plus a snapshot review that tells you whether a server's tool definitions changed under you.

## Why this exists

Almost every MCP security tool today is written from one of two angles: the enterprise gateway, or scanning somebody else's repository. The largest and least-protected surface is neither of those — it is the handful of `mcp.json` files sitting on an individual developer's laptop, full of API keys, pointing at servers that were installed once and never reviewed.

`mcp-checkup` reads those files, normalises them, and runs detection rules over the text their author wrote. It can also fingerprint a server's declared tools, so the next time they change you find out whether it was a typo or a new shell tool. On its default path it never starts a server, never imports one, and never opens a socket — the single exception is the explicitly opt-in `snapshot` command.

The attack-surface model behind the rule set is written up in [`docs/威胁模型.md`](docs/威胁模型.md) (Chinese).

## What it does today (v0.4)

```bash
python -m mcp_checkup list                       # every known client config on this machine
python -m mcp_checkup scan                       # run the rule engine over them
python -m mcp_checkup scan -v                    # + the explanation line for each finding
python -m mcp_checkup scan --project D:\my-repo  # include project-level .mcp.json / .cursor/mcp.json
python -m mcp_checkup scan --config path/x.json  # audit an arbitrary file
python -m mcp_checkup scan --out report.md       # shareable Markdown report (.json also works)
python -m mcp_checkup scan --fail-on high        # exit 1 on a high finding - ready for CI

python -m mcp_checkup snapshot --server demo-fs --allow-exec   # record a tool-definition baseline
python -m mcp_checkup diff old.json new.json --out changes.md  # compare two snapshots, offline
```

Sample output against `examples/fixture_suspicious.mcp.json` (rule titles are bilingual by design — Chinese corpora rules report in Chinese, English ones in English):

```
mcp-checkup v0.4.0 - 规则体检（28 条规则 · 离线 · 只读）
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

Sample documents: [checkup report](docs/示例报告.md) · [change review](docs/示例变更审查.md)

## Snapshots and change review (v0.4)

A **rug-pull** is a server whose published tool description is not the one you end up running. Catching it needs a baseline to compare against:

```bash
python -m mcp_checkup snapshot --server demo-fs --allow-exec --dir snapshots
```

- It **starts the server process** to run the `initialize` + `tools/list` handshake, so it refuses to run without `--allow-exec`. stdio only for now; http/sse need auth handling and are not implemented.
- Do this for servers you already launch in your client every day. It adds no new execution surface in practice, but it is still an execution — hence the explicit gate.
- A snapshot contains tool definitions and a SHA-256 fingerprint over canonical JSON. **No env values** — there is a test for that.
- Re-running `snapshot` diffs against the previous capture automatically; `diff` does it manually on two files.

The classification is the point:

| Change | How it is judged | Severity |
|---|---|---|
| Cosmetic edit | identical once whitespace / punctuation / case are stripped | low |
| Description rewritten | meaning changed but no injection rule fires | medium |
| **Description now matches a poisoning rule** | did not match before, matches after (same 28 rules as the scanner) | **high** |
| New tool / new required parameter / parameter type change | capability growth | **high** |
| New optional parameter / removed parameter / widened enum | needs a human look | medium |

## Supported clients

Claude Desktop, Cursor, Windsurf, VS Code, Cline, Qoder, Zed, Gemini CLI, opencode, Continue — plus project-level files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`). The path list is a fixed allowlist in [`mcp_checkup/clients.py`](mcp_checkup/clients.py): no filesystem walks, so nothing gets read that you did not ask for.

## Design constraints

| Constraint | What it means in practice |
|---|---|
| **Offline** | No network calls, no registry lookups |
| **Read-only** | The checkup path only parses files; `snapshot` is the one command that starts a process, and it needs `--allow-exec` |
| **Zero dependencies** | Python standard library only (3.10+); `git clone` and run |
| **No secret leakage** | `env` / header **values** never enter the data model, reports, or snapshots — only key names are kept |

## Rules (28)

Rules are data, not code: drop an entry into `rules/*.json` and it takes effect without touching Python.

| File | Surface | Representative rules |
|---|---|---|
| [`rules/poisoning_zh.json`](rules/poisoning_zh.json) (9) | ② tool definitions | `zh.override` instruction-override in Chinese · `zh.hide_from_user` · `zh.exfiltrate` · `zh.bypass` · `zh.silent` · `zh.role_change` · `zh.invalidate_prev` · `zh.read_sensitive` · `zh.mandatory_call` |
| [`rules/poisoning_en.json`](rules/poisoning_en.json) (8) | ② same, English corpora | `en.override` · `en.hide_from_user` · `en.exfiltrate` · `en.bypass` · `en.silent` · `en.role_change` · `en.prepend_call` · `en.internal_note` |
| [`rules/structural.json`](rules/structural.json) (11) | ②③⑤ | `st.zero_width` invisible/bidi chars · `st.long_base64` · `st.pipe_to_shell` · `st.dynamic_exec` · `st.powershell_encoded` · `st.base64_decode` · `st.wildcard_bind` · `st.root_path` / `st.home_dir` over-broad grants · `st.dotenv` · `st.exfil_endpoint` |
| built into the engine | ①④ | `st.secret_in_config` (fires only when the key looks like a credential **and** has a value) · `st.plaintext_http` · `st.remote_no_auth` · `st.typosquat` (edit distance ≤2 from an official package) · `st.unknown_official_scope` |

Scanned scope is limited to text the config author controls — `command`, `args[i]`, `url`, description-style fields. `localhost` and `127.0.0.1` are exempt from the plaintext-HTTP and no-auth checks, so ordinary local development does not light up the report.

## What this tool cannot find

Read this before trusting a clean scan:

- **The checkup is static.** Commands assembled at runtime, reflection, and sandbox escapes are out of scope (v0.5 is where that starts).
- **Snapshots cover stdio only, and only if you take them.** A server you never baselined cannot be checked for rug-pull; http/sse baselines are not implemented.
- **No registry access.** Typosquat matching runs against a bundled official-package list, so a malicious package that appeared last week is not recognised.
- **Behaviour is invisible.** Anything a tool does that its description does not mention is beyond any static method.
- A finding is not proof of compromise, and zero findings is not proof of safety. The report is a triage starting point.

## Roadmap

| Version | Scope | Status |
|---|---|---|
| v0.1 | Config discovery, normalised view, secret redaction | done |
| v0.2 | Rule engine: hygiene + zh/en tool-description poisoning (28 rules) | done |
| v0.3 | Report layer: Markdown / JSON output with verdict and limits | done |
| v0.4 | Rug-pull review: JCS fingerprint snapshots + offline diff, cosmetic vs material | done |
| v0.5 | Dynamic detection: local range + eval / exec / reflection probing | planned |

Static first, dynamic later — deliberately. Pure static rules were proven unable to follow the runtime path of 2026's most severe MCP RCE, so dynamic checks are the real endgame; they just need a range, which is an order of magnitude more work.

## Layout

```
mcp_checkup/     clients.py (path allowlist) · config_loader.py (normalise + redact)
                 rules.py (engine + built-in checks) · known_names.py
                 report.py · jcs.py (canonical JSON + fingerprint)
                 snapshot.py (stdio handshake) · diff_tools.py (change triage) · cli.py
rules/           poisoning_zh.json · poisoning_en.json · structural.json   <- add rules here
tests/           stdlib unittest: loading / redaction / detection / false-positive bar / report / snapshot+diff
examples/        clean.mcp.json · fixture_suspicious.mcp.json (inert payloads)
docs/            威胁模型.md · 示例报告.md (sample report) · 示例变更审查.md (sample change review)
SECURITY.md      red lines and coordinated disclosure
```

## Tests

```bash
PYTHONPATH=. python -m unittest discover -s tests -v      # 38 cases, no pytest needed
```

`FalsePositiveBarTest` pins the "clean config, zero findings" bar. `SnapshotExecTest` runs a real stdio handshake against the fake MCP server committed in `tests/` — no network, no third-party package. `NamingTest` keeps two captures in the same second from overwriting each other.

## Red lines

Defensive detection only: no network, no executing third-party server code without an explicit flag, ranges stay local, disclosure is coordinated. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) · Copyright © 2026 tiangang0245
