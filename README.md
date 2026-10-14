# mcp-checkup

> 给**个人 Agent 用户**的 MCP 配置体检器：离线、只读、零依赖。
> An offline, read-only, dependency-free MCP config checkup for individual agent users.

现有 MCP 安全工具几乎都是**企业网关 / 仓库扫描**视角。但真实世界里量最大、防护最薄的一环是：个人开发者笔记本上那几个 `mcp.json`。本工具从这一端切入。

## 现在能做什么（v0.1）

```bash
python -m mcp_checkup list                      # 扫描本机所有已知客户端配置
python -m mcp_checkup list --project F:\my-repo # 追加项目级 .mcp.json / .cursor/mcp.json
python -m mcp_checkup list --config path/x.json # 指定任意配置文件
python -m mcp_checkup list --json               # 机器可读输出（不含密钥值）
```

输出示例：

```
mcp-checkup v0.1 - config discovery (read-only, never executes server code)
4 config files / 4 servers

  user-supplied  examples\clean.mcp.json
    2 servers
    filesystem                   stdio   npx -y @modelcontextprotocol/server-filesystem /srv/data
    weather                      http    https://mcp.example.com/weather

  user-supplied  examples\fixture_suspicious.mcp.json
    2 servers
    filesystem-utils             stdio   sh -c <REMOTE-SCRIPT-PIPE-PAYLOAD>  [secret-env:OPENAI_API_KEY]
    pdf-tools                    stdio   python -c <DYNAMIC-EVAL-PAYLOAD>
```

支持的客户端配置：Claude Desktop、Cursor、Windsurf、VS Code、Cline、Qoder、Zed、Gemini CLI、opencode、Continue（路径清单见 `mcp_checkup/clients.py`）。

## 设计约束

| 约束 | 含义 |
|---|---|
| **离线** | 不发起任何网络请求，不查询注册表 |
| **只读** | 只读配置文件，绝不启动 / import 任何 MCP server |
| **零依赖** | 只用 Python 标准库（3.10+），`git clone` 即可跑 |
| **不泄密** | env / headers 的值**不进入**数据结构与报告，只显示键名 |

## 路线图

| 版本 | 内容 | 状态 |
|---|---|---|
| v0.1 | 配置发现 + 归一化视图 + 密钥脱敏 | ✅ 本仓库 |
| v0.2 | 规则引擎：配置卫生（明文密钥 / `0.0.0.0` / typosquat）+ 中·英工具描述投毒检测 | 计划 |
| v0.3 | 报告层：终端分级 + Markdown / JSON 报告 | 计划 |
| v0.4 | rug-pull 审查：工具定义 JCS 哈希固化 + 两次快照 diff | 计划 |
| v0.5 | 动态检测：本地靶场 + eval / exec / 反射行为探测 | 计划 |

为什么先做静态、后做动态：静态扫描器已被证明会漏掉 2026 年最严重的 MCP RCE（纯规则追不了运行时动态执行路径），动态检测才是终局；但它需要靶场，工程量大一个量级，所以放在后面。

## 与现有工具的差异

1. **个人客户端视角** —— 读你机器上真实的 `mcp.json`，不是扫别人的仓库；
2. **中文语料投毒规则** —— 工具描述里的中文指令注入是语义问题，英文规则库水土不服（v0.2）；
3. **离线 / 只读 / 零依赖** —— 配置里全是密钥，工具本身不该再成为泄露面；
4. **报告即素材** —— 输出可直接用于团队自查或技术写作。

## 目录结构

```
mcp_checkup/     clients.py（已知路径）· config_loader.py（归一化+脱敏）· cli.py
tests/           unittest（stdlib，无需 pytest）
examples/        clean.mcp.json · fixture_suspicious.mcp.json（惰性样例，载荷已占位符化）
docs/            威胁模型.md
SECURITY.md      红线与协调披露
```

## 跑测试

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
```

## 红线

只做防御性检测：**不联网、不执行 server 代码、靶场全本地、披露走协调披露**。详见 [SECURITY.md](SECURITY.md)。

## License

MIT
