# mcp-checkup

[English](README.md) · **简体中文**

> 给**个人 Agent 用户**的 MCP 配置体检器：离线、只读、零依赖，外加"工具定义变了没有"的快照审查。

## 为什么做这个

现在谈 MCP 安全的工具基本站在两个位置：企业网关，或者扫别人的仓库。但真实世界里量最大、防护最薄的一环不在这两处——它躺在个人开发者的笔记本上：几个 `mcp.json`，里面塞满 API key，指向当年装完就再没回看过的 server。

`mcp-checkup` 读这些配置，把它们归一化成同一套结构，然后对**配置作者写下的文本**跑检测规则；还能给 server 的工具定义拍快照，下次变了就分得清是"改了个错别字"还是"多了个能跑 shell 的工具"。默认路径下它不启动任何 server、不 import 任何 server、不开任何网络连接（唯一的例外是显式加 `--allow-exec` 的 snapshot，见下）。

## 现在能做什么（v0.4）

```bash
python -m mcp_checkup list                       # 扫描本机所有已知客户端配置
python -m mcp_checkup scan                       # 对同一批配置跑规则体检
python -m mcp_checkup scan -v                    # 附每条规则的说明行
python -m mcp_checkup scan --project F:\my-repo  # 追加项目级 .mcp.json / .cursor/mcp.json
python -m mcp_checkup scan --config path/x.json  # 指定任意配置文件
python -m mcp_checkup scan --out report.md       # 出可分享的 Markdown 报告（.json 亦可）
python -m mcp_checkup scan --fail-on high        # 出现 high 就退出码 1（可进 CI）

python -m mcp_checkup snapshot --server demo-fs --allow-exec   # 记录工具定义基线（会启动该 server）
python -m mcp_checkup diff old.json new.json --out 变更.md      # 离线比对两份快照
```

对 `examples/fixture_suspicious.mcp.json` 的真实输出（规则标题本来就是双语的：中文语料规则报中文、英文语料规则报英文）：

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

干净配置（`examples/clean.mcp.json`）输出 `发现 0 findings`——**零误报是验收线，由测试守着，不是靠自觉**。

示例文档：[体检报告](docs/示例报告.md) · [变更审查报告](docs/示例变更审查.md)

## 快照与变更审查（v0.4）

**rug-pull** 指的是：审核时给你看的工具描述，和运行时真正喂给模型的那份，不是同一份。要发现它，必须先有一份"当初长什么样"的基线。

```bash
python -m mcp_checkup snapshot --server demo-fs --allow-exec --dir snapshots
```

- 它会**启动该 server** 走 `initialize` + `tools/list` 握手，所以默认拒绝执行，必须显式加 `--allow-exec`；只支持 stdio（http/sse 涉及鉴权，尚未实现）。
- 只对你**本来就已经在客户端里天天启动**的 server 做这件事——它不引入新的执行面，但确实是一次执行，所以门槛写在这。
- 快照文件里只有工具定义与指纹（SHA-256 over 规范化 JSON），**不含 env 值**（有测试专门验）。
- 再次 snapshot 时会自动和上一份 diff；也可以单独 `diff`。

变更会被分成两类，这是这节的重点：

| 分类 | 判定 | 级别 |
|---|---|---|
| 外观改动 | 去空格/标点/大小写后完全相同 | 低 |
| 描述实质改写 | 语义变了但不命中投毒规则 | 中 |
| **描述命中投毒规则** | 改动前不命中、改动后命中（复用 v0.2 的 28 条规则） | **高** |
| 新增工具 / 新增必填参数 / 参数类型变化 | 能力扩张 | **高** |
| 新增可选参数 / 移除参数 / 枚举放宽 | 需要确认 | 中 |

## 支持的客户端

Claude Desktop、Cursor、Windsurf、VS Code、Cline、Qoder、Zed、Gemini CLI、opencode、Continue，外加项目级文件（`.mcp.json`、`.cursor/mcp.json`、`.vscode/mcp.json`）。路径是 [`mcp_checkup/clients.py`](mcp_checkup/clients.py) 里的**固定白名单**，不做全盘遍历——不会去读你没让它读的文件。

## 设计约束

| 约束 | 含义 |
|---|---|
| **离线** | 不发起任何网络请求，不查询注册表 |
| **只读** | 体检路径只读配置文件；`snapshot` 是唯一会启动进程的命令，需 `--allow-exec` 显式确认 |
| **零依赖** | 只用 Python 标准库（3.10+），`git clone` 即可跑 |
| **不泄密** | env / headers 的**值**不进入数据结构、报告与快照，只保留键名 |

## 规则清单（28 条）

规则是**数据不是代码**：往 `rules/*.json` 里加一条即生效，不用改 Python。

| 文件 | 覆盖攻击面 | 代表规则 |
|---|---|---|
| [`rules/poisoning_zh.json`](rules/poisoning_zh.json)（9） | ② 工具定义语义 | `zh.override` 忽略之前的所有指令 · `zh.hide_from_user` 对用户隐瞒 · `zh.exfiltrate` 外传密钥 · `zh.bypass` 绕过审批 · `zh.silent` 静默执行 · `zh.role_change` 角色改写 · `zh.invalidate_prev` 作废上下文 · `zh.read_sensitive` 指向敏感路径 · `zh.mandatory_call` 强制前置调用 |
| [`rules/poisoning_en.json`](rules/poisoning_en.json)（8） | ② 同上，英文语料 | `en.override` · `en.hide_from_user` · `en.exfiltrate` · `en.bypass` · `en.silent` · `en.role_change` · `en.prepend_call` · `en.internal_note` |
| [`rules/structural.json`](rules/structural.json)（11） | ②③⑤ | `st.zero_width` 不可见字符 · `st.long_base64` · `st.pipe_to_shell` · `st.dynamic_exec` · `st.powershell_encoded` · `st.base64_decode` · `st.wildcard_bind` 0.0.0.0 · `st.root_path` / `st.home_dir` 权限过宽 · `st.dotenv` · `st.exfil_endpoint` |
| 引擎内置（`rules.py`） | ①④⑥ | `st.secret_in_config`（键名像凭据**且已填值**才报）· `st.plaintext_http` · `st.remote_no_auth` · `st.typosquat`（与官方包编辑距离 ≤2）· `st.unknown_official_scope` |

扫描范围只含配置作者能写的文本（`command` / `args[i]` / `url` / 描述类字段）；**env 与 headers 的值永不进入匹配与输出**。`localhost` 与 `127.0.0.1` 不报明文 http / 无鉴权，免得把本地开发的常态打成一片告警。

## 与现有工具的差异

1. **个人客户端视角** —— 读你机器上真实的 `mcp.json`，不是扫别人的仓库；
2. **中文语料投毒规则** —— 工具描述里的中文指令注入是语义问题，英文规则库水土不服；
3. **快照 + 实质/外观分类** —— 把"改描述"这件事拆成不需要警觉和必须人看两类，而不是给一堆 diff 让人自己读；
4. **离线 / 只读 / 零依赖** —— 配置里全是密钥，工具本身不该再成为泄露面；
5. **报告即素材** —— 输出可直接用于团队自查或技术写作。

## 这个工具查不出什么

**在看懂这一节之前，别相信一份干净的报告。**

- **配置体检是静态的**：运行时才拼出来的命令、反射调用、沙箱逃逸不在能力内（v0.5 才开始碰）。
- **快照只覆盖 stdio**，且要你主动打；http/sse server 的基线还没实现。没打过基线的 server 谈不上 rug-pull 检测。
- **不联网**：仿冒名比对用的是内置官方包清单，上周才出现的恶意包认不出来。
- **工具描述之外的行为看不见**：描述没写、但代码里干的事，任何静态手段都拦不住。
- 命中不等于已中招，未命中不等于安全；报告是排查起点，不是结论。

## 路线图

| 版本 | 内容 | 状态 |
|---|---|---|
| v0.1 | 配置发现 + 归一化视图 + 密钥脱敏 | 已完成 |
| v0.2 | 规则引擎：配置卫生 + 中·英工具描述投毒检测（28 条） | 已完成 |
| v0.3 | 报告层：Markdown / JSON 报告落盘 + 结论与边界声明 | 已完成 |
| v0.4 | rug-pull 审查：JCS 指纹快照 + 离线 diff + 实质/外观分类 | 已完成 |
| v0.5 | 动态检测：本地靶场 + eval / exec / 反射行为探测 | 计划 |

先静态后动态是刻意的：纯静态规则已被证明追不上 2026 年那次最严重 MCP RCE 的运行时路径，动态检测才是终局；但它需要靶场，工程量大一个量级，所以排在后面。

## 目录结构

```
mcp_checkup/     clients.py（路径白名单）· config_loader.py（归一化+脱敏）
                 rules.py（引擎+内置语义规则）· known_names.py（官方包清单）
                 report.py（体检报告）· jcs.py（规范化 JSON+指纹）
                 snapshot.py（stdio 握手抓工具定义）· diff_tools.py（变更分类）· cli.py
rules/           poisoning_zh.json · poisoning_en.json · structural.json   ← 加规则改这里
tests/           unittest（stdlib）：加载/脱敏 · 检出 · 零误报 · 报告 · 快照与 diff
examples/        clean.mcp.json · fixture_suspicious.mcp.json（惰性样例，载荷已占位符化）
docs/            威胁模型.md · 示例报告.md · 示例变更审查.md
SECURITY.md      红线与协调披露
```

## 跑测试

```bash
PYTHONPATH=. python -m unittest discover -s tests -v      # 38 个用例
```

其中 `FalsePositiveBarTest` 锁"干净配置零告警"，`SnapshotExecTest` 拿仓库自带的假 MCP server 走一遍真握手（不联网、不下第三方包），`NamingTest` 锁住"同秒两份快照不许互相覆盖"。

## 红线

只做防御性检测：**不联网、不执行第三方 server 代码（snapshot 需显式确认且只对你自己在跑的 server）、靶场全本地、披露走协调披露**。详见 [SECURITY.md](SECURITY.md)。

## 许可

[MIT](LICENSE) · Copyright © 2026 tiangang0245
