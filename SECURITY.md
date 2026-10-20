# SECURITY.md — 红线与披露

> **TL;DR (EN)** — This tool is defensive: it reads config files offline and does not execute, import, or
> connect to MCP servers. The one exception is `snapshot`, which starts a server to read its tool
> definitions and therefore requires an explicit `--allow-exec`; use it only for servers you already run
> in your client. Research must target **your own** servers and a local range only; publishing malicious
> samples to any registry is a crime. Vulnerability reports go through **coordinated disclosure** — vendor
> first, write-up second.

## 本工具的边界

- **只读**：只解析配置文件，不 import、不启动、不连接任何 MCP server。
- **唯一例外**：`snapshot` 为了读工具定义会启动该 server 进程，因此默认拒绝执行，必须显式加 `--allow-exec`，且只支持 stdio。请只对**你本来就在客户端里每天启动**的 server 使用它——它不新增执行面，但确实是一次执行。
- **离线**：无对外网络请求。typosquat 检测用内置名单与编辑距离，不查注册表。
- **可选面板 `serve`**：它监听的是 socket，但方向朝内——只接受 loopback（`--host 0.0.0.0` 直接报错退出），Host 头非 `127.0.0.1` / `localhost` / `::1` 一律 403（挡 DNS rebinding 读你本机数据），静态文件走固定路由表、不拼接用户路径，页面不加载任何外部资源，接口返回的对象里本来就没有 env / headers 的值。它依然不发起任何对外请求，也不写任何文件。不想用就整体删掉：`git rm -r web mcp_checkup/web.py tests/test_web.py`，其余命令不受影响（有测试断言这一点）。
- **不收集**：不把配置内容写到仓库外的任何地方；`--json` 输出与快照文件都不含 env / headers 的值（有测试验证）。

## 使用本工具做研究时的红线

1. 投毒样例、Fuzz 载荷**只针对自己拥有的 server 和本地靶场**；向任何公共注册表 / npm / PyPI 提交恶意样本是犯罪。
2. 复现攻击链时**禁止连接真实第三方端点**，全程离线或内网靶场。
3. 本仓库 `examples/` 中的样例是**惰性 fixture**：恶意载荷已替换为 `<...-PAYLOAD>` 占位符，不含可执行命令与真实凭据。请勿将其改写成可执行载荷后分发。
4. 发现某客户端 / server 的漏洞：走**协调披露**——先报厂商或平台，留出修复窗口，再公开发文或发 PR。
5. 检测规则若引用外部 PoC，注明来源与授权范围。

## 漏洞报告

用 Issue 模板或私密渠道提交，勿在公开 Issue 直接贴可用攻击链。
