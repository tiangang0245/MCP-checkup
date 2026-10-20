/* Vanilla JS, no external assets. All text from the API is inserted via
   textContent - tool descriptions are attacker-controllable data, never markup. */
"use strict";

const SEV = { high: "高危", medium: "中危", low: "低危", info: "提示" };
const WEIGHT = { high: 10, medium: 4, low: 1, info: 0 };
const state = { data: null, rules: null };

const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const $ = (sel) => document.querySelector(sel);
const activeSeverities = () =>
  new Set([...document.querySelectorAll("#filters input:checked")].map((i) => i.dataset.sev));

function score(findings) {
  return findings.reduce((sum, f) => sum + (WEIGHT[f.severity] || 0), 0);
}
function verdict(counts) {
  if (!counts.high && !counts.medium && !counts.low && !counts.info) return "未发现问题";
  if (counts.high) return "存在高危项，建议先清";
  if (counts.medium) return "有中低危项，建议修";
  return "仅提示项";
}

function renderSummary() {
  const box = $("#summary");
  box.textContent = "";
  const { counts, findings, servers, rules_loaded: rules } = state.data;
  const stats = [
    ["结论", verdict(counts), counts.high ? "bad" : counts.medium ? "warn" : "good"],
    ["风险分", String(score(findings))],
    ["命中", `${findings.length} 条`],
    ...Object.keys(SEV).map((k) => [SEV[k], String(counts[k] || 0), counts[k] ? k : ""]),
    ["server", `${servers.length} 个`],
    ["规则", `${rules} 条`],
  ];
  for (const [label, value, cls] of stats) {
    const card = el("div", "stat" + (cls ? " " + cls : ""));
    card.append(el("span", "k", label), el("strong", "v", value));
    box.append(card);
  }
}

function renderFiles() {
  const ul = $("#files");
  ul.textContent = "";
  for (const f of state.data.files) {
    const li = el("li", "file");
    li.append(el("b", "", f.client || "?"));
    li.append(el("span", "path", f.path));
    li.append(el("i", "", f.error ? "读取失败：" + f.error : `${f.servers} 个 server`));
    ul.append(li);
  }
}

function findingRow(f) {
  const row = el("div", "finding " + f.severity);
  row.append(el("span", "sev", SEV[f.severity] || f.severity));
  row.append(el("code", "rule", f.rule));
  row.append(el("code", "field", f.field));
  row.append(el("span", "title", f.title));
  if (f.excerpt) row.append(el("pre", "excerpt", f.excerpt));
  if (f.detail) row.append(el("p", "detail", f.detail));
  return row;
}

function renderServers() {
  const keep = activeSeverities();
  const byServer = new Map();
  for (const f of state.data.findings) {
    const key = f.source + "\u0000" + f.server;
    if (!byServer.has(key)) byServer.set(key, []);
    byServer.get(key).push(f);
  }

  const host = $("#servers");
  host.textContent = "";
  const nav = $("#nav");
  nav.textContent = "";

  for (const s of state.data.servers) {
    const all = byServer.get(s.source + "\u0000" + s.name) || [];
    const shown = all.filter((f) => keep.has(f.severity));
    // the badge and the colour bar report the server's real state; the severity
    // filters only decide which rows are visible, so a filtered-out hit never
    // reads as "clean".
    const li = el("li");
    const link = el("a", "", s.name);
    link.href = "#s-" + encodeURIComponent(s.name);
    li.append(link, el("i", "", all.length ? `${all.length} 项` : "干净"));
    if (shown.length) li.classList.add("hit");
    nav.append(li);

    const card = el("article", "server" + (all.length ? " dirty" : " clean"));
    card.id = "s-" + encodeURIComponent(s.name);
    const head = el("header");
    head.append(el("h3", "", s.name));
    head.append(el("span", "transport", s.transport));
    head.append(el("code", "target", s.url || [s.command, ...s.args].filter(Boolean).join(" ")));
    card.append(head);

    const meta = el("div", "meta-line");
    meta.append(el("span", "", s.client || "?"));
    meta.append(el("span", "path", s.source));
    if (s.env_keys.length) meta.append(el("span", "", "env 键：" + s.env_keys.join(", ")));
    if (s.header_keys.length) meta.append(el("span", "", "headers：" + s.header_keys.join(", ")));
    if (s.disabled) meta.append(el("span", "badge", "已禁用"));
    card.append(meta);

    if (shown.length) shown.forEach((f) => card.append(findingRow(f)));
    else if (all.length) card.append(el("p", "detail", "当前筛选下没有可显示的命中项。"));
    else card.append(el("p", "ok", "未命中任何规则。"));
    host.append(card);
  }
}

async function load() {
  const res = await fetch("/api/scan");
  state.data = await res.json();
  $("#meta").textContent = `v${state.data.version} · 离线 · 只读 · ${new Date().toLocaleTimeString()}`;
  renderSummary();
  renderFiles();
  renderServers();
}

async function loadRules() {
  if (!state.rules) {
    const res = await fetch("/api/rules");
    state.rules = (await res.json()).rules;
  }
  const host = $("#rules");
  host.textContent = "";
  const table = el("table", "rule-table");
  const head = el("tr");
  ["级别", "规则", "标题", "说明"].forEach((t) => head.append(el("th", "", t)));
  table.append(head);
  for (const r of state.rules) {
    const tr = el("tr", r.severity);
    tr.append(el("td", "", SEV[r.severity] || r.severity), el("td", "", r.id),
              el("td", "", r.title), el("td", "detail", r.detail));
    table.append(tr);
  }
  host.append(table);
}

function wire() {
  $("#run").addEventListener("click", async () => {
    const path = $("#cfg").value.trim();
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(path ? { configs: [path] } : {}),
    });
    const data = await res.json();
    if (data.error) {
      $("#meta").textContent = "错误：" + data.error;
      return;
    }
    state.data = data;
    renderSummary();
    renderFiles();
    renderServers();
  });
  document.querySelectorAll("#filters input").forEach((i) => i.addEventListener("change", renderServers));
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.id !== "tab-" + b.dataset.tab; });
    if (b.dataset.tab === "rules") loadRules();
  }));
}

wire();
load().catch((e) => { $("#meta").textContent = "载入失败：" + e.message; });
