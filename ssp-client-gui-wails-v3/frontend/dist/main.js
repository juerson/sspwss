// ==============================================================================
// 前端逻辑
// Wails v3：从注入的 /wails/runtime 导入运行时，
// 服务方法用 Call.ByName("main.App.<方法名>") 调用，事件用 Events.On 监听
// ==============================================================================

import { Call, Events, Window } from "/wails/runtime.js";

const $ = (id) => document.getElementById(id);

// 后端绑定方法（main.App 服务的导出方法）
const App = {
  GetState: () => Call.ByName("main.App.GetState"),
  SelectServer: (id) => Call.ByName("main.App.SelectServer", id),
  SaveCurrentServer: (f) => Call.ByName("main.App.SaveCurrentServer", f),
  AddServer: (n) => Call.ByName("main.App.AddServer", n),
  RenameServer: (id, n) => Call.ByName("main.App.RenameServer", id, n),
  DeleteServer: (id) => Call.ByName("main.App.DeleteServer", id),
  SetCore: (n) => Call.ByName("main.App.SetCore", n),
  SetSystemProxy: (b) => Call.ByName("main.App.SetSystemProxy", b),
  SetAutoStart: (b) => Call.ByName("main.App.SetAutoStart", b),
  SetAutoStartHide: (b) => Call.ByName("main.App.SetAutoStartHide", b),
  StartCore: () => Call.ByName("main.App.StartCore"),
  StopCore: () => Call.ByName("main.App.StopCore"),
  SetDirty: (b) => Call.ByName("main.App.SetDirty", b),
  HideWindow: () => Call.ByName("main.App.HideWindow"),
  OpenCsvWindow: () => Call.ByName("main.App.OpenCsvWindow"),
  OpenCidrsWindow: () => Call.ByName("main.App.OpenCidrsWindow"),
};

const TEXT_FIELDS = ["fServer", "fToken", "fIp", "fDns", "fFallback", "fEch", "fUa", "fListen"];
const SELECT_FIELDS = ["fUseECH", "fRouting", "fLogLevel"];
// 这四个输入框平时密文显示，聚焦时明文
const PASSWORD_FIELDS = ["fServer", "fToken", "fIp", "fFallback"];

let state = null;      // 最近一次 UIState
let lastServerId = null;
let loading = false;   // 程序填充表单时抑制 dirty
let dirty = false;

const logBox = () => $("logBox");

// ==============================================================================
// 等比自适应：内容按 700x720 紧凑设计，CSS zoom 跟随窗口尺寸整体等比缩放。
// zoom 只缩放内容、不改变视口像素尺寸，因此按视口计算不会产生回环。
// 常规屏幕下 zoom=1（字体按钮保持原始大小），只有窗口比设计还小才等比缩小。
// ==============================================================================

const DESIGN_W = 700;
const DESIGN_H = 720;

function applyZoom() {
  const s = Math.min(1, window.innerWidth / DESIGN_W, window.innerHeight / DESIGN_H);
  document.body.style.zoom = Math.max(0.7, s).toFixed(3);
}

// 启动时若窗口在当前屏幕放不下，等比缩小到刚好放下；放得下则不动。
// 只调大小、不改位置：尊重记住的窗口位置（main.go 创建窗口时恢复）
function fitWindow() {
  try {
    if (!Window || !Window.SetSize) return;
    const availW = window.screen.availWidth - 24;
    const availH = window.screen.availHeight - 80;
    if (window.outerWidth <= availW && window.outerHeight <= availH) return;
    const s = Math.min(1, availW / DESIGN_W, availH / DESIGN_H);
    if (s < 0.7) s = 0.7;
    Window.SetSize(Math.round(DESIGN_W * s), Math.round(DESIGN_H * s));
  } catch (e) {
    console.warn("窗口自适应失败", e);
  }
}

window.addEventListener("resize", applyZoom);

// ==============================================================================
// 表单
// ==============================================================================

function fillForm(srv) {
  loading = true;
  if (srv) {
    $("fServer").value = srv.server || "";
    $("fToken").value = srv.token || "";
    $("fIp").value = srv.ip || "";
    $("fDns").value = srv.dns || "";
    $("fFallback").value = srv.fallback || "";
    $("fEch").value = srv.ech || "";
    $("fUa").value = srv.ua || "";
    $("fListen").value = srv.listen || "";
    $("fUseECH").value = srv.use_ech === "false" ? "false" : "true";
    const routing = srv.routing_mode || "rule";
    $("fRouting").value = [...$("fRouting").options].some((o) => o.value === routing) ? routing : "rule";
    $("fLogLevel").value = srv.loglevel || "INFO";
  } else {
    TEXT_FIELDS.forEach((id) => ($(id).value = ""));
    $("fUseECH").value = "true";
    $("fRouting").value = "rule";
    $("fLogLevel").value = "INFO";
  }
  loading = false;
  setDirty(false);
}

function collectForm() {
  const cur = state && state.currentServer ? state.currentServer : {};
  return {
    id: cur.id || "",
    name: cur.name || "",
    server: $("fServer").value,
    listen: $("fListen").value,
    token: $("fToken").value,
    ip: $("fIp").value,
    fallback: $("fFallback").value,
    ua: $("fUa").value,
    dns: $("fDns").value,
    ech: $("fEch").value,
    routing_mode: $("fRouting").value,
    loglevel: $("fLogLevel").value,
    use_ech: $("fUseECH").value,
  };
}

function setDirty(v) {
  dirty = v;
  $("btnSave").textContent = v ? "保存*" : "保存";
  App.SetDirty(v).catch(() => {});
}

function markDirty() {
  if (loading) return;
  if (!dirty) setDirty(true);
}

// ==============================================================================
// 状态渲染
// ==============================================================================

function render(s) {
  state = s;

  // 一次性提示（来自后端：已创建默认配置、保存失败、启动错误等）
  if (s.notice) showToast(s.notice, true);

  // 服务器下拉
  const sel = $("serverSelect");
  sel.innerHTML = "";
  (s.servers || []).forEach((sv) => {
    const o = document.createElement("option");
    o.value = sv.id;
    o.textContent = sv.name;
    sel.appendChild(o);
  });
  sel.value = s.currentServer ? s.currentServer.id : "";

  // 核心下拉（核心共存时后端按注册表顺序默认 Rust 优先）
  const cs = $("coreSelect");
  cs.innerHTML = "";
  (s.cores || []).forEach((c) => {
    const o = document.createElement("option");
    o.value = c.name;
    o.textContent = c.name + "（" + (c.kind === "rs" ? "Rust" : "Go") + "）";
    cs.appendChild(o);
  });
  cs.value = s.selectedCore || "";

  // 复选框（来自 last_state）
  const ls = s.lastState || {};
  $("cbProxy").checked = !!ls.system_proxy_enabled;
  $("cbAutoStart").checked = !!ls.auto_start_checked;
  $("cbAutoStartHide").checked = !!ls.auto_start_hide_checked;
  $("cbAutoStartHide").disabled = !ls.auto_start_checked;

  // 与后端同步脏标记（保存成功/切换服务器后由后端清除）
  if (!!s.dirty !== dirty) {
    dirty = !!s.dirty;
    $("btnSave").textContent = dirty ? "保存*" : "保存";
  }

  // 运行状态冻结（文本框只读、下拉/服务器按钮/核心选择禁用，保存与复选框仍可用）
  TEXT_FIELDS.forEach((id) => ($(id).readOnly = !!s.running));
  ["fUseECH", "fRouting", "fLogLevel", "serverSelect", "coreSelect"].forEach(
    (id) => ($(id).disabled = !!s.running)
  );
  ["btnAdd", "btnRename", "btnDel"].forEach((id) => ($(id).disabled = !!s.running));
  $("btnStart").disabled = !!s.running;
  $("btnStop").disabled = !s.running;

  // 当前服务器变化时重填表单（托盘/删除等间接切换也会生效）
  const curId = s.currentServer ? s.currentServer.id : null;
  if (curId !== lastServerId) {
    lastServerId = curId;
    fillForm(s.currentServer);
  }
}

// ==============================================================================
// 日志
// ==============================================================================

function appendLog(line) {
  const box = logBox();
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 100;
  const div = document.createElement("div");
  div.className = "logline";
  div.textContent = line;
  box.appendChild(div);
  // 超过 1000 行时保留最后 500 行并提示
  if (box.childElementCount > 1000) {
    const keep = 500;
    while (box.childElementCount > keep) box.removeChild(box.firstChild);
    const note = document.createElement("div");
    note.className = "logline hint";
    note.textContent = "[日志已截断，保留最后" + keep + "行]";
    box.appendChild(note);
  }
  if (atBottom) box.scrollTop = box.scrollHeight;
}

// ==============================================================================
// 输入对话框（新增/重命名；空文本时确定按钮禁用、输入框变红）
// ==============================================================================

function inputDialog(title, label, defVal) {
  return new Promise((resolve) => {
    const inp = $("dlgInput");
    $("dlgTitle").textContent = title;
    $("dlgLabel").textContent = label;
    inp.value = defVal || "";
    const updateOk = () => {
      const empty = inp.value.trim() === "";
      $("dlgOk").disabled = empty;
      inp.classList.toggle("empty", empty);
    };
    updateOk();
    $("dlgMask").hidden = false;
    inp.focus();
    inp.select();
    const close = (v) => {
      $("dlgMask").hidden = true;
      $("dlgOk").onclick = null;
      $("dlgCancel").onclick = null;
      inp.oninput = null;
      inp.onkeydown = null;
      resolve(v);
    };
    $("dlgOk").onclick = () => close(inp.value.trim());
    $("dlgCancel").onclick = () => close(null);
    inp.oninput = updateOk;
    inp.onkeydown = (ev) => {
      if (ev.key === "Enter" && !$("dlgOk").disabled) close(inp.value.trim());
      if (ev.key === "Escape") close(null);
    };
  });
}

function showError(e) {
  console.error(e);
  const msg = typeof e === "string" ? e : e && e.message ? e.message : String(e);
  showToast(msg, true);
}

// 一次性提示（替代旧版的模态 MessageBox，非阻塞）
let toastTimer = null;
function showToast(msg, isError) {
  const t = $("toast");
  t.textContent = msg;
  t.className = isError ? "error" : "";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), isError ? 5000 : 2500);
}

// 确认对话框（删除服务器等）
function confirmDialog(title, message) {
  return new Promise((resolve) => {
    $("cfmTitle").textContent = title;
    $("cfmMsg").textContent = message;
    $("cfmMask").hidden = false;
    const close = (v) => {
      $("cfmMask").hidden = true;
      $("cfmOk").onclick = null;
      $("cfmCancel").onclick = null;
      resolve(v);
    };
    $("cfmOk").onclick = () => close(true);
    $("cfmCancel").onclick = () => close(false);
  });
}

// ==============================================================================
// 事件绑定
// ==============================================================================

$("serverSelect").addEventListener("change", async () => {
  if (loading || !state) return;
  try {
    const st = await App.SelectServer($("serverSelect").value);
    render(st);
  } catch (e) {
    showError(e);
    render(await App.GetState());
  }
});

$("btnSave").addEventListener("click", async () => {
  try {
    const st = await App.SaveCurrentServer(collectForm());
    render(st);
    showToast("保存成功");
  } catch (e) {
    showError(e); // 保存失败
  }
});

$("btnAdd").addEventListener("click", async () => {
  const name = await inputDialog("新增服务器", "服务器名称:", "No." + Math.floor(1000 + Math.random() * 9000));
  if (name === null) return;
  try {
    const st = await App.AddServer(name);
    render(st);
  } catch (e) {
    showError(e);
  }
});

$("btnRename").addEventListener("click", async () => {
  if (!state || !state.currentServer) return;
  const name = await inputDialog("重命名服务器", "请输入新的服务器名称:", state.currentServer.name);
  if (name === null || name === state.currentServer.name) return;
  try {
    const st = await App.RenameServer(state.currentServer.id, name);
    render(st);
  } catch (e) {
    showError(e);
  }
});

$("btnDel").addEventListener("click", async () => {
  if (!state || !state.currentServer) return;
  const ok = await confirmDialog(
    "删除确认",
    '确定要删除服务器 "' + state.currentServer.name + '" 吗？\n\n此操作不可撤销。'
  );
  if (!ok) return;
  try {
    const st = await App.DeleteServer(state.currentServer.id);
    render(st);
  } catch (e) {
    showError(e);
  }
});

$("coreSelect").addEventListener("change", async () => {
  try {
    const st = await App.SetCore($("coreSelect").value);
    render(st);
  } catch (e) {
    showError(e);
    render(await App.GetState());
  }
});

$("btnStart").addEventListener("click", async () => {
  logBox().textContent = "";
  try {
    // 有未保存的修改时先静默保存再启动（否则启动用的是上次保存的值，
    // 会出现"改了 ECH 地址/DOH 等参数却没生效"的困惑）
    if (dirty) {
      const st = await App.SaveCurrentServer(collectForm());
      render(st);
    }
    await App.StartCore(); // 校验失败时后端返回错误并附带提示
  } catch (e) {
    showError(e);
  }
});

$("btnStop").addEventListener("click", () => App.StopCore().catch(showError));

$("cbProxy").addEventListener("change", () => App.SetSystemProxy($("cbProxy").checked).catch(showError));
$("cbAutoStart").addEventListener("change", () => App.SetAutoStart($("cbAutoStart").checked).catch(showError));
$("cbAutoStartHide").addEventListener("change", () => App.SetAutoStartHide($("cbAutoStartHide").checked).catch(showError));

$("linkClearLog").addEventListener("click", () => (logBox().textContent = ""));

// 数据库管理窗口入口：点击参数设置里的"ProxyIP" / "优选地址"标签打开对应窗口
//（懒创建，关闭即隐藏，可反复打开）
$("lblCsv").addEventListener("click", () => App.OpenCsvWindow().catch(showError));
$("lblCidrs").addEventListener("click", () => App.OpenCidrsWindow().catch(showError));

TEXT_FIELDS.forEach((id) => $(id).addEventListener("input", markDirty));
SELECT_FIELDS.forEach((id) => $(id).addEventListener("change", markDirty));

PASSWORD_FIELDS.forEach((id) => {
  const el = $(id);
  el.addEventListener("focus", () => (el.type = "text"));
  el.addEventListener("blur", () => (el.type = "password"));
});

// ==============================================================================
// 后端事件 + 初始化
// ==============================================================================

Events.On("log", (ev) => appendLog(ev.data));
Events.On("state", (ev) => render(ev.data));

// 数据库子窗口"复制并填充"：把复制的值写进主窗口对应输入框（覆盖原内容）。
// 与手输一致标记未保存（保存*），由用户自行点保存写盘；切换服务器会重新载入配置值。
Events.On("fill-field", (ev) => {
  const d = ev && ev.data ? ev.data : {};
  const targets = { fallback: "fFallback", ip: "fIp" };
  const el = d.field ? $(targets[d.field]) : null;
  if (!el) return;
  el.value = String(d.value ?? "");
  markDirty();
});

// X 关闭 + 脏标记：后端先拦截关闭并发事件，前端确认后再隐藏到托盘
Events.On("close-requested", async () => {
  const ok = await confirmDialog("退出确认", "有未保存的更改，确定要退出吗？");
  if (ok) {
    App.HideWindow().catch(showError);
  }
});

(async function init() {
  fitWindow();
  applyZoom();
  try {
    render(await App.GetState());
  } catch (e) {
    document.title = "初始化失败: " + (e && e.message ? e.message : String(e));
    console.error("初始化失败", e);
  }
})();

// 临时诊断：JS 错误显示到窗口标题（便于无 DevTools 环境定位）
window.addEventListener("error", (ev) => {
  document.title = "JS错误: " + (ev.message || "unknown");
});
window.addEventListener("unhandledrejection", (ev) => {
  const r = ev.reason;
  document.title = "Promise错误: " + (r && r.message ? r.message : String(r));
});
