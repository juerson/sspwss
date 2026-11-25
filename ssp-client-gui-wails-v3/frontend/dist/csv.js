// ==============================================================================
// ProxyIP 管理窗口
// 分页浏览（每页 500）、列/模式搜索、内置源下载（GitHub 直连）、自定义 URL、
// 本地文件合并、选中删除、清空、去重；点击行号复制 IP:Port
// ==============================================================================

import { Call } from "/wails/runtime.js";
import { toast, showError, confirmDialog, copyText, copyAndFill, debounce } from "./dbwin.js";

const $ = (id) => document.getElementById(id);

const App = {
  GetPage: (page, search, column, mode) =>
    Call.ByName("main.App.CsvGetPage", page, search, column, mode),
  BuiltinDownload: (overwrite) => Call.ByName("main.App.CsvBuiltinDownload", overwrite),
  UrlDownload: (url, overwrite) => Call.ByName("main.App.CsvUrlDownload", url, overwrite),
  MergeFiles: (overwrite) => Call.ByName("main.App.CsvMergeFiles", overwrite),
  DeleteRows: (ids) => Call.ByName("main.App.CsvDeleteRows", ids),
  ClearAll: () => Call.ByName("main.App.CsvClearAll"),
  RemoveDuplicates: () => Call.ByName("main.App.CsvRemoveDuplicates"),
};

const PAGE_SIZE = 500;

let page = 1;
let pages = 1;
let total = 0;
let rows = [];          // 当前页数据 [id, ip, port, country, org]
let selected = new Set(); // 当页选中行 id
let busy = false;       // 操作互斥（下载/删除/去重等期间禁用）

function overwrite() {
  return $("writeMode").value === "overwrite";
}

function resultText(res) {
  if (overwrite()) {
    return `覆盖模式: 共处理 ${res.processed} 条数据`;
  }
  return `追加模式(去重): 共处理 ${res.processed} 条数据，实际新增 ${res.inserted} 条`;
}

// ==============================================================================
// 数据加载与渲染
// ==============================================================================

async function loadPage() {
  const st = await App.GetPage(page, $("searchInput").value.trim(),
    $("colSelect").value, $("matchSelect").value);
  page = st.page;
  pages = st.pages;
  total = st.total;
  rows = st.rows || [];
  selected.clear();
  render();
  return st;
}

function render() {
  const tbody = $("tbody");
  tbody.textContent = "";
  const frag = document.createDocumentFragment();
  rows.forEach((r, i) => {
    const tr = document.createElement("tr");
    tr.dataset.id = r[0];

    const tdSel = document.createElement("td");
    tdSel.className = "cSel";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.addEventListener("change", () => {
      if (cb.checked) selected.add(r[0]);
      else selected.delete(r[0]);
      updateSelState();
    });
    tdSel.appendChild(cb);

    const tdId = document.createElement("td");
    tdId.className = "num clickable";
    tdId.textContent = (page - 1) * PAGE_SIZE + i + 1;
    tdId.title = "点击复制 IP:Port 并填充主窗口 ProxyIP 输入框";
    tdId.addEventListener("click", async () => {
      const s = `${r[1]}:${r[2]}`;
      if (await copyAndFill("fallback", s)) toast("已复制并填充主窗口: " + s);
      else toast("复制失败", true);
    });

    tr.appendChild(tdSel);
    tr.appendChild(tdId);
    // IP/Port/Country/Organization（country/org 的空值在后端以单空格占位）
    for (let c = 1; c <= 4; c++) {
      const td = document.createElement("td");
      td.textContent = String(r[c] ?? "").trim();
      td.style.userSelect = "text";
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);

  $("selAll").checked = rows.length > 0 && selected.size === rows.length;
  $("pageInfo").textContent = `第${page}页/共${pages}页 | 当页${rows.length}条/共${total}条`;
  $("btnPrev").disabled = page <= 1;
  $("btnNext").disabled = page >= pages;
  updateSelState();
}

function updateSelState() {
  $("btnDelete").disabled = busy || selected.size === 0;
  $("selAll").checked = rows.length > 0 && selected.size === rows.length;
}

function setBusy(v) {
  busy = v;
  ["btnBuiltin", "btnMerge", "btnUrl", "btnDedup", "btnClear", "btnRefresh",
    "btnPrev", "btnNext", "writeMode"].forEach((id) => ($(id).disabled = v));
  updateSelState();
}

// ==============================================================================
// 操作
// ==============================================================================

function showResult(res) {
  if (res && (res.processed > 0 || res.removed > 0 || res.message)) {
    toast(resultText(res));
  }
  // 用户取消文件选择：后端返回空结果，静默
}

async function reload() {
  await loadPage();
}

// 内置数据源下载（首次打开空库时自动执行）
async function runBuiltin() {
  setBusy(true);
  const btn = $("btnBuiltin");
  const orig = btn.textContent;
  btn.textContent = "加载中...";
  try {
    const res = await App.BuiltinDownload(overwrite());
    btn.textContent = orig;
    setBusy(false);
    await reload();
    if (res && res.processed > 0) toast(resultText(res));
  } catch (e) {
    btn.textContent = orig;
    setBusy(false);
    await reload().catch(() => {});
    showError(e);
  }
}

async function runUrlDownload() {
  const url = $("urlInput").value.trim();
  if (!url) {
    toast("请输入下载链接", true);
    return;
  }
  setBusy(true);
  const btn = $("btnUrl");
  btn.textContent = "下载中...";
  try {
    const res = await App.UrlDownload(url, overwrite());
    btn.textContent = "自定义下载";
    setBusy(false);
    await reload();
    showResult(res);
  } catch (e) {
    btn.textContent = "自定义下载";
    setBusy(false);
    showError(e);
  }
}

async function runMerge() {
  setBusy(true);
  const btn = $("btnMerge");
  btn.textContent = "合并中...";
  try {
    const res = await App.MergeFiles(overwrite());
    btn.textContent = "合并数据";
    setBusy(false);
    await reload();
    showResult(res);
  } catch (e) {
    btn.textContent = "合并数据";
    setBusy(false);
    showError(e);
  }
}

async function runDelete() {
  if (selected.size === 0) {
    toast("请先勾选要删除的行", true);
    return;
  }
  if (selected.size > 500) {
    toast("选中行数过多，请选择小于等于500行进行删除", true);
    return;
  }
  const ok = await confirmDialog("确认删除", `确定要删除选中的 ${selected.size} 行数据吗？`);
  if (!ok) return;
  setBusy(true);
  try {
    await App.DeleteRows([...selected]);
    await reload();
    toast("删除成功");
  } catch (e) {
    showError(e);
    await reload().catch(() => {});
  } finally {
    setBusy(false);
  }
}

async function runDedup() {
  const ok = await confirmDialog("确认清理",
    "确定要删除重复数据吗？\n只保留每个IP:Port组合的首条记录，其它重复的记录将被删除。");
  if (!ok) return;
  setBusy(true);
  const btn = $("btnDedup");
  btn.textContent = "清理中...";
  try {
    const res = await App.RemoveDuplicates();
    btn.textContent = "删除重复行";
    setBusy(false);
    await reload();
    if (res) toast(`删除完成，共删除 ${res.removed} 条重复记录`);
  } catch (e) {
    btn.textContent = "删除重复行";
    setBusy(false);
    showError(e);
  }
}

async function runClear() {
  const ok = await confirmDialog("确认清空", "确定要清空所有数据吗？此操作不可恢复！");
  if (!ok) return;
  setBusy(true);
  const btn = $("btnClear");
  btn.textContent = "清空中...";
  try {
    await App.ClearAll();
    btn.textContent = "清空全部";
    setBusy(false);
    page = 1;
    $("searchInput").value = "";
    await reload();
    toast("数据已清空");
  } catch (e) {
    btn.textContent = "清空全部";
    setBusy(false);
    showError(e);
  }
}

// ==============================================================================
// 事件绑定
// ==============================================================================

$("btnBuiltin").addEventListener("click", () => { if (!busy) runBuiltin(); });
$("btnUrl").addEventListener("click", () => { if (!busy) runUrlDownload(); });
$("urlInput").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    if (!busy) runUrlDownload();
  }
});
$("btnMerge").addEventListener("click", () => { if (!busy) runMerge(); });
$("btnDelete").addEventListener("click", () => { if (!busy) runDelete(); });
$("btnDedup").addEventListener("click", () => { if (!busy) runDedup(); });
$("btnClear").addEventListener("click", () => { if (!busy) runClear(); });
$("btnRefresh").addEventListener("click", () => { if (!busy) reload().catch(showError); });

$("btnPrev").addEventListener("click", () => {
  if (busy || page <= 1) return;
  page--;
  loadPage().catch(showError);
});
$("btnNext").addEventListener("click", () => {
  if (busy || page >= pages) return;
  page++;
  loadPage().catch(showError);
});

$("selAll").addEventListener("change", () => {
  const on = $("selAll").checked;
  selected.clear();
  if (on) rows.forEach((r) => selected.add(r[0]));
  document.querySelectorAll("#tbody input[type=checkbox]").forEach((cb) => (cb.checked = on));
  updateSelState();
});

// 搜索：回车执行；列/匹配方式变化时已有搜索词则防抖重查（300ms 防抖）
$("searchInput").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    page = 1;
    loadPage().catch(showError);
  }
});
const rerunSearch = debounce(() => {
  if ($("searchInput").value.trim() === "") return;
  page = 1;
  loadPage().catch(showError);
}, 300);
$("colSelect").addEventListener("change", rerunSearch);
$("matchSelect").addEventListener("change", rerunSearch);

// ==============================================================================
// 初始化：加载第 1 页；空库时自动执行内置源下载
// ==============================================================================

(async function init() {
  try {
    const st = await loadPage();
    if (st.total === 0) {
      runBuiltin(); // 按钮内显示"加载中..."，完成后写库并刷新
    }
  } catch (e) {
    showError(e);
  }
})();
