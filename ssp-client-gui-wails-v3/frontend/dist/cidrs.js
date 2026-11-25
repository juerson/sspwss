// ==============================================================================
// 优选地址（CIDR）管理窗口
// 分页浏览（每页 500，按前两段数值排序）、关键字搜索（CIDR/备注）、
// 内置源下载（Cloudflare IPv4 + GitHub Release，直连）、自定义 URL、本地文件导入、
// 选中删除、清空、一键去重、备注编辑；点击行号复制 CIDR，点击 CIDR 生成随机 IP
// ==============================================================================

import { Call } from "/wails/runtime.js";
import { toast, showError, confirmDialog, copyText, copyAndFill } from "./dbwin.js";

const $ = (id) => document.getElementById(id);

const App = {
  GetPage: (page, search) => Call.ByName("main.App.CidrGetPage", page, search),
  BuiltinDownload: (overwrite) => Call.ByName("main.App.CidrBuiltinDownload", overwrite),
  UrlDownload: (url, overwrite) => Call.ByName("main.App.CidrUrlDownload", url, overwrite),
  MergeFiles: (overwrite) => Call.ByName("main.App.CidrMergeFiles", overwrite),
  DeleteRows: (ids) => Call.ByName("main.App.CidrDeleteRows", ids),
  ClearAll: () => Call.ByName("main.App.CidrClearAll"),
  RemoveDuplicates: () => Call.ByName("main.App.CidrRemoveDuplicates"),
  UpdateRemark: (id, remark) => Call.ByName("main.App.CidrUpdateRemark", id, remark),
  RandomIP: (cidr) => Call.ByName("main.App.CidrRandomIP", cidr),
};

const PAGE_SIZE = 500;

let page = 1;
let pages = 1;
let total = 0;
let rows = [];            // 当前页数据 [id, cidr, remark]
let selected = new Set(); // 当页选中行 id
let busy = false;         // 操作互斥

function overwrite() {
  return $("writeMode").value === "overwrite";
}

function resultText(res) {
  if (overwrite()) {
    return `覆盖模式: 共处理 ${res.processed} 条数据，实际新增 ${res.inserted} 条`;
  }
  return `追加模式 (去重): 共处理 ${res.processed} 条数据，实际新增 ${res.inserted} 条`;
}

// ==============================================================================
// 数据加载与渲染
// ==============================================================================

async function loadPage() {
  const st = await App.GetPage(page, $("searchInput").value.trim());
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
    const [id, cidr, remark] = r;
    const tr = document.createElement("tr");

    const tdSel = document.createElement("td");
    tdSel.className = "cSel";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.addEventListener("change", () => {
      if (cb.checked) selected.add(id);
      else selected.delete(id);
      updateSelState();
    });
    tdSel.appendChild(cb);

    const tdId = document.createElement("td");
    tdId.className = "num clickable";
    tdId.textContent = (page - 1) * PAGE_SIZE + i + 1;
    tdId.title = "点击复制 CIDR 并填充主窗口优选地址输入框";
    tdId.addEventListener("click", async () => {
      if (await copyAndFill("ip", cidr)) toast("已复制并填充主窗口: " + cidr);
      else toast("复制失败", true);
    });

    const tdCidr = document.createElement("td");
    tdCidr.className = "mono clickable";
    tdCidr.textContent = cidr;
    tdCidr.title = "点击从该网段随机生成一个 IP";
    tdCidr.addEventListener("click", async () => {
      try {
        const ip = await App.RandomIP(cidr);
        if (await copyText(ip)) toast("已随机生成 IP: " + ip);
        else toast("生成成功：" + ip + "（复制失败）", true);
      } catch (e) {
        showError(e);
      }
    });

    const tdRemark = document.createElement("td");
    const inp = document.createElement("input");
    inp.className = "remark";
    inp.value = String(remark ?? "").trim();
    inp.placeholder = "双击或点击编辑备注";
    inp.addEventListener("change", () => {
      // 备注静默保存（失焦/回车触发 change）
      App.UpdateRemark(id, inp.value).catch((e) => showError(e));
    });
    tdRemark.appendChild(inp);

    tr.appendChild(tdSel);
    tr.appendChild(tdId);
    tr.appendChild(tdCidr);
    tr.appendChild(tdRemark);
    frag.appendChild(tr);
  });
  tbody.appendChild(frag);

  $("pageInfo").textContent = `第${page}/${pages}页 | 当页${rows.length}条/共${total}条`;
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

async function reload() {
  await loadPage();
}

// 内置数据源下载（首次打开空库时自动执行，按钮文字"首次加载..."）
async function runBuiltin(auto) {
  setBusy(true);
  const btn = $("btnBuiltin");
  const orig = btn.textContent;
  btn.textContent = auto ? "首次加载..." : "下载中...";
  try {
    const res = await App.BuiltinDownload(overwrite());
    btn.textContent = orig;
    setBusy(false);
    await reload();
    if (res && res.processed > 0) {
      toast(`内置源下载完成，共获取 ${res.processed} 条 CIDR 记录\n` + resultText(res));
    }
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
    btn.textContent = "下载";
    setBusy(false);
    await reload();
    if (res && res.processed > 0) {
      toast(`下载完成，共获取 ${res.processed} 条 CIDR 记录\n` + resultText(res));
    } else {
      toast("未获取到有效数据", true);
    }
  } catch (e) {
    btn.textContent = "下载";
    setBusy(false);
    showError(e);
  }
}

async function runMerge() {
  setBusy(true);
  const btn = $("btnMerge");
  btn.textContent = "导入中...";
  try {
    const res = await App.MergeFiles(overwrite());
    btn.textContent = "导入本地文件";
    setBusy(false);
    await reload();
    if (res && res.processed > 0) {
      toast(`导入完成，共处理 ${res.processed} 条 CIDR 记录\n` + resultText(res));
    }
  } catch (e) {
    btn.textContent = "导入本地文件";
    setBusy(false);
    showError(e);
  }
}

async function runDelete() {
  if (selected.size === 0) {
    toast("请先勾选要删除的行", true);
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
  const ok = await confirmDialog("确认清理", "确定要删除重复数据吗？\n只保留每个 CIDR 的首条记录。");
  if (!ok) return;
  setBusy(true);
  const btn = $("btnDedup");
  btn.textContent = "清理中...";
  try {
    const res = await App.RemoveDuplicates();
    btn.textContent = "一键去重";
    setBusy(false);
    await reload();
    if (res) toast(`删除完成，共删除 ${res.removed} 条重复记录`);
  } catch (e) {
    btn.textContent = "一键去重";
    setBusy(false);
    showError(e);
  }
}

async function runClear() {
  const ok = await confirmDialog("确认清空", "确定要清空所有数据吗？");
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
    toast("清空完成");
  } catch (e) {
    btn.textContent = "清空全部";
    setBusy(false);
    showError(e);
  }
}

// ==============================================================================
// 事件绑定
// ==============================================================================

$("btnBuiltin").addEventListener("click", () => { if (!busy) runBuiltin(false); });
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

// 搜索：回车执行
$("searchInput").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    page = 1;
    loadPage().catch(showError);
  }
});

// ==============================================================================
// 初始化：加载第 1 页；空库时自动执行内置源下载
// ==============================================================================

(async function init() {
  try {
    const st = await loadPage();
    if (st.total === 0) {
      runBuiltin(true);
    }
  } catch (e) {
    showError(e);
  }
})();
