// ==============================================================================
// 数据库管理窗口共享辅助（csv.js / cidrs.js 共用）
// 提示、确认对话框、剪贴板、防抖 —— 交互模式与主窗口 main.js 一致
// ==============================================================================

import { Call } from "/wails/runtime.js";

const $ = (id) => document.getElementById(id);

// 一次性提示（替代旧版模态 MessageBox，非阻塞）
let toastTimer = null;
export function toast(msg, isError) {
  const t = $("toast");
  t.textContent = msg;
  t.className = isError ? "error" : "";
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), isError ? 5000 : 2500);
}

export function showError(e) {
  const msg = typeof e === "string" ? e : e && e.message ? e.message : String(e);
  toast(msg, true);
}

// 确认对话框（清空/删除/去重；替代旧版 MessageBox YesNo）
export function confirmDialog(title, message) {
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

// 复制到剪贴板：走后端（v3 前端运行时没有 ClipboardSetText 导出；
// navigator.clipboard 在 WebView2 下权限不可靠，仅作兜底）
export async function copyText(text) {
  try {
    if (await Call.ByName("main.App.CopyText", text)) return true;
  } catch (e) {
    /* 继续尝试浏览器 API */
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    return false;
  }
}

// 复制到剪贴板并广播 fill-field 事件：主窗口收到后把值填进对应输入框
//（field: "fallback"=ProxyIP / "ip"=优选地址，后端白名单校验）
export async function copyAndFill(field, text) {
  try {
    return await Call.ByName("main.App.CopyAndFill", field, text);
  } catch (e) {
    return false;
  }
}

export function debounce(fn, ms) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
