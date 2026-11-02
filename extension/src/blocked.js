import { KIND_LABELS } from "./rules.js";

const params = new URLSearchParams(location.search);
const kind = params.get("k") || "x";
let target = params.get("u");

const $ = (id) => document.getElementById(id);

function render(url, reasons) {
  $("url").textContent = url || "(không rõ địa chỉ)";
  if (kind === "h") {
    $("title").textContent = "Trang này có dấu hiệu giả mạo";
    $("why").textContent = `Địa chỉ có nhiều đặc điểm của trang lừa đảo (điểm rủi ro ${params.get("s") || "?"}/100).`;
  } else {
    $("why").textContent = `Trang này được xác định là ${KIND_LABELS[kind] || KIND_LABELS.x}` +
      (params.get("src") ? ` theo nguồn ${params.get("src")}.` : ".");
  }
  const list = $("reasons");
  list.replaceChildren(...reasons.map((r) => Object.assign(document.createElement("li"), { textContent: r })));
}

async function init() {
  let reasons = (params.get("r") || "").split(" · ").filter(Boolean);
  if (!target) {
    // Blocked by a network rule: the URL is not in our query string, so ask
    // the service worker what this tab was navigating to.
    const res = await chrome.runtime.sendMessage({ type: "blocked_context" }).catch(() => null);
    target = res?.info?.url || null;
  }
  render(target, reasons);
  $("proceed").disabled = !target || !/^https?:/i.test(target);
}

$("back").addEventListener("click", () => {
  // Going back may land on the blocked URL again, which is simply re-blocked.
  if (history.length > 1) history.back();
  else location.href = "about:blank";
});

$("proceed").addEventListener("click", async () => {
  if (!target) return;
  const res = await chrome.runtime.sendMessage({ type: "proceed", url: target }).catch(() => null);
  if (res?.ok) location.replace(target);
});

init();
