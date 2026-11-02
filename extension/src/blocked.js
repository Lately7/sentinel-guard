import { KIND_LABELS } from "./rules.js";

const params = new URLSearchParams(location.search);
const kind = params.get("k") || "x";
let target = params.get("u");

const $ = (id) => document.getElementById(id);

function render(url, reasons) {
  $("url").textContent = url || "(không rõ địa chỉ)";
  if (kind === "h") {
    $("title").textContent = "Trang có dấu hiệu giả mạo";
    $("why").textContent = `Điểm rủi ro ${params.get("s") || "?"}/100`;
  } else {
    $("why").textContent = (KIND_LABELS[kind] || KIND_LABELS.x) + (params.get("src") ? ` · nguồn ${params.get("src")}` : "");
  }
  const list = $("reasons");
  list.replaceChildren(...reasons.map((r) => Object.assign(document.createElement("li"), { textContent: r })));
}

async function init() {
  let reasons = (params.get("r") || "").split(" · ").filter(Boolean);
  // Blocked by a network rule: the URL is not in our query string, so ask
  // the service worker what this tab was navigating to. A service worker that
  // was asleep may need a moment, hence the short retry.
  for (let i = 0; !target && i < 10; i++) {
    const res = await chrome.runtime.sendMessage({ type: "blocked_context" }).catch(() => null);
    target = res?.info?.url || null;
    if (!target) await new Promise((r) => setTimeout(r, 200));
  }
  render(target, reasons);
  const usable = !!target && /^https?:/i.test(target);
  $("proceed").disabled = !usable;
  $("always").disabled = !usable;
}

$("back").addEventListener("click", () => {
  // Going back may land on the blocked URL again, which is simply re-blocked.
  if (history.length > 1) history.back();
  else location.href = "about:blank";
});

// "Mở một lần" lets this tab open the page until it leaves the site;
// "Luôn tin cậy" adds the host to the trusted list (removable in the app).
async function proceed(always) {
  if (!target) return;
  const res = await chrome.runtime.sendMessage({ type: "proceed", url: target, always }).catch(() => null);
  if (res?.ok && !res.navigated) location.replace(target);
}
$("proceed").addEventListener("click", () => proceed(false));
$("always").addEventListener("click", () => proceed(true));

init();
