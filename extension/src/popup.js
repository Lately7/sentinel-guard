const $ = (id) => document.getElementById(id);
let currentHost = "";

async function load() {
  const res = await chrome.runtime.sendMessage({ type: "popup_state" });
  if (!res?.ok) return;
  const { state, agent, tab } = res;
  $("enabled").checked = state.enabled;
  $("size").textContent = state.blocklistSize ? state.blocklistSize.toLocaleString("vi-VN") : "chưa đồng bộ";
  if (state.enabled && state.syncError) {
    // Degraded: protection is on but the network rules could not be loaded.
    $("size").textContent = "chưa đồng bộ — đang thử lại";
    $("size").className = "bad";
    $("size").title = state.syncError;
  }
  $("s-blocked").textContent = state.stats.blocked || 0;
  $("s-warned").textContent = state.stats.warned || 0;
  $("s-downloads").textContent = state.stats.downloads || 0;
  const waiting = (state.pendingDownloads || []).length;
  if (waiting) {
    $("s-downloads").textContent += ` (+${waiting} chờ)`;
    $("s-downloads").title = `${waiting} tệp tải về chưa được agent kiểm tra`;
  }

  if (agent && !agent.error) {
    $("agent").textContent = `đã kết nối (v${agent.version})`;
    $("agent").className = "ok";
  } else {
    $("agent").textContent = "chưa kết nối";
    $("agent").className = "bad";
    $("agent").title = agent?.error || "";
  }

  const page = $("page");
  const reasons = $("reasons");
  reasons.replaceChildren();
  if (!tab || !/^https?:/i.test(tab.url || "")) {
    page.textContent = "Không áp dụng cho trang này";
    page.className = "state muted";
    $("trust").disabled = true;
    return;
  }
  currentHost = new URL(tab.url).hostname;
  const info = tab.info || {};
  const rep = info.reputation;
  const score = info.total ?? tab.heuristic.score;
  const items = [...(tab.heuristic.reasons || []).map((r) => r.detail), ...(info.page || []).map((s) => s.detail)];
  if (rep?.verdict === "malicious") {
    page.textContent = `Nguy hiểm: ${rep.kind || "độc hại"} (${rep.source})`;
    page.className = "state bad";
  } else if (rep?.verdict === "allowed") {
    page.textContent = "Bạn đã tin cậy trang này";
    page.className = "state muted";
  } else if (score >= 70) {
    page.textContent = `Rủi ro cao (${score}/100)`;
    page.className = "state bad";
  } else if (score >= 40) {
    page.textContent = `Đáng ngờ (${score}/100)`;
    page.className = "state warn";
  } else {
    page.textContent = "Không phát hiện vấn đề";
    page.className = "state ok";
  }
  reasons.replaceChildren(...items.map((t) => Object.assign(document.createElement("li"), { textContent: t })));
}

$("enabled").addEventListener("change", async (e) => {
  await chrome.runtime.sendMessage({ type: "set_enabled", enabled: e.target.checked });
  load();
});
$("sync").addEventListener("click", async () => {
  $("sync").disabled = true;
  $("sync").textContent = "Đang đồng bộ…";
  const res = await chrome.runtime.sendMessage({ type: "sync_now" });
  $("sync").textContent = res?.ok ? "Đã đồng bộ" : "Lỗi: chưa kết nối agent";
  $("sync").disabled = false;
  load();
});
$("trust").addEventListener("click", async () => {
  if (!currentHost) return;
  await chrome.runtime.sendMessage({ type: "trust_site", host: currentHost.toLowerCase() });
  load();
});

load();
