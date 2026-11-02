import { scoreUrl } from "./url_heuristics.js";
import { buildBlockRules, buildAllowRules, ALLOW_BASE_ID, KIND_CODES, KIND_LABELS } from "./rules.js";
import * as native from "./native.js";

const WARN_AT = 70; // heuristic score that earns a full-page warning
const NOTE_AT = 40; // heuristic score shown in the popup / in-page banner
const SYNC_MINUTES = 360;
const BLOCKED_PAGE = chrome.runtime.getURL("src/blocked.html");

const DEFAULTS = { enabled: true, blocklistVersion: "", blocklistSize: 0, allowHosts: [], stats: { blocked: 0, warned: 0, downloads: 0 } };

async function getState() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

async function bumpStat(key) {
  const s = await getState();
  s.stats[key] = (s.stats[key] || 0) + 1;
  await chrome.storage.local.set({ stats: s.stats });
}

// Per-tab context survives service-worker restarts via storage.session.
async function setTabInfo(tabId, info) {
  await chrome.storage.session.set({ ["tab:" + tabId]: { ...info, ts: Date.now() } });
}
async function getTabInfo(tabId) {
  const k = "tab:" + tabId;
  return (await chrome.storage.session.get(k))[k] || null;
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function isAllowed(host) {
  const { allowHosts } = await getState();
  return allowHosts.some((h) => host === h || host.endsWith("." + h));
}

function report(action, url, reason) {
  native.request("report", { action, url: String(url).slice(0, 8000), reason: String(reason || "").slice(0, 1000) }).catch(() => {});
}

// ---------------------------------------------------------------- blocklist

async function syncBlocklist(force = false) {
  let hello;
  try {
    hello = await native.request("hello");
  } catch {
    return { ok: false, error: "agent not connected" };
  }
  const state = await getState();
  if (!force && hello.blocklist_version === state.blocklistVersion) return { ok: true, unchanged: true };

  const hosts = [];
  let offset = 0;
  for (;;) {
    const page = await native.request("get_blocklist", { offset, limit: 20000 }, 30000);
    hosts.push(...page.hosts);
    offset += page.hosts.length;
    if (!page.hosts.length || offset >= page.total) break;
  }
  const rules = [...buildBlockRules(hosts), ...buildAllowRules(state.allowHosts)];
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id), addRules: rules });
  await chrome.storage.local.set({ blocklistVersion: hello.blocklist_version, blocklistSize: hosts.length });
  return { ok: true, hosts: hosts.length, rules: rules.length };
}

async function refreshAllowRules() {
  const { allowHosts } = await getState();
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.filter((r) => r.id >= ALLOW_BASE_ID).map((r) => r.id),
    addRules: buildAllowRules(allowHosts),
  });
}

async function setEnabled(enabled) {
  await chrome.storage.local.set({ enabled });
  // Disabling keeps the rules but turns off matching by removing them; the next
  // sync (forced) rebuilds them when protection is switched back on.
  if (!enabled) {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id) });
    await chrome.storage.local.set({ blocklistVersion: "" });
  } else {
    await syncBlocklist(true).catch(() => {});
  }
  updateBadge();
}

// --------------------------------------------------------------- navigation

function warnUrl(params) {
  return BLOCKED_PAGE + "?" + new URLSearchParams(params).toString();
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/i.test(d.url)) return;
  const { enabled } = await getState();
  if (!enabled) return;
  // Remember the target first: if a blocklist rule redirects this request,
  // the warning page asks us what was blocked.
  await setTabInfo(d.tabId, { url: d.url, pending: true });
  const host = hostOf(d.url);
  if (await isAllowed(host)) return;

  const h = scoreUrl(d.url);
  let rep = null;
  try {
    rep = (await native.request("check_url", { url: d.url }, 3000)).result;
  } catch {
    /* agent offline: heuristics only */
  }
  await setTabInfo(d.tabId, { url: d.url, heuristic: h, reputation: rep });

  if (rep && rep.verdict === "malicious") {
    const kind = KIND_CODES[rep.kind] || "x";
    chrome.tabs.update(d.tabId, { url: warnUrl({ k: kind, u: d.url, src: rep.source || "" }) });
    bumpStat("blocked");
    report("blocked", d.url, `${KIND_LABELS[kind]} (${rep.source})`);
  } else if (h.score >= WARN_AT) {
    chrome.tabs.update(d.tabId, { url: warnUrl({ k: "h", u: d.url, s: String(h.score), r: h.reasons.map((r) => r.detail).join(" · ") }) });
    bumpStat("warned");
    report("warned", d.url, h.reasons.map((r) => r.id).join(","));
  }
  updateBadge(d.tabId);
});

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  // Available for unpacked installs: count blocks of sub-resources too.
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    if (info.request.type !== "main_frame") bumpStat("blocked");
  });
}

// ---------------------------------------------------------------- downloads

chrome.downloads.onCreated.addListener(async (item) => {
  const { enabled } = await getState();
  if (!enabled) return;
  const url = item.finalUrl || item.url;
  if (!/^https?:/i.test(url) || (await isAllowed(hostOf(url)))) return;
  let rep = null;
  try {
    rep = (await native.request("check_url", { url }, 3000)).result;
  } catch {
    return;
  }
  if (rep && rep.verdict === "malicious") {
    chrome.downloads.cancel(item.id).catch(() => {});
    notify("Đã chặn tải xuống nguy hiểm", `${hostOf(url)} — ${rep.kind || "độc hại"} (${rep.source})`);
    report("download_blocked", url, rep.source);
    bumpStat("blocked");
  }
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state?.current !== "complete") return;
  const { enabled } = await getState();
  if (!enabled) return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !item.filename) return;
  bumpStat("downloads");
  let res;
  try {
    res = await native.request("scan_download", { path: item.filename, url: item.finalUrl || item.url }, 180000);
  } catch {
    return;
  }
  const label = res.verdict.label;
  const name = item.filename.split(/[\\/]/).pop();
  if (label === "malicious") {
    notify(res.quarantined ? "Đã cách ly tệp tải về nguy hiểm" : "Tệp tải về nguy hiểm", `${name}: ${res.reason}`);
  } else if (label === "suspicious") {
    notify("Tệp tải về đáng ngờ", `${name}: ${res.reason} (điểm ${res.verdict.score})`);
  }
});

function notify(title, message) {
  chrome.notifications.create({ type: "basic", iconUrl: "icons/icon128.png", title, message: message.slice(0, 300), priority: 2 });
}

// ------------------------------------------------------------------ messages

const VALID = {
  blocked_context: () => true,
  proceed: (m) => typeof m.url === "string" && m.url.length < 8000,
  page_signals: (m) => Array.isArray(m.signals) && m.signals.length <= 20 && m.signals.every((s) => typeof s?.id === "string" && typeof s?.score === "number"),
  popup_state: () => true,
  set_enabled: (m) => typeof m.enabled === "boolean",
  sync_now: () => true,
  trust_site: (m) => typeof m.host === "string" && /^[a-z0-9.-]{1,253}$/.test(m.host),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg || typeof msg.type !== "string" || !VALID[msg.type]?.(msg)) {
    sendResponse({ ok: false, error: "invalid message" });
    return false;
  }
  handle(msg, sender).then(sendResponse, (e) => sendResponse({ ok: false, error: String(e) }));
  return true;
});

async function handle(msg, sender) {
  const tabId = sender.tab?.id;
  switch (msg.type) {
    case "blocked_context":
      return { ok: true, info: tabId != null ? await getTabInfo(tabId) : null };
    case "proceed": {
      const host = hostOf(msg.url);
      if (!host) return { ok: false };
      // Trust only the exact host the user chose to open, not its whole domain.
      await trust(host);
      report("proceeded", msg.url, "");
      return { ok: true };
    }
    case "trust_site":
      await trust(msg.host);
      return { ok: true };
    case "page_signals": {
      // Only content scripts in a tab may report; pages are never trusted with the score.
      if (tabId == null || !sender.url) return { ok: false };
      const info = (await getTabInfo(tabId)) || {};
      const h = scoreUrl(sender.url);
      const pageScore = msg.signals.reduce((s, x) => s + Math.max(0, Math.min(40, x.score)), 0);
      const total = Math.min(100, h.score + pageScore);
      await setTabInfo(tabId, { ...info, url: sender.url, heuristic: h, page: msg.signals, total });
      updateBadge(tabId);
      if (total >= NOTE_AT && !(await isAllowed(hostOf(sender.url)))) {
        report("page_threat", sender.url, msg.signals.map((s) => s.id).join(","));
        return { ok: true, warn: true, score: total, reasons: [...h.reasons.map((r) => r.detail), ...msg.signals.map((s) => s.detail)] };
      }
      return { ok: true, warn: false };
    }
    case "popup_state": {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const state = await getState();
      let agent = null;
      try {
        agent = await native.request("hello", {}, 3000);
      } catch (e) {
        agent = { error: String(e.message || e) };
      }
      return { ok: true, state, agent, tab: tab ? { url: tab.url, info: await getTabInfo(tab.id), heuristic: scoreUrl(tab.url || "") } : null };
    }
    case "set_enabled":
      await setEnabled(msg.enabled);
      return { ok: true };
    case "sync_now":
      return await syncBlocklist(true);
  }
  return { ok: false };
}

async function trust(host) {
  const state = await getState();
  if (!state.allowHosts.includes(host)) {
    state.allowHosts.push(host);
    await chrome.storage.local.set({ allowHosts: state.allowHosts });
  }
  await refreshAllowRules();
  native.request("allow_host", { host }).catch(() => {});
}

// --------------------------------------------------------------------- badge

async function updateBadge(tabId) {
  const { enabled } = await getState();
  if (!enabled) {
    chrome.action.setBadgeText({ text: "TẮT" });
    chrome.action.setBadgeBackgroundColor({ color: "#888" });
    return;
  }
  if (tabId == null) {
    chrome.action.setBadgeText({ text: "" });
    return;
  }
  const info = await getTabInfo(tabId);
  const score = info?.total ?? info?.heuristic?.score ?? 0;
  const bad = info?.reputation?.verdict === "malicious";
  const text = bad ? "!" : score >= NOTE_AT ? String(score) : "";
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: bad || score >= WARN_AT ? "#c62828" : "#b7791f" });
}

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove("tab:" + tabId));

// ------------------------------------------------------------------ schedule

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create("sync", { periodInMinutes: SYNC_MINUTES, delayInMinutes: 1 });
  syncBlocklist(true).catch(() => {});
  updateBadge();
});
chrome.runtime.onStartup.addListener(() => {
  syncBlocklist(false).catch(() => {});
  updateBadge();
});
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "sync") syncBlocklist(false).catch(() => {});
});
