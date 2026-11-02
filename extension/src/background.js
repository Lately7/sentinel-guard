import { scoreUrl } from "./url_heuristics.js";
import { buildBlockRules, buildAllowRules, ALLOW_BASE_ID, KIND_CODES, KIND_LABELS } from "./rules.js";
import * as native from "./native.js";

const WARN_AT = 70; // heuristic score that earns a full-page warning
const NOTE_AT = 40; // heuristic score shown in the popup / in-page banner
const SYNC_MINUTES = 360;
const BLOCKED_PAGE = chrome.runtime.getURL("src/blocked.html");

const DEFAULTS = { enabled: true, blocklistVersion: "", allowVersion: "", blocklistSize: 0, allowHosts: [], stats: { blocked: 0, warned: 0, downloads: 0 } };

async function getState() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

// Read-modify-write of counters is serialised through one promise chain;
// concurrent blocked requests would otherwise overwrite each other's increments.
let statsChain = Promise.resolve();
function bumpStat(key) {
  statsChain = statsChain.then(async () => {
    const { stats } = await getState();
    stats[key] = (stats[key] || 0) + 1;
    await chrome.storage.local.set({ stats });
  }).catch(() => {});
  return statsChain;
}

// Latest navigation per tab, kept in memory synchronously so a network-rule
// redirect that happens before any await still finds its context.
const navs = new Map(); // tabId -> { url, seq }
let navSeq = 0;

async function setTabInfo(tabId, info) {
  await chrome.storage.session.set({ ["tab:" + tabId]: { ...info, ts: Date.now() } });
}
async function getTabInfo(tabId) {
  const mem = navs.get(tabId);
  const k = "tab:" + tabId;
  const stored = (await chrome.storage.session.get(k))[k] || null;
  if (mem && (!stored || stored.url !== mem.url)) return { url: mem.url, pending: true };
  return stored;
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

let syncing = null;
function syncBlocklist(force = false) {
  // One sync at a time; alarms, start-up and the popup can all ask at once.
  if (!syncing) syncing = doSync(force).finally(() => (syncing = null));
  return syncing;
}

async function doSync(force) {
  const state = await getState();
  if (!state.enabled) return { ok: false, error: "protection is off" };
  let hello;
  try {
    hello = await native.request("hello");
  } catch {
    return { ok: false, error: "agent not connected" };
  }
  let allowHosts = state.allowHosts;
  if (force || hello.allow_version !== state.allowVersion) {
    // The agent's list is authoritative: a site un-trusted in the dashboard
    // must lose its exemption here too.
    const res = await native.request("get_allowlist");
    allowHosts = res.hosts.filter((h) => typeof h === "string");
    await chrome.storage.local.set({ allowHosts, allowVersion: res.allow_version });
  }
  const blocklistChanged = force || hello.blocklist_version !== state.blocklistVersion;
  if (!blocklistChanged) {
    await refreshAllowRules();
    return { ok: true, unchanged: true };
  }
  const hosts = [];
  let offset = 0;
  for (;;) {
    const page = await native.request("get_blocklist", { offset, limit: 20000 }, 30000);
    hosts.push(...page.hosts);
    offset += page.hosts.length;
    if (!page.hosts.length || offset >= page.total) break;
  }
  if (!(await getState()).enabled) return { ok: false, error: "protection is off" }; // switched off mid-sync
  const rules = [...buildBlockRules(hosts), ...buildAllowRules(allowHosts)];
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id), addRules: rules });
  await chrome.storage.local.set({ blocklistVersion: hello.blocklist_version, blocklistSize: hosts.length });
  return { ok: true, hosts: hosts.length, rules: rules.length };
}

async function refreshAllowRules() {
  const { allowHosts, enabled } = await getState();
  if (!enabled) return;
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.filter((r) => r.id >= ALLOW_BASE_ID).map((r) => r.id),
    addRules: buildAllowRules(allowHosts),
  });
}

async function setEnabled(enabled) {
  await chrome.storage.local.set({ enabled });
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
  const seq = ++navSeq;
  navs.set(d.tabId, { url: d.url, seq }); // before any await (see navs)
  const current = () => navs.get(d.tabId)?.seq === seq;

  const { enabled } = await getState();
  if (!enabled || !current()) return;
  await setTabInfo(d.tabId, { url: d.url, pending: true });
  if (await isAllowed(hostOf(d.url))) return;

  const h = scoreUrl(d.url);
  let rep = null;
  try {
    rep = (await native.request("check_url", { url: d.url }, 3000)).result;
  } catch {
    /* agent offline: heuristics only */
  }
  // The user may have navigated elsewhere while we waited: never apply a stale verdict.
  if (!current()) return;
  await setTabInfo(d.tabId, { url: d.url, heuristic: h, reputation: rep });

  if (rep && rep.verdict === "malicious") {
    const kind = KIND_CODES[rep.kind] || "x";
    chrome.tabs.update(d.tabId, { url: warnUrl({ k: kind, u: d.url, src: rep.source || "" }) });
    bumpStat("blocked");
    report("blocked", d.url, `${KIND_LABELS[kind]} (${rep.source})`);
  } else if (h.score >= WARN_AT && rep?.verdict !== "allowed") {
    chrome.tabs.update(d.tabId, { url: warnUrl({ k: "h", u: d.url, s: String(h.score), r: h.reasons.map((r) => r.detail).join(" · ") }) });
    bumpStat("warned");
    report("warned", d.url, h.reasons.map((r) => r.id).join(","));
  }
  updateBadge(d.tabId);
});

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  // Available for unpacked installs: count blocks of sub-resources too.
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    if (info.request.type !== "main_frame" && info.rule.ruleId < ALLOW_BASE_ID) bumpStat("blocked");
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
    // May lose the race against a small download; the completed-file scan
    // below then quarantines it because of the same URL verdict.
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
  page_signals: (m) => Array.isArray(m.signals) && m.signals.length <= 20 && m.signals.every((s) => typeof s?.id === "string" && typeof s?.score === "number" && typeof s?.detail === "string"),
  popup_state: () => true,
  set_enabled: (m) => typeof m.enabled === "boolean",
  sync_now: () => true,
  trust_site: (m) => typeof m.host === "string" && /^[a-z0-9.-]{1,253}$/.test(m.host),
};

// Messages that only our own extension pages (popup, warning page) may send;
// content scripts run inside arbitrary websites.
const EXTENSION_PAGE_ONLY = new Set(["blocked_context", "proceed", "popup_state", "set_enabled", "sync_now", "trust_site"]);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fromExtensionPage = typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
  if (sender.id !== chrome.runtime.id || !msg || typeof msg.type !== "string" || !VALID[msg.type]?.(msg)
      || (EXTENSION_PAGE_ONLY.has(msg.type) && !fromExtensionPage)) {
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
      // Only the top-level warning page, and only for the URL this tab was
      // actually stopped on: a site framing blocked.html can't trick a click
      // into trusting a host of its choice.
      if (tabId == null || sender.frameId !== 0 || !sender.url.startsWith(BLOCKED_PAGE)) return { ok: false };
      const info = await getTabInfo(tabId);
      const fromQuery = new URL(sender.url).searchParams.get("u");
      if (msg.url !== info?.url && msg.url !== fromQuery) return { ok: false };
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
      if (tabId == null || !sender.url || sender.frameId !== 0) return { ok: false };
      const { enabled } = await getState();
      if (!enabled || (await isAllowed(hostOf(sender.url)))) return { ok: true, warn: false };
      const info = (await getTabInfo(tabId)) || {};
      const h = scoreUrl(sender.url);
      const pageScore = msg.signals.reduce((s, x) => s + Math.max(0, Math.min(40, x.score)), 0);
      const total = Math.min(100, h.score + pageScore);
      await setTabInfo(tabId, { ...info, url: sender.url, heuristic: h, page: msg.signals.map((s) => ({ id: s.id.slice(0, 64), score: s.score, detail: s.detail.slice(0, 300) })), total });
      updateBadge(tabId);
      if (total >= NOTE_AT) {
        report("page_threat", sender.url, msg.signals.map((s) => s.id).join(","));
        return { ok: true, warn: true, score: total, reasons: [...h.reasons.map((r) => r.detail), ...msg.signals.map((s) => s.detail.slice(0, 300))] };
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
  try {
    await native.request("allow_host", { host });
    // Our own change: remember the agent's new version so the next sync
    // doesn't treat it as a dashboard edit.
    const hello = await native.request("hello", {}, 3000);
    await chrome.storage.local.set({ allowVersion: hello.allow_version });
  } catch {
    /* agent offline: kept locally, merged on next sync */
  }
}

// --------------------------------------------------------------------- badge

async function updateBadge(tabId) {
  const { enabled } = await getState();
  if (!enabled) {
    chrome.action.setBadgeText({ text: "TẮT" });
    chrome.action.setBadgeBackgroundColor({ color: "#888" });
    return;
  }
  chrome.action.setBadgeText({ text: "" });
  if (tabId == null) return;
  const info = await getTabInfo(tabId);
  const score = info?.total ?? info?.heuristic?.score ?? 0;
  const bad = info?.reputation?.verdict === "malicious";
  const text = bad ? "!" : score >= NOTE_AT ? String(score) : "";
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: bad || score >= WARN_AT ? "#c62828" : "#b7791f" });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  navs.delete(tabId);
  chrome.storage.session.remove("tab:" + tabId);
});

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
