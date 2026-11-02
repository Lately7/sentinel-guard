import { scoreUrl } from "./url_heuristics.js";
import { buildBlockRules, buildAllowRules, buildOnceRule, ALLOW_BASE_ID, ONCE_BASE_ID, ONCE_SLOTS, KIND_CODES, KIND_LABELS } from "./rules.js";
import * as native from "./native.js";
import { VALID } from "./messages.js";
import { APPROVAL_MS, recordFailure, recordSuccess, refused, retryable } from "./pending.js";
import { fetchAllowlist } from "./allowlist.js";

const WARN_AT = 70; // heuristic score that earns a full-page warning
const NOTE_AT = 40; // heuristic score shown in the popup / in-page banner
const SYNC_MINUTES = 360;
const BLOCKED_PAGE = chrome.runtime.getURL("src/blocked.html");

const DEFAULTS = { enabled: true, blocklistVersion: "", allowVersion: "", blocklistSize: 0, allowHosts: [], pendingAllow: [], pendingDownloads: [], syncError: "", stats: { blocked: 0, warned: 0, downloads: 0 } };

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

// One-time passes (RT-022): "Mở một lần" on the warning page lets one tab
// open one host until the tab leaves it or closes. Nothing is added to the
// trusted list and downloads from the host stay blocked.
async function getOnce() {
  return (await chrome.storage.session.get("once")).once || {};
}

async function allowOnce(tabId, host) {
  await exclusive(async () => {
    const { once = {}, onceSeq = 0 } = await chrome.storage.session.get(["once", "onceSeq"]);
    const prev = once[tabId];
    const id = ONCE_BASE_ID + (onceSeq % ONCE_SLOTS);
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [id, ...(prev ? [prev.ruleId] : [])],
      addRules: [buildOnceRule(id, host, tabId)],
    });
    once[tabId] = { host, ruleId: id };
    await chrome.storage.session.set({ once, onceSeq: onceSeq + 1 });
  });
}

async function onceAllowed(tabId, host) {
  const o = (await getOnce())[tabId];
  return !!o && (host === o.host || host.endsWith("." + o.host));
}

async function dropOnce(tabId) {
  const once = await getOnce();
  const o = once[tabId];
  if (!o) return;
  delete once[tabId];
  await chrome.storage.session.set({ once });
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [o.ruleId] }).catch(() => {});
}

chrome.tabs.onRemoved.addListener((tabId) => {
  dropOnce(tabId).catch(() => {});
});

function report(action, url, reason) {
  native.request("report", { action, url: String(url).slice(0, 8000), reason: String(reason || "").slice(0, 1000) }).catch(() => {});
}

// ---------------------------------------------------------------- blocklist

// Every change to the rule set — sync, enable, disable, trust — runs through
// this one queue, so "off" can never be overwritten by a sync that was
// already half-way through when the user switched protection off.
let ruleQueue = Promise.resolve();
function exclusive(fn) {
  const run = ruleQueue.then(fn, fn);
  ruleQueue = run.catch(() => {});
  return run;
}

function syncBlocklist(force = false) {
  return exclusive(() => doSync(force)).then(async (res) => {
    await chrome.storage.local.set({ syncError: res.ok ? "" : res.error || "sync failed" });
    // Retry soon while the agent is unreachable, instead of waiting six hours
    // with no rules after protection was switched on.
    if (!res.ok && res.error !== "protection is off") chrome.alarms.create("sync-retry", { delayInMinutes: 1 });
    return res;
  });
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
  // Trust given while the agent was offline is uploaded first, so the
  // agent's (authoritative) list below already contains it.
  for (const host of state.pendingAllow) {
    try {
      await native.request("allow_host", { host }, APPROVAL_MS);
    } catch (e) {
      // An administrator said no: that is an answer, not something to retry.
      if (refused(e)) {
        await forgetTrust(host);
        continue;
      }
      return { ok: false, error: "agent not connected" };
    }
  }
  if (state.pendingAllow.length) {
    await chrome.storage.local.set({ pendingAllow: [] });
    hello = await native.request("hello");
  }
  let allowHosts = state.allowHosts;
  if (force || state.pendingAllow.length || hello.allow_version !== state.allowVersion) {
    // The agent's list is authoritative: a site un-trusted in the dashboard
    // must lose its exemption here too.
    const res = await fetchAllowlist((offset) => native.request("get_allowlist", { offset }));
    if (!res) return { ok: false, error: "allowlist kept changing during sync" };
    allowHosts = res.hosts;
    await chrome.storage.local.set({ allowHosts, allowVersion: res.version });
  }
  const blocklistChanged = force || hello.blocklist_version !== state.blocklistVersion;
  if (!blocklistChanged) {
    await applyAllowRules(allowHosts);
    return { ok: true, unchanged: true };
  }
  let hosts, version;
  for (let attempt = 0; ; attempt++) {
    // Pages must all come from one blocklist version; a feed update landing
    // mid-sync shifts offsets, so start over (a few times at most).
    ({ hosts, version } = await fetchBlocklist());
    if (version !== null || attempt >= 2) break;
  }
  if (version === null) return { ok: false, error: "blocklist kept changing during sync" };
  const rules = [...buildBlockRules(hosts), ...buildAllowRules(allowHosts)];
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id), addRules: rules });
  await chrome.storage.local.set({ blocklistVersion: version, blocklistSize: hosts.length });
  return { ok: true, hosts: hosts.length, rules: rules.length };
}

async function fetchBlocklist() {
  const hosts = [];
  let offset = 0;
  let version;
  for (;;) {
    const page = await native.request("get_blocklist", { offset, limit: 20000 }, 30000);
    if (version === undefined) version = page.version;
    else if (page.version !== version) return { hosts, version: null };
    hosts.push(...page.hosts);
    offset += page.hosts.length;
    if (!page.hosts.length || offset >= page.total) break;
  }
  return { hosts, version };
}

async function applyAllowRules(allowHosts) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.filter((r) => r.id >= ALLOW_BASE_ID).map((r) => r.id),
    addRules: buildAllowRules(allowHosts),
  });
}

async function setEnabled(enabled) {
  if (!enabled) {
    await exclusive(async () => {
      await chrome.storage.local.set({ enabled: false, syncError: "" });
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: existing.map((r) => r.id) });
      await chrome.storage.local.set({ blocklistVersion: "" });
    });
  } else {
    await chrome.storage.local.set({ enabled: true });
    await syncBlocklist(true); // failure is recorded in syncError and shown by the popup
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
  const host = hostOf(d.url);
  if (await onceAllowed(d.tabId, host)) return;
  if ((await getOnce())[d.tabId]) await dropOnce(d.tabId); // left the site: the pass ends
  if (await isAllowed(host)) return;

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
  await scanDownload({ id: item.id, path: item.filename, url: item.finalUrl || item.url });
});

// Pending list updates are serialised like the counters: two downloads can
// finish (or fail) at the same moment.
let pendingChain = Promise.resolve();
function updatePending(fn) {
  pendingChain = pendingChain.then(async () => {
    const { pendingDownloads } = await getState();
    await chrome.storage.local.set({ pendingDownloads: fn(pendingDownloads) });
  }).catch(() => {});
  return pendingChain;
}

async function scanDownload(d) {
  const name = d.path.split(/[\\/]/).pop();
  let res;
  try {
    res = await native.request("scan_download", { path: d.path, url: d.url }, 180000);
  } catch (e) {
    // Not checked is not "scanned": keep it, tell the user once, retry later.
    let first = false;
    await updatePending((list) => {
      first = !list.some((p) => p.id === d.id);
      return recordFailure(list, d, e, Date.now());
    });
    if (first) notify("Chưa kiểm tra được tệp tải về", `${name}: agent trên máy chưa phản hồi — sẽ thử lại`);
    chrome.alarms.create("download-retry", { delayInMinutes: 2 });
    return;
  }
  await updatePending((list) => recordSuccess(list, d.id));
  bumpStat("downloads");
  const label = res.verdict.label;
  if (label === "malicious") {
    notify(res.quarantined ? "Đã cách ly tệp tải về nguy hiểm" : "Tệp tải về nguy hiểm", `${name}: ${res.reason}`);
  } else if (label === "suspicious") {
    notify("Tệp tải về đáng ngờ", `${name}: ${res.reason} (điểm ${res.verdict.score})`);
  } else if (label === "unknown") {
    // Not checked is not clean: a required engine did not finish.
    notify("Chưa kiểm tra xong tệp tải về", `${name}: chưa nên mở tệp này. Hãy quét lại sau.`);
  }
}

function notify(title, message) {
  chrome.notifications.create({ type: "basic", iconUrl: "icons/icon128.png", title, message: message.slice(0, 300), priority: 2 });
}

// ------------------------------------------------------------------ messages

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
      // Only the top-level warning page, only for the URL this tab was
      // actually navigating to, and only if that URL really is flagged. The
      // page's own ?u= parameter is display-only: blocked.html is web
      // accessible, so a site can open it with any URL it likes.
      if (tabId == null || sender.frameId !== 0 || !sender.url.startsWith(BLOCKED_PAGE)) return { ok: false };
      const info = await getTabInfo(tabId);
      if (!info?.url || msg.url !== info.url) return { ok: false };
      const host = hostOf(msg.url);
      if (!host) return { ok: false };
      let flagged = scoreUrl(msg.url).score >= WARN_AT;
      if (!flagged) {
        try {
          flagged = (await native.request("check_url", { url: msg.url }, 3000)).result.verdict === "malicious";
        } catch {
          flagged = info.reputation?.verdict === "malicious";
        }
      }
      if (!flagged) return { ok: false };
      // Trust only the exact host the user chose to open, not its whole domain,
      // and only for this tab unless the user asked to always trust it.
      if (msg.always) {
        if (!(await trust(host))) return { ok: false, refused: true };
        report("proceeded", msg.url, "always");
      } else {
        await allowOnce(tabId, host);
        report("proceeded", msg.url, "once");
        // Navigate from here, after the rule is in place, so the warning page
        // cannot race ahead of updateSessionRules.
        await chrome.tabs.update(tabId, { url: msg.url });
        return { ok: true, navigated: true };
      }
      return { ok: true };
    }
    case "trust_site":
      return { ok: await trust(msg.host) };
    case "page_signals": {
      if (tabId == null || !sender.url || sender.frameId !== 0) return { ok: false };
      const { enabled } = await getState();
      if (!enabled || (await isAllowed(hostOf(sender.url))) || (await onceAllowed(tabId, hostOf(sender.url)))) {
        return { ok: true, warn: false };
      }
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

async function forgetTrust(host) {
  const state = await getState();
  const allowHosts = state.allowHosts.filter((h) => h !== host);
  await chrome.storage.local.set({ allowHosts });
  if (state.enabled) await applyAllowRules(allowHosts);
}

async function trust(host) {
  return await exclusive(async () => {
    // Asked first: with the service installed this waits for an administrator,
    // and until then the page stays blocked.
    try {
      await native.request("allow_host", { host }, APPROVAL_MS);
      // Our own change: remember the agent's new version so the next sync
      // doesn't treat it as a dashboard edit.
      const hello = await native.request("hello", {}, 3000);
      await chrome.storage.local.set({ allowVersion: hello.allow_version });
    } catch (e) {
      if (refused(e)) return false;
      // Agent offline: queued and uploaded by the next successful sync.
      const { pendingAllow } = await getState();
      if (!pendingAllow.includes(host)) await chrome.storage.local.set({ pendingAllow: [...pendingAllow, host] });
      chrome.alarms.create("sync-retry", { delayInMinutes: 1 });
    }
    const state = await getState();
    if (!state.allowHosts.includes(host)) {
      state.allowHosts.push(host);
      await chrome.storage.local.set({ allowHosts: state.allowHosts });
    }
    if (state.enabled) await applyAllowRules(state.allowHosts);
    return true;
  });
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
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "sync" || a.name === "sync-retry") syncBlocklist(false).catch(() => {});
  if (a.name === "download-retry") {
    const { pendingDownloads } = await getState();
    for (const d of retryable(pendingDownloads)) await scanDownload(d);
  }
});
