// End-to-end check of the extension in Helium with a throw-away profile.
// Usage: add a local test host first (see README "Kiểm thử"), then
//   node tools/helium_e2e.mjs <path-to-extension> [screenshot-dir]
// Set SENTINEL_HOME to a temporary folder (and block the test host there) to
// keep the agent's real data untouched: Helium passes its environment on to
// the native host it launches.
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const HELIUM = process.env.LOCALAPPDATA + "\\imput\\Helium\\Application\\chrome.exe";
// Absolute: the browser resolves --load-extension against its own directory.
const EXT = resolve(process.argv[2] || "extension");
const SHOTS = process.argv[3] ? resolve(process.argv[3]) : null;
const EXT_ID = "ljnncmaoolpbiifaidkgekkeimmjlcgn";
const PORT = 9333;
const profile = mkdtempSync(join(tmpdir(), "sg-helium-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = spawn(HELIUM, [
  `--user-data-dir=${profile}`, `--load-extension=${EXT}`, `--remote-debugging-port=${PORT}`,
  "--disable-features=DisableLoadExtensionCommandLineSwitch", "--no-first-run", "--no-default-browser-check", "about:blank",
], { stdio: "ignore", shell: false });

async function json(path) {
  for (let i = 0; i < 40; i++) {
    try { return await (await fetch(`http://127.0.0.1:${PORT}${path}`)).json(); } catch { await sleep(250); }
  }
  throw new Error("DevTools endpoint not reachable");
}

function session(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const waiting = new Map();
  const events = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); } else events.push(msg);
  };
  const ready = new Promise((r) => (ws.onopen = r));
  const send = async (method, params = {}, sessionId) => {
    await ready;
    const mid = ++id;
    ws.send(JSON.stringify({ id: mid, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((r) => waiting.set(mid, r));
  };
  return { send, events, close: () => ws.close() };
}

const results = {};
let cdp = null;
try {
  const version = await json("/json/version");
  results.browser = version.Browser;
  cdp = session(version.webSocketDebuggerUrl);
  await cdp.send("Target.setDiscoverTargets", { discover: true });

  let sw = null;
  for (let i = 0; i < 40 && !sw; i++) {
    const { result } = await cdp.send("Target.getTargets");
    sw = result.targetInfos.find((t) => t.type === "service_worker" && t.url.includes(EXT_ID));
    if (!sw) await sleep(250);
  }
  results.extension_loaded = !!sw;
  if (!sw) throw new Error("extension service worker not found (is --load-extension honoured?)");

  const { result: att } = await cdp.send("Target.attachToTarget", { targetId: sw.targetId, flatten: true });
  const swSid = att.sessionId;
  await cdp.send("Runtime.enable", {}, swSid);
  const evalSw = async (expr) => (await cdp.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, swSid)).result?.result?.value;

  // Wait for the first blocklist sync from the agent.
  let state = null;
  for (let i = 0; i < 120; i++) {
    state = await evalSw("chrome.storage.local.get(null).then(s => ({size: s.blocklistSize, ver: s.blocklistVersion, enabled: s.enabled}))");
    if (state?.size) break;
    await sleep(500);
  }
  results.sync = state;
  results.dynamic_rules = await evalSw("chrome.declarativeNetRequest.getDynamicRules().then(r => r.length)");

  async function open(url, waitMs = 4000) {
    const { result: t } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { result: a } = await cdp.send("Target.attachToTarget", { targetId: t.targetId, flatten: true });
    await cdp.send("Page.enable", {}, a.sessionId);
    await cdp.send("Page.navigate", { url }, a.sessionId);
    await sleep(waitMs);
    const ev = async (expression) => (await cdp.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, a.sessionId)).result?.result?.value;
    const shot = async (name, width, height) => {
      if (!SHOTS) return;
      await cdp.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1.5, mobile: false }, a.sessionId);
      await sleep(400);
      const { result: img } = await cdp.send("Page.captureScreenshot", { format: "png" }, a.sessionId);
      writeFileSync(join(SHOTS, name), Buffer.from(img.data, "base64"));
    };
    return { ev, shot, where: await ev("location.href + ' | ' + document.title") };
  }
  const visit = async (url, ms) => (await open(url, ms)).where;
  const allowHosts = () => evalSw("chrome.storage.local.get('allowHosts').then(s => s.allowHosts || [])");
  // The click may navigate away, which ends that evaluation; read the location afterwards.
  const click = async (ev, id) => {
    await ev(`document.querySelector('details').open = true; document.getElementById('${id}').click(); true`);
    await sleep(2500);
    return (await ev("location.href")) || "";
  };
  const sessionRules = () => evalSw("chrome.declarativeNetRequest.getSessionRules().then(r => r.length)");

  const blocked = await open("http://blocked-selftest.sentinelguard.invalid/login");
  results.blocklisted = blocked.where;
  await blocked.ev("document.querySelector('details').open = true");
  await blocked.shot("blocked.png", 900, 640);
  const warned = await open("http://secure-paypal.account-verify.invalid/signin/verify");
  results.heuristic = warned.where;
  results.normal = await visit("https://example.com/", 5000);

  // A warning page opened directly with an attacker-chosen ?u= must not grant anything.
  const crafted = await open(`chrome-extension://${EXT_ID}/src/blocked.html?k=p&u=${encodeURIComponent("http://attacker-choice.invalid/")}`, 1500);
  await click(crafted.ev, "always");
  results.crafted_proceed_rejected = !(await allowHosts()).includes("attacker-choice.invalid");
  // "Mở một lần": the page opens in this tab, nothing is added to the trusted list (RT-022)...
  const onceUrl = await click(blocked.ev, "proceed");
  results.once_opened = !onceUrl.includes("blocked.html");
  results.once_not_trusted = !(await allowHosts()).includes("blocked-selftest.sentinelguard.invalid");
  results.once_session_rules = await sessionRules();
  results.once_debug = { url: onceUrl, rules: await evalSw("chrome.declarativeNetRequest.getSessionRules()"),
                         once: await evalSw("chrome.storage.session.get(['once']).then(s => s.once)"),
                         matched: await evalSw("chrome.declarativeNetRequest.getMatchedRules({}).then(r => r.rulesMatchedInfo.slice(-4).map(m => ({rule: m.rule, tab: m.tabId})))") };
  // ...and leaving the site ends the pass.
  await blocked.ev("location.href = 'https://example.com/'");
  await sleep(4000);
  results.once_dropped_after_leaving = (await sessionRules()) === 0;
  // "Luôn tin cậy" trusts exactly that host.
  await click(warned.ev, "always");
  results.always_trusted = (await allowHosts()).includes("secure-paypal.account-verify.invalid");

  const popup = await open(`chrome-extension://${EXT_ID}/src/popup.html`, 2500);
  await popup.shot("popup.png", 320, 300);

} catch (e) {
  results.error = String(e);
} finally {
  if (cdp) {
    const errors = cdp.events.filter((e) => e.method === "Runtime.exceptionThrown" || (e.method === "Runtime.consoleAPICalled" && e.params.type === "error"));
    results.sw_errors = errors.map((e) => JSON.stringify(e.params).slice(0, 400));
    cdp.close();
  }
  browser.kill();
  console.log(JSON.stringify(results, null, 2));
}
