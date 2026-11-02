// End-to-end check of the extension in Helium with a throw-away profile.
// Usage: add a local test host first (see README "Kiểm thử"), then
//   node tools/helium_e2e.mjs <path-to-extension>
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const HELIUM = process.env.LOCALAPPDATA + "\\imput\\Helium\\Application\\chrome.exe";
// Absolute: the browser resolves --load-extension against its own directory.
const EXT = resolve(process.argv[2] || "extension");
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
try {
  const version = await json("/json/version");
  results.browser = version.Browser;
  const cdp = session(version.webSocketDebuggerUrl);
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
    return { ev, where: await ev("location.href + ' | ' + document.title") };
  }
  const visit = async (url, ms) => (await open(url, ms)).where;
  const allowHosts = () => evalSw("chrome.storage.local.get('allowHosts').then(s => s.allowHosts || [])");
  const clickProceed = (ev) => ev("document.querySelector('details').open = true; document.getElementById('proceed').click(); new Promise(r => setTimeout(r, 1500)).then(() => location.href)");

  results.blocklisted = await visit("http://blocked-selftest.sentinelguard.invalid/login");
  const warned = await open("http://secure-paypal.account-verify.invalid/signin/verify");
  results.heuristic = warned.where;
  results.normal = await visit("https://example.com/", 5000);

  // A warning page opened directly with an attacker-chosen ?u= must not grant trust.
  const crafted = await open(`chrome-extension://${EXT_ID}/src/blocked.html?k=p&u=${encodeURIComponent("http://attacker-choice.invalid/")}`, 1500);
  await clickProceed(crafted.ev);
  results.crafted_proceed_rejected = !(await allowHosts()).includes("attacker-choice.invalid");
  // The genuine warning page's proceed trusts exactly that host.
  await clickProceed(warned.ev);
  results.genuine_proceed_trusted = (await allowHosts()).includes("secure-paypal.account-verify.invalid");

  const errors = cdp.events.filter((e) => e.method === "Runtime.exceptionThrown" || (e.method === "Runtime.consoleAPICalled" && e.params.type === "error"));
  results.sw_errors = errors.map((e) => JSON.stringify(e.params).slice(0, 300));
  cdp.close();
} catch (e) {
  results.error = String(e);
} finally {
  browser.kill();
  console.log(JSON.stringify(results, null, 2));
}
