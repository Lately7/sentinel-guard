// Request/response client over the native-messaging port to the local agent.

const HOST = "com.sentinelguard.host";

let port = null;
let nextId = 1;
const pending = new Map();
let lastError = null;

function connect() {
  if (port) return port;
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch (e) {
    lastError = String(e);
    port = null;
    return null;
  }
  port.onMessage.addListener((msg) => {
    const p = msg && pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    clearTimeout(p.timer);
    msg.ok ? p.resolve(msg) : p.reject(new Error(msg.error || "agent error"));
  });
  port.onDisconnect.addListener(() => {
    lastError = chrome.runtime.lastError?.message || "disconnected";
    port = null;
    for (const p of pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error(lastError));
    }
    pending.clear();
  });
  return port;
}

export function request(type, payload = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const p = connect();
    if (!p) return reject(new Error(lastError || "native host unavailable"));
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("timeout"));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    try {
      p.postMessage({ id, type, ...payload });
    } catch (e) {
      clearTimeout(timer);
      pending.delete(id);
      reject(e);
    }
  });
}

export function status() {
  return { connected: !!port, lastError };
}
