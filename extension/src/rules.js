// Builds declarativeNetRequest rules from the agent's host blocklist. Pure, so
// it is unit-tested without a browser.

export const CHUNK = 5000;
export const ALLOW_BASE_ID = 900000;
export const KIND_CODES = { malware: "m", phishing: "p", scam: "s", miner: "c", pup: "u", threat: "t", custom: "x" };

// hosts: [[host, kind], ...]
export function buildBlockRules(hosts) {
  const byKind = new Map();
  for (const entry of hosts) {
    if (!Array.isArray(entry) || typeof entry[0] !== "string") continue;
    const host = entry[0].toLowerCase();
    const kind = KIND_CODES[entry[1]] ? entry[1] : "custom";
    if (!/^[a-z0-9._-]+$/.test(host) || !host.includes(".")) continue;
    if (!byKind.has(kind)) byKind.set(kind, []);
    byKind.get(kind).push(host);
  }
  const rules = [];
  let id = 1;
  for (const [kind, list] of byKind) {
    for (let i = 0; i < list.length; i += CHUNK) {
      const domains = list.slice(i, i + CHUNK);
      // Top-level navigations go to the warning page so the user learns why;
      // everything else (scripts, iframes, miners, beacons) is dropped silently.
      rules.push({
        id: id++,
        priority: 1,
        action: { type: "redirect", redirect: { extensionPath: `/src/blocked.html?k=${KIND_CODES[kind]}` } },
        condition: { requestDomains: domains, resourceTypes: ["main_frame"] },
      });
      rules.push({
        id: id++,
        priority: 1,
        action: { type: "block" },
        // Exclusion instead of a list, so resource types added to Chromium
        // later (webtransport, webbundle, csp_report ...) are blocked too.
        condition: { requestDomains: domains, excludedResourceTypes: ["main_frame"] },
      });
    }
  }
  return rules;
}

// One-time passes: session rules limited to one tab (tabIds is session-only in DNR).
export const ONCE_BASE_ID = 950000;
export const ONCE_SLOTS = 40000;

export function buildOnceRule(id, host, tabId) {
  return {
    id,
    priority: 10,
    action: { type: "allow" },
    condition: { requestDomains: [host], tabIds: [tabId] },
  };
}

export function buildAllowRules(hosts) {
  return hosts
    .filter((h) => typeof h === "string" && /^[a-z0-9._-]+$/.test(h))
    .slice(0, 5000)
    .map((h, i) => ({
      id: ALLOW_BASE_ID + i,
      priority: 10,
      // "allow" exempts only requests *to* the trusted host. allowAllRequests
      // would also exempt everything a trusted page loads, so a compromised
      // trusted site could pull scripts from blocklisted malware hosts.
      action: { type: "allow" },
      condition: { requestDomains: [h] },
    }));
}

export const KIND_LABELS = {
  m: "phát tán mã độc",
  p: "lừa đảo (phishing)",
  c: "đào tiền ảo trái phép",
  s: "lừa đảo mua bán / cửa hàng giả",
  u: "phân phối phần mềm không mong muốn (PUP)",
  t: "nằm trong nguồn tình báo mối đe dọa (lừa đảo, mã độc, scam)",
  x: "nằm trong danh sách chặn",
  h: "có dấu hiệu giả mạo",
};
