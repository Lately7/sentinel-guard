// Structural URL risk scoring. Pure functions: no chrome.*, no network, so it
// runs identically in the service worker and in node --test.

const MULTI_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
  "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "info.vn", "biz.vn", "name.vn", "pro.vn", "health.vn", "ac.vn",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "co.kr", "or.kr", "go.kr", "ac.kr",
  "com.sg", "edu.sg", "gov.sg", "com.my", "com.ph", "co.th", "in.th", "co.id", "or.id", "go.id",
  "co.in", "net.in", "org.in", "gov.in", "ac.in",
  "com.tw", "org.tw", "edu.tw", "com.hk", "org.hk", "com.mx", "com.ar", "com.tr", "co.za", "co.nz",
]);

// Brand -> registrable domains it legitimately owns.
export const BRANDS = {
  paypal: ["paypal.com", "paypal.me", "paypalobjects.com"],
  apple: ["apple.com", "icloud.com", "apple.news", "cdn-apple.com"],
  microsoft: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "msn.com", "azure.com", "windows.net", "bing.com", "sharepoint.com", "office365.com", "skype.com"],
  google: ["google.com", "google.com.vn", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com", "googleusercontent.com", "withgoogle.com", "goo.gl", "g.co", "blogger.com"],
  facebook: ["facebook.com", "fb.com", "fbcdn.net", "messenger.com", "meta.com", "instagram.com", "whatsapp.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.co.jp", "amazon.de", "amazonaws.com", "aws.amazon.com", "media-amazon.com"],
  netflix: ["netflix.com", "nflxext.com", "nflximg.net"],
  binance: ["binance.com", "binance.us", "bnbstatic.com"],
  metamask: ["metamask.io"],
  coinbase: ["coinbase.com"],
  steam: ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
  vietcombank: ["vietcombank.com.vn"],
  techcombank: ["techcombank.com.vn", "techcombank.com"],
  mbbank: ["mbbank.com.vn"],
  vietinbank: ["vietinbank.vn"],
  agribank: ["agribank.com.vn"],
  momo: ["momo.vn"],
  zalo: ["zalo.me", "zalo.vn", "zaloapp.com", "zdn.vn"],
  shopee: ["shopee.vn", "shopee.com", "shopee.co.id", "shopee.sg", "shopee.com.my", "susercontent.com"],
  lazada: ["lazada.vn", "lazada.com", "lazada.sg"],
  tiktok: ["tiktok.com", "tiktokcdn.com", "tiktokv.com"],
  telegram: ["telegram.org", "t.me", "telegram.me"],
  github: ["github.com", "githubusercontent.com", "github.io", "githubassets.com"],
};

// TLDs that abuse statistics consistently rank as over-represented. A weak
// signal on its own; it only matters combined with others.
const ABUSED_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "support", "cam", "cfd", "sbs", "icu", "buzz", "monster"]);

const LOGIN_WORDS = /(log-?in|sign-?in|verify|verification|account|password|passwd|wallet|banking|secure|update-?info|unlock|recover)/i;

export function registrableDomain(hostname) {
  if (typeof hostname !== "string") return "";
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (!h || isIp(h)) return h;
  const labels = h.split(".");
  if (labels.length <= 2) return h;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

export function isIp(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host.split(".").every((n) => Number(n) <= 255);
  return host.startsWith("[") || /^[0-9a-f:]+$/i.test(host) && host.includes(":");
}

function editDistanceAtMostOne(a, b) {
  if (a === b) return false; // identical is not a lookalike
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) i++;
    else if (a.length < b.length) j++;
    else { i++; j++; }
  }
  return edits + (a.length - i) + (b.length - j) <= 1;
}

function isOfficial(brand, regDomain, hostname) {
  return BRANDS[brand].some((d) => regDomain === d || hostname === d || hostname.endsWith("." + d));
}

const IGNORED_SCHEMES = new Set(["chrome:", "about:", "chrome-extension:", "file:", "edge:", "helium:", "devtools:", "view-source:", "data:", "blob:", "javascript:"]);

export function scoreUrl(url) {
  const reasons = [];
  const add = (id, score, detail) => reasons.push({ id, score, detail });
  let u;
  try {
    u = new URL(url);
  } catch {
    return { score: 0, reasons };
  }
  if (IGNORED_SCHEMES.has(u.protocol) || (u.protocol !== "http:" && u.protocol !== "https:")) return { score: 0, reasons };

  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "[::1]") return { score: 0, reasons };

  const reg = registrableDomain(host);
  const regLabel = reg.split(".")[0] || "";
  const tld = host.split(".").pop() || "";
  const sub = host.endsWith(reg) ? host.slice(0, Math.max(0, host.length - reg.length - 1)) : "";

  if (isIp(host)) add("ip_host", 30, "địa chỉ IP thay cho tên miền");
  if (host.split(".").some((l) => l.startsWith("xn--"))) add("punycode", 25, "tên miền dùng ký tự quốc tế (punycode) có thể giả mạo chữ cái");
  if (u.username || u.password) add("userinfo", 30, "URL chứa '@' để che tên miền thật");
  if (host.length > 60) add("long_host", 10, "tên miền rất dài");
  if (sub && sub.split(".").length >= 4) add("deep_subdomain", 15, "quá nhiều tầng tên miền con");
  if (u.port && u.port !== "80" && u.port !== "443") add("odd_port", 10, `cổng không chuẩn :${u.port}`);
  if (ABUSED_TLDS.has(tld)) add("abused_tld", 10, `đuôi .${tld} hay bị lạm dụng`);
  if ((regLabel.match(/-/g) || []).length >= 3) add("many_hyphens", 10, "tên miền nhiều dấu gạch ngang");

  const pathAndQuery = decodeSafe(u.pathname + u.search);
  if (u.protocol === "http:" && LOGIN_WORDS.test(pathAndQuery)) add("http_login", 20, "trang đăng nhập/xác minh không mã hoá (http)");

  let brandHit = false;
  const tokens = regLabel.split("-").filter(Boolean);
  for (const brand of Object.keys(BRANDS)) {
    if (isOfficial(brand, reg, host)) continue;
    const looksLike = brand.length >= 5 && tokens.some((t) => editDistanceAtMostOne(t, brand) || (t !== brand && unLeet(t) === brand));
    if (looksLike) {
      add("lookalike_brand", 45, `tên miền "${reg}" nhái thương hiệu ${brand}`);
      brandHit = true;
      break;
    }
    const inSub = sub.split(/[.-]/).includes(brand) || sub.includes(brand);
    const inLabel = regLabel !== brand && regLabel.includes(brand) && brand.length >= 5;
    const inPath = brand.length >= 5 && new RegExp(`(^|[^a-z])${brand}([^a-z]|$)`, "i").test(pathAndQuery) && LOGIN_WORDS.test(pathAndQuery);
    if (inLabel) {
      // The brand inside someone else's domain name ("vietcombank-xacminh.click")
      // is as deliberate as a one-letter lookalike.
      add("brand_in_domain", 45, `tên miền "${reg}" mạo danh ${brand}`);
      brandHit = true;
      break;
    }
    if (inSub || inPath) {
      add("brand_elsewhere", 35, `nhắc tới ${brand} nhưng không phải tên miền chính thức của ${brand}`);
      brandHit = true;
      break;
    }
  }
  if (brandHit && LOGIN_WORDS.test(host + pathAndQuery)) add("brand_login", 15, "kết hợp thương hiệu với từ khoá đăng nhập/xác minh");

  const score = Math.min(100, reasons.reduce((s, r) => s + r.score, 0));
  return { score, reasons };
}

// Digits commonly swapped for letters in lookalike domains ("micros0ft", "paypa1").
function unLeet(s) {
  return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t");
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
