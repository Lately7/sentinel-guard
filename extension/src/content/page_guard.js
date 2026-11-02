// Page-level signals for credential-theft pages. Runs in the isolated world;
// it only reads the DOM and never sends page content anywhere but the
// extension's own service worker.
(() => {
  if (window.top !== window || !/^https?:$/.test(location.protocol)) return;

  function regDomain(host) {
    const parts = host.toLowerCase().split(".");
    if (parts.length <= 2) return host.toLowerCase();
    const two = parts.slice(-2).join(".");
    return /^(com|net|org|edu|gov|co|ac|or|ne|go)\.[a-z]{2}$/.test(two) ? parts.slice(-3).join(".") : two;
  }

  function collect() {
    const signals = [];
    const pw = document.querySelectorAll('input[type="password"]');
    if (!pw.length) return signals;
    const here = regDomain(location.hostname);

    if (location.protocol === "http:") {
      signals.push({ id: "password_over_http", score: 25, detail: "trang yêu cầu mật khẩu qua kết nối không mã hoá" });
    }
    for (const form of new Set([...pw].map((i) => i.form).filter(Boolean))) {
      const action = form.getAttribute("action");
      if (!action) continue;
      try {
        const target = new URL(action, location.href);
        if (/^https?:$/.test(target.protocol) && regDomain(target.hostname) !== here) {
          signals.push({ id: "password_cross_domain", score: 25, detail: `form mật khẩu gửi dữ liệu sang tên miền khác (${target.hostname})` });
          break;
        }
      } catch {
        /* unparsable action: ignore */
      }
    }
    // A login page that is a lone form with almost no links is typical of kits
    // hosted on throwaway domains; real sites have navigation and footers.
    const links = document.querySelectorAll("a[href]").length;
    if (links <= 3) signals.push({ id: "bare_login_page", score: 10, detail: "trang đăng nhập gần như không có liên kết nào khác" });
    return signals;
  }

  function banner(reasons, score) {
    if (document.getElementById("sentinel-guard-banner")) return;
    const host = document.createElement("div");
    host.id = "sentinel-guard-banner";
    host.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    const box = document.createElement("div");
    box.style.cssText = "font:14px/1.45 'Segoe UI',system-ui,sans-serif;background:#b42318;color:#fff;padding:10px 16px;display:flex;gap:12px;align-items:flex-start;box-shadow:0 2px 8px rgba(0,0,0,.3)";
    const text = document.createElement("div");
    text.style.flex = "1";
    const title = document.createElement("b");
    title.textContent = `Sentinel Guard: trang này có dấu hiệu lừa đảo (điểm ${score}). Đừng nhập mật khẩu hay thông tin thẻ.`;
    const list = document.createElement("div");
    list.style.opacity = ".9";
    list.textContent = reasons.join(" · ");
    text.append(title, list);
    const close = document.createElement("button");
    close.textContent = "Đóng";
    close.style.cssText = "background:#fff;color:#b42318;border:0;border-radius:6px;padding:4px 10px;cursor:pointer;font:inherit";
    close.addEventListener("click", () => host.remove());
    box.append(text, close);
    root.append(box);
    document.documentElement.append(host);
  }

  // Re-sent whenever the set of signals changes, in either direction: a
  // single-page app may show a login form late, retarget it, or remove it.
  let sentKey = "";
  function check() {
    const signals = collect();
    const key = signals.map((s) => s.id).sort().join(",");
    if (key === sentKey) return;
    sentKey = key;
    if (!signals.length) {
      document.getElementById("sentinel-guard-banner")?.remove();
      return;
    }
    chrome.runtime.sendMessage({ type: "page_signals", signals }, (res) => {
      if (chrome.runtime.lastError) return;
      if (res && res.warn) banner(res.reasons || [], res.score);
    });
  }

  // Throttled, for the page's whole lifetime: a busy page mutating
  // constantly costs one cheap check per second at most.
  let pending = false;
  const schedule = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => {
      pending = false;
      check();
    }, 1000);
  };
  check();
  new MutationObserver(schedule).observe(document.documentElement,
    { childList: true, subtree: true, attributes: true, attributeFilter: ["action", "type"] });
})();
