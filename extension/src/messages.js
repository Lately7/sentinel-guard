// Shape checks for every message the service worker accepts. Content scripts
// run inside arbitrary websites, so a page_signals message is treated as
// attacker-crafted: only known signal ids, finite bounded integer scores and
// short strings get through.

export const PAGE_SIGNAL_IDS = new Set(["password_over_http", "password_cross_domain", "bare_login_page"]);
export const MAX_SIGNAL_SCORE = 40;
const MAX_DETAIL = 300;

function isSignal(s) {
  return s !== null && typeof s === "object"
    && typeof s.id === "string" && PAGE_SIGNAL_IDS.has(s.id)
    && Number.isInteger(s.score) && s.score >= 0 && s.score <= MAX_SIGNAL_SCORE
    && typeof s.detail === "string" && s.detail.length <= MAX_DETAIL;
}

export function validPageSignals(m) {
  if (!Array.isArray(m.signals) || m.signals.length > PAGE_SIGNAL_IDS.size) return false;
  if (!m.signals.every(isSignal)) return false;
  // Each signal counts once; repeating one would multiply its score.
  return new Set(m.signals.map((s) => s.id)).size === m.signals.length;
}

export const VALID = {
  blocked_context: () => true,
  proceed: (m) => typeof m.url === "string" && m.url.length < 8000,
  page_signals: validPageSignals,
  popup_state: () => true,
  set_enabled: (m) => typeof m.enabled === "boolean",
  sync_now: () => true,
  trust_site: (m) => typeof m.host === "string" && /^[a-z0-9.-]{1,253}$/.test(m.host),
};
