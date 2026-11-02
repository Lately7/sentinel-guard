// What the popup says about the current page. "No problem found" is only
// shown when the agent actually checked the page's reputation; a structural
// URL score alone is not a check (RT-025).

export function pageStatus(info, heuristicScore) {
  const rep = info?.reputation;
  const score = info?.total ?? heuristicScore;
  if (rep?.verdict === "malicious") return { text: `Nguy hiểm: ${rep.kind || "độc hại"} (${rep.source})`, cls: "bad" };
  if (rep?.verdict === "allowed") return { text: "Bạn đã tin cậy trang này", cls: "muted" };
  if (score >= 70) return { text: `Rủi ro cao (${score}/100)`, cls: "bad" };
  if (score >= 40) return { text: `Đáng ngờ (${score}/100)`, cls: "warn" };
  if (info?.pending) return { text: "Đang kiểm tra…", cls: "muted" };
  if (!rep) return { text: "Chưa kiểm tra danh tiếng — agent chưa phản hồi", cls: "warn" };
  return { text: "Không phát hiện vấn đề", cls: "ok" };
}
