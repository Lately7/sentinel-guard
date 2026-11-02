// Reads URLs (one per line) on stdin, prints one JSON score per line.
import { scoreUrl } from "../extension/src/url_heuristics.js";

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  const out = input.split(/\r?\n/).filter(Boolean).map((u) => {
    const r = scoreUrl(u);
    return JSON.stringify({ url: u, score: r.score, reasons: r.reasons.map((x) => x.id) });
  });
  process.stdout.write(out.join("\n") + "\n");
});
