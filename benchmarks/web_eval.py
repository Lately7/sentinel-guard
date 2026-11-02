"""Measure web protection on live data with a hold-out, so the numbers are honest.

* Detection: current OpenPhish URLs, checked against a DB built from every
  other feed (OpenPhish itself excluded), plus the URL heuristics.
* False positives: Tranco ranks 10,001-20,000 (outside the top-10k list the
  feeds are filtered against, so the filter can't hide blocklist mistakes),
  and the top 10,000 for the heuristics.

Usage: python benchmarks/web_eval.py [--out reports]
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))


def heuristic_scores(urls: list[str]) -> list[dict]:
    proc = subprocess.run(["node", str(ROOT / "benchmarks" / "score_urls.mjs")], input="\n".join(urls),
                          capture_output=True, text=True, encoding="utf-8", check=True, shell=False)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "reports"))
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SENTINEL_HOME"] = tmp
        from sentinel import feeds, urlintel
        from sentinel.db import Database

        db = Database()
        holdout = [f for f in feeds.FEEDS if f.name != "openphish"]
        feeds.update_popular(db)
        feed_status = feeds.update_all(db, holdout)

        phish = list(dict.fromkeys(feeds.parse_urls(feeds.fetch("https://openphish.com/feed.txt"))))
        raw = feeds._fetch_bytes(feeds.TRANCO_URL)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            rows = zf.read(zf.namelist()[0]).decode().splitlines()
        tranco = [r.split(",", 1)[1].strip() for r in rows[:20_000]]
        top10k, next10k = tranco[:10_000], tranco[10_000:20_000]

        def listed(url: str) -> str | None:
            r = urlintel.check(db, url)
            return r["source"] if r["verdict"] == "malicious" else None

        p_list = [listed(u) for u in phish]
        p_heur = heuristic_scores(phish)
        legit_urls = [f"https://{d}/" for d in next10k]
        l_list = [(u, listed(u)) for u in legit_urls]
        top_heur = heuristic_scores([f"https://{d}/" for d in top10k])
        next_heur = heuristic_scores(legit_urls)
        db.close()

    n = len(phish)
    by_list = sum(1 for s in p_list if s)
    by_heur70 = sum(1 for h in p_heur if h["score"] >= 70)
    by_heur40 = sum(1 for h in p_heur if h["score"] >= 40)
    blocked = sum(1 for s, h in zip(p_list, p_heur) if s or h["score"] >= 70)
    warned_or_blocked = sum(1 for s, h in zip(p_list, p_heur) if s or h["score"] >= 40)
    sources: dict[str, int] = {}
    for s in p_list:
        if s:
            sources[s] = sources.get(s, 0) + 1
    fp_list = [(u, s) for u, s in l_list if s]
    fp_h70 = [h for h in top_heur + next_heur if h["score"] >= 70]
    fp_h40 = [h for h in top_heur + next_heur if h["score"] >= 40]
    missed = [u for u, s, h in zip(phish, p_list, p_heur) if not s and h["score"] < 40]

    pct = lambda a, b: round(100 * a / b, 1) if b else 0.0
    result = {
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "holdout_feeds": feed_status,
        "phishing_sample": {"source": "openphish (live, excluded from blocklist)", "urls": n,
                            "blocklist_hits": by_list, "blocklist_pct": pct(by_list, n),
                            "heuristic_ge70": by_heur70, "heuristic_ge70_pct": pct(by_heur70, n),
                            "heuristic_ge40": by_heur40, "heuristic_ge40_pct": pct(by_heur40, n),
                            "blocked_total": blocked, "blocked_total_pct": pct(blocked, n),
                            "blocked_or_warned": warned_or_blocked, "blocked_or_warned_pct": pct(warned_or_blocked, n),
                            "hits_by_source": sources, "missed_examples": missed[:25]},
        "legit_sample": {"blocklist_checked": len(l_list), "blocklist_false_positives": len(fp_list),
                         "blocklist_fp_pct": pct(len(fp_list), len(l_list)), "blocklist_fp_examples": fp_list[:25],
                         "heuristic_checked": len(top_heur) + len(next_heur),
                         "heuristic_ge70": len(fp_h70), "heuristic_ge70_pct": pct(len(fp_h70), len(top_heur) + len(next_heur)),
                         "heuristic_ge40": len(fp_h40), "heuristic_ge40_pct": pct(len(fp_h40), len(top_heur) + len(next_heur)),
                         "heuristic_fp_examples": fp_h70[:25]},
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "web-eval.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in result["phishing_sample"].items() if k != "missed_examples"}, indent=2))
    print(json.dumps({k: v for k, v in result["legit_sample"].items() if not k.endswith("examples")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
