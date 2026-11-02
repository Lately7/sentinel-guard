"""Protection status report (HTML + JSON), for the user or to attach to a support request."""

from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path
from typing import Any

from . import __version__, config
from .db import Database
from .engine import defender


def collect(db: Database, settings: config.Settings) -> dict[str, Any]:
    events = db.events(500)
    quarantine = db.quarantine_items()
    by_level: dict[str, int] = {}
    for e in events:
        by_level[e["level"]] = by_level.get(e["level"], 0) + 1
    return {
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "version": __version__,
        "settings": {
            "realtime": settings.realtime,
            "watch_dirs": settings.watch_dirs,
            "auto_quarantine": settings.auto_quarantine,
            "defender_second_opinion": settings.use_defender and defender.available(),
        },
        "indicators": db.counts(),
        "feeds": db.feed_status(),
        "events_by_level": by_level,
        "threats": [e for e in events if e["level"] == "threat"][:100],
        "warnings": [e for e in events if e["level"] == "warning"][:100],
        "quarantine": [{k: q[k] for k in ("id", "original_path", "sha256", "size", "ts")} for q in quarantine],
        "allowed_hosts": db.allowed_hosts(),
    }


def _ts(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M") if ts else "—"


def render_html(data: dict[str, Any]) -> str:
    e = html.escape
    ind = data["indicators"]
    s = data["settings"]

    def rows(items, cols):
        if not items:
            return f'<tr><td colspan="{len(cols)}" class="muted">Không có</td></tr>'
        return "".join("<tr>" + "".join(f"<td>{e(str(fn(i)))}</td>" for _, fn in cols) + "</tr>" for i in items)

    def table(items, cols):
        head = "".join(f"<th>{e(h)}</th>" for h, _ in cols)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{rows(items, cols)}</tbody></table>"

    feed_cols = [("Nguồn", lambda f: f["name"]), ("Cập nhật", lambda f: _ts(f["updated"])),
                 ("Số mục", lambda f: f["count"] if f["count"] is not None else "—"), ("Trạng thái", lambda f: f["status"])]
    ev_cols = [("Thời gian", lambda x: _ts(x["ts"])), ("Nguồn", lambda x: x["source"]),
               ("Sự kiện", lambda x: x["title"]), ("Chi tiết", lambda x: x["detail"])]
    q_cols = [("Thời gian", lambda q: _ts(q["ts"])), ("Vị trí gốc", lambda q: q["original_path"]),
              ("SHA-256", lambda q: q["sha256"][:16] + "…")]
    status = "BẬT" if s["realtime"] else "TẮT"
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Báo cáo Sentinel Guard</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#1d2330; --card:#fff; --muted:#6b7280; --line:#e3e6ea; --ok:#1f9d55; --bad:#c62828; --warn:#b7791f; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14171c; --fg:#e7e9ee; --card:#1c2028; --muted:#9aa3b2; --line:#2c323d; }} }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 "Segoe UI", system-ui, sans-serif; }}
main {{ max-width:1000px; margin:0 auto; padding:24px 16px 48px; }}
h1 {{ font-size:24px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:28px 0 8px; }}
.muted {{ color:var(--muted); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-top:16px; }}
.tile {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 14px; }}
.tile b {{ display:block; font-size:22px; font-variant-numeric:tabular-nums; }}
.ok {{ color:var(--ok); }} .bad {{ color:var(--bad); }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:10px; overflow:hidden; display:block; overflow-x:auto; }}
th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; font-size:14px; }}
th {{ font-weight:600; }} td {{ word-break:break-word; }}
</style></head><body><main>
<h1>Báo cáo Sentinel Guard</h1>
<div class="muted">Tạo lúc {e(data['generated'])} · phiên bản {e(data['version'])}</div>
<div class="grid">
<div class="tile">Bảo vệ thời gian thực<b class="{'ok' if s['realtime'] else 'bad'}">{status}</b></div>
<div class="tile">Mối đe dọa ghi nhận<b class="{'bad' if data['threats'] else 'ok'}">{len(data['threats'])}</b></div>
<div class="tile">Đang cách ly<b>{ind['quarantine']}</b></div>
<div class="tile">Chữ ký hash<b>{ind['bad_hashes']:,}</b></div>
<div class="tile">Tên miền độc hại<b>{ind['bad_hosts']:,}</b></div>
<div class="tile">URL độc hại<b>{ind['bad_urls']:,}</b></div>
</div>
<p class="muted">Defender làm ý kiến thứ hai: {'có' if s['defender_second_opinion'] else 'không'} · Tự cách ly: {'có' if s['auto_quarantine'] else 'không'} · Theo dõi: {e(', '.join(s['watch_dirs']))}</p>
<h2>Nguồn dữ liệu mối đe dọa</h2>{table(data['feeds'], feed_cols)}
<h2>Mối đe dọa</h2>{table(data['threats'], ev_cols)}
<h2>Cảnh báo</h2>{table(data['warnings'], ev_cols)}
<h2>Tệp đang cách ly</h2>{table(data['quarantine'], q_cols)}
</main></body></html>"""


def write_report(db: Database, settings: config.Settings, out_dir: Path | None = None) -> dict[str, str]:
    out = out_dir or (config.data_dir() / "reports")
    out.mkdir(parents=True, exist_ok=True)
    data = collect(db, settings)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    jp = out / f"sentinel-report-{stamp}.json"
    hp = out / f"sentinel-report-{stamp}.html"
    jp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    hp.write_text(render_html(data), encoding="utf-8")
    return {"json": str(jp), "html": str(hp)}
