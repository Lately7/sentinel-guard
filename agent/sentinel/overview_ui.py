"""Home tab: one line of overall state, the three protections as cards, recent activity."""

from __future__ import annotations

import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import TYPE_CHECKING

from . import theme

if TYPE_CHECKING:
    from .tray import App

FEEDS_STALE = 3 * 86400
EXTENSION_STALE = 7 * 86400
LEVEL_COLOR = {"threat": theme.BAD, "warning": theme.WARN, "info": theme.OFF}


@dataclass
class State:
    level: str  # "ok" | "attention" | "off"
    title: str
    detail: str

    @property
    def color(self) -> str:
        return {"ok": theme.OK, "attention": theme.WARN, "off": theme.BAD}[self.level]


def protection_state(app: "App", now: float | None = None) -> State:
    """The single answer to "am I protected?", with the most important reason first."""
    now = time.time() if now is None else now
    rt = app.realtime and app.realtime.running
    if not rt:
        return State("off", "Bảo vệ đang tắt", "Tệp mới tải về sẽ không được kiểm tra")
    issues = []
    last_feed = max((f["updated"] or 0 for f in app.db.feed_status()), default=0)
    if now - last_feed > FEEDS_STALE:
        issues.append("dữ liệu mối đe dọa đã cũ" if last_feed else "chưa tải dữ liệu mối đe dọa")
    if app.engine_status.snapshot.clamav_status not in ("ready", "off", "checking"):
        issues.append("ClamAV chưa sẵn sàng")
    seen = float(app.db.get_meta("extension_seen", "0") or 0)
    if now - seen > EXTENSION_STALE:
        issues.append("chưa thấy tiện ích trình duyệt")
    if issues:
        more = f" (+{len(issues) - 1})" if len(issues) > 1 else ""
        return State("attention", "Cần chú ý", issues[0][0].upper() + issues[0][1:] + more)
    q = app.db.counts()["quarantine"]
    return State("ok", "Đang bảo vệ", f"Dữ liệu cập nhật {theme.ago(last_feed, now)} · {q} tệp đang cách ly")


class Card:
    def __init__(self, parent: tk.Misc, title: str) -> None:
        pad = theme.px(parent, 16)
        self.frame = ttk.Frame(parent, style="Card.TFrame", padding=(pad, pad - 2, pad, pad))
        ttk.Label(self.frame, text=title, style="CardTitle.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        self.dot = theme.Dot(self.frame)
        self.dot.grid(row=1, column=0, sticky="w", padx=(0, 6), pady=(6, 0))
        self.value = ttk.Label(self.frame, style="CardValue.TLabel")
        self.value.grid(row=1, column=1, sticky="w", pady=(6, 0))
        self.note = ttk.Label(self.frame, style="CardMuted.TLabel", wraplength=theme.px(parent, 280))
        self.note.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 12))
        self.actions = ttk.Frame(self.frame, style="Card.TFrame")
        self.actions.grid(row=3, column=0, columnspan=2, sticky="w")
        self.frame.columnconfigure(1, weight=1)

    def show(self, color: str, value: str, note: str, busy: bool = False) -> None:
        self.dot.set(color, busy)
        self.value.configure(text=value)
        self.note.configure(text=note)


class Overview:
    def __init__(self, nb: ttk.Notebook, app: "App") -> None:
        self.app = app
        gap = theme.px(nb, 12)
        self.frame = ttk.Frame(nb, padding=(gap, gap, gap, gap))
        nb.add(self.frame, text="Tổng quan")

        cards = ttk.Frame(self.frame)
        cards.pack(fill="x")
        self.rt = Card(cards, "Bảo vệ thời gian thực")
        self.web = Card(cards, "Bảo vệ web")
        self.scan = Card(cards, "Quét")
        for i, c in enumerate((self.rt, self.web, self.scan)):
            c.frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else gap // 2, 0 if i == 2 else gap // 2))
            cards.columnconfigure(i, weight=1, uniform="card")

        self.rt_btn = ttk.Button(self.rt.actions, command=self._toggle_rt)
        self.rt_btn.pack(side="left")
        ttk.Button(self.web.actions, text="Cập nhật dữ liệu", command=app.update_feeds_async).pack(side="left")
        ttk.Button(self.scan.actions, text="Quét ngay", style="Primary.TButton", command=self._scan_now).pack(side="left")
        more = ttk.Menubutton(self.scan.actions, text="Khác")
        menu = theme.dark_menu(more)
        menu.add_command(label="Chọn tệp…", command=lambda: self._go_scan("file"))
        menu.add_command(label="Chọn thư mục…", command=lambda: self._go_scan("folder"))
        menu.add_separator()
        menu.add_command(label="Quét sâu (toàn bộ ổ đĩa)…", command=lambda: self._go_scan("deep"))
        more["menu"] = menu
        more.pack(side="left", padx=(8, 0))

        ttk.Label(self.frame, text="Hoạt động gần đây", style="Section.TLabel").pack(anchor="w", pady=(gap * 2, 6))
        self.recent = ttk.Frame(self.frame, style="Card.TFrame", padding=(gap, gap // 2))
        self.recent.pack(fill="both", expand=True)

    # -- actions -----------------------------------------------------------

    def _toggle_rt(self) -> None:
        self.app.toggle_realtime()
        self.app.refresh()

    def _scan_now(self) -> None:
        self._go_scan("quick")

    def _go_scan(self, kind: str) -> None:
        gate = self.app.gate
        if gate is None:
            return
        gate.select()
        {"quick": gate.scan_quick, "file": gate.scan_file, "folder": gate.scan_folder, "deep": gate.scan_full}[kind]()

    # -- refresh -----------------------------------------------------------

    def refresh(self) -> None:
        app, now = self.app, time.time()
        rt = app.realtime if app.realtime and app.realtime.running else None
        if rt:
            n = len(rt.files.dirs)
            self.rt.show(theme.OK, f"Đang bật · {n} thư mục", "Kiểm tra tệp ngay sau khi được ghi xuống đĩa")
            self.rt_btn.configure(text="Tắt")
        else:
            self.rt.show(theme.BAD, "Đang tắt", "Tệp mới tải về sẽ không được kiểm tra tự động")
            self.rt_btn.configure(text="Bật")

        c = app.db.counts()
        last_feed = max((f["updated"] or 0 for f in app.db.feed_status()), default=0)
        seen = float(app.db.get_meta("extension_seen", "0") or 0)
        hosts = f"{c['bad_hosts']:,}".replace(",", ".")
        if now - seen <= EXTENSION_STALE:
            self.web.show(theme.OK, "Tiện ích đã kết nối", f"Liên lạc {theme.ago(seen, now)} · {hosts} tên miền độc hại")
        else:
            self.web.show(theme.WARN, "Chưa thấy tiện ích",
                          f"Cài tiện ích Sentinel Guard trong Helium · dữ liệu cập nhật {theme.ago(last_feed, now)}")

        job = app.gate.job if app.gate else None
        if job and job.progress.running:
            p = job.progress
            self.scan.show(theme.TEXT, "Đang quét…", f"{p.scanned:,} tệp đã kiểm tra".replace(",", "."), busy=True)
        else:
            last = app.db.events(1, source="scan")
            if last:
                e = last[0]
                color = theme.BAD if e["level"] == "threat" else theme.WARN if e["level"] == "warning" else theme.OK
                self.scan.show(color, f"Lần cuối {theme.ago(e['ts'], now)}", e["detail"].split(": ", 1)[-1])
            else:
                self.scan.show(theme.OFF, "Chưa quét lần nào", "Quét ngay kiểm tra các thư mục hay nhận tệp mới")
        self._fill_recent(now)

    def _fill_recent(self, now: float) -> None:
        for w in self.recent.winfo_children():
            w.destroy()
        events = self.app.db.events(8)
        if not events:
            ttk.Label(self.recent, text="Chưa có hoạt động nào.", style="CardMuted.TLabel").pack(anchor="w", pady=6)
            return
        for e in events:
            row = ttk.Frame(self.recent, style="Card.TFrame")
            row.pack(fill="x", pady=3)
            dot = theme.Dot(row, size=7)
            dot.canvas.itemconfigure(dot.item, fill=LEVEL_COLOR.get(e["level"], theme.OFF))
            dot.pack(side="left", padx=(0, 8))
            ttk.Label(row, text=e["title"], style="Card.TLabel").pack(side="left")
            detail = (e["detail"] or "").replace("\n", " ")
            if detail:
                ttk.Label(row, text=detail[:90] + ("…" if len(detail) > 90 else ""),
                          style="CardMuted.TLabel").pack(side="left", padx=(10, 0))
            ttk.Label(row, text=theme.ago(e["ts"], now), style="CardMuted.TLabel").pack(side="right")
