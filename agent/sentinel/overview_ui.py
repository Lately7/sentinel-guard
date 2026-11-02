"""Home page: one big state, one scan button, three tiles, a few numbers. Words kept to a minimum."""

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
        return State("off", "Bảo vệ đang tắt", "Bật bảo vệ thời gian thực")
    issues = []
    last_feed = max((f["updated"] or 0 for f in app.db.feed_status()), default=0)
    if now - last_feed > FEEDS_STALE:
        issues.append("Dữ liệu mối đe dọa đã cũ" if last_feed else "Chưa tải dữ liệu mối đe dọa")
    if app.engine_status.snapshot.clamav_status not in ("ready", "off", "checking"):
        issues.append("ClamAV chưa sẵn sàng")
    seen = float(app.db.get_meta("extension_seen", "0") or 0)
    if now - seen > EXTENSION_STALE:
        issues.append("Chưa thấy tiện ích trình duyệt")
    if issues:
        more = f"  +{len(issues) - 1}" if len(issues) > 1 else ""
        return State("attention", "Cần chú ý", issues[0] + more)
    return State("ok", "Đang bảo vệ", f"Cập nhật {theme.ago(last_feed, now)}")


def _n(x: int) -> str:
    return f"{x:,}".replace(",", ".")


class StateMark:
    """The logo drawn large; its frame takes the state colour."""

    def __init__(self, parent: tk.Misc, size: int = 72) -> None:
        self.size = theme.px(parent, size)
        self.canvas = tk.Canvas(parent, width=self.size, height=self.size, bg=theme.SURFACE, highlightthickness=0, bd=0)
        self.color = ""

    def set(self, color: str) -> None:
        if color == self.color:
            return
        self.color = color
        n, c = self.size, self.canvas
        c.delete("all")
        inset, stroke = round(3 * n / 32), max(2, round(n / 16))
        side = (7 * n) // 16
        o = (n - side) // 2
        h = stroke / 2
        c.create_rectangle(inset + h, inset + h, n - inset - h, n - inset - h, outline=color, width=stroke)
        c.create_rectangle(o, o, o + side, o + side, fill=theme.TEXT, outline="")


class Tile:
    def __init__(self, parent: tk.Misc, icon: str, title: str) -> None:
        pad = theme.px(parent, 18)
        self.frame = ttk.Frame(parent, style="Card.TFrame", padding=(pad, pad))
        top = ttk.Frame(self.frame, style="Card.TFrame")
        top.pack(fill="x")
        self.icon = theme.Icon(top, icon, 22, theme.MUTED)
        self.icon.canvas.pack(side="left")
        ttk.Label(top, text=title, style="TileTitle.TLabel").pack(side="left", padx=(10, 0))
        self.right = ttk.Frame(top, style="Card.TFrame")
        self.right.pack(side="right")
        self.value = ttk.Label(self.frame, style="TileValue.TLabel")
        self.value.pack(anchor="w", pady=(theme.px(parent, 14), 0))
        self.meta = ttk.Label(self.frame, style="CardMuted.TLabel")
        self.meta.pack(anchor="w", pady=(2, 0))

    def show(self, value: str, meta: str, color: str) -> None:
        self.value.configure(text=value, foreground=color)
        self.meta.configure(text=meta)


class Overview:
    def __init__(self, pages: ttk.Frame, app: "App") -> None:
        self.app = app
        gap = theme.px(pages, 14)
        self.frame = ttk.Frame(pages, padding=(gap * 2, gap * 2, gap * 2, gap))
        pages.add(self.frame, text="Tổng quan", icon="home")

        hero = ttk.Frame(self.frame, style="Card.TFrame", padding=(gap * 2, gap * 2))
        hero.pack(fill="x")
        self.mark = StateMark(hero)
        self.mark.canvas.pack(side="left")
        words = ttk.Frame(hero, style="Card.TFrame")
        words.pack(side="left", padx=(gap * 2, 0))
        self.title = ttk.Label(words, style="Hero.TLabel")
        self.title.pack(anchor="w")
        self.sub = ttk.Label(words, style="HeroSub.TLabel")
        self.sub.pack(anchor="w", pady=(4, 0))
        self.scan_btn = ttk.Button(hero, text="Quét", style="Big.Primary.TButton", command=self._scan_now)
        self.scan_btn.pack(side="right")

        tiles = ttk.Frame(self.frame)
        tiles.pack(fill="x", pady=(gap, 0))
        self.rt = Tile(tiles, "realtime", "Thời gian thực")
        self.web = Tile(tiles, "web", "Web")
        self.scan = Tile(tiles, "scan", "Lần quét cuối")
        for i, t in enumerate((self.rt, self.web, self.scan)):
            t.frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else gap // 2, 0 if i == 2 else gap // 2))
            tiles.columnconfigure(i, weight=1, uniform="tile")
        self.rt_switch = theme.Switch(self.rt.right, command=self._set_rt)
        self.rt_switch.canvas.pack()
        more = ttk.Menubutton(self.scan.right, text="Khác")
        menu = theme.dark_menu(more)
        menu.add_command(label="Chọn tệp…", command=lambda: self._go_scan("file"))
        menu.add_command(label="Chọn thư mục…", command=lambda: self._go_scan("folder"))
        menu.add_separator()
        menu.add_command(label="Quét sâu…", command=lambda: self._go_scan("deep"))
        more["menu"] = menu
        more.pack()

        stats = ttk.Frame(self.frame)
        stats.pack(fill="x", pady=(gap * 2, 0))
        self.stats: dict[str, ttk.Label] = {}
        for i, (key, label) in enumerate((("quarantine", "Trong cách ly"), ("hosts", "Tên miền bị chặn"),
                                          ("alerts", "Cảnh báo 7 ngày"))):
            cell = ttk.Frame(stats)
            cell.grid(row=0, column=i, sticky="w")
            stats.columnconfigure(i, weight=1, uniform="stat")
            v = ttk.Label(cell, style="PageTitle.TLabel")
            v.pack(anchor="w")
            ttk.Label(cell, text=label, style="Muted.TLabel").pack(anchor="w")
            self.stats[key] = v

    # -- actions -----------------------------------------------------------

    def _set_rt(self, on: bool) -> None:
        running = bool(self.app.realtime and self.app.realtime.running)
        if on != running:
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
        st = protection_state(app, now)
        self.mark.set(st.color)
        self.title.configure(text=st.title)
        self.sub.configure(text=st.detail)

        rt = app.realtime if app.realtime and app.realtime.running else None
        self.rt_switch.set(bool(rt))
        if rt:
            self.rt.show("Bật", f"{len(rt.files.dirs)} thư mục", theme.TEXT)
        else:
            self.rt.show("Tắt", "—", theme.BAD)

        c = app.db.counts()
        seen = float(app.db.get_meta("extension_seen", "0") or 0)
        if now - seen <= EXTENSION_STALE:
            self.web.show("Đã kết nối", theme.ago(seen, now), theme.TEXT)
        else:
            self.web.show("Chưa kết nối", "Helium", theme.WARN)

        job = app.gate.job if app.gate else None
        if job and job.progress.running:
            self.scan.show("Đang quét", f"{_n(job.progress.scanned)} tệp", theme.TEXT)
            self.scan_btn.configure(state="disabled")
        else:
            self.scan_btn.configure(state="normal")
            last = app.db.events(1, source="scan")
            if not last:
                self.scan.show("Chưa quét", "—", theme.MUTED)
            else:
                e = last[0]
                if e["level"] == "info":
                    self.scan.show("Sạch", theme.ago(e["ts"], now), theme.TEXT)
                else:
                    self.scan.show("Cần xem", theme.ago(e["ts"], now), theme.WARN)

        week = [e for e in app.db.events(500) if e["ts"] > now - 7 * 86400 and e["level"] in ("threat", "warning")]
        self.stats["quarantine"].configure(text=_n(c["quarantine"]))
        self.stats["hosts"].configure(text=_n(c["bad_hosts"]))
        self.stats["alerts"].configure(text=_n(len(week)))
