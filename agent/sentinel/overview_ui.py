"""Home page: one state, one scan button, three tiles, three numbers, three recent events."""

from __future__ import annotations

import threading
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
LEVEL_COLOR = {"threat": theme.BAD, "warning": theme.WARN, "info": theme.FAINT}


@dataclass
class State:
    level: str  # "ok" | "attention" | "off"
    title: str
    detail: str

    @property
    def color(self) -> str:
        return {"ok": theme.OK, "attention": theme.WARN, "off": theme.BAD}[self.level]


def protection_state(app: "App", now: float | None = None,
                     service_status: dict[str, object] | None = None) -> State:
    """The single answer to "am I protected?", with the most important reason first."""
    now = time.time() if now is None else now
    rt = app.realtime and app.realtime.running
    if not rt:
        return State("off", "Bảo vệ đang tắt", "Bật bảo vệ thời gian thực")
    if service_status and service_status.get("worker_failure"):
        return State("attention", "Cần chú ý", "Bộ quét không hoạt động; bảo vệ tệp trên máy đang bị gián đoạn")
    issues = []
    last_feed = max((f["updated"] or 0 for f in app.db.feed_status()), default=0)
    if now - last_feed > FEEDS_STALE:
        issues.append("Dữ liệu đe dọa đã cũ" if last_feed else "Chưa có dữ liệu đe dọa")
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
    """The logo mark: a 2 px frame in the state colour around a light 16 px core, 8 px apart."""

    def __init__(self, parent: tk.Misc, size: int = 44) -> None:
        self.size = theme.px(parent, size)
        self.canvas = tk.Canvas(parent, width=self.size, height=self.size, bg=theme.SURFACE, highlightthickness=0, bd=0)
        self.color = ""
        self._job: str | None = None

    def set(self, color: str) -> None:
        if color == self.color:
            return
        start, self.color = self.color or color, color
        if self._job is not None:
            self.canvas.after_cancel(self._job)
        self._fade(start, color, 0 if theme.MOTION else theme.FAST_MS)

    def _fade(self, a: str, b: str, elapsed: int) -> None:
        t = min(1.0, elapsed / theme.FAST_MS)
        self._draw(theme.mix(a, b, theme.ease_out(t)))
        if t < 1.0:
            self._job = self.canvas.after(theme.FRAME_MS, self._fade, a, b, elapsed + theme.FRAME_MS)

    def _draw(self, frame: str) -> None:
        c, n = self.canvas, self.size
        c.delete("all")
        stroke, core = theme.px(c, 2), theme.px(c, 16)
        c.create_rectangle(stroke / 2, stroke / 2, n - stroke / 2, n - stroke / 2, outline=frame, width=stroke)
        o = (n - core) / 2
        c.create_rectangle(o, o, o + core, o + core, fill=theme.INDICATOR, outline="")


class Tile:
    def __init__(self, parent: tk.Misc, icon: str, title: str) -> None:
        pad = theme.px(parent, 16)
        self.frame = ttk.Frame(parent, style="Card.TFrame", padding=(pad, pad), height=theme.px(parent, 128))
        self.frame.grid_propagate(False)
        self.frame.pack_propagate(False)
        top = ttk.Frame(self.frame, style="Card.TFrame")
        top.pack(fill="x")
        self.icon = theme.Icon(top, icon, 20, theme.MUTED)
        self.icon.canvas.pack(side="left")
        ttk.Label(top, text=title, style="TileTitle.TLabel").pack(side="left", padx=(10, 0))
        self.right = ttk.Frame(top, style="Card.TFrame")
        self.right.pack(side="right")
        self.value = ttk.Label(self.frame, style="TileValue.TLabel")
        self.value.pack(anchor="w", pady=(theme.px(parent, 16), 0))
        self.meta = ttk.Label(self.frame, style="CardMuted.TLabel")
        self.meta.pack(anchor="w", pady=(2, 0))

    def show(self, value: str, meta: str = "", color: str = theme.TEXT) -> None:
        self.value.configure(text=value, foreground=color)
        self.meta.configure(text=meta)


class Overview:
    def __init__(self, pages: ttk.Frame, app: "App") -> None:
        self.app = app
        self._service_status: dict[str, object] | None = None
        self._service_checked = float("-inf")
        self._service_pending = False
        self._service_lock = threading.Lock()
        pad, gap = theme.px(pages, 24), theme.px(pages, 16)
        self.frame = ttk.Frame(pages, padding=(pad, pad, pad, pad))
        pages.add(self.frame, text="Tổng quan", icon="home")

        hero = ttk.Frame(self.frame, style="Card.TFrame", padding=(theme.px(pages, 20), 0), height=theme.px(pages, 112))
        hero.pack(fill="x")
        hero.pack_propagate(False)
        self.mark = StateMark(hero)
        self.mark.canvas.pack(side="left")
        words = ttk.Frame(hero, style="Card.TFrame")
        words.pack(side="left", padx=(gap, 0))
        self.title = ttk.Label(words, style="Hero.TLabel")
        self.title.pack(anchor="w")
        self.sub = ttk.Label(words, style="HeroSub.TLabel")
        self.sub.pack(anchor="w")
        self.scan_btn = ttk.Button(hero, text="Quét", style="Primary.TButton", command=self._scan_now, width=12)
        self.scan_btn.pack(side="right", ipady=theme.px(pages, 4))

        tiles = ttk.Frame(self.frame)
        tiles.pack(fill="x", pady=(gap, 0))
        self.rt = Tile(tiles, "realtime", "Thời gian thực")
        self.web = Tile(tiles, "web", "Web")
        self.scan = Tile(tiles, "scan", "Quét gần nhất")
        for i, t in enumerate((self.rt, self.web, self.scan)):
            t.frame.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else gap // 2, 0 if i == 2 else gap // 2))
            tiles.columnconfigure(i, weight=1, uniform="tile")
        self.rt_switch = theme.Switch(self.rt.right, command=self._set_rt)
        self.rt_switch.canvas.pack()

        stats = ttk.Frame(self.frame, height=theme.px(pages, 56))
        stats.pack(fill="x", pady=(gap, 0))
        self.stats: dict[str, ttk.Label] = {}
        for i, (key, label) in enumerate((("quarantine", "Trong cách ly"), ("hosts", "Tên miền trong danh sách chặn"),
                                          ("alerts", "Cảnh báo 7 ngày"))):
            cell = ttk.Frame(stats)
            cell.grid(row=0, column=i, sticky="w")
            stats.columnconfigure(i, weight=1, uniform="stat")
            v = ttk.Label(cell, style="Stat.TLabel")
            v.pack(side="left")
            ttk.Label(cell, text=label, style="Muted.TLabel").pack(side="left", padx=(8, 0), pady=(4, 0))
            self.stats[key] = v

        ttk.Label(self.frame, text="Gần đây", style="Section.TLabel").pack(anchor="w", pady=(gap, theme.px(pages, 12)))
        self.recent = ttk.Frame(self.frame)
        self.recent.pack(fill="x")

    # -- actions -----------------------------------------------------------

    def _set_rt(self, on: bool) -> None:
        running = bool(self.app.realtime and self.app.realtime.running)
        if on != running:
            self.app.toggle_realtime()
        self.app.refresh()

    def _scan_now(self) -> None:
        gate = self.app.gate
        if gate is not None:
            gate.select()
            gate.scan_quick()

    # -- refresh -----------------------------------------------------------

    def _poll_service(self) -> None:
        if self.app.lease is None:
            return
        with self._service_lock:
            if self._service_pending or time.monotonic() - self._service_checked < 5.0:
                return
            self._service_pending = True

        def read() -> None:
            try:
                status = self.app.lease.status()
            except Exception:
                status = None
            with self._service_lock:
                self._service_status = status
                self._service_checked = time.monotonic()
                self._service_pending = False
            self.app.ui(self.refresh)

        threading.Thread(target=read, daemon=True, name="service-overview-status").start()

    def refresh(self) -> None:
        app, now = self.app, time.time()
        self._poll_service()
        with self._service_lock:
            service_status = self._service_status
        st = protection_state(app, now, service_status)
        self.mark.set(st.color)
        self.title.configure(text=st.title)
        self.sub.configure(text=st.detail)

        rt = app.realtime if app.realtime and app.realtime.running else None
        self.rt_switch.set(bool(rt))
        if rt:
            self.rt.show(f"Bật · {len(rt.files.dirs)} thư mục")
        else:
            self.rt.show("Tắt", color=theme.BAD)

        c = app.db.counts()
        seen = float(app.db.get_meta("extension_seen", "0") or 0)
        if now - seen <= EXTENSION_STALE:
            self.web.show(f"Đã thấy {theme.ago(seen, now)}", "tiện ích Helium")
        else:
            self.web.show("Chưa thấy tiện ích", "Helium", theme.WARN)

        job = app.gate.job if app.gate else None
        if job and job.progress.running:
            self.scan.show("Đang quét", f"{_n(job.progress.scanned)} tệp")
            self.scan_btn.configure(state="disabled")
        else:
            self.scan_btn.configure(state="normal")
            last = app.db.events(1, source="scan")
            if not last:
                self.scan.show("Chưa quét", "", theme.MUTED)
            elif last[0]["level"] == "info":
                self.scan.show("Sạch", theme.ago(last[0]["ts"], now))
            else:
                self.scan.show("Cần xem", theme.ago(last[0]["ts"], now), theme.WARN)

        week = [e for e in app.db.events(500) if e["ts"] > now - 7 * 86400 and e["level"] in ("threat", "warning")]
        self.stats["quarantine"].configure(text=_n(c["quarantine"]))
        self.stats["hosts"].configure(text=_n(c["bad_hosts"]))
        self.stats["alerts"].configure(text=_n(len(week)))
        self._fill_recent(now)

    def _fill_recent(self, now: float) -> None:
        for w in self.recent.winfo_children():
            w.destroy()
        events = self.app.db.events(3)
        if not events:
            ttk.Label(self.recent, text="Chưa có hoạt động", style="Muted.TLabel").pack(anchor="w")
            return
        for e in events:
            row = ttk.Frame(self.recent, height=theme.px(self.recent, 40))
            row.pack(fill="x")
            row.pack_propagate(False)
            mark = tk.Canvas(row, width=theme.px(row, 8), height=theme.px(row, 8), bg=theme.BG, highlightthickness=0, bd=0)
            mark.create_rectangle(0, 0, theme.px(row, 8), theme.px(row, 8), fill=LEVEL_COLOR.get(e["level"], theme.FAINT), outline="")
            mark.pack(side="left", padx=(0, 12))
            ttk.Label(row, text=e["title"]).pack(side="left")
            ttk.Label(row, text=theme.ago(e["ts"], now), style="Muted.TLabel").pack(side="right")
