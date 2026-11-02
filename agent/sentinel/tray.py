"""Tray icon + dashboard window. Tk owns the main thread; pystray runs detached."""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from . import config, feeds, quarantine, report, theme, yarafeed
from .db import Database
from .engine import clamav, defender
from .engine.scanner import Scanner
from .engine.signatures import SignatureEngine
from .gate_ui import GatePanel
from .singleton import AppInstance
from .watcher import RealtimeProtection

log = logging.getLogger(__name__)

APP = "Sentinel Guard"
# The logo is a black-to-grey square in a thin outline; only the outline colour
# carries state, so the icon stays the same shape in every situation.
GREEN, AMBER, RED = (150, 150, 156), (220, 150, 20), (220, 60, 50)


def _icon_image(ring: tuple[int, int, int]):
    return theme.logo_image(64, ring)


def _fmt_ts(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%d/%m %H:%M:%S") if ts else "—"


class App:
    def __init__(self) -> None:
        self.settings = config.Settings.load()
        self.db = Database()
        moved = self.db.check_and_repair()
        if moved:
            self.db.add_event("system", "warning", "Cơ sở dữ liệu bị hỏng và đã được tạo lại",
                              f"Bản hỏng được giữ tại {moved}. Danh sách mối đe dọa sẽ được tải lại.")
        self.db.prune_cache()
        self.scanner = Scanner(self.db, use_defender=self.settings.use_defender, use_clamav=self.settings.use_clamav)
        self.gate: GatePanel | None = None
        self.realtime: RealtimeProtection | None = None
        self.ui_queue: queue.Queue = queue.Queue()
        theme.enable_dpi_awareness()
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP)
        theme.apply(self.root)
        self.window: tk.Toplevel | None = None
        self.logo: theme.LogoMark | None = None
        self.icon = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def run(self) -> None:
        import pystray

        if self.settings.realtime:
            self.start_realtime()
        threading.Thread(target=self._clamav_bootstrap, daemon=True, name="clamav").start()
        menu = pystray.Menu(
            pystray.MenuItem("Mở bảng điều khiển", lambda: self.ui(self.show), default=True),
            pystray.MenuItem("Quét nhanh", lambda: self.quick_scan()),
            pystray.MenuItem("Quét thư mục…", lambda: self.ui(self.pick_and_scan)),
            pystray.MenuItem("Cập nhật dữ liệu mối đe dọa", lambda: self.update_feeds_async()),
            pystray.MenuItem("Bảo vệ thời gian thực", lambda: self.toggle_realtime(),
                             checked=lambda _: bool(self.realtime and self.realtime.running)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Thoát", lambda: self.ui(self.quit)),
        )
        self.icon = pystray.Icon("sentinel-guard", _icon_image(GREEN if self.settings.realtime else AMBER), APP, menu)
        self.icon.run_detached()
        threading.Thread(target=self._notifier, daemon=True, name="notifier").start()
        threading.Thread(target=self._feed_scheduler, daemon=True, name="feeds").start()
        self.root.after(200, self._pump)
        self.root.mainloop()

    def quit(self) -> None:
        self._stop.set()
        if self.realtime:
            self.realtime.stop()
        if self.gate and self.gate.job:
            self.gate.job.cancel()
        if self.scanner.clamav is not None:
            self.scanner.clamav.stop()  # only a clamd this process started
        if self.icon:
            self.icon.stop()
        self.root.destroy()

    def ui(self, fn, *args) -> None:
        """pystray callbacks run on its thread; Tk calls must happen on the main thread."""
        self.ui_queue.put((fn, args))

    def _pump(self) -> None:
        try:
            while True:
                fn, args = self.ui_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        if self.window is not None and self.window.winfo_exists() and int(time.time()) % 3 == 0:
            self.refresh()
        self.root.after(500, self._pump)

    # -- background work ---------------------------------------------------

    def start_realtime(self) -> None:
        try:
            self.realtime = RealtimeProtection(self.db, self.settings, self.scanner)
            self.realtime.start()
            self.db.add_event("system", "info", "Bảo vệ thời gian thực đã bật", ", ".join(self.realtime.files.dirs))
        except Exception as e:
            log.exception("realtime start failed")
            self.db.add_event("system", "warning", "Không bật được bảo vệ thời gian thực", str(e))
            self.realtime = None

    def toggle_realtime(self) -> None:
        if self.realtime and self.realtime.running:
            self.realtime.stop()
            self.realtime = None
            self.settings.realtime = False
            self.db.add_event("system", "warning", "Bảo vệ thời gian thực đã TẮT", "Máy không được bảo vệ khi tải tệp mới.")
        else:
            self.settings.realtime = True
            self.start_realtime()
        self.settings.save()
        if self.icon:
            self.icon.icon = _icon_image(GREEN if self.realtime else AMBER)
            self.icon.update_menu()

    def _notifier(self) -> None:
        while not self._stop.wait(2.0):
            try:
                for ev in self.db.take_unnotified():
                    if self.icon:
                        self.icon.notify(ev["detail"][:250], ev["title"])
                    if ev["level"] == "threat" and self.icon:
                        self.icon.icon = _icon_image(RED)
            except Exception:
                log.exception("notifier failed")

    def _feed_scheduler(self) -> None:
        # Let start-up (watcher, icon) settle before a long download.
        if self._stop.wait(30):
            return
        while not self._stop.is_set():
            try:
                if feeds.is_due(self.db, self.settings.feed_interval_hours):
                    self.update_feeds()
            except Exception:
                log.exception("scheduled feed update failed")
            self._stop.wait(600)

    def _clamav_bootstrap(self) -> None:
        eng = self.scanner.clamav
        if eng is None:
            return
        if not clamav.has_database():
            res = clamav.update()
            self.db.add_event("feeds", "info" if res == "ok" else "warning", "Tải chữ ký ClamAV lần đầu", res)
            self.db.set_meta("clamav_updated", str(time.time()))
        if not eng.start(wait=120):
            self.db.add_event("system", "warning", "Lớp ClamAV chưa sẵn sàng", eng.status())

    def update_feeds(self) -> dict[str, str]:
        res = feeds.update_all(self.db)
        if self.scanner.clamav is not None:
            # ClamAV asks clients not to check more often than hourly.
            last = float(self.db.get_meta("clamav_updated", "0") or 0)
            if time.time() - last > 4 * 3600:
                res["clamav"] = clamav.update()
                self.db.set_meta("clamav_updated", str(time.time()))
        last = float(self.db.get_meta("yara_updated", "0") or 0)
        if time.time() - last > 24 * 3600:
            res["yara-forge"] = yarafeed.update()
            self.db.set_meta("yara_updated", str(time.time()))
            if res["yara-forge"].startswith("ok"):
                # New rules only take effect in a freshly built scanner.
                self.scanner.sigs = SignatureEngine(self.db)
        if "skipped" in res:
            return res
        ok = sum(1 for v in res.values() if v.startswith("ok"))
        level = "info" if ok == len(res) else "warning"
        self.db.add_event("feeds", level, "Đã cập nhật dữ liệu mối đe dọa", f"{ok}/{len(res)} nguồn thành công", res)
        return res

    def update_feeds_async(self) -> None:
        threading.Thread(target=self.update_feeds, daemon=True).start()

    def quick_scan_paths(self) -> list[str]:
        # The places a download or a persistence drop lands: the watched folders.
        return [d for d in self.settings.watch_dirs if Path(d).is_dir()]

    def quick_scan(self) -> None:
        self.ui(lambda: (self.show(), self.gate and self.gate.scan_quick()))

    def pick_and_scan(self) -> None:
        self.show()
        if self.gate:
            self.gate.scan_folder()

    # -- dashboard ---------------------------------------------------------

    def show(self) -> None:
        if self.window is not None and self.window.winfo_exists():
            self.window.deiconify()
            self.window.lift()
            return
        w = tk.Toplevel(self.root, bg=theme.BG)
        w.title(APP)
        w.geometry(f"{theme.px(w, 1100)}x{theme.px(w, 660)}")
        w.minsize(theme.px(w, 860), theme.px(w, 480))
        from PIL import ImageTk

        self._window_icon = ImageTk.PhotoImage(theme.logo_image(32))
        w.iconphoto(False, self._window_icon)
        theme.dark_title_bar(w)
        self.window = w
        head = ttk.Frame(w, padding=(12, 10, 12, 2))
        head.pack(fill="x")
        self.logo = theme.LogoMark(head, size=20)
        self.logo.pack(side="left")
        ttk.Label(head, text=APP, style="Title.TLabel").pack(side="left", padx=(8, 0))
        self.head_var = tk.StringVar()
        ttk.Label(head, textvariable=self.head_var, style="Muted.TLabel").pack(side="right")
        nb = ttk.Notebook(w)
        nb.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.gate = GatePanel(nb, self)

        ov = ttk.Frame(nb, padding=12)
        nb.add(ov, text="Tổng quan")
        self.status_var = tk.StringVar()
        ttk.Label(ov, textvariable=self.status_var, justify="left").pack(anchor="w")
        bar = ttk.Frame(ov)
        bar.pack(anchor="w", pady=12)
        for text, cmd in (("Quét nhanh", self.quick_scan), ("Quét thư mục…", self.pick_and_scan),
                          ("Cập nhật dữ liệu", self.update_feeds_async),
                          ("Bật/tắt bảo vệ thời gian thực", self.toggle_realtime),
                          ("Xuất báo cáo", self.export_report)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=4)

        self.events_tv = self._table(nb, "Sự kiện", ("Thời gian", "Nguồn", "Mức", "Nội dung"), (130, 90, 70, 640))
        qf = ttk.Frame(nb)
        nb.add(qf, text="Cách ly")
        self.q_tv = self._table(qf, None, ("ID", "Thời gian", "Vị trí gốc", "Lý do"), (0, 130, 380, 400))
        qb = ttk.Frame(qf)
        qb.pack(anchor="w", pady=6)
        ttk.Button(qb, text="Khôi phục (tin cậy tệp này)", command=self.restore_selected).pack(side="left", padx=4)
        ttk.Button(qb, text="Xóa vĩnh viễn", command=self.delete_selected).pack(side="left", padx=4)
        self.web_tv = self._table(nb, "Web", ("Thời gian", "Mức", "Nội dung"), (130, 70, 720))
        af = ttk.Frame(nb)
        nb.add(af, text="Trang được tin cậy")
        self.allow_tv = self._table(af, None, ("Tên miền",), (600,))
        ttk.Button(af, text="Bỏ tin cậy", command=self.unallow_selected).pack(anchor="w", pady=6)
        self.refresh()

    def _table(self, parent, tab: str | None, cols, widths) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        # A notebook page is placed by the notebook; packing it as well pulls it
        # out of the notebook and stacks it over the tab bar.
        if tab:
            parent.add(frame, text=tab)
        else:
            frame.pack(fill="both", expand=True)
        tv = ttk.Treeview(frame, columns=cols, show="headings")
        for c, wdt in zip(cols, widths):
            tv.heading(c, text=c)
            tv.column(c, width=theme.px(tv, wdt), stretch=wdt > 300, minwidth=0)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tv

    def scanning(self, on: bool) -> None:
        if self.logo is not None:
            (self.logo.start if on else self.logo.stop)()

    def refresh(self) -> None:
        if self.gate is not None:
            self.gate.refresh_layers()
        c = self.db.counts()
        fs = self.db.feed_status()
        last = max((f["updated"] or 0 for f in fs), default=0)
        rt = self.realtime and self.realtime.running
        self.status_var.set(
            f"Bảo vệ thời gian thực: {'BẬT' if rt else 'TẮT'}\n"
            f"Thư mục theo dõi: {', '.join(self.realtime.files.dirs) if rt else '—'}\n"
            f"Microsoft Defender (ý kiến thứ hai): {'có' if defender.available() and self.settings.use_defender else 'không'}\n"
            f"ClamAV: {self.scanner.clamav.status() if self.scanner.clamav else 'không dùng'}\n"
            f"Chữ ký hash: {c['bad_hashes']:,} · Tên miền độc hại: {c['bad_hosts']:,} · URL độc hại: {c['bad_urls']:,}\n"
            f"Cập nhật dữ liệu lần cuối: {_fmt_ts(last) if last else 'chưa'}\n"
            f"Tệp đang cách ly: {c['quarantine']}"
        )
        self.head_var.set(f"Bảo vệ thời gian thực {'bật' if rt else 'tắt'} · {c['quarantine']} tệp đang cách ly")
        _fill(self.events_tv, [(e["id"], (_fmt_ts(e["ts"]), e["source"], e["level"], f"{e['title']} — {e['detail']}"))
                               for e in self.db.events(300)])
        items = []
        for q in self.db.quarantine_items():
            try:
                why = json.loads(q["verdict"])["findings"][0]["detail"]
            except (ValueError, KeyError, IndexError):
                why = ""
            items.append((q["id"], (q["id"], _fmt_ts(q["ts"]), q["original_path"], why)))
        _fill(self.q_tv, items)
        web = [e for e in self.db.events(300) if e["source"] in ("web", "download")]
        _fill(self.web_tv, [(e["id"], (_fmt_ts(e["ts"]), e["level"], f"{e['title']} — {e['detail']}")) for e in web])
        _fill(self.allow_tv, [(h, (h,)) for h in self.db.allowed_hosts()])

    def restore_selected(self) -> None:
        sel = self.q_tv.selection()
        if not sel:
            return
        if not messagebox.askyesno(APP, "Khôi phục tệp này? Tệp sẽ được đánh dấu tin cậy và không bị quét chặn lại."):
            return
        for qid in sel:
            try:
                p = quarantine.restore(self.db, qid)
                self.db.add_event("system", "warning", "Đã khôi phục tệp từ cách ly", str(p))
            except quarantine.QuarantineError as e:
                messagebox.showerror(APP, str(e))
        self.refresh()

    def delete_selected(self) -> None:
        sel = self.q_tv.selection()
        if sel and messagebox.askyesno(APP, f"Xóa vĩnh viễn {len(sel)} tệp? Không thể hoàn tác."):
            for qid in sel:
                quarantine.delete(self.db, qid)
            self.refresh()

    def unallow_selected(self) -> None:
        for host in self.allow_tv.selection():
            self.db.remove_allowed_host(host)
        self.db.bump_generation()
        self.refresh()

    def export_report(self) -> None:
        paths = report.write_report(self.db, self.settings)
        os.startfile(paths["html"])  # type: ignore[attr-defined]


def _fill(tv: ttk.Treeview, rows) -> None:
    keep = tv.selection()
    tv.delete(*tv.get_children())
    for iid, values in rows:
        tv.insert("", "end", iid=str(iid), values=values)
    present = [i for i in keep if tv.exists(i)]
    if present:
        tv.selection_set(present)


def main() -> None:
    instance = AppInstance()
    if not instance.claim():
        # Already running (e.g. autostart + desktop shortcut): bring it forward.
        instance.signal_existing()
        return
    app = App()
    instance.on_show_request(lambda: app.ui(app.show))
    app.run()
