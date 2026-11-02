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
from .engine import clamav
from .engine.scanner import Scanner
from .engine.signatures import SignatureEngine
from .gate_ui import GatePanel
from .engine_status import EngineStatus
from .overview_ui import Overview
from .service.bridge import install as install_lease
from .singleton import AppInstance
from .watcher import RealtimeProtection

log = logging.getLogger(__name__)

APP = "Sentinel Guard"
# The logo is a black-to-grey square in a thin outline; only the outline colour
# carries state, so the icon stays the same shape in every situation.
GREEN, AMBER, RED = (116, 116, 122), (212, 163, 42), (224, 82, 74)
_TRAY_FILES = {GREEN: "tray-normal.png", AMBER: "tray-warning.png", RED: "tray-threat.png"}


def _icon_image(ring: tuple[int, int, int]):
    # Hand-tuned rasters from assets/brand; the procedural logo is only a fallback.
    from PIL import Image

    path = Path(__file__).with_name("icons") / _TRAY_FILES.get(ring, "tray-normal.png")
    try:
        return Image.open(path).convert("RGBA")
    except OSError:
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
        quarantine.reconcile(self.db)
        self.lease = install_lease()
        self._service_items: set[str] = set()
        self.scanner = Scanner(self.db, use_defender=self.settings.use_defender, use_clamav=self.settings.use_clamav)
        self.gate: GatePanel | None = None
        self.engine_status = EngineStatus(self.scanner, on_change=lambda: self.ui(self.refresh))
        self.realtime: RealtimeProtection | None = None
        self.ui_queue: queue.Queue = queue.Queue()
        theme.enable_dpi_awareness()
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP)
        theme.apply(self.root)
        self.window: tk.Toplevel | None = None
        self.logo: theme.LogoMark | None = None
        self.overview: Overview | None = None
        self._events: dict[str, dict] = {}
        self.icon = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def run(self) -> None:
        import pystray

        if self.settings.realtime:
            self.start_realtime()
        threading.Thread(target=self._clamav_bootstrap, daemon=True, name="clamav").start()
        self.engine_status.start()
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
        self.engine_status.stop()
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
            # Turning protection off is the service's to allow, if there is one.
            if self.lease.available() and not self.lease.approve("disable_protection", {}):
                return
            # Called on the Tk thread: wait briefly. A quarantine that already
            # started finishes on its own; none can start after this.
            closed = self.realtime.stop(timeout=2.0)
            self.realtime = None
            self.settings.realtime = False
            detail = "Máy không được bảo vệ khi tải tệp mới."
            if not closed:
                detail += " Một thao tác cách ly bắt đầu trước khi tắt vẫn đang chạy cho xong."
            self.db.add_event("system", "warning", "Bảo vệ thời gian thực đã TẮT", detail)
        else:
            self.lease.enable_protection()
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
            feeds.record_engine_update(self.db, "clamav", res)
        if not eng.start(wait=120):
            self.db.add_event("system", "warning", "Lớp ClamAV chưa sẵn sàng", eng.status())

    def update_feeds(self) -> dict[str, str]:
        res = feeds.update_all(self.db)
        # ClamAV asks clients not to check more often than hourly; a failure is
        # retried after feeds.ENGINE_RETRY_AFTER rather than a whole period.
        if self.scanner.clamav is not None and feeds.engine_update_due(self.db, "clamav", 4 * 3600):
            res["clamav"] = clamav.update()
            feeds.record_engine_update(self.db, "clamav", res["clamav"])
        if feeds.engine_update_due(self.db, "yara", 24 * 3600):
            res["yara-forge"] = yarafeed.update()
            feeds.record_engine_update(self.db, "yara", res["yara-forge"])
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
        w.geometry(f"{theme.px(w, 1080)}x{theme.px(w, 680)}")
        w.minsize(theme.px(w, 880), theme.px(w, 520))
        from PIL import ImageTk

        self._window_icon = ImageTk.PhotoImage(theme.logo_image(32))
        w.iconphoto(False, self._window_icon)
        theme.dark_title_bar(w)
        self.window = w
        gap = theme.px(w, 16)
        side = tk.Frame(w, bg=theme.BG, width=theme.px(w, 72))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        self.logo = theme.LogoMark(side, size=26)
        self.logo.pack(pady=(gap * 1.2, gap * 1.6))
        tk.Frame(w, bg=theme.LINE, width=1).pack(side="left", fill="y")
        nb = theme.Pages(w, side)
        nb.pack(side="left", fill="both", expand=True)
        self.overview = Overview(nb, self)
        self.gate = GatePanel(nb, self)
        hf = ttk.Frame(nb, padding=(gap * 2, gap * 2, gap * 2, gap))
        nb.add(hf, text="Lịch sử", icon="history")
        ttk.Label(hf, text="Lịch sử", style="PageTitle.TLabel").pack(anchor="w", pady=(0, gap))
        self.events_tv = self._table(hf, None, ("Thời gian", "Sự kiện", "Mức"), (112, 640, 96))
        self.events_tv.bind("<<TreeviewSelect>>", lambda _e: self._show_event_detail())
        self.event_detail = ttk.Label(hf, style="Muted.TLabel", wraplength=theme.px(w, 760), justify="left")
        self.event_detail.pack(anchor="w", pady=(10, 0))
        qf = ttk.Frame(nb, padding=(gap * 2, gap * 2, gap * 2, gap))
        nb.add(qf, text="Cách ly", icon="quarantine")
        ttk.Label(qf, text="Cách ly", style="PageTitle.TLabel").pack(anchor="w", pady=(0, gap))
        self.q_tv = self._table(qf, None, ("Tệp", "Thời gian", "Lý do", "Vị trí gốc"), (220, 112, 300, 400))
        qb = ttk.Frame(qf)
        qb.pack(anchor="w", pady=(10, 0))
        ttk.Button(qb, text="Khôi phục", command=self.restore_selected).pack(side="left", padx=(0, 8))
        ttk.Button(qb, text="Xóa vĩnh viễn", command=self.delete_selected).pack(side="left")
        wf = ttk.Frame(nb, padding=(gap * 2, gap * 2, gap * 2, gap))
        nb.add(wf, text="Web", icon="web")
        ttk.Label(wf, text="Web", style="PageTitle.TLabel").pack(anchor="w", pady=(0, gap))
        self.web_tv = self._table(wf, None, ("Thời gian", "Mức", "Nội dung"), (130, 80, 720))
        ttk.Label(wf, text="Trang đã tin cậy", style="Section.TLabel").pack(anchor="w", pady=(gap, 6))
        self.allow_tv = self._table(wf, None, ("Tên miền",), (600,), height=5)
        ab = ttk.Frame(wf)
        ab.pack(anchor="w", pady=(10, 0))
        ttk.Button(ab, text="Bỏ tin cậy", command=self.unallow_selected).pack(side="left", padx=(0, 8))
        ttk.Button(ab, text="Xuất báo cáo", command=self.export_report).pack(side="left")
        nb.select(self.overview.frame)
        self.refresh()

    def _table(self, parent, tab: str | None, cols, widths, height: int | None = None) -> ttk.Treeview:
        frame = ttk.Frame(parent, style="Card.TFrame")
        # A notebook page is placed by the notebook; packing it as well pulls it
        # out of the notebook and stacks it over the tab bar.
        if tab:
            parent.add(frame, text=tab)
        else:
            frame.pack(fill="both", expand=height is None)
        tv = ttk.Treeview(frame, columns=cols, show="tree headings", selectmode="browse",
                          **({"height": height} if height else {}))
        tv.column("#0", width=theme.px(tv, 10), stretch=False, minwidth=0)
        for c, wdt in zip(cols, widths):
            tv.heading(c, text=c, anchor="w")
            tv.column(c, width=theme.px(tv, wdt), stretch=wdt > 300, minwidth=0, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tv

    def scanning(self, on: bool) -> None:
        if self.window is not None and self.window.winfo_exists():
            self.overview.refresh()

    def refresh(self) -> None:
        if self.window is None or not self.window.winfo_exists():
            return
        if self.gate is not None:
            self.gate.refresh_layers()
        self.overview.refresh()
        self._events = {str(e["id"]): e for e in self.db.events(300)}
        _fill(self.events_tv, [(e["id"], (_fmt_ts(e["ts"]), f"{SOURCE_VI.get(e['source'], e['source'])} · {e['title']}",
                                          LEVEL_VI.get(e["level"], e["level"])), e["level"])
                               for e in self._events.values()])
        items = []
        held = self.lease.quarantine_items() or []
        self._service_items = {q["id"] for q in held}
        for q in held:
            items.append((q["id"], (os.path.basename(q["original_path"]), _fmt_ts(q["ts"]), "Do dịch vụ giữ",
                                    os.path.dirname(q["original_path"])), "threat"))
        for q in self.db.quarantine_items():
            try:
                why = json.loads(q["verdict"])["findings"][0]["detail"]
            except (ValueError, KeyError, IndexError):
                why = ""
            items.append((q["id"], (os.path.basename(q["original_path"]), _fmt_ts(q["ts"]), why,
                                    os.path.dirname(q["original_path"])), "threat"))
        _fill(self.q_tv, items)
        web = [e for e in self.db.events(300) if e["source"] in ("web", "download")]
        _fill(self.web_tv, [(e["id"], (_fmt_ts(e["ts"]), LEVEL_VI.get(e["level"], e["level"]),
                                       f"{e['title']} · {e['detail']}"), e["level"]) for e in web])
        _fill(self.allow_tv, [(h, (h,), "") for h in self.db.allowed_hosts()])

    def _show_event_detail(self) -> None:
        sel = self.events_tv.selection()
        e = self._events.get(sel[0]) if sel else None
        self.event_detail.configure(text=f"{e['title']}\n{e['detail']}" if e else "")

    def restore_selected(self) -> None:
        sel = self.q_tv.selection()
        if not sel:
            return
        if not messagebox.askyesno(APP, "Khôi phục tệp này về vị trí cũ?\n\nChỉ tệp này, ở đúng vị trí này, được bỏ qua "
                                        "khi quét. Bản sao ở nơi khác vẫn bị chặn."):
            return
        for qid in sel:
            if qid in self._service_items:
                if not self.lease.approve("restore_quarantine", {"quarantine_id": qid}):
                    messagebox.showerror(APP, "Chưa khôi phục: cần xác nhận của quản trị viên.")
                continue
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
                if qid not in self._service_items:
                    quarantine.delete(self.db, qid)
                elif not self.lease.approve("delete_quarantine", {"quarantine_id": qid}):
                    messagebox.showerror(APP, "Chưa xóa: cần xác nhận của quản trị viên.")
            self.refresh()

    def unallow_selected(self) -> None:
        for host in self.allow_tv.selection():
            self.db.remove_allowed_host(host)
        self.db.bump_generation()
        self.refresh()

    def export_report(self) -> None:
        paths = report.write_report(self.db, self.settings)
        os.startfile(paths["html"])  # type: ignore[attr-defined]


SOURCE_VI = {"scan": "Quét", "realtime": "Thời gian thực", "web": "Web", "download": "Tải về",
             "feeds": "Dữ liệu", "system": "Hệ thống", "persistence": "Khởi động"}
LEVEL_VI = {"threat": "đe dọa", "warning": "cảnh báo", "info": "thông tin"}


def _fill(tv: ttk.Treeview, rows) -> None:
    keep = tv.selection()
    tv.delete(*tv.get_children())
    for iid, values, level in rows:
        # Only a 3 px leading mark carries severity; the text stays neutral.
        color = {"threat": theme.BAD, "warning": theme.WARN}.get(level)
        tv.insert("", "end", iid=str(iid), values=values, **({"image": theme.row_mark(tv, color)} if color else {}))
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
