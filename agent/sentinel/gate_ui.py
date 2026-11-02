"""Scan page: idle / running / finished states, items that need attention, engine layers on request."""

from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any

from . import theme
from .engine import clamav
from .scanjob import ScanJob, ScanProgress, describe_paths, fixed_drives

if TYPE_CHECKING:
    from .tray import App

LAYERS = (("sentinel", "Lõi Sentinel"), ("rules+yara", "Luật + YARA-X"), ("clamav", "ClamAV"),
          ("defender", "Microsoft Defender"))
LABEL_VI = {"clean": "sạch", "suspicious": "nghi ngờ", "malicious": "mối đe dọa"}
OK, WARN, BAD, OFF = theme.OK, theme.WARN, theme.BAD, theme.OFF
MAX_ROWS = 6


def layer_text(status: str | None) -> str:
    if not status:
        return "—"
    head = status.split(":", 1)[0]
    return {"clean": "sạch", "detected": "có tín hiệu", "skipped": "bỏ qua", "unavailable": "không chạy",
            "error": "lỗi", "timeout": "hết giờ", "partial": "một phần",
            "trusted by the user": "tin cậy"}.get(head, status[:20])


def short_reason(v: dict[str, Any]) -> str:
    """A few words for the table row; the full finding stays in the detail dialog."""
    if not v.get("findings"):
        return ""
    f = v["findings"][0]
    rule, name = f.get("rule", ""), v.get("name", "")
    if rule == "eicar.test_file":
        return "EICAR kiểm thử"
    if rule in ("filetype.double_extension", "filetype.mismatch"):
        parts = name.lower().rsplit(".", 2)
        return f"Giả dạng {parts[-2].upper()}" if len(parts) == 3 else "Đuôi tệp đánh lừa"
    return {"filetype.rtlo": "Tên tệp đảo chiều", "filetype.padded_name": "Tên tệp độn khoảng trắng",
            "pe.inflated": "Tệp chạy được bị độn", "pe.malformed": "Cấu trúc PE hỏng", "office.macros": "Có macro",
            "origin.blocklisted_source": "Tải từ nguồn độc hại", "archive.encrypted_executable": "Tệp chạy được có mật khẩu",
            "archive.bomb": "Bom giải nén", "defender.detection": "Defender phát hiện",
            }.get(rule, (f["detail"][:40] + "…") if len(f["detail"]) > 40 else f["detail"])


def _n(x: int) -> str:
    return f"{x:,}".replace(",", ".")


class GatePanel:
    def __init__(self, nb: ttk.Frame, app: "App") -> None:
        self.app = app
        self.nb = nb
        self.job: ScanJob | None = None
        pad, gap = theme.px(nb, 24), theme.px(nb, 16)
        frame = self.frame = ttk.Frame(nb, padding=(pad, pad, pad, pad))
        nb.add(frame, text="Quét", icon="scan")

        ttk.Label(frame, text="Quét", style="PageTitle.TLabel").pack(anchor="w", pady=(0, gap))
        ctl = self.ctl = ttk.Frame(frame)
        ctl.pack(fill="x")
        self.scan_btn = ttk.Button(ctl, text="Quét ngay", style="Primary.TButton", command=self.scan_quick, width=12)
        self.scan_btn.pack(side="left", ipady=theme.px(nb, 4))
        self.pick = ttk.Menubutton(ctl, text="Chọn mục")
        menu = theme.dark_menu(self.pick)
        menu.add_command(label="Tệp…", command=self.scan_file)
        menu.add_command(label="Thư mục…", command=self.scan_folder)
        menu.add_separator()
        menu.add_command(label="Quét sâu (toàn bộ ổ đĩa)…", command=self.scan_full)
        self.pick["menu"] = menu
        self.pick.pack(side="left", padx=(8, 0), ipady=theme.px(nb, 4))
        self.details_btn = ttk.Button(ctl, text="Lớp kiểm tra", style="Quiet.TButton", command=self.toggle_layers)
        self.details_btn.pack(side="right")
        self.stop_btn = ttk.Button(ctl, text="Dừng", command=self.stop)

        # Engine layers: one short status each; hidden unless asked for.
        self.layers = ttk.Frame(frame, style="Card.TFrame", padding=(gap, theme.px(nb, 6)))
        self.lights: dict[str, tuple[theme.Dot, ttk.Label]] = {}
        for row, (key, title) in enumerate(LAYERS):
            dot = theme.Dot(self.layers, size=8)
            dot.grid(row=row, column=0, padx=(0, 10), pady=theme.px(nb, 8))
            ttk.Label(self.layers, text=title, style="CardValue.TLabel", width=20).grid(row=row, column=1, sticky="w")
            st = ttk.Label(self.layers, style="Card.TLabel")
            st.grid(row=row, column=2, sticky="w")
            self.lights[key] = (dot, st)
        self.clam_actions = ttk.Frame(self.layers, style="Card.TFrame")
        self.update_btn = ttk.Button(self.clam_actions, text="Cập nhật chữ ký", command=self.update_clamav)
        self.update_btn.pack(side="left", padx=(0, 8))
        ttk.Button(self.clam_actions, text="Khởi động ClamAV", command=self.start_clamav).pack(side="left")
        self.layers_shown = False

        # Status area: exactly one of idle / progress is shown.
        self.status = ttk.Frame(frame)
        self.status.pack(fill="x", pady=(gap, 0))
        self.idle = ttk.Frame(self.status, style="Card.TFrame", height=theme.px(nb, 96))
        self.idle.pack_propagate(False)
        self.idle_label = ttk.Label(self.idle, text="Sẵn sàng quét", style="CardMuted.TLabel")
        self.idle_label.place(relx=0.5, rely=0.5, anchor="center")
        self.progress = ttk.Frame(self.status)
        self.heading = ttk.Label(self.progress, style="Outcome.TLabel")
        self.heading.pack(anchor="w")
        self.bar = theme.ActivityBar(self.progress)
        self.bar.pack(fill="x", pady=(theme.px(nb, 8), 0))
        self.counts = ttk.Frame(self.progress)
        self.counts.pack(fill="x", pady=(theme.px(nb, 8), 0))
        self.count_labels: dict[str, ttk.Label] = {}
        for key in ("scanned", "threats", "suspicious", "quarantined", "unreadable"):
            lbl = ttk.Label(self.counts)
            self.count_labels[key] = lbl
        self.current_var = tk.StringVar()
        ttk.Label(self.progress, textvariable=self.current_var, style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.idle.pack(fill="x")

        self.results_title = ttk.Label(frame, text="Cần xem", style="Section.TLabel")
        self.box = ttk.Frame(frame, style="Card.TFrame")
        cols = ("Tệp", "Kết luận", "Xử lý", "Lý do")
        self.tv = ttk.Treeview(self.box, columns=cols, show="tree headings", height=1, selectmode="browse")
        self.tv.column("#0", width=theme.px(self.tv, 10), stretch=False, minwidth=0)
        for c, w in zip(cols, (28, 14, 15, 43)):
            self.tv.heading(c, text=c, anchor="w")
            self.tv.column(c, width=theme.px(self.tv, w * 9), stretch=True, minwidth=0, anchor="w")
        self.sb = ttk.Scrollbar(self.box, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=self.sb.set)
        self.tv.pack(side="left", fill="both", expand=True)
        self.flash = theme.RowFlash(self.tv)
        self.tv.bind("<Double-1>", self.show_detail)
        self.tv.bind("<Return>", self.show_detail)
        self.details: dict[str, dict[str, Any]] = {}
        self.refresh_layers()

    def select(self) -> None:
        self.nb.select(self.frame)

    def toggle_layers(self) -> None:
        if self.layers_shown:
            self.layers.pack_forget()
        else:
            self.layers.pack(fill="x", pady=(theme.px(self.frame, 16), 0), after=self.ctl)
        self.layers_shown = not self.layers_shown
        self.details_btn.configure(text="Ẩn lớp kiểm tra" if self.layers_shown else "Lớp kiểm tra")

    # -- layer status ------------------------------------------------------

    def refresh_layers(self) -> None:
        sc = self.app.scanner
        n_rules, n_yara = len(sc.sigs.pattern_rules), sc.sigs.yara_rules
        self._set("sentinel", OK, "Bật")
        self._set("rules+yara", OK if (n_rules or n_yara) else WARN,
                  f"{_n(n_rules + n_yara)} luật" if (n_rules or n_yara) else "Chưa có luật")
        # Slow probes (PowerShell, clamd pings) run in EngineStatus; this only reads its snapshot.
        snap = self.app.engine_status.snapshot
        clam_ready = False
        if sc.clamav is None:
            self._set("clamav", BAD, "Chưa cài" if clamav.install_dir() is None else "Tắt trong cài đặt")
        elif snap.clamav_status == "ready":
            clam_ready = True
            self._set("clamav", OK, "Sẵn sàng")
        else:
            vi = {"no database": "Chưa có chữ ký", "not running": "Đang khởi động",
                  "not installed": "Chưa cài", "checking": "Đang kiểm tra"}.get(snap.clamav_status, snap.clamav_status)
            busy = snap.clamav_status in ("not running", "checking")
            self._set("clamav", WARN if busy else BAD, vi, busy=busy)
        if not self.app.settings.use_defender:
            self._set("defender", OFF, "Tắt trong cài đặt")
        elif not snap.checked:
            self._set("defender", OFF, "Đang kiểm tra", busy=True)
        elif snap.defender_active:
            self._set("defender", OK, "Đang hoạt động")
        else:
            self._set("defender", OFF, "Không hoạt động")
        if sc.clamav is not None and not clam_ready:
            self.clam_actions.grid(row=len(LAYERS), column=0, columnspan=3, sticky="w", pady=(4, 8))
        else:
            self.clam_actions.grid_forget()

    def _set(self, key: str, color: str, text: str, busy: bool = False) -> None:
        dot, st = self.lights[key]
        dot.set(color, busy)
        st.configure(text=text)

    def update_clamav(self) -> None:
        self.update_btn.configure(state="disabled", text="Đang cập nhật…")

        def work() -> None:
            res = clamav.update()
            self.app.db.add_event("feeds", "info" if res == "ok" else "warning", "Cập nhật chữ ký ClamAV", res)
            if res == "ok" and self.app.scanner.clamav is not None:
                self.app.scanner.clamav.start(wait=120)
            self.app.engine_status.refresh_soon()
            self.app.ui(self._update_done, res)
        threading.Thread(target=work, daemon=True).start()

    def _update_done(self, res: str) -> None:
        self.update_btn.configure(state="normal", text="Cập nhật chữ ký")
        if res != "ok":
            messagebox.showwarning("Sentinel Guard", f"Không cập nhật được chữ ký ClamAV:\n{res}")
        self.refresh_layers()

    def start_clamav(self) -> None:
        eng = self.app.scanner.clamav
        if eng is None:
            return
        threading.Thread(target=lambda: (eng.start(wait=120), self.app.engine_status.refresh_soon()), daemon=True).start()

    # -- scans -------------------------------------------------------------

    def scan_file(self) -> None:
        files = filedialog.askopenfilenames(title="Chọn tệp để quét")
        if files:
            self.run(list(files), f"Quét {len(files)} tệp")

    def scan_folder(self) -> None:
        d = filedialog.askdirectory(title="Chọn thư mục để quét")
        if d:
            self.run([d], f"Quét {os.path.basename(d) or d}")

    def scan_quick(self) -> None:
        self.run(self.app.quick_scan_paths(), "Quét nhanh")

    def scan_full(self) -> None:
        drives = fixed_drives()
        if messagebox.askyesno("Quét sâu", f"Quét toàn bộ ổ {', '.join(drives)}?\n\nCó thể mất nhiều giờ. "
                                             "Bạn có thể dừng bất cứ lúc nào."):
            self.run(drives, "Quét sâu")

    def run(self, paths: list[str], title: str) -> None:
        if self.job and self.job.progress.running:
            return
        self.tv.delete(*self.tv.get_children())
        self.details.clear()
        self._show_results()
        self.job = ScanJob(self.app.scanner, self.app.db, self.app.settings, paths, title,
                           on_result=lambda v, o: self.app.ui(self.add_row, v, o),
                           on_done=lambda p: self.app.ui(self.finished, p)).start()
        self.scan_btn.configure(state="disabled")
        self.pick.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.stop_btn.pack(side="right", padx=(0, 8), before=self.details_btn)
        self.idle.pack_forget()
        self.progress.pack(fill="x")
        self.heading.configure(text=f"{title} · {describe_paths(paths)}")
        self.bar.canvas.pack(fill="x", pady=(theme.px(self.frame, 8), 0), after=self.heading)
        self.bar.start()
        self.app.scanning(True)
        self.tick()

    def stop(self) -> None:
        if self.job:
            self.job.cancel()
            self.stop_btn.configure(state="disabled")

    def _set_counts(self, p: ScanProgress) -> None:
        values = {"scanned": (f"{_n(p.scanned)} tệp", theme.TEXT),
                  "threats": (f"{p.threats} mối đe dọa", BAD) if p.threats else None,
                  "suspicious": (f"{p.suspicious} nghi ngờ", WARN) if p.suspicious else None,
                  "quarantined": (f"{p.quarantined} đã cách ly", theme.TEXT) if p.quarantined else None,
                  "unreadable": (f"{_n(p.unreadable + len(p.errors))} chưa đọc được", theme.MUTED)
                  if (p.unreadable or p.errors) else None}
        for key, lbl in self.count_labels.items():
            v = values[key]
            if v is None:
                lbl.pack_forget()
            else:
                lbl.configure(text=v[0], foreground=v[1])
                lbl.pack(side="left", padx=(0, theme.px(self.frame, 16)))

    def tick(self) -> None:
        if not self.job or not self.job.progress.running:
            return
        p = self.job.progress
        self._set_counts(p)
        name = os.path.basename(p.current)
        self.current_var.set(name if len(name) <= 64 else name[:63] + "…")
        self.tv.after(250, self.tick)

    def finished(self, p: ScanProgress) -> None:
        self.bar.stop()
        self.bar.canvas.pack_forget()
        self.app.scanning(False)
        self.scan_btn.configure(state="normal")
        self.pick.configure(state="normal")
        self.stop_btn.pack_forget()
        took = time.strftime("%H:%M:%S", time.gmtime((p.finished or time.time()) - p.started))
        if p.cancelled:
            head = f"Đã dừng sau {took}"
        elif p.detections:
            head = f"Cần xem {p.detections} mục"
        else:
            head = "Không phát hiện mối đe dọa"
        self.heading.configure(text=head)
        self._set_counts(p)
        note = []
        if p.unverified:
            note.append(f"{_n(p.unverified)} tệp chỉ được lõi Sentinel kiểm tra.")
        if p.unreadable or p.errors:
            note.append("Tệp chưa đọc được thường đang bị khoá.")
        self.current_var.set(" ".join(note))
        self._show_results()
        self.app.refresh()

    def _show_results(self) -> None:
        n = len(self.tv.get_children())
        if n:
            self.results_title.pack(anchor="w", pady=(theme.px(self.frame, 16), 6))
            self.tv.configure(height=min(n, MAX_ROWS))
            if n > MAX_ROWS:
                self.sb.pack(side="right", fill="y")
            else:
                self.sb.pack_forget()
            self.box.pack(fill="x")
        else:
            self.results_title.pack_forget()
            self.box.pack_forget()

    def add_row(self, v: dict[str, Any], outcome: dict[str, Any]) -> None:
        action = ("đã cách ly" if outcome.get("quarantined") else
                  "lỗi cách ly" if outcome.get("error") else "chỉ báo")
        path = v.get("path") or v["name"]
        iid = str(len(self.details))
        self.details[iid] = {**v, "outcome": outcome}
        bad = v["label"] == "malicious"
        self.tv.insert("", 0, iid=iid, image=theme.row_mark(self.tv, BAD if bad else WARN), values=(
            os.path.basename(path), LABEL_VI.get(v["label"], v["label"]), action, short_reason(v)))
        self._show_results()
        self.flash.add(iid, "bad" if bad else "warn")

    def show_detail(self, _event: object = None) -> None:
        sel = self.tv.selection()
        if not sel:
            return
        v = self.details[sel[0]]
        text = [f"Tệp: {v.get('path') or v['name']}", f"SHA-256: {v['sha256']}", f"Kích thước: {_n(v['size'])} byte",
                f"Kết luận: {LABEL_VI.get(v['label'], v['label'])} (điểm {v['score']})", "", "Từng lớp kiểm tra:"]
        text += [f"  {k}: {layer_text(s)}  ({s})" for k, s in v.get("engines", {}).items()]
        text += ["", "Tín hiệu:"] + [f"  [{f['severity']}] {f['engine']}/{f['rule']}: {f['detail']}" for f in v["findings"]]
        if v["outcome"].get("error"):
            text += ["", f"Lỗi cách ly: {v['outcome']['error']}"]
        messagebox.showinfo("Chi tiết", "\n".join(text))
