"""Scan tab: start/stop scans, progress, items that need attention; engine details on request."""

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

LAYERS = (
    ("sentinel", "Lõi Sentinel", "hash, EICAR, tên tệp đánh lừa, cấu trúc PE, tệp ZIP"),
    ("rules+yara", "Luật + YARA-X", "gói luật và luật YARA trong thư mục rules"),
    ("clamav", "ClamAV", "engine mã nguồn mở, mở 7z/RAR/CAB/ISO/PDF/Office"),
    ("defender", "Microsoft Defender", "chỉ khi Defender là phần mềm diệt virus đang chạy"),
)
LABEL_VI = {"clean": "sạch", "suspicious": "nghi ngờ", "malicious": "mối đe dọa"}
OK, WARN, BAD, OFF = theme.OK, theme.WARN, theme.BAD, theme.OFF


def layer_text(status: str | None) -> str:
    if not status:
        return "—"
    head = status.split(":", 1)[0]
    return {"clean": "sạch", "detected": "có tín hiệu", "skipped": "bỏ qua", "unavailable": "không chạy",
            "error": "lỗi", "timeout": "hết giờ", "partial": "một phần",
            "trusted by the user": "tin cậy"}.get(head, status[:20])


def _n(x: int) -> str:
    return f"{x:,}".replace(",", ".")


class GatePanel:
    def __init__(self, nb: ttk.Notebook, app: "App") -> None:
        self.app = app
        self.nb = nb
        self.job: ScanJob | None = None
        gap = theme.px(nb, 12)
        frame = self.frame = ttk.Frame(nb, padding=(gap, gap, gap, gap))
        nb.add(frame, text="Quét")

        ctl = ttk.Frame(frame)
        ctl.pack(fill="x")
        self.buttons = []
        for text, cmd, style in (("Quét ngay", self.scan_quick, "Primary.TButton"),
                                 ("Chọn tệp…", self.scan_file, "TButton"),
                                 ("Chọn thư mục…", self.scan_folder, "TButton"),
                                 ("Quét sâu…", self.scan_full, "TButton")):
            b = ttk.Button(ctl, text=text, command=cmd, style=style)
            b.pack(side="left", padx=(0, 8))
            self.buttons.append(b)
        self.stop_btn = ttk.Button(ctl, text="Dừng", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.details_btn = ttk.Button(ctl, text="Chi tiết kỹ thuật", command=self.toggle_layers)
        self.details_btn.pack(side="right")

        # Engine-by-engine status is for people who want it; hidden by default.
        self.layers = ttk.Frame(frame, style="Card.TFrame", padding=(gap, gap))
        self.lights: dict[str, tuple[theme.Dot, ttk.Label]] = {}
        for row, (key, title, hint) in enumerate(LAYERS):
            dot = theme.Dot(self.layers)
            dot.grid(row=row, column=0, padx=(0, 8), pady=3)
            ttk.Label(self.layers, text=title, style="CardValue.TLabel", width=18).grid(row=row, column=1, sticky="w")
            st = ttk.Label(self.layers, text="…", style="Card.TLabel", width=46)
            st.grid(row=row, column=2, sticky="w")
            ttk.Label(self.layers, text=hint, style="CardMuted.TLabel").grid(row=row, column=3, sticky="w", padx=8)
            self.lights[key] = (dot, st)
        cb = ttk.Frame(self.layers, style="Card.TFrame")
        cb.grid(row=len(LAYERS), column=0, columnspan=4, sticky="w", pady=(8, 0))
        self.update_btn = ttk.Button(cb, text="Cập nhật chữ ký ClamAV", command=self.update_clamav)
        self.update_btn.pack(side="left", padx=(0, 8))
        ttk.Button(cb, text="Khởi động ClamAV", command=self.start_clamav).pack(side="left")
        self.layers_shown = False

        self.bar = theme.ActivityBar(frame)
        self.bar.pack(fill="x", pady=(gap, 0))
        self.bar_widget = self.bar.canvas
        self.progress_var = tk.StringVar(value="Chưa quét lần nào trong phiên này.")
        ttk.Label(frame, textvariable=self.progress_var, justify="left").pack(anchor="w", pady=(8, 2))
        self.current_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.current_var, style="Muted.TLabel").pack(anchor="w", pady=(0, gap))

        ttk.Label(frame, text="Cần xem", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        cols = ("Tệp", "Kết luận", "Xử lý", "Lý do", "Thư mục")
        widths = (220, 90, 100, 330, 260)
        box = ttk.Frame(frame, style="Card.TFrame")
        box.pack(fill="both", expand=True)
        self.tv = ttk.Treeview(box, columns=cols, show="headings", height=8)
        for c, w in zip(cols, widths):
            self.tv.heading(c, text=c, anchor="w")
            self.tv.column(c, width=theme.px(self.tv, w), stretch=c in ("Lý do", "Thư mục"), minwidth=0, anchor="w")
        self.tv.tag_configure("malicious", foreground=BAD)
        self.tv.tag_configure("suspicious", foreground=WARN)
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        self.tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.empty = ttk.Label(box, text="Chưa có mục cần xử lý.\nMối đe dọa và tệp nghi ngờ sẽ hiện ở đây.",
                               style="CardMuted.TLabel", justify="center")
        self.empty.place(relx=0.5, rely=0.5, anchor="center")
        self.flash = theme.RowFlash(self.tv)
        self.tv.bind("<Double-1>", self.show_detail)
        self.details: dict[str, dict[str, Any]] = {}
        self.refresh_layers()

    def select(self) -> None:
        self.nb.select(self.frame)

    def toggle_layers(self) -> None:
        if self.layers_shown:
            self.layers.pack_forget()
        else:
            self.layers.pack(fill="x", pady=(theme.px(self.frame, 12), 0), after=self.details_btn.master)
        self.layers_shown = not self.layers_shown
        self.details_btn.configure(text="Ẩn chi tiết kỹ thuật" if self.layers_shown else "Chi tiết kỹ thuật")

    # -- layer status ------------------------------------------------------

    def refresh_layers(self) -> None:
        sc = self.app.scanner
        n_rules, n_yara = len(sc.sigs.pattern_rules), sc.sigs.yara_rules
        self._set("sentinel", OK, f"bật · {_n(self.app.db.counts()['bad_hashes'])} hash đã biết")
        self._set("rules+yara", OK if (n_rules or n_yara) else WARN,
                  f"{n_rules} luật mẫu, {_n(n_yara)} luật YARA" if (n_rules or n_yara) else "chưa cài bộ luật")
        # Slow probes (PowerShell, clamd pings) run in EngineStatus; this only reads its snapshot.
        snap = self.app.engine_status.snapshot
        if sc.clamav is None:
            msg = "chưa cài ClamAV" if clamav.install_dir() is None else "đang tắt trong cài đặt"
            self._set("clamav", BAD, msg)
        elif snap.clamav_status == "ready":
            self._set("clamav", OK, f"sẵn sàng · {snap.clamav_version or ''}")
        else:
            vi = {"no database": "chưa có chữ ký — bấm Cập nhật", "not running": "đang khởi động…",
                  "not installed": "chưa cài", "checking": "đang kiểm tra…"}.get(snap.clamav_status, snap.clamav_status)
            busy = snap.clamav_status in ("not running", "checking")
            self._set("clamav", WARN if busy else BAD, vi, busy=busy)
        if not self.app.settings.use_defender:
            self._set("defender", OFF, "tắt trong cài đặt")
        elif not snap.checked:
            self._set("defender", OFF, "đang kiểm tra…", busy=True)
        elif snap.defender_active:
            self._set("defender", OK, "đang hoạt động · ý kiến thứ hai cho tệp rủi ro")
        else:
            self._set("defender", OFF, "không hoạt động (phần mềm diệt virus khác đang chạy)")

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
        self.update_btn.configure(state="normal", text="Cập nhật chữ ký ClamAV")
        if res != "ok":
            messagebox.showwarning("Sentinel Guard", f"Không cập nhật được chữ ký ClamAV:\n{res}")
        self.refresh_layers()

    def start_clamav(self) -> None:
        eng = self.app.scanner.clamav
        if eng is None:
            messagebox.showinfo("Sentinel Guard", "ClamAV chưa được cài hoặc đang tắt trong cài đặt.")
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
        if messagebox.askyesno("Quét sâu",
                               f"Quét toàn bộ ổ {', '.join(drives)}?\n\nCó thể mất nhiều giờ. Máy vẫn dùng bình thường "
                               "trong lúc quét và bạn có thể dừng bất cứ lúc nào."):
            self.run(drives, "Quét sâu")

    def run(self, paths: list[str], title: str) -> None:
        if self.job and self.job.progress.running:
            messagebox.showinfo("Sentinel Guard", "Đang có một lượt quét. Hãy dừng nó trước.")
            return
        self.tv.delete(*self.tv.get_children())
        self.details.clear()
        self.empty.place(relx=0.5, rely=0.5, anchor="center")
        self.job = ScanJob(self.app.scanner, self.app.db, self.app.settings, paths, title,
                           on_result=lambda v, o: self.app.ui(self.add_row, v, o),
                           on_done=lambda p: self.app.ui(self.finished, p)).start()
        for b in self.buttons:
            b.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.bar.start()
        self.app.scanning(True)
        self.tick()

    def stop(self) -> None:
        if self.job:
            self.job.cancel()
            self.stop_btn.configure(state="disabled")

    @staticmethod
    def counts_text(p: ScanProgress) -> str:
        parts = [f"{_n(p.scanned)} tệp đã kiểm tra"]
        if p.threats:
            parts.append(f"{p.threats} mối đe dọa")
        if p.suspicious:
            parts.append(f"{p.suspicious} nghi ngờ")
        if p.quarantined:
            parts.append(f"{p.quarantined} đã cách ly")
        if p.unreadable or p.errors:
            parts.append(f"{_n(p.unreadable + len(p.errors))} chưa đọc được")
        return " · ".join(parts)

    def tick(self) -> None:
        if not self.job or not self.job.progress.running:
            return
        p = self.job.progress
        self.progress_var.set(f"{p.title} · {describe_paths(p.paths)} — {self.counts_text(p)}")
        cur = p.current
        self.current_var.set(cur if len(cur) < 120 else "…" + cur[-118:])
        self.tv.after(250, self.tick)

    def finished(self, p: ScanProgress) -> None:
        self.bar.stop()
        self.app.scanning(False)
        for b in self.buttons:
            b.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        took = time.strftime("%H:%M:%S", time.gmtime((p.finished or time.time()) - p.started))
        head = "Đã dừng" if p.cancelled else "Xong"
        self.progress_var.set(f"{head} sau {took} — {self.counts_text(p)}")
        note = []
        if p.unverified:
            note.append(f"{_n(p.unverified)} tệp chỉ được lõi Sentinel kiểm tra (ClamAV và Defender không chạy).")
        if p.unreadable or p.errors:
            note.append("Tệp chưa đọc được thường đang bị khoá hoặc cần quyền quản trị.")
        self.current_var.set(" ".join(note))
        self.app.refresh()

    def add_row(self, v: dict[str, Any], outcome: dict[str, Any]) -> None:
        action = ("đã cách ly" if outcome.get("quarantined") else
                  "lỗi cách ly" if outcome.get("error") else "chỉ báo")
        reason = v["findings"][0]["detail"] if v.get("findings") else ""
        path = v.get("path") or v["name"]
        iid = str(len(self.details))
        self.details[iid] = {**v, "outcome": outcome}
        self.empty.place_forget()
        self.tv.insert("", 0, iid=iid, tags=(v["label"],), values=(
            os.path.basename(path), LABEL_VI.get(v["label"], v["label"]), action, reason, os.path.dirname(path)))
        self.flash.add(iid, "bad" if v["label"] == "malicious" else "warn")

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
