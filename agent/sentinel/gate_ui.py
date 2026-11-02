"""Dashboard tab for the scan gate: layer status, on-demand scans, per-layer results."""

from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any

from . import theme
from .engine import clamav, defender
from .scanjob import ScanJob, ScanProgress, describe_paths, fixed_drives

if TYPE_CHECKING:
    from .tray import App

LAYERS = (
    ("sentinel", "Lõi Sentinel", "hash, EICAR, tên tệp đánh lừa, cấu trúc PE, tệp ZIP"),
    ("rules+yara", "Luật + YARA-X", "gói luật và luật YARA trong thư mục rules"),
    ("clamav", "ClamAV", "engine mã nguồn mở, mở 7z/RAR/CAB/ISO/PDF/Office"),
    ("defender", "Microsoft Defender", "chỉ khi Defender là phần mềm diệt virus đang chạy"),
)
LABEL_VI = {"clean": "sạch", "suspicious": "đáng ngờ", "malicious": "độc hại"}
OK, WARN, BAD, OFF = theme.OK, theme.WARN, theme.BAD, theme.OFF


def layer_text(status: str | None) -> str:
    if not status:
        return "—"
    head = status.split(":", 1)[0]
    return {"clean": "sạch", "detected": "PHÁT HIỆN", "skipped": "bỏ qua", "unavailable": "không có",
            "error": "lỗi", "partial": "sạch (một phần)",
            "trusted by the user": "tin cậy"}.get(head, status[:20])


class GatePanel:
    def __init__(self, nb: ttk.Notebook, app: "App") -> None:
        self.app = app
        self.job: ScanJob | None = None
        frame = ttk.Frame(nb, padding=10)
        nb.insert(0, frame, text="Cổng quét")
        nb.select(frame)

        layers = ttk.LabelFrame(frame, text="Các lớp kiểm tra (tệp phải qua tất cả)", padding=8)
        layers.pack(fill="x")
        self.lights: dict[str, tuple[theme.Dot, ttk.Label]] = {}
        for row, (key, title, hint) in enumerate(LAYERS):
            dot = theme.Dot(layers)
            dot.grid(row=row, column=0, padx=(0, 8), pady=2)
            ttk.Label(layers, text=title, style="CardTitle.TLabel", width=20).grid(row=row, column=1, sticky="w")
            st = ttk.Label(layers, text="…", style="Card.TLabel", width=52)
            st.grid(row=row, column=2, sticky="w")
            ttk.Label(layers, text=hint, style="CardMuted.TLabel").grid(row=row, column=3, sticky="w", padx=8)
            self.lights[key] = (dot, st)
        cb = ttk.Frame(layers, style="Card.TFrame")
        cb.grid(row=len(LAYERS), column=0, columnspan=4, sticky="w", pady=(6, 0))
        self.update_btn = ttk.Button(cb, text="Cập nhật chữ ký ClamAV", command=self.update_clamav)
        self.update_btn.pack(side="left", padx=(0, 6))
        ttk.Button(cb, text="Khởi động ClamAV", command=self.start_clamav).pack(side="left")

        ctl = ttk.Frame(frame)
        ctl.pack(fill="x", pady=10)
        self.buttons = []
        for text, cmd in (("Quét tệp…", self.scan_file), ("Quét thư mục…", self.scan_folder),
                          ("Quét nhanh", self.scan_quick), ("Quét toàn máy", self.scan_full)):
            b = ttk.Button(ctl, text=text, command=cmd, style="Primary.TButton" if cmd == self.scan_quick else "TButton")
            b.pack(side="left", padx=(0, 6))
            self.buttons.append(b)
        self.stop_btn = ttk.Button(ctl, text="Dừng", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(12, 0))

        self.bar = theme.ActivityBar(frame)
        self.bar.pack(fill="x")
        self.progress_var = tk.StringVar(value="Chưa quét.")
        ttk.Label(frame, textvariable=self.progress_var, justify="left", style="Muted.TLabel").pack(anchor="w", pady=(6, 8))

        cols = ("Tệp", "Kết luận", "Điểm", "Lõi", "Luật/YARA", "ClamAV", "Defender", "Xử lý", "Lý do")
        widths = (300, 75, 45, 80, 75, 80, 75, 80, 300)
        box = ttk.Frame(frame)
        box.pack(fill="both", expand=True)
        self.tv = ttk.Treeview(box, columns=cols, show="headings", height=10)
        for c, w in zip(cols, widths):
            self.tv.heading(c, text=c)
            self.tv.column(c, width=theme.px(self.tv, w), stretch=c in ("Tệp", "Lý do"), minwidth=0)
        self.tv.tag_configure("malicious", foreground=BAD)
        self.tv.tag_configure("suspicious", foreground=WARN)
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        self.tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.flash = theme.RowFlash(self.tv)
        self.tv.bind("<Double-1>", self.show_detail)
        self.details: dict[str, dict[str, Any]] = {}
        self.refresh_layers()

    # -- layer status ------------------------------------------------------

    def refresh_layers(self) -> None:
        sc = self.app.scanner
        n_rules, n_yara = len(sc.sigs.pattern_rules), sc.sigs.yara_rules
        self._set("sentinel", OK, f"bật · chữ ký hash: {self.app.db.counts()['bad_hashes']:,}")
        self._set("rules+yara", OK if (n_rules or n_yara) else WARN,
                  f"{n_rules} luật mẫu, {n_yara} luật YARA" if (n_rules or n_yara) else "chưa có luật nào")
        if sc.clamav is None:
            msg = "chưa cài ClamAV" if clamav.install_dir() is None else "đang tắt trong cài đặt"
            self._set("clamav", BAD, msg)
        else:
            st = sc.clamav.status()
            if st == "ready":
                self._set("clamav", OK, f"sẵn sàng · {sc.clamav.version() or ''}")
            else:
                vi = {"no database": "chưa có chữ ký — bấm Cập nhật", "not running": "đang khởi động…",
                      "not installed": "chưa cài"}.get(st, st)
                self._set("clamav", WARN if st == "not running" else BAD, vi, busy=st == "not running")
        if not self.app.settings.use_defender:
            self._set("defender", OFF, "đang tắt trong cài đặt")
        elif defender.available():
            self._set("defender", OK, "đang hoạt động · ý kiến thứ hai cho tệp rủi ro")
        else:
            self._set("defender", OFF, "không phải phần mềm diệt virus đang chạy (bỏ qua)")

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
        threading.Thread(target=lambda: (eng.start(wait=120), self.app.ui(self.refresh_layers)), daemon=True).start()

    # -- scans -------------------------------------------------------------

    def scan_file(self) -> None:
        files = filedialog.askopenfilenames(title="Chọn tệp để quét")
        if files:
            self.run(list(files), f"Quét {len(files)} tệp")

    def scan_folder(self) -> None:
        d = filedialog.askdirectory(title="Chọn thư mục để quét")
        if d:
            self.run([d], f"Quét thư mục {d}")

    def scan_quick(self) -> None:
        self.run(self.app.quick_scan_paths(), "Quét nhanh")

    def scan_full(self) -> None:
        drives = fixed_drives()
        if messagebox.askyesno("Sentinel Guard",
                               f"Quét toàn bộ ổ {', '.join(drives)}? Có thể mất nhiều giờ; máy vẫn dùng được trong lúc quét."):
            self.run(drives, "Quét toàn máy")

    def run(self, paths: list[str], title: str) -> None:
        if self.job and self.job.progress.running:
            messagebox.showinfo("Sentinel Guard", "Đang có một lượt quét chạy. Hãy dừng nó trước.")
            return
        self.tv.delete(*self.tv.get_children())
        self.details.clear()
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

    def tick(self) -> None:
        if not self.job or not self.job.progress.running:
            return
        p = self.job.progress
        cur = p.current if len(p.current) < 110 else "…" + p.current[-108:]
        self.progress_var.set(f"{p.title} · {describe_paths(p.paths)}\n"
                              f"Đã quét {p.scanned:,} tệp ({p.rate():.0f}/giây) · phát hiện {p.detections} · "
                              f"cách ly {p.quarantined}\n{cur}")
        self.tv.after(400, self.tick)

    def finished(self, p: ScanProgress) -> None:
        self.bar.stop()
        self.app.scanning(False)
        for b in self.buttons:
            b.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        took = time.strftime("%H:%M:%S", time.gmtime((p.finished or time.time()) - p.started))
        lines = [f"{'Đã dừng' if p.cancelled else 'Xong'}: {p.scanned:,} tệp trong {took} · "
                 f"phát hiện {p.detections} · đã cách ly {p.quarantined}"]
        if p.unverified:
            lines.append(f"{p.unverified:,} tệp chỉ được lõi Sentinel kiểm tra (ClamAV/Defender không sẵn sàng).")
        if p.unreadable or p.errors:
            lines.append(f"{p.unreadable + len(p.errors):,} tệp/thư mục không đọc được (đang bị khoá hoặc không có quyền).")
        self.progress_var.set("\n".join(lines))
        self.app.refresh()

    def add_row(self, v: dict[str, Any], outcome: dict[str, Any]) -> None:
        eng = v.get("engines", {})
        action = ("đã cách ly" if outcome.get("quarantined") else
                  "lỗi cách ly" if outcome.get("error") else "chỉ báo")
        reason = v["findings"][0]["detail"] if v.get("findings") else ""
        iid = str(len(self.details))
        self.details[iid] = {**v, "outcome": outcome}
        self.tv.insert("", 0, iid=iid, tags=(v["label"],), values=(
            v.get("path") or v["name"], LABEL_VI.get(v["label"], v["label"]), v["score"],
            layer_text(eng.get("sentinel")), layer_text(eng.get("rules+yara")),
            layer_text(eng.get("clamav")), layer_text(eng.get("defender")), action, reason))
        self.flash.add(iid)

    def show_detail(self, _event: object = None) -> None:
        sel = self.tv.selection()
        if not sel:
            return
        v = self.details[sel[0]]
        text = [f"Tệp: {v.get('path') or v['name']}", f"SHA-256: {v['sha256']}", f"Kích thước: {v['size']:,} byte",
                f"Kết luận: {LABEL_VI.get(v['label'], v['label'])} (điểm {v['score']})", "", "Các lớp:"]
        text += [f"  {k}: {s}" for k, s in v.get("engines", {}).items()]
        text += ["", "Phát hiện:"] + [f"  [{f['severity']}] {f['engine']}/{f['rule']}: {f['detail']}" for f in v["findings"]]
        if v["outcome"].get("error"):
            text += ["", f"Lỗi cách ly: {v['outcome']['error']}"]
        messagebox.showinfo("Chi tiết", "\n".join(text))
