"""Dark, compact look for the Tk dashboard, the logo, and small UI animations."""

from __future__ import annotations

import ctypes
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

BG = "#0b0b0c"
SURFACE = "#121214"
RAISED = "#1a1a1d"
HOVER = "#232327"
LINE = "#26262a"
TEXT = "#e8e8ea"
MUTED = "#8a8a90"
FAINT = "#55555b"
SELECT = "#2e2e33"
OK, WARN, BAD, OFF = "#4caf7a", "#d4a32a", "#e0524a", "#55555b"

FONT = "Segoe UI"
SIZE = 9


def enable_dpi_awareness() -> None:
    # Without this Windows bitmap-stretches the whole window on scaled displays,
    # which is what makes Tk text look blurry. Must run before the first Tk().
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


def px(widget: tk.Misc, n: float) -> int:
    """Pixels for a size designed at 96 DPI; the process is DPI-aware, so Tk works in real pixels."""
    return round(n * widget.winfo_fpixels("1i") / 96)


def dark_title_bar(win: tk.Misc) -> None:
    if sys.platform != "win32":
        return
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id()) or win.winfo_id()
        on = ctypes.c_int(1)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 10 2004+); 19 on older builds.
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on), ctypes.sizeof(on)) == 0:
                break
    except (AttributeError, OSError):
        pass


def apply(root: tk.Tk) -> ttk.Style:
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(name).configure(family=FONT, size=SIZE)
        except tk.TclError:
            pass
    root.configure(bg=BG)
    root.option_add("*Background", BG)
    root.option_add("*Foreground", TEXT)
    root.option_add("*selectBackground", SELECT)
    root.option_add("*selectForeground", TEXT)
    # Native file dialogs and message boxes keep the system look; only Tk widgets follow these.
    root.option_add("*TCombobox*Listbox.background", RAISED)

    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE, bordercolor=LINE,
                darkcolor=BG, lightcolor=BG, troughcolor=SURFACE, focuscolor=LINE,
                selectbackground=SELECT, selectforeground=TEXT, insertcolor=TEXT, font=(FONT, SIZE))
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=SURFACE)
    s.configure("TLabel", background=BG, foreground=TEXT)
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("Card.TLabel", background=SURFACE)
    s.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED)
    s.configure("CardTitle.TLabel", background=SURFACE, font=(FONT, SIZE, "bold"))
    s.configure("Title.TLabel", font=(FONT, SIZE + 2, "bold"))
    s.configure("Section.TLabel", foreground=MUTED, font=(FONT, SIZE - 1, "bold"))

    s.configure("TButton", background=RAISED, foreground=TEXT, bordercolor=LINE, lightcolor=RAISED,
                darkcolor=RAISED, relief="flat", padding=(10, 4), focusthickness=0)
    s.map("TButton",
          background=[("disabled", SURFACE), ("pressed", SELECT), ("active", HOVER)],
          foreground=[("disabled", FAINT)],
          bordercolor=[("active", FAINT)],
          lightcolor=[("active", HOVER)], darkcolor=[("active", HOVER)])
    s.configure("Primary.TButton", background=TEXT, foreground=BG, lightcolor=TEXT, darkcolor=TEXT,
                bordercolor=TEXT, font=(FONT, SIZE, "bold"))
    s.map("Primary.TButton",
          background=[("disabled", SURFACE), ("pressed", MUTED), ("active", "#ffffff")],
          foreground=[("disabled", FAINT)],
          lightcolor=[("active", "#ffffff")], darkcolor=[("active", "#ffffff")])

    s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    s.configure("TNotebook.Tab", background=BG, foreground=MUTED, bordercolor=BG, lightcolor=BG,
                darkcolor=BG, padding=(12, 5))
    s.map("TNotebook.Tab",
          background=[("selected", SURFACE), ("active", RAISED)],
          foreground=[("selected", TEXT), ("active", TEXT)],
          lightcolor=[("selected", SURFACE)], bordercolor=[("selected", LINE)])

    s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT,
                bordercolor=LINE, lightcolor=SURFACE, darkcolor=SURFACE, rowheight=px(root, 20), borderwidth=0)
    s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", TEXT)])
    s.configure("Treeview.Heading", background=BG, foreground=MUTED, bordercolor=LINE, lightcolor=BG,
                darkcolor=BG, relief="flat", font=(FONT, SIZE - 1, "bold"), padding=(6, 3))
    s.map("Treeview.Heading", background=[("active", RAISED)], foreground=[("active", TEXT)])

    s.configure("TLabelframe", background=SURFACE, bordercolor=LINE, lightcolor=SURFACE, darkcolor=SURFACE)
    s.configure("TLabelframe.Label", background=SURFACE, foreground=MUTED, font=(FONT, SIZE - 1, "bold"))
    for orient in ("Vertical", "Horizontal"):
        s.configure(f"{orient}.TScrollbar", background=RAISED, troughcolor=BG, bordercolor=BG,
                    lightcolor=RAISED, darkcolor=RAISED, arrowcolor=MUTED, gripcount=0, arrowsize=10)
        s.map(f"{orient}.TScrollbar", background=[("active", HOVER)])
    s.configure("TCheckbutton", background=BG, foreground=TEXT, indicatorbackground=SURFACE)
    s.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT, bordercolor=LINE)
    return s


# -- logo ------------------------------------------------------------------

def logo_image(size: int = 64, ring: tuple[int, int, int] | None = None):
    """A small black-to-grey square inside a thin outline; the outline colour can carry state."""
    from PIL import Image, ImageDraw

    scale = 4  # draw large and downsample so the thin outline stays crisp at 16 px
    n = size * scale
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    stroke = max(scale, round(n * 0.045))
    gap = round(n * 0.09)
    d.rectangle([0, 0, n - 1, n - 1], outline=(ring or (58, 58, 62)) + (255,), width=stroke)
    top, bottom = (6, 6, 7), (118, 118, 124)
    x0 = y0 = stroke + gap
    x1 = y1 = n - 1 - stroke - gap
    h = max(1, y1 - y0)
    for y in range(y0, y1 + 1):
        t = (y - y0) / h
        # Ease the gradient so most of the square stays black and only the bottom turns grey.
        t = t * t
        c = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom))
        d.line([(x0, y), (x1, y)], fill=c + (255,))
    return img.resize((size, size), Image.LANCZOS)


# -- animation -------------------------------------------------------------

def _rgb(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(ra, rb))


class Dot:
    """Status light that fades between colours and can breathe while a layer is busy."""

    def __init__(self, parent: tk.Misc, bg: str = SURFACE, size: int = 10) -> None:
        size = px(parent, size)
        self.canvas = tk.Canvas(parent, width=size + 4, height=size + 4, bg=bg, highlightthickness=0, bd=0)
        self.item = self.canvas.create_oval(2, 2, size + 2, size + 2, fill=OFF, outline="")
        self.color = OFF
        self.busy = False
        self.bg = bg
        self._job: str | None = None
        self._phase = 0

    def grid(self, **kw) -> None:
        self.canvas.grid(**kw)

    def set(self, color: str, busy: bool = False) -> None:
        if (color, busy) == (self.color, self.busy):
            return  # refreshes repeat the same state; restarting would make the light flicker
        self._cancel()
        start, self.color, self.busy = self.color, color, busy
        if busy:
            self._breathe()
        else:
            self._fade(start, color, 0)

    def _fade(self, a: str, b: str, step: int, steps: int = 8) -> None:
        self.canvas.itemconfigure(self.item, fill=mix(a, b, step / steps))
        if step < steps:
            self._job = self.canvas.after(25, self._fade, a, b, step + 1, steps)

    def _breathe(self) -> None:
        import math

        self._phase = (self._phase + 1) % 40
        t = (1 - math.cos(self._phase / 40 * 2 * math.pi)) / 2
        self.canvas.itemconfigure(self.item, fill=mix(self.bg, self.color, 0.35 + 0.65 * t))
        self._job = self.canvas.after(50, self._breathe)

    def _cancel(self) -> None:
        if self._job is not None:
            self.canvas.after_cancel(self._job)
            self._job = None


class ActivityBar:
    """Thin bar with a sliding highlight while work is running; flat line when idle."""

    def __init__(self, parent: tk.Misc, height: int = 2, bg: str = BG) -> None:
        height = px(parent, height)
        self.canvas = tk.Canvas(parent, height=height, bg=bg, highlightthickness=0, bd=0)
        self.track = self.canvas.create_rectangle(0, 0, 0, height, fill=LINE, outline="")
        self.glow = self.canvas.create_rectangle(0, 0, 0, height, fill=TEXT, outline="", state="hidden")
        self.height = height
        self._job: str | None = None
        self._x = 0.0
        self.canvas.bind("<Configure>", self._resize)

    def pack(self, **kw) -> None:
        self.canvas.pack(**kw)

    def _resize(self, _e: object = None) -> None:
        self.canvas.coords(self.track, 0, 0, self.canvas.winfo_width(), self.height)

    def start(self) -> None:
        if self._job is None:
            self.canvas.itemconfigure(self.glow, state="normal")
            self._tick()

    def stop(self) -> None:
        if self._job is not None:
            self.canvas.after_cancel(self._job)
            self._job = None
        self.canvas.itemconfigure(self.glow, state="hidden")

    def _tick(self) -> None:
        w = max(1, self.canvas.winfo_width())
        seg = max(40, w // 5)
        self._x = (self._x + w / 90) % (w + seg)
        self.canvas.coords(self.glow, self._x - seg, 0, self._x, self.height)
        self._job = self.canvas.after(16, self._tick)


class LogoMark:
    """The logo in the header; a light sweep crosses it while a scan runs."""

    def __init__(self, parent: tk.Misc, size: int = 22, bg: str = BG) -> None:
        from PIL import ImageTk

        size = px(parent, size)
        self.size = size
        self.canvas = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self._photo = ImageTk.PhotoImage(logo_image(size))
        self.canvas.create_image(0, 0, anchor="nw", image=self._photo)
        self.sweep = self.canvas.create_line(0, 0, 0, 0, fill=MUTED, width=1, state="hidden")
        self._job: str | None = None
        self._y = 0

    def pack(self, **kw) -> None:
        self.canvas.pack(**kw)

    def start(self) -> None:
        if self._job is None:
            self.canvas.itemconfigure(self.sweep, state="normal")
            self._tick()

    def stop(self) -> None:
        if self._job is not None:
            self.canvas.after_cancel(self._job)
            self._job = None
        self.canvas.itemconfigure(self.sweep, state="hidden")

    def _tick(self) -> None:
        inset = max(3, round(self.size * 0.2))
        span = self.size - 2 * inset
        self._y = (self._y + 1) % max(1, span)
        y = inset + self._y
        self.canvas.coords(self.sweep, inset, y, self.size - inset, y)
        self._job = self.canvas.after(40, self._tick)


class RowFlash:
    """New Treeview rows start highlighted and fade into the normal background."""

    STEPS = 6

    def __init__(self, tv: ttk.Treeview, base: str = SURFACE, flash: str = "#3a3a40") -> None:
        self.tv = tv
        for i in range(self.STEPS):
            tv.tag_configure(f"flash{i}", background=mix(flash, base, i / (self.STEPS - 1)))

    def add(self, iid: str) -> None:
        self._step(iid, 0)

    def _step(self, iid: str, i: int) -> None:
        if not self.tv.exists(iid):
            return
        tags = [t for t in self.tv.item(iid, "tags") if not str(t).startswith("flash")]
        if i < self.STEPS:
            tags.append(f"flash{i}")
            self.tv.item(iid, tags=tags)
            self.tv.after(90, self._step, iid, i + 1)
        else:
            self.tv.item(iid, tags=tags)
