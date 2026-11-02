"""Dark, compact look for the Tk dashboard, the logo, and small UI animations."""

from __future__ import annotations

import ctypes
import math
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# Tonal steps rather than borders carry the hierarchy: page < card < control.
BG = "#111113"
SURFACE = "#18181b"
RAISED = "#222226"
HOVER = "#2b2b30"
LINE = "#2c2c31"
TEXT = "#ececee"
MUTED = "#9a9aa1"
FAINT = "#5f5f66"
SELECT = "#34343a"
OK, WARN, BAD, OFF = "#4caf7a", "#d4a32a", "#e0524a", "#5f5f66"

FONT = "Segoe UI"
FONT_STRONG = "Segoe UI Semibold"
SIZE = 10
SMALL = 9

# Windows motion timings (Fluent): fast state changes, slightly longer fades.
FAST_MS, FADE_MS = 167, 333


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


def animations_enabled() -> bool:
    """Windows "Show animations in Windows" (Accessibility > Visual effects)."""
    if sys.platform != "win32":
        return True
    try:
        on = ctypes.c_int(1)
        # 0x1042 = SPI_GETCLIENTAREAANIMATION
        if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(on), 0):
            return bool(on.value)
    except (AttributeError, OSError):
        pass
    return True


MOTION = True  # set by apply(); every animation below checks it


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
    global MOTION, FONT_STRONG
    MOTION = animations_enabled()
    families = set(tkfont.families(root))
    if FONT_STRONG not in families:
        FONT_STRONG = FONT
    strong = (FONT_STRONG, SIZE) if FONT_STRONG != FONT else (FONT, SIZE, "bold")
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
    root.option_add("*Menu.background", RAISED)
    root.option_add("*Menu.foreground", TEXT)
    root.option_add("*Menu.activeBackground", HOVER)
    root.option_add("*Menu.activeForeground", TEXT)
    root.option_add("*Menu.relief", "flat")
    root.option_add("*Menu.borderWidth", 0)

    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE, bordercolor=LINE,
                darkcolor=BG, lightcolor=BG, troughcolor=SURFACE, focuscolor=LINE,
                selectbackground=SELECT, selectforeground=TEXT, insertcolor=TEXT, font=(FONT, SIZE))
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=SURFACE)
    s.configure("TLabel", background=BG, foreground=TEXT)
    s.configure("Muted.TLabel", foreground=MUTED, font=(FONT, SMALL))
    s.configure("Card.TLabel", background=SURFACE)
    s.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED, font=(FONT, SMALL))
    s.configure("CardTitle.TLabel", background=SURFACE, foreground=MUTED, font=(FONT, SMALL))
    s.configure("CardValue.TLabel", background=SURFACE, font=strong)
    s.configure("Title.TLabel", font=(FONT_STRONG, 14) if FONT_STRONG != FONT else (FONT, 14, "bold"))
    s.configure("State.TLabel", font=strong)
    s.configure("Section.TLabel", foreground=MUTED, font=(FONT, SMALL))
    s.configure("Nav.TLabel", background=BG, foreground=MUTED, font=(FONT, 8))
    s.configure("NavOn.TLabel", background=BG, foreground=TEXT, font=(FONT, 8))
    s.configure("Hero.TLabel", background=SURFACE, font=(FONT_STRONG, 22) if FONT_STRONG != FONT else (FONT, 22, "bold"))
    s.configure("HeroSub.TLabel", background=SURFACE, foreground=MUTED, font=(FONT, SIZE))
    s.configure("TileTitle.TLabel", background=SURFACE, foreground=MUTED, font=(FONT, SMALL))
    s.configure("TileValue.TLabel", background=SURFACE, font=(FONT_STRONG, 13) if FONT_STRONG != FONT else (FONT, 13, "bold"))
    s.configure("PageTitle.TLabel", font=(FONT_STRONG, 15) if FONT_STRONG != FONT else (FONT, 15, "bold"))
    s.configure("Big.Primary.TButton", font=(FONT_STRONG, 12) if FONT_STRONG != FONT else (FONT, 12, "bold"), padding=(28, 10))

    s.configure("TButton", background=RAISED, foreground=TEXT, bordercolor=RAISED, lightcolor=RAISED,
                darkcolor=RAISED, relief="flat", padding=(12, 5), focusthickness=0)
    s.map("TButton",
          background=[("disabled", SURFACE), ("pressed", SELECT), ("active", HOVER)],
          foreground=[("disabled", FAINT)],
          bordercolor=[("active", HOVER)],
          lightcolor=[("active", HOVER)], darkcolor=[("active", HOVER)])
    s.configure("Primary.TButton", background=TEXT, foreground=BG, lightcolor=TEXT, darkcolor=TEXT,
                bordercolor=TEXT, font=strong)
    s.map("Primary.TButton",
          background=[("disabled", SURFACE), ("pressed", MUTED), ("active", "#ffffff")],
          foreground=[("disabled", FAINT)],
          lightcolor=[("active", "#ffffff")], darkcolor=[("active", "#ffffff")])
    s.configure("Link.TButton", background=SURFACE, foreground=MUTED, bordercolor=SURFACE, lightcolor=SURFACE,
                darkcolor=SURFACE, padding=(0, 2), font=(FONT, SMALL))
    s.map("Link.TButton", foreground=[("active", TEXT)], background=[("active", SURFACE)])
    s.configure("TMenubutton", background=RAISED, foreground=TEXT, bordercolor=RAISED, lightcolor=RAISED,
                darkcolor=RAISED, relief="flat", padding=(12, 5), arrowcolor=MUTED)
    s.map("TMenubutton", background=[("active", HOVER)], arrowcolor=[("active", TEXT)])

    s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    s.configure("TNotebook.Tab", background=BG, foreground=MUTED, bordercolor=BG, lightcolor=BG,
                darkcolor=BG, padding=(14, 6))
    s.map("TNotebook.Tab",
          background=[("selected", BG), ("active", BG)],
          foreground=[("selected", TEXT), ("active", TEXT)],
          lightcolor=[("selected", BG)], bordercolor=[("selected", BG)])

    s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT,
                bordercolor=SURFACE, lightcolor=SURFACE, darkcolor=SURFACE, rowheight=px(root, 24), borderwidth=0)
    s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", TEXT)])
    s.configure("Treeview.Heading", background=SURFACE, foreground=MUTED, bordercolor=SURFACE, lightcolor=SURFACE,
                darkcolor=SURFACE, relief="flat", font=(FONT, SMALL), padding=(8, 5))
    s.map("Treeview.Heading", background=[("active", SURFACE)], foreground=[("active", TEXT)])

    s.configure("TLabelframe", background=SURFACE, bordercolor=SURFACE, lightcolor=SURFACE, darkcolor=SURFACE)
    s.configure("TLabelframe.Label", background=SURFACE, foreground=MUTED, font=(FONT, SMALL))
    for orient in ("Vertical", "Horizontal"):
        s.configure(f"{orient}.TScrollbar", background=RAISED, troughcolor=SURFACE, bordercolor=SURFACE,
                    lightcolor=RAISED, darkcolor=RAISED, arrowcolor=MUTED, gripcount=0, arrowsize=10)
        s.map(f"{orient}.TScrollbar", background=[("active", HOVER)])
    s.configure("TCheckbutton", background=BG, foreground=TEXT, indicatorbackground=SURFACE)
    s.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT, bordercolor=LINE)
    return s


def dark_menu(parent: tk.Misc) -> tk.Menu:
    return tk.Menu(parent, tearoff=False, bg=RAISED, fg=TEXT, activebackground=HOVER, activeforeground=TEXT,
                   bd=0, relief="flat", font=(FONT, SIZE))


def ago(ts: float | None, now: float) -> str:
    """Vietnamese relative time: "vừa xong", "5 phút trước", "3 giờ trước", "2 ngày trước"."""
    if not ts:
        return "chưa bao giờ"
    d = max(0.0, now - ts)
    if d < 60:
        return "vừa xong"
    if d < 3600:
        return f"{int(d // 60)} phút trước"
    if d < 86400:
        return f"{int(d // 3600)} giờ trước"
    return f"{int(d // 86400)} ngày trước"


# -- logo ------------------------------------------------------------------

def logo_image(size: int = 64, ring: tuple[int, int, int] | None = None,
               core: tuple[int, int, int] = (10, 10, 11)):
    """A small flat square inside a detached thin frame; the frame colour can carry state.

    Same geometry and rounding as assets/brand/make_icons.py, drawn at the final
    size so edges land on whole pixels instead of being blurred by resampling.
    """
    from PIL import Image, ImageDraw

    n = size
    inset = int(3 * n / 32 + 0.5)
    stroke = max(1, int(n / 16 + 0.5))
    side = (7 * n) // 16
    o = (n - side) // 2
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rectangle([inset, inset, n - 1 - inset, n - 1 - inset], outline=(ring or (116, 116, 122)) + (255,), width=stroke)
    d.rectangle([o, o, o + side - 1, o + side - 1], fill=core + (255,))
    return img


# -- animation -------------------------------------------------------------

def _rgb(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def mix(a: str, b: str, t: float) -> str:
    ra, rb = _rgb(a), _rgb(b)
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(ra, rb))


def ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


def ease_in_out(t: float) -> float:
    return 4 * t ** 3 if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


FRAME_MS = 16


class Dot:
    """Status light. Fades between colours on change; can pulse while something
    is starting, and stops pulsing after `busy_for` seconds so a stuck start does
    not animate forever."""

    PULSE_MS = 1600

    def __init__(self, parent: tk.Misc, bg: str = SURFACE, size: int = 9) -> None:
        size = px(parent, size)
        self.canvas = tk.Canvas(parent, width=size + 4, height=size + 4, bg=bg, highlightthickness=0, bd=0)
        self.item = self.canvas.create_oval(2, 2, size + 2, size + 2, fill=OFF, outline="")
        self.color = OFF
        self.busy = False
        self.bg = bg
        self._job: str | None = None
        self._t0 = 0

    def grid(self, **kw) -> None:
        self.canvas.grid(**kw)

    def pack(self, **kw) -> None:
        self.canvas.pack(**kw)

    def set(self, color: str, busy: bool = False, busy_for: float = 120.0) -> None:
        if (color, busy) == (self.color, self.busy):
            return  # refreshes repeat the same state; restarting would make the light flicker
        self._cancel()
        start, self.color, self.busy = self.color, color, busy
        if not MOTION:
            self.canvas.itemconfigure(self.item, fill=color)
        elif busy:
            self._pulse(0, int(busy_for * 1000))
        else:
            self._fade(start, color, 0)

    def _fade(self, a: str, b: str, elapsed: int) -> None:
        t = min(1.0, elapsed / FAST_MS)
        self.canvas.itemconfigure(self.item, fill=mix(a, b, ease_out(t)))
        if t < 1.0:
            self._job = self.canvas.after(FRAME_MS, self._fade, a, b, elapsed + FRAME_MS)

    def _pulse(self, elapsed: int, limit: int) -> None:
        if elapsed >= limit:
            self.canvas.itemconfigure(self.item, fill=self.color)
            self.busy = False
            return
        phase = (elapsed % self.PULSE_MS) / self.PULSE_MS
        t = (1 - math.cos(phase * 2 * math.pi)) / 2
        self.canvas.itemconfigure(self.item, fill=mix(self.bg, self.color, 0.6 + 0.4 * t))
        self._job = self.canvas.after(50, self._pulse, elapsed + 50, limit)

    def _cancel(self) -> None:
        if self._job is not None:
            self.canvas.after_cancel(self._job)
            self._job = None


class ActivityBar:
    """Thin progress line. Indeterminate: a 25 % segment eases across in 1.4 s."""

    CYCLE_MS = 1400

    def __init__(self, parent: tk.Misc, height: int = 2, bg: str = BG) -> None:
        height = px(parent, height)
        self.canvas = tk.Canvas(parent, height=height, bg=bg, highlightthickness=0, bd=0)
        self.track = self.canvas.create_rectangle(0, 0, 0, height, fill=LINE, outline="")
        self.glow = self.canvas.create_rectangle(0, 0, 0, height, fill=TEXT, outline="", state="hidden")
        self.height = height
        self._job: str | None = None
        self._elapsed = 0
        self.canvas.bind("<Configure>", self._resize)

    def pack(self, **kw) -> None:
        self.canvas.pack(**kw)

    def _resize(self, _e: object = None) -> None:
        self.canvas.coords(self.track, 0, 0, self.canvas.winfo_width(), self.height)

    def start(self) -> None:
        if self._job is not None:
            return
        self.canvas.itemconfigure(self.glow, state="normal")
        if MOTION:
            self._tick()
        else:
            self.canvas.coords(self.glow, 0, 0, self.canvas.winfo_width(), self.height)

    def stop(self) -> None:
        if self._job is not None:
            self.canvas.after_cancel(self._job)
            self._job = None
        self.canvas.itemconfigure(self.glow, state="hidden")

    def _tick(self) -> None:
        w = max(1, self.canvas.winfo_width())
        seg = w * 0.25
        t = ease_in_out((self._elapsed % self.CYCLE_MS) / self.CYCLE_MS)
        x = -seg + t * (w + seg)
        self.canvas.coords(self.glow, x, 0, x + seg, self.height)
        self._elapsed += FRAME_MS
        self._job = self.canvas.after(FRAME_MS, self._tick)


class LogoMark:
    """The logo in the header. Static on purpose: scan progress has its own bar."""

    def __init__(self, parent: tk.Misc, size: int = 22, bg: str = BG) -> None:
        from PIL import ImageTk

        size = px(parent, size)
        self.canvas = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self._photo = ImageTk.PhotoImage(logo_image(size))
        self.canvas.create_image(0, 0, anchor="nw", image=self._photo)

    def pack(self, **kw) -> None:
        self.canvas.pack(**kw)


class RowFlash:
    """An actionable row appears with a faint severity tint that fades out once (333 ms)."""

    STEPS = 8

    def __init__(self, tv: ttk.Treeview, base: str = SURFACE) -> None:
        self.tv = tv
        for kind, color in (("bad", BAD), ("warn", WARN)):
            start = mix(base, color, 0.12)
            for i in range(self.STEPS):
                tv.tag_configure(f"flash-{kind}{i}", background=mix(start, base, ease_out(i / (self.STEPS - 1))))

    def add(self, iid: str, kind: str) -> None:
        if MOTION:
            self._step(iid, kind, 0)

    def _step(self, iid: str, kind: str, i: int) -> None:
        if not self.tv.exists(iid):
            return
        tags = [t for t in self.tv.item(iid, "tags") if not str(t).startswith("flash-")]
        if i < self.STEPS:
            tags.append(f"flash-{kind}{i}")
            self.tv.item(iid, tags=tags)
            self.tv.after(FADE_MS // self.STEPS, self._step, iid, kind, i + 1)
        else:
            self.tv.item(iid, tags=tags)


# -- icons and navigation ----------------------------------------------------

def draw_icon(c: tk.Canvas, name: str, x: float, y: float, s: float, color: str, w: float = 1.6) -> None:
    """Simple line icons drawn on a canvas; (x, y) is the top-left of an s x s box."""
    w = max(1.0, w * s / 24)
    cx, cy, r = x + s / 2, y + s / 2, s * 0.38
    if name == "home":
        o = s * 0.2
        c.create_rectangle(x + o, y + o, x + s - o, y + s - o, outline=color, width=w)
        c.create_rectangle(cx - s * 0.1, cy - s * 0.1, cx + s * 0.1, cy + s * 0.1, fill=color, outline="")
    elif name == "scan":
        rr = s * 0.28
        c.create_oval(cx - rr - s * 0.08, cy - rr - s * 0.08, cx + rr - s * 0.08, cy + rr - s * 0.08, outline=color, width=w)
        c.create_line(cx + rr * 0.55, cy + rr * 0.55, x + s * 0.86, y + s * 0.86, fill=color, width=w * 1.4, capstyle="round")
    elif name == "history":
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=color, width=w)
        c.create_line(cx, cy - r * 0.6, cx, cy, cx + r * 0.45, cy + r * 0.3, fill=color, width=w, capstyle="round")
    elif name == "quarantine":
        o = s * 0.2
        c.create_rectangle(x + o, y + s * 0.38, x + s - o, y + s - o, outline=color, width=w)
        c.create_line(x + o - s * 0.04, y + s * 0.38, x + s - o + s * 0.04, y + s * 0.38, fill=color, width=w)
        c.create_arc(cx - s * 0.17, y + s * 0.14, cx + s * 0.17, y + s * 0.56, start=0, extent=180, style="arc",
                     outline=color, width=w)
    elif name == "web":
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=color, width=w)
        c.create_oval(cx - r * 0.42, cy - r, cx + r * 0.42, cy + r, outline=color, width=w)
        c.create_line(cx - r, cy, cx + r, cy, fill=color, width=w)
    elif name == "realtime":
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=color, width=w)
        c.create_oval(cx - r * 0.55, cy - r * 0.55, cx + r * 0.55, cy + r * 0.55, outline=color, width=w)
        c.create_oval(cx - r * 0.16, cy - r * 0.16, cx + r * 0.16, cy + r * 0.16, fill=color, outline="")


class Icon:
    def __init__(self, parent: tk.Misc, name: str, size: int = 24, color: str = TEXT, bg: str = SURFACE) -> None:
        s = px(parent, size)
        self.canvas = tk.Canvas(parent, width=s, height=s, bg=bg, highlightthickness=0, bd=0)
        self.name, self.size = name, s
        self.set_color(color)

    def set_color(self, color: str) -> None:
        self.canvas.delete("all")
        draw_icon(self.canvas, self.name, 1, 1, self.size - 2, color)


class Switch:
    """On/off switch; the knob slides in 167 ms. Calls `command(new_state)` on click."""

    def __init__(self, parent: tk.Misc, command, bg: str = SURFACE) -> None:
        self.w, self.h = px(parent, 40), px(parent, 22)
        self.canvas = tk.Canvas(parent, width=self.w, height=self.h, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.command = command
        self.on = False
        self._pos = 0.0
        self._job: str | None = None
        self.canvas.bind("<Button-1>", lambda _e: self.command(not self.on))
        self._draw()

    def set(self, on: bool) -> None:
        if on == self.on:
            return
        self.on = on
        if self._job is not None:
            self.canvas.after_cancel(self._job)
        if MOTION:
            self._slide(self._pos, 1.0 if on else 0.0, 0)
        else:
            self._pos = 1.0 if on else 0.0
            self._draw()

    def _slide(self, a: float, b: float, elapsed: int) -> None:
        t = min(1.0, elapsed / FAST_MS)
        self._pos = a + (b - a) * ease_out(t)
        self._draw()
        if t < 1.0:
            self._job = self.canvas.after(FRAME_MS, self._slide, a, b, elapsed + FRAME_MS)

    def _draw(self) -> None:
        # Square track and knob: flat and technical rather than a rounded pill.
        c, w, h, p = self.canvas, self.w, self.h, self._pos
        c.delete("all")
        c.create_rectangle(0, 0, w - 1, h - 1, fill=mix(RAISED, OK, p), outline=mix(LINE, OK, p))
        pad = px(c, 3)
        k = h - 2 * pad
        kx = pad + p * (w - k - 2 * pad)
        c.create_rectangle(kx, pad, kx + k, pad + k, fill=TEXT if p > 0.5 else MUTED, outline="")


class Pages(ttk.Frame):
    """Content area driven by an icon sidebar; offers the bits of ttk.Notebook the panels use."""

    def __init__(self, parent: tk.Misc, sidebar: tk.Misc) -> None:
        super().__init__(parent)
        self.sidebar = sidebar
        self._frames: list[tk.Misc] = []
        self._buttons: dict[str, tuple[tk.Frame, Icon, ttk.Label, tk.Frame]] = {}
        self._current: tk.Misc | None = None

    def add(self, frame: tk.Misc, text: str = "", icon: str = "home") -> None:
        self._frames.append(frame)
        cell = tk.Frame(self.sidebar, bg=BG, cursor="hand2")
        cell.pack(fill="x", pady=px(self, 2))
        mark = tk.Frame(cell, bg=BG, width=px(self, 3))
        mark.pack(side="left", fill="y")
        inner = tk.Frame(cell, bg=BG)
        inner.pack(side="left", fill="x", expand=True, pady=px(self, 6))
        ic = Icon(inner, icon, 22, MUTED, BG)
        ic.canvas.pack()
        lbl = ttk.Label(inner, text=text, style="Nav.TLabel")
        lbl.pack(pady=(px(self, 3), 0))
        for wdg in (cell, inner, ic.canvas, lbl):
            wdg.bind("<Button-1>", lambda _e, f=frame: self.select(f))
        self._buttons[str(frame)] = (cell, ic, lbl, mark)

    def tabs(self) -> list[str]:
        return [str(f) for f in self._frames]

    def select(self, frame: tk.Misc | str) -> None:
        if isinstance(frame, str):
            frame = self.nametowidget(frame)
        if self._current is frame:
            return
        if self._current is not None:
            self._current.pack_forget()
        frame.pack(fill="both", expand=True)
        self._current = frame
        for key, (_cell, ic, lbl, mark) in self._buttons.items():
            on = key == str(frame)
            ic.set_color(TEXT if on else MUTED)
            lbl.configure(style="NavOn.TLabel" if on else "Nav.TLabel")
            mark.configure(bg=TEXT if on else BG)
