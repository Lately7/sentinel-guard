You are a senior product designer reviewing the desktop UI of Sentinel Guard,
the repository owner's own Windows 11 anti-malware prototype, in the current
directory. Read-only: do NOT modify, create or delete any file.

The attached images are the current UI (v3), rendered with harmless demo data:
1 home, 2 scan running, 3 scan with engine layers shown, 4 history,
5 home with real-time protection off. The code is
`agent/sentinel/theme.py` (palette, fonts, motion, icons, switch, sidebar),
`agent/sentinel/overview_ui.py` (home), `agent/sentinel/gate_ui.py` (scan),
`agent/sentinel/tray.py` (window, history, quarantine, web pages).
Earlier versions for comparison: `docs/ui/v1-dashboard.png`, `docs/ui/v2/`.
Your earlier critique is in `docs/handoff/codex-product-r6.md` part 5.

Owner's direction (Vietnamese, paraphrased): the feel of Malwarebytes but not
a copy; technical and simple; very little text; dark; crisp; compact; subtle
animation; the logo is a small flat square inside a detached thin frame.
Constraints: Tkinter/ttk on Windows only (Canvas drawing allowed, no web view,
no new dependencies beyond Pillow), no third-party logos or brand assets.

Give, concretely and briefly:

1. The 10 changes with the biggest visual payoff, ranked. For each: what is
   wrong in the screenshot, the exact change (sizes in px at 96 DPI, colours
   as hex, font size/weight, spacing, alignment), and which function/line in
   the code to change.
2. Text to remove or shorten, item by item (Vietnamese), so each page reads
   in under three seconds.
3. Layout of the home page as a precise spec (grid, sizes, spacing,
   hierarchy), and of the scan page while idle, while running, and when
   finished with results.
4. Motion: what to animate on each page (state change, scan progress, scan
   finished, tile hover, switch), with durations/easing, and what must stay
   static. Respect "Show animations" off.
5. Iconography: review the canvas-drawn icons (home, scan, history,
   quarantine, web, realtime) and the state mark; propose exact geometry for
   any that read poorly at 22 px.
6. Anything that looks unfinished or "AI-generated", and how to fix it.

Answer in English, Markdown, with file:line references. Do not propose
features beyond the UI; do not claim to have run anything you did not run.
