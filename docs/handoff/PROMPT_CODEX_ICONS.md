You are designing the icon set for Sentinel Guard, the repository owner's own
Windows 11 anti-malware prototype, in this git worktree.

## Scope (strict)

You may create or modify files ONLY under `assets/brand/`. Do not touch any
other path: no production code, tests, extension files, or documentation
outside `assets/brand/`. Claude integrates your output into the app later and
checks `git status` for anything outside that folder.

## Brief from the owner

- A small black square logo with a thin outline around it.
- Colour runs from black to grey ("đen > xám"): the square is black and eases
  to grey; the outline is thin and dark.
- Dark product theme, crisp, compact, not "AI-looking": no glow, no shield
  cliché, no gradients beyond the black-to-grey ramp, no text in the icon.
- It must stay legible at 16x16 in the Windows tray on BOTH a dark and a light
  taskbar, and in the Chromium toolbar on dark and light themes. Pixel-snap the
  small sizes by hand rather than relying on downscaling.
- The tray outline colour carries state: normal (neutral grey), warning
  (amber, real-time protection off), threat (red). Same shape in every state.

Reference: the current procedural version is `logo_image()` in
`agent/sentinel/theme.py` (read it; do not edit it).

## Deliverables in `assets/brand/`

1. `logo.svg` — master vector (and `logo-16.svg` if the 16 px needs its own
   hand-tuned geometry).
2. `make_icons.py` — deterministic generator, Python 3.12+, Pillow only, no
   network. It writes into `assets/brand/out/`:
   - `icon16.png`, `icon48.png`, `icon128.png` (extension toolbar/store sizes)
   - `sentinel.ico` with 16, 24, 32, 48, 64, 256
   - `tray-normal.png`, `tray-warning.png`, `tray-threat.png` (64x64)
   - `preview.png`: every size and state on a dark (#0b0b0c) and a light
     (#f3f3f3) background side by side, for review.
3. Run the generator. Pillow is available in the interpreter at
   `C:\Users\lately07\Desktop\Folder Group\sentinel-guard\.venv\Scripts\python.exe`
   (use it by absolute path; do not install anything).
4. `README.md` in `assets/brand/` — design rationale in a few lines, colour
   values, how to regenerate, and how Claude should wire the outputs in
   (which file replaces which).

Look at your own `preview.png` before finishing and fix anything that is
blurry or illegible at 16 px. Report what you created and the exact command you
ran with its result. Never claim a command ran unless you ran it.
