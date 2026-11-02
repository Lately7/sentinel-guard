# Sentinel Guard icon set

The mark is deliberately literal: one compact square, a one-colour status
outline, and a black core easing to grey. There is no glow, symbol, text, or
decorative effect. `logo-16.svg` and every small raster are separately
pixel-snapped so the one-pixel outline stays crisp.

Colours: core `#050506` → `#707076`; normal outline `#74747a`; warning outline
`#d4a32a`; threat outline `#e0524a`. The canvas outside the mark is transparent.

Regenerate from PowerShell:

```powershell
& 'C:\Users\lately07\Desktop\Folder Group\sentinel-guard\.venv\Scripts\python.exe' .\assets\brand\make_icons.py
```

Integration map for Claude:

- Copy `out/icon16.png`, `out/icon48.png`, and `out/icon128.png` over the same
  names in `extension/icons/`; the manifest and notification icon already point
  there.
- Use `out/sentinel.ico` for Windows executable/package shortcuts and the app
  window icon where a multi-resolution ICO is accepted.
- Replace the images produced by `theme.logo_image(64, ring)` in the tray with
  `out/tray-normal.png`, `out/tray-warning.png`, and `out/tray-threat.png` for
  protected, real-time protection off, and threat states respectively.
- `logo.svg` is the general vector master; use `logo-16.svg` when a true 16 px
  vector surface is required.
