# Sentinel Guard icon set

The mark is a small, flat-colour square inside a detached status frame. There
is no gradient, glow, symbol, text, or rounded decoration. The transparent gap
makes the compact core and frame read as separate forms at tray size.

## Colours

- Black core (default): `#0a0a0b`
- Grey core: `#6e6e74`
- Normal frame: `#74747a`
- Warning frame: `#d4a32a`
- Threat frame: `#e0524a`
- Preview backgrounds: dark `#0b0b0c`, light `#f3f3f3`

Everything outside the frame is transparent.

## Exact geometry

For a square canvas of side `S` pixels, the raster generator uses whole device
pixels and draws directly at the final size:

- frame outer inset: round-half-up(`3S / 32`) = 9.375% nominal;
- frame stroke: round-half-up(`S / 16`) = 6.25% nominal;
- core side: floor(`7S / 16`) = 43.75% maximum;
- core origin on each axis: floor(`(S - core_side) / 2`).

The supported `16/24/32/48/64/128/256` sizes therefore use insets
`2/2/3/5/6/12/24`, strokes `1/2/2/3/4/8/16`, and core sides
`7/10/14/21/28/56/112`. The clear core-to-frame gap is 1--2 stroke pixels at
16 px (the unavoidable odd-pixel split), 1.5 strokes at 24 px, and 1.67--2
strokes at the larger supported sizes. When an odd core leaves one extra pixel,
it is placed on the right and bottom. These are the ratios and rounding rules
to mirror in `agent/sentinel/theme.py`.

`logo.svg` is the 64 px black-core master. `logo-16.svg` uses hand-snapped 16
px coordinates; change its core fill to `#6e6e74` when a grey vector is needed.

## Regenerate

From the repository root in PowerShell, generate both canonical variants:

```powershell
& 'C:\Users\lately07\Desktop\Folder Group\sentinel-guard\.venv\Scripts\python.exe' .\assets\brand\make_icons.py
& 'C:\Users\lately07\Desktop\Folder Group\sentinel-guard\.venv\Scripts\python.exe' .\assets\brand\make_icons.py --core grey
```

The default black set is written to `out/`; the grey set, with the same file
names, is written to `out/grey/`. Each `preview.png` contains both variants,
all seven sizes, all three frame states, and both preview backgrounds.

## Integration map for Claude

- Copy `out/icon16.png`, `out/icon48.png`, and `out/icon128.png` over the same
  names in `extension/icons/`; use `out/grey/` instead when the grey core is
  selected.
- Use the selected `sentinel.ico` for Windows executable/package shortcuts and
  the app window icon where a multi-resolution ICO is accepted.
- Replace the images produced by `theme.logo_image(64, ring)` with the selected
  `tray-normal.png`, `tray-warning.png`, and `tray-threat.png` for protected,
  real-time protection off, and threat states respectively.
- `logo.svg` is the general vector master; use `logo-16.svg` on a true 16 px
  vector surface.
