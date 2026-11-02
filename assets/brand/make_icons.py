"""Generate Sentinel Guard icons from pixel-snapped geometry.

The SVG files are the vector references. Raster output is drawn directly so
small icon sizes never depend on a generic SVG rasterizer or downscaling.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

RGBA = tuple[int, int, int, int]
RGB = tuple[int, int, int]

CORE_TOP: RGB = (5, 5, 6)
CORE_BOTTOM: RGB = (112, 112, 118)
RINGS: dict[str, RGB] = {
    "normal": (116, 116, 122),  # #74747a
    "warning": (212, 163, 42),  # #d4a32a
    "threat": (224, 82, 74),  # #e0524a
}
SIZES = (16, 24, 32, 48, 64, 128, 256)
ICO_SIZES = (16, 24, 32, 48, 64, 256)


def _mix(a: RGB, b: RGB, amount: float) -> RGB:
    return tuple(round(x + (y - x) * amount) for x, y in zip(a, b))  # type: ignore[return-value]


def _geometry(size: int) -> tuple[int, int, int]:
    """Return outer inset, stroke, and clear gap in whole device pixels."""
    if size < 16:
        raise ValueError("icon size must be at least 16 pixels")
    inset = round(size / 64)
    stroke = max(1, round(size / 32))
    gap = max(2, round(size * 5 / 64))
    return inset, stroke, gap


def draw_icon(size: int, state: str = "normal") -> Image.Image:
    """Draw one icon at its final size, with no post-draw resampling."""
    try:
        ring = RINGS[state]
    except KeyError as exc:
        raise ValueError(f"unknown state: {state}") from exc

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    inset, stroke, gap = _geometry(size)
    outer_end = size - 1 - inset
    draw.rectangle(
        (inset, inset, outer_end, outer_end),
        outline=ring + (255,),
        width=stroke,
    )

    core_start = inset + stroke + gap
    core_end = size - 1 - core_start
    height = core_end - core_start
    for y in range(core_start, core_end + 1):
        linear = (y - core_start) / max(1, height)
        colour = _mix(CORE_TOP, CORE_BOTTOM, linear * linear)
        draw.line((core_start, y, core_end, y), fill=colour + (255,))
    return image


def _save_png(image: Image.Image, path: Path) -> None:
    image.save(path, format="PNG", optimize=True, compress_level=9)


def _make_preview() -> Image.Image:
    margin = 24
    label_width = 62
    tile_pad = 6
    pair_gap = 8
    state_gap = 18
    row_gap = 16
    label_height = 18
    widest_pair = 2 * (max(SIZES) + 2 * tile_pad) + pair_gap
    width = margin * 2 + label_width + 3 * widest_pair + 2 * state_gap
    height = margin * 2 + sum(size + label_height + row_gap for size in SIZES)

    preview = Image.new("RGB", (width, height), (29, 29, 32))
    draw = ImageDraw.Draw(preview)
    font = ImageFont.load_default()
    dark: RGB = (11, 11, 12)
    light: RGB = (243, 243, 243)
    ink: RGB = (224, 224, 226)
    quiet: RGB = (150, 150, 156)

    y = margin
    for size in SIZES:
        tile = size + 2 * tile_pad
        pair_width = 2 * tile + pair_gap
        draw.text((margin, y + label_height + tile_pad), f"{size}px", fill=ink, font=font)
        x = margin + label_width
        for state in ("normal", "warning", "threat"):
            draw.text((x, y), state.upper(), fill=quiet, font=font)
            icon = draw_icon(size, state)
            tile_y = y + label_height
            draw.rectangle((x, tile_y, x + tile - 1, tile_y + tile - 1), fill=dark)
            preview.paste(icon, (x + tile_pad, tile_y + tile_pad), icon)
            light_x = x + tile + pair_gap
            draw.rectangle((light_x, tile_y, light_x + tile - 1, tile_y + tile - 1), fill=light)
            preview.paste(icon, (light_x + tile_pad, tile_y + tile_pad), icon)
            x += pair_width + state_gap
        y += label_height + tile + row_gap
    return preview


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    for size in (16, 48, 128):
        _save_png(draw_icon(size), OUT / f"icon{size}.png")

    ico_frames = [draw_icon(size) for size in ICO_SIZES]
    ico_frames[-1].save(
        OUT / "sentinel.ico",
        format="ICO",
        sizes=[(size, size) for size in ICO_SIZES],
        append_images=ico_frames[:-1],
    )

    for state in ("normal", "warning", "threat"):
        _save_png(draw_icon(64, state), OUT / f"tray-{state}.png")

    _save_png(_make_preview(), OUT / "preview.png")


if __name__ == "__main__":
    main()
