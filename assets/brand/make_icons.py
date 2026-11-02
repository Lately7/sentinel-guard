"""Generate Sentinel Guard icons from pixel-snapped, flat-colour geometry.

Raster output is drawn directly at every target size. No target is produced by
resampling another icon, which keeps the 16, 24, and 32 px frames crisp.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"

RGB = tuple[int, int, int]

CORES: dict[str, RGB] = {
    "black": (10, 10, 11),  # #0a0a0b
    "grey": (110, 110, 116),  # #6e6e74
}
FRAMES: dict[str, RGB] = {
    "normal": (116, 116, 122),  # #74747a
    "warning": (212, 163, 42),  # #d4a32a
    "threat": (224, 82, 74),  # #e0524a
}
SIZES = (16, 24, 32, 48, 64, 128, 256)
ICO_SIZES = (16, 24, 32, 48, 64, 256)


def _round_half_up(numerator: int, denominator: int) -> int:
    """Round a positive rational without Python's round-to-even behaviour."""
    return (2 * numerator + denominator) // (2 * denominator)


def geometry(size: int) -> tuple[int, int, int]:
    """Return outer inset, frame stroke, and core side in device pixels."""
    if size < 16:
        raise ValueError("icon size must be at least 16 pixels")
    inset = _round_half_up(3 * size, 32)
    stroke = max(1, _round_half_up(size, 16))
    core_side = 7 * size // 16
    return inset, stroke, core_side


def draw_icon(
    size: int,
    state: str = "normal",
    core: str = "black",
) -> Image.Image:
    """Draw one icon at its final size, with no post-draw resampling."""
    try:
        frame_colour = FRAMES[state]
    except KeyError as exc:
        raise ValueError(f"unknown state: {state}") from exc
    try:
        core_colour = CORES[core]
    except KeyError as exc:
        raise ValueError(f"unknown core: {core}") from exc

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    inset, stroke, core_side = geometry(size)

    frame_end = size - 1 - inset
    draw.rectangle(
        (inset, inset, frame_end, frame_end),
        outline=frame_colour + (255,),
        width=stroke,
    )

    core_start = (size - core_side) // 2
    core_end = core_start + core_side - 1
    draw.rectangle(
        (core_start, core_start, core_end, core_end),
        fill=core_colour + (255,),
    )
    return image


def _save_png(image: Image.Image, path: Path) -> None:
    image.save(path, format="PNG", optimize=True, compress_level=9)


def _make_preview() -> Image.Image:
    margin = 24
    label_width = 58
    tile_pad = 6
    pair_gap = 8
    state_gap = 16
    variant_gap = 30
    row_gap = 16
    row_header = 32

    max_tile = max(SIZES) + 2 * tile_pad
    max_pair = 2 * max_tile + pair_gap
    max_group = 3 * max_pair + 2 * state_gap
    width = margin * 2 + label_width + 2 * max_group + variant_gap
    height = margin * 2 + sum(
        row_header + size + 2 * tile_pad + row_gap for size in SIZES
    )

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
        group_width = 3 * pair_width + 2 * state_gap
        tile_y = y + row_header
        draw.text((margin, tile_y + tile_pad), f"{size}px", fill=ink, font=font)

        x = margin + label_width
        for core in ("black", "grey"):
            draw.text((x, y), f"{core.upper()} CORE", fill=ink, font=font)
            state_x = x
            for state in ("normal", "warning", "threat"):
                draw.text(
                    (state_x, y + 14),
                    f"{state[0].upper()}  DARK / LIGHT",
                    fill=quiet,
                    font=font,
                )
                icon = draw_icon(size, state, core)
                draw.rectangle(
                    (state_x, tile_y, state_x + tile - 1, tile_y + tile - 1),
                    fill=dark,
                )
                preview.paste(icon, (state_x + tile_pad, tile_y + tile_pad), icon)
                light_x = state_x + tile + pair_gap
                draw.rectangle(
                    (light_x, tile_y, light_x + tile - 1, tile_y + tile - 1),
                    fill=light,
                )
                preview.paste(icon, (light_x + tile_pad, tile_y + tile_pad), icon)
                state_x += pair_width + state_gap
            x += group_width + variant_gap

        y += row_header + tile + row_gap
    return preview


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--core",
        choices=tuple(CORES),
        default="black",
        help="flat core colour to generate (default: black)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    destination = OUT if args.core == "black" else OUT / "grey"
    destination.mkdir(parents=True, exist_ok=True)

    for size in (16, 48, 128):
        _save_png(
            draw_icon(size, core=args.core),
            destination / f"icon{size}.png",
        )

    ico_frames = [draw_icon(size, core=args.core) for size in ICO_SIZES]
    ico_frames[-1].save(
        destination / "sentinel.ico",
        format="ICO",
        sizes=[(size, size) for size in ICO_SIZES],
        append_images=ico_frames[:-1],
    )

    for state in FRAMES:
        _save_png(
            draw_icon(64, state, args.core),
            destination / f"tray-{state}.png",
        )

    _save_png(_make_preview(), destination / "preview.png")


if __name__ == "__main__":
    main()
