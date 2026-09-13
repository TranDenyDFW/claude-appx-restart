#!/usr/bin/env python3
"""Render assets/ClaudeRestart.ico and assets/ClaudeRestart-256.png with Pillow.

The glyph is a neutral "recovery" mark: a warm circular arrow with a check mark
inside, on a charcoal rounded tile. It is drawn from scratch and deliberately
does not resemble any Anthropic or Claude branding.

    py -3 tools/make_icon.py          # regenerate both files
    py -3 tools/make_icon.py --check  # exit 1 if the committed files differ

Requires Pillow (see requirements-build.txt). The build never needs this script
unless the icon changes; the generated files are committed.
"""

from __future__ import annotations

import argparse
import io
import math
from pathlib import Path
import sys

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ICO_PATH = ROOT / "assets" / "ClaudeRestart.ico"
PNG_PATH = ROOT / "assets" / "ClaudeRestart-256.png"
SIZES = (16, 24, 32, 48, 64, 128, 256)
SUPERSAMPLE = 8

TILE = (43, 43, 46, 255)  # charcoal
ARROW = (217, 116, 74, 255)  # terracotta
CHECK = (245, 237, 227, 255)  # cream
TRANSPARENT = (0, 0, 0, 0)

ARC_START = 0  # degrees, Pillow convention: 0 at 3 o'clock, clockwise
ARC_END = 300  # the gap between 300 and 360 holds the arrowhead


def _polar(center: float, radius: float, degrees: float) -> tuple[float, float]:
    angle = math.radians(degrees)
    return center + radius * math.cos(angle), center + radius * math.sin(angle)


def render(size: int) -> Image.Image:
    """Draw one icon frame at `size` pixels, supersampled for smooth edges."""
    canvas = size * SUPERSAMPLE
    image = Image.new("RGBA", (canvas, canvas), TRANSPARENT)
    draw = ImageDraw.Draw(image)

    small = size <= 24
    draw.rounded_rectangle((0, 0, canvas - 1, canvas - 1), radius=canvas * 0.22, fill=TILE)

    stroke = canvas * (0.15 if small else 0.10)
    margin = canvas * (0.17 if small else 0.20)
    center = canvas / 2
    radius = center - margin
    draw.arc(
        (margin, margin, canvas - margin, canvas - margin),
        start=ARC_START,
        end=ARC_END,
        fill=ARROW,
        width=int(stroke),
    )

    # Arrowhead at the end of the arc, pointing along the clockwise tangent.
    tip_angle = math.radians(ARC_END)
    tangent = (-math.sin(tip_angle), math.cos(tip_angle))
    normal = (math.cos(tip_angle), math.sin(tip_angle))
    end_x, end_y = _polar(center, radius, ARC_END)
    head_length = stroke * 2.3
    head_width = stroke * 2.7
    back_x = end_x - tangent[0] * stroke * 0.35
    back_y = end_y - tangent[1] * stroke * 0.35
    tip = (back_x + tangent[0] * head_length, back_y + tangent[1] * head_length)
    left = (back_x + normal[0] * head_width / 2, back_y + normal[1] * head_width / 2)
    right = (back_x - normal[0] * head_width / 2, back_y - normal[1] * head_width / 2)
    draw.polygon([tip, left, right], fill=ARROW)

    if not small:
        # Kept inside the ring: farthest point plus half the stroke stays under the
        # ring's inner radius (0.25 of the canvas).
        check = [
            (center - canvas * 0.145, center + canvas * 0.005),
            (center - canvas * 0.045, center + canvas * 0.105),
            (center + canvas * 0.145, center - canvas * 0.105),
        ]
        check_width = stroke * 0.75
        draw.line(check, fill=CHECK, width=int(check_width), joint="curve")
        cap = check_width / 2
        for x, y in (check[0], check[-1]):
            draw.ellipse((x - cap, y - cap, x + cap, y + cap), fill=CHECK)

    return image.resize((size, size), Image.LANCZOS)


def build() -> tuple[bytes, bytes]:
    frames = {size: render(size) for size in SIZES}
    ico = io.BytesIO()
    frames[256].save(
        ico,
        format="ICO",
        sizes=[(size, size) for size in SIZES],
        append_images=[frames[size] for size in SIZES if size != 256],
    )
    png = io.BytesIO()
    frames[256].save(png, format="PNG", optimize=True)
    return ico.getvalue(), png.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the ClaudeRestart icon.")
    parser.add_argument("--check", action="store_true", help="compare with the committed files instead of writing")
    args = parser.parse_args()

    ico, png = build()
    if args.check:
        same_ico = ICO_PATH.is_file() and ICO_PATH.read_bytes() == ico
        same_png = PNG_PATH.is_file() and PNG_PATH.read_bytes() == png
        print(f"{ICO_PATH.name}: {'unchanged' if same_ico else 'DIFFERS'}")
        print(f"{PNG_PATH.name}: {'unchanged' if same_png else 'DIFFERS'}")
        return 0 if same_ico and same_png else 1

    ICO_PATH.parent.mkdir(parents=True, exist_ok=True)
    ICO_PATH.write_bytes(ico)
    PNG_PATH.write_bytes(png)
    print(f"wrote {ICO_PATH} ({len(ico)} bytes) and {PNG_PATH} ({len(png)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
