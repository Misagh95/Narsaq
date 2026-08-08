#!/usr/bin/env python3
"""ساخت آیکن Narsaq (.ico) — شبیه لوگوی وب UI: مربع نارنجی با حرف N."""
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "..", "assets", "narsaq.ico")
SIZE = 256


def _font(size):
    for p in [
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/segoeuib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ]:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


def make(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # گرادیان نارنجی عمودی (c75d00 -> ffa55e)
    steps = 64
    for i in range(steps):
        t = i / (steps - 1)
        r = int(0xC7 + (0xFF - 0xC7) * t)
        g = int(0x5D + (0xA5 - 0x5D) * t)
        b = int(0x00 + (0x5E - 0x00) * t)
        y0 = int(size * i / steps)
        y1 = int(size * (i + 1) / steps)
        d.rounded_rectangle(
            [(0, y0), (size - 1, y1)],
            radius=int(size * 0.22),
            fill=(r, g, b, 255),
        )

    # حرف N سفید وسط
    fnt = _font(int(size * 0.55))
    bbox = d.textbbox((0, 0), "N", font=fnt)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    x0 = (size - tw) // 2 - bbox[0]
    y0 = (size - th) // 2 - bbox[1]
    d.text((x0, y0), "N", font=fnt, fill=(255, 255, 255, 255))
    return img


def main():
    img = make(SIZE)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    print(f"icon: {OUT} ({os.path.getsize(OUT)} bytes)")


if __name__ == "__main__":
    main()
