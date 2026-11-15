#!/usr/bin/env python3
"""Draw assets/icon.png (64x64): a log page with an information badge. Stdlib only."""

import struct
import zlib
from pathlib import Path

S = 64
img = [[(0, 0, 0, 0)] * S for _ in range(S)]


def rect(x0, y0, w, h, c):
    for y in range(max(0, y0), min(S, y0 + h)):
        for x in range(max(0, x0), min(S, x0 + w)):
            img[y][x] = c


def disc(cx, cy, r, c):
    for y in range(S):
        for x in range(S):
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                img[y][x] = c


K, W, G, D, N, B = (10, 10, 10, 255), (255, 255, 255, 255), (192, 192, 192, 255), (128, 128, 128, 255), (0, 0, 128, 255), (0, 0, 192, 255)
rect(8, 4, 40, 54, K)          # page outline
rect(10, 6, 36, 50, W)         # page
rect(10, 6, 36, 8, N)          # title band
for i, y in enumerate(range(20, 52, 6)):
    rect(14, y, 6, 3, (224, 0, 0, 255) if i == 1 else (230, 200, 0, 255) if i == 3 else B)  # type marks
    rect(23, y, 19 - (i % 3) * 3, 3, D)                                                       # text lines
disc(46, 46, 14, K)
disc(46, 46, 12, B)
rect(44, 37, 4, 4, W)
rect(44, 43, 4, 11, W)

raw = b"".join(b"\x00" + b"".join(bytes(p) for p in row) for row in img)


def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


out = Path(__file__).resolve().parents[1] / "assets" / "icon.png"
out.parent.mkdir(exist_ok=True)
out.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", S, S, 8, 6, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
print(out, out.stat().st_size, "bytes")
